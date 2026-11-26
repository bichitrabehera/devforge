"""Integration tests over REAL localhost sockets.

Each service (registry, IdP, three nodes, messaging endpoint) runs as an
in-process threaded server here (the same code paths as the subprocess
deployment in demo_networked.py, which spawns them as separate OS
processes). Timing assertions use the REAL clock and real poll intervals.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import crypto, netutil, tokens  # noqa: E402
from src.messaging import CONTEXT, _msg_aad, _key_commitment  # noqa: E402


class NetworkedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dirs = {k: tempfile.mkdtemp(prefix="t4net_%s_" % k)
                for k in ("reg", "idp", "na", "nb", "nc", "recv")}
        os.environ["TRACK4_REGISTRY_DIR"] = dirs["reg"]
        os.environ["TRACK4_IDP_DIR"] = dirs["idp"]
        cls.dirs = dirs
        import services.registry_server as reg
        import services.idp_server as idp
        import services.node_server as node
        import services.messenger_server as msgr
        cls.reg, cls.idp, cls.node = reg, idp, node
        reg.IDP_BASE = None   # set after ports are known (setUpClass)
        ports = {k: netutil.free_port()
                 for k in ("reg", "idp", "na", "nb", "nc", "recv")}
        cls.base = {k: "http://127.0.0.1:%d" % v for k, v in ports.items()}
        cls.reg_state = reg._load_or_recover()
        netutil.serve(reg.ROUTES, ports["reg"], state=cls.reg_state)
        netutil.serve(idp.ROUTES, ports["idp"])
        cls.na = node.Node("node-a", ports["na"], cls.base["reg"],
                           cls.base["idp"], 0.3, dirs["na"])
        cls.nb = node.Node("node-b", ports["nb"], cls.base["reg"],
                           cls.base["idp"], 1.0, dirs["nb"])
        cls.nc = node.Node("node-c", ports["nc"], cls.base["reg"],
                           cls.base["idp"], 1.5, dirs["nc"])
        netutil.serve(node.build_routes(cls.na), ports["na"])
        netutil.serve(node.build_routes(cls.nb), ports["nb"])
        netutil.serve(node.build_routes(cls.nc), ports["nc"])
        for n in (cls.na, cls.nb, cls.nc):
            threading.Thread(target=n.poll_loop, daemon=True).start()
        cls.recv = msgr.Endpoint("recv", ports["recv"], "user-blair",
                                 "user-alex", idp=cls.base["idp"],
                                 registry=cls.base["reg"])
        netutil.serve(msgr.build_routes(cls.recv), ports["recv"])
        cls.REQ = staticmethod(
            lambda url, payload=None, method=None:
                netutil.request(url, payload, method)[1])
        assert netutil.wait_healthy(cls.base["reg"])
        assert netutil.wait_healthy(cls.base["idp"])
        reg.IDP_BASE = cls.base["idp"]   # control-plane auth wired
        reg._jwks_pk = None              # fresh JWKS fetch for this IdP
        # shared setup: identities, policy, tokens (all tests read-only here)
        R = cls.REQ
        # device keys for proof-of-possession token issuance
        cls.dev_alex = crypto.dsa_keypair()
        cls.dev_blair = crypto.dsa_keypair()
        cls.dev_carol = crypto.dsa_keypair()
        R(cls.base["idp"] + "/register",
          {"identity": "user-alex", "device": "device-alex",
           "dsa_pk": cls.dev_alex[0].hex()}, "POST")
        R(cls.base["idp"] + "/register",
          {"identity": "user-blair", "device": "device-blair",
           "dsa_pk": cls.dev_blair[0].hex()}, "POST")
        R(cls.base["idp"] + "/register",
          {"identity": "user-carol", "device": "device-carol",
           "dsa_pk": cls.dev_carol[0].hex()}, "POST")
        R(cls.base["reg"] + "/setup",
          {"owners": {"report.txt": "user-alex",
                      "notes.txt": "user-blair"},
           "contents": {"report.txt": "Q3 numbers are green",
                        "notes.txt": "blair's own notes"},
           "grace_seconds": 2.0}, "POST")
        for ident, device in (("user-alex", "device-alex"),
                              ("user-blair", "device-blair"),
                              ("user-carol", "device-carol"),
                              ("node-a", "node-a"), ("node-b", "node-b"),
                              ("node-c", "node-c"),
                              ("gossip-node", "gossip-node")):
            R(cls.base["reg"] + "/identities/register",
              {"identity": ident, "device": device}, "POST")
        req = tokens.device_proof(cls.dev_alex[1].hex(), "user-alex",
                                  "device-alex")
        req["ttl_s"] = 900
        cls.tok = R(cls.base["idp"] + "/token", req, "POST")["token"]
        req = tokens.device_proof(cls.dev_blair[1].hex(), "user-blair",
                                  "device-blair")
        req["ttl_s"] = 900
        cls.tokb = R(cls.base["idp"] + "/token", req, "POST")["token"]
        req = tokens.device_proof(cls.dev_carol[1].hex(), "user-carol",
                                  "device-carol")
        req["ttl_s"] = 900
        cls.tokc = R(cls.base["idp"] + "/token", req, "POST")["token"]
        time.sleep(1.3)   # real poll intervals apply the initial policy

    @classmethod
    def tearDownClass(cls):
        for d in cls.dirs.values():
            shutil.rmtree(d, ignore_errors=True)

    def test_01_identity_tokens_and_reads(self):
        R = self.REQ
        r = R(self.base["na"] + "/read",
              {"token": self.tok, "asset": "report.txt"}, "POST")
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["body"], "Q3 numbers are green")
        r = R(self.base["na"] + "/read",
              {"token": self.tokb, "asset": "report.txt"}, "POST")
        self.assertEqual(r["decision"], "deny")
        # expired token (real clock: TTL already in the past)
        expired = tokens.issue(self.idp.KEYS["dsa_sk"], "user-alex",
                               "device-alex", ttl_s=-1.0)
        r = R(self.base["na"] + "/read",
              {"token": expired, "asset": "report.txt"}, "POST")
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "token_expired")

    def test_02_rotation_real_cutoff(self):
        R = self.REQ
        r = R(self.base["reg"] + "/keys/rotate", {"grace_seconds": 2.0},
              "POST")
        v_old = r["old_version"]
        time.sleep(0.5)     # node-a's poll applies the new version
        r = R(self.base["na"] + "/authenticate",
              {"token": self.tok, "key_version": v_old}, "POST")
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r.get("outcome"), "grace")
        time.sleep(2.2)     # REAL cutoff elapses
        r = R(self.base["na"] + "/authenticate",
              {"token": self.tok, "key_version": v_old}, "POST")
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "old_key_after_cutoff")
        # node-c (slowest poll) applies the new version by its own poll
        v_new = R(self.base["reg"] + "/keys/current")["version"]
        r = R(self.base["nc"] + "/authenticate",
              {"token": self.tok, "key_version": v_new}, "POST")
        self.assertEqual(r["decision"], "allow")

    def test_03_revocation_real_propagation(self):
        R = self.REQ
        # self-service revoke: token subject must match the actor
        r = R(self.base["reg"] + "/revoke",
              {"actor": "user-carol", "device": "device-carol",
               "token": self.tokc}, "POST")
        t0 = time.time()
        # Nodes converge by real polling (node-a: 0.3 s): wait until the
        # revocation is genuinely enforced (reason == "revoked"), not a
        # routine not-owner denial that would pass trivially.
        deadline = t0 + 3.0
        while time.time() < deadline:
            r = R(self.base["na"] + "/read",
                  {"token": self.tokc, "asset": "report.txt"}, "POST")
            if r["decision"] == "deny" and r.get("reason") == "revoked":
                break
            time.sleep(0.05)
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "revoked")
        self.assertLess(time.time() - t0, 3.0)   # enforced within a poll
        r = R(self.base["na"] + "/read",
              {"token": self.tok, "asset": "report.txt"}, "POST")
        self.assertEqual(r["decision"], "allow")  # others unaffected
        # node-b must ALSO enforce (real poll) - every node is checked
        deadline = time.time() + 4.0
        rb = None
        while time.time() < deadline:
            rb = R(self.base["nb"] + "/read",
                   {"token": self.tokc, "asset": "report.txt"}, "POST")
            if rb["decision"] == "deny" and rb.get("reason") == "revoked":
                break
            time.sleep(0.1)
        self.assertEqual(rb["decision"], "deny")
        self.assertEqual(rb["reason"], "revoked")
        # node-c is the slowest poller: it must ALSO enforce (real poll)
        deadline = time.time() + 4.0
        while time.time() < deadline:
            rc = R(self.base["nc"] + "/read",
                   {"token": self.tokc, "asset": "report.txt"}, "POST")
            if rc["decision"] == "deny" and rc.get("reason") == "revoked":
                break
            time.sleep(0.1)
        self.assertEqual(rc["decision"], "deny")
        self.assertEqual(rc["reason"], "revoked")
        # measured, real propagation recorded by each node
        status = R(self.base["na"] + "/status")
        self.assertTrue(status["enforcement_log"])
        self.assertGreaterEqual(
            status["enforcement_log"][-1]["propagation_s"], 0.0)
        status_c = R(self.base["nc"] + "/status")
        self.assertTrue(status_c["enforcement_log"])


    def test_07_control_plane_and_session_auth(self):
        """Second-pass audit findings: unauthenticated control plane,
        identity re-registration, sender spoofing - all now closed."""
        R = self.REQ
        # 1. unauthenticated revoke refused
        r = R(self.base["reg"] + "/revoke",
              {"actor": "user-alex", "device": "device-alex"}, "POST")
        self.assertEqual(r["message"], "unauthorized")
        # 2. another user's token cannot revoke someone else
        r = R(self.base["reg"] + "/revoke",
              {"actor": "user-blair", "device": "device-blair",
               "token": self.tok}, "POST")     # alex's token
        self.assertEqual(r["message"], "unauthorized")
        self.assertEqual(r["reason"], "not_permitted")
        # 3. identity re-registration refused: different device or key
        r = R(self.base["idp"] + "/register",
              {"identity": "user-alex", "device": "attacker-device",
               "dsa_pk": self.dev_alex[0].hex()}, "POST")
        self.assertEqual(r["message"], "identity_exists")
        atk_pk, atk_sk = crypto.dsa_keypair()
        r = R(self.base["idp"] + "/register",
              {"identity": "user-alex", "device": "device-alex",
               "dsa_pk": atk_pk.hex()}, "POST")
        self.assertEqual(r["message"], "identity_exists")
        # idempotent same-device+key registration still works
        r = R(self.base["idp"] + "/register",
              {"identity": "user-alex", "device": "device-alex",
               "dsa_pk": self.dev_alex[0].hex()}, "POST")
        self.assertEqual(r["status"], "ok")
        # 3b. token issuance WITHOUT proof-of-possession refused
        r = R(self.base["idp"] + "/token",
              {"identity": "user-alex", "ttl_s": 60}, "POST")
        self.assertEqual(r["message"], "proof_required")
        # token with a WRONG device key refused
        req = tokens.device_proof(atk_sk.hex(), "user-alex", "device-alex")
        r = R(self.base["idp"] + "/token", req, "POST")
        self.assertEqual(r["message"], "bad_proof")
        # token with a STALE timestamp refused (replay window)
        stale = tokens.device_proof(self.dev_alex[1].hex(), "user-alex",
                                    "device-alex", ts=time.time() - 300)
        r = R(self.base["idp"] + "/token", stale, "POST")
        self.assertEqual(r["message"], "proof_stale")
        # token for an UNREGISTERED identity refused
        req = tokens.device_proof(atk_sk.hex(), "user-mallory", "dev-x")
        r = R(self.base["idp"] + "/token", req, "POST")
        self.assertEqual(r["message"], "unknown_identity")
        # 3c. a VALID proof is single-use: replaying it is refused even
        # inside the freshness window (fourth-pass audit finding)
        replay = tokens.device_proof(self.dev_alex[1].hex(), "user-alex",
                                     "device-alex")
        r = R(self.base["idp"] + "/token", dict(replay), "POST")
        self.assertEqual(r["status"], "ok")
        r = R(self.base["idp"] + "/token", dict(replay), "POST")
        self.assertEqual(r["message"], "proof_replayed")
        # 3c-2. Changing UNSIGNED fields must not make a used proof fresh.
        replay2 = tokens.device_proof(self.dev_alex[1].hex(), "user-alex",
                                      "device-alex")
        r = R(self.base["idp"] + "/token", dict(replay2), "POST")
        self.assertEqual(r["status"], "ok")
        tweaked = dict(replay2, ttl_s=120, clock_skew=86400.0)
        r = R(self.base["idp"] + "/token", tweaked, "POST")
        self.assertEqual(r["message"], "proof_replayed")
        # 3d. ttl_s is capped server-side: a 24h request yields <= 1h
        big = tokens.device_proof(self.dev_alex[1].hex(), "user-alex",
                                  "device-alex")
        big["ttl_s"] = 86400
        r = R(self.base["idp"] + "/token", big, "POST")
        self.assertEqual(r["status"], "ok")
        self.assertLessEqual(r["ttl_s"], 3600.0)
        payload, err = tokens.verify(
            self.idp.KEYS["dsa_pk"], r["token"])
        self.assertIsNone(err)
        self.assertLessEqual(payload["exp"] - payload["iat"], 3601.0)
        # 3e. client clock_skew is ignored by the IdP; a future-dated iat
        # is rejected by every verifier (node read path exercised here).
        skew_req = tokens.device_proof(self.dev_alex[1].hex(), "user-alex",
                                       "device-alex")
        skew_req["clock_skew"] = 86400.0
        r = R(self.base["idp"] + "/token", skew_req, "POST")
        self.assertEqual(r["status"], "ok")
        payload, err = tokens.verify(self.idp.KEYS["dsa_pk"], r["token"])
        self.assertIsNone(err)
        self.assertLessEqual(payload["iat"], time.time() + 2.0)
        future = tokens.issue(self.idp.KEYS["dsa_sk"], "user-alex",
                              "device-alex", ttl_s=600, skew=86400.0)
        r = R(self.base["na"] + "/read",
              {"token": future, "asset": "report.txt"}, "POST")
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "token_not_yet_valid")
        # 4. messaging session offer without a token refused
        r = R(self.base["recv"] + "/session/offer",
              {"sender": "user-alex"}, "POST")
        self.assertEqual(r["message"], "unauthorized")
        # 5. offer + establish with MISMATCHED tokens refused
        offer = R(self.base["recv"] + "/session/offer",
                  {"sender": "user-alex", "token": self.tok}, "POST")
        ct, _ = crypto.kem_encaps(
            bytes.fromhex(offer["encapsulation_key"]))
        r = R(self.base["recv"] + "/session/establish",
              {"sid": offer["sid"], "ciphertext": ct.hex(),
               "sender": "user-alex", "token": self.tokb}, "POST")
        # blair's token is valid but the offer was bound to alex's device
        self.assertEqual(r["message"], "device_mismatch")
        # establish with the right token works
        ct2, _ = crypto.kem_encaps(
            bytes.fromhex(offer["encapsulation_key"]))
        r = R(self.base["recv"] + "/session/establish",
              {"sid": offer["sid"], "ciphertext": ct2.hex(),
               "sender": "user-alex", "token": self.tok}, "POST")
        self.assertEqual(r["state"], "established")
        # 6. envelope with a spoofed sender refused (must match session)
        env = {"sid": offer["sid"], "sender": "user-mallory",
               "recipient": "user-blair", "counter": 1,
               "msg_id": "f" * 24, "nonce": "0" * 24, "ciphertext": "00",
               "context": CONTEXT,
               "key_version": R(self.base["reg"] + "/keys/current")["version"]}
        r = R(self.base["recv"] + "/message/receive", env, "POST")
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "sender_mismatch")

    def test_04_backup_and_log_integrity(self):
        R = self.REQ
        R(self.base["reg"] + "/backup", {"backup_id": "it-bak"}, "POST")
        R(self.base["reg"] + "/damage_backup", {"backup_id": "it-bak"},
          "POST")
        r = R(self.base["reg"] + "/restore_backup",
              {"backup_id": "it-bak"}, "POST")
        self.assertEqual(r["message"], "backup_integrity_failure")
        self.assertFalse(r["restored"])
        self.assertTrue(R(self.base["reg"] + "/verify_log")["valid"])
        R(self.base["na"] + "/tamper_log", {"seq": 1, "field": "actor",
                                            "value": "attacker"}, "POST")
        r = R(self.base["na"] + "/verify_log")
        self.assertFalse(r["valid"])

    def test_05_messaging_endpoint_real_sockets(self):
        R = self.REQ
        offer = R(self.base["recv"] + "/session/offer",
                  {"sender": "user-alex", "token": self.tok}, "POST")
        sid = offer["sid"]
        ct, ss = crypto.kem_encaps(
            bytes.fromhex(offer["encapsulation_key"]))
        r = R(self.base["recv"] + "/session/establish",
              {"sid": sid, "ciphertext": ct.hex(), "sender": "user-alex",
               "token": self.tok}, "POST")
        self.assertFalse(r["ephemeral_sk_retained"])   # zeroized in RAM
        key = crypto.hkdf(ss, ("track4-session:%s:%s:%s"
                               % (sid, "user-alex", "user-blair")).encode())

        key_version = R(self.base["reg"] + "/keys/current")["version"]

        def envelope(counter, plaintext):
            nonce = crypto.hkdf(key, b"track4-nonce:%d" % counter, 12)
            msg_id = crypto.sha256_hex(crypto.canonical(
                {"sid": sid, "counter": counter}).encode())[:24]
            aad = _msg_aad(sid, "user-alex", "user-blair", counter,
                           msg_id=msg_id, context=CONTEXT,
                           key_version=key_version,
                           key_commitment=_key_commitment(key.hex()))
            c = crypto.aead_encrypt(key, nonce, plaintext.encode(), aad)
            return {"sid": sid, "sender": "user-alex",
                    "recipient": "user-blair", "counter": counter,
                    "nonce": nonce.hex(), "ciphertext": c.hex(),
                    "msg_id": msg_id, "context": CONTEXT,
                    "key_version": key_version}

        e1, e2, e3 = envelope(1, "one"), envelope(2, "two"), envelope(3, "3")
        # real reorder: 3 first (buffered), then 1 (delivers 1), then 2
        self.assertEqual(R(self.base["recv"] + "/message/receive", e3,
                           "POST")["decision"], "buffered")
        r = R(self.base["recv"] + "/message/receive", e1, "POST")
        self.assertEqual(r["decision"], "deliver")
        self.assertEqual([m["plaintext"] for m in r["messages"]], ["one"])
        r = R(self.base["recv"] + "/message/receive", e2, "POST")
        self.assertEqual(r["decision"], "deliver")
        self.assertEqual([m["plaintext"] for m in r["messages"]],
                         ["two", "3"])   # buffered 3 flushes after two
        # duplicate over the real socket
        r = R(self.base["recv"] + "/message/receive", e1, "POST")
        self.assertEqual(r["reason"], "duplicate_replay")
        # wrong recipient binding
        bad = dict(e3, recipient="user-mallory")
        r = R(self.base["recv"] + "/message/receive", bad, "POST")
        self.assertEqual(r["reason"], "recipient_binding_mismatch")
        # tampered ciphertext (fresh msg) -> authentication_failed
        bad = dict(envelope(4, "four"),
                   ciphertext="00" * 32)
        r = R(self.base["recv"] + "/message/receive", bad, "POST")
        self.assertEqual(r["reason"], "authentication_failed")
        # keys in RAM only
        st = R(self.base["recv"] + "/session/status")
        self.assertTrue(st["key_in_ram"])
        self.assertFalse(st["keys_persisted_to_disk"])
        # close + resumption bound to the peer
        r = R(self.base["recv"] + "/session/close",
              {"peer": "user-alex"}, "POST")
        self.assertTrue(r["key_zeroized"])
        resumption_token = r["resumption_token"]
        # Resumption needs BOTH the session resumption token and a CURRENT
        # authenticated IdP token bound to the same peer/device.
        r = R(self.base["recv"] + "/session/resume",
              {"peer": "user-alex", "resumption_token": resumption_token}, "POST")
        self.assertEqual(r["decision"], "reject")
        self.assertTrue(r["reason"].startswith("token_"))
        r = R(self.base["recv"] + "/session/resume",
              {"peer": "user-alex", "resumption_token": resumption_token,
               "token": self.tok}, "POST")
        self.assertEqual(r["decision"], "allow")
        # A wrong peer is refused even with a valid session token.
        r = R(self.base["recv"] + "/session/resume",
              {"peer": "user-mallory", "resumption_token": resumption_token,
               "token": self.tok}, "POST")
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "resume_sub_mismatch")

    def test_09_node_to_node_gossip(self):
        """A node PROCESS sends an encrypted, authenticated policy-ack
        into the next node's messaging inbox over the real E2E machinery
        (PoP token from the node's own key + ephemeral ML-KEM session)."""
        import services.messenger_server as msgr
        R = self.REQ
        # node-b's inbox, bound to identity node-b (token-authenticated)
        inbox = msgr.Endpoint("msgr-b", 0, "node-b", "node-a",
                              idp=self.base["idp"], registry=self.base["reg"])
        port = netutil.free_port()
        netutil.serve(msgr.build_routes(inbox), port)
        # node-a gossips to node-b's inbox; node-a's own key is already
        # registered at the IdP by the Node constructor's keyfile
        gossip_node = self.node.Node(
            "node-a", netutil.free_port(), self.base["reg"],
            self.base["idp"], 0.3,
            os.path.join(self.dirs["na"], "gossip_test"),
            gossip_next="http://127.0.0.1:%d" % port)
        # register node-a's key (the IdP /register is first-write-wins,
        # so use a fresh name for the gossip test node)
        R(self.base["idp"] + "/register",
          {"identity": "gossip-node", "device": "gossip-node",
           "dsa_pk": gossip_node.dsa_pk}, "POST")
        gossip_node.name = "gossip-node"
        gossip_node._poll_once()      # first poll gossips immediately
        # the endpoint stores only AUTHENTICATED deliveries
        delivered = inbox.session["delivered"]
        acks = [json.loads(m["plaintext"]) for m in delivered
                if str(m.get("plaintext", "")).startswith("{")]
        self.assertTrue(acks)
        self.assertEqual(acks[-1]["type"], "policy_ack")
        self.assertEqual(acks[-1]["node"], "gossip-node")
        self.assertIn("epoch", acks[-1])
        self.assertIn("key_version", acks[-1])
        # the node recorded the delivery decision in its gossip log
        self.assertEqual(gossip_node.gossip_log[-1]["decision"], "deliver")

    def test_06_registry_log_integrity(self):
        r = self.REQ(self.base["reg"] + "/verify_log")
        self.assertTrue(r["valid"])
        self.assertGreater(r["entries"], 0)


    def test_08_real_lost_device_recovery(self):
        """The owner uses a SEPARATE recovery identity; the lost device key
        is never needed. The service generates a distinct replacement device
        credential at runtime and the old device stays revoked."""
        R = self.REQ
        # Genuine device loss: revoke the lost device FIRST and prove every
        # node denies it before any recovery is attempted.
        r = R(self.base["reg"] + "/revoke",
              {"actor": "user-blair", "device": "device-blair",
               "token": self.tokb}, "POST")
        self.assertEqual(r["status"], "ok")
        time.sleep(2.0)
        for key in ("na", "nb", "nc"):
            r = R(self.base[key] + "/read",
                  {"token": self.tokb, "asset": "notes.txt"}, "POST")
            self.assertEqual(r["decision"], "deny")
            self.assertEqual(r["reason"], "revoked")
        rec_pk, rec_sk = crypto.dsa_keypair()
        R(self.base["idp"] + "/register",
          {"identity": "recovery-user-blair", "device": "recovery-device",
           "dsa_pk": rec_pk.hex()}, "POST")
        req = tokens.device_proof(rec_sk.hex(), "recovery-user-blair",
                                  "recovery-device")
        req["ttl_s"] = 300
        rec_tok = R(self.base["idp"] + "/token", req, "POST")["token"]
        # Knowing the user id alone is not enough; a foreign token is refused.
        r = R(self.base["idp"] + "/recover/provision",
              {"identity": "user-blair", "token": self.tok}, "POST")
        self.assertEqual(r.get("reason"), "not_permitted")
        r = R(self.base["idp"] + "/recover/provision",
              {"identity": "user-blair"}, "POST")
        self.assertEqual(r["status"], "error")
        prov = R(self.base["idp"] + "/recover/provision",
                 {"identity": "user-blair", "token": rec_tok}, "POST")
        self.assertEqual(prov["status"], "ok")
        new_device = prov["device"]
        self.assertNotEqual(new_device, "device-blair")
        self.assertNotIn("dsa_sk", prov)
        self.assertNotIn("kem_sk", prov)
        # Registry re-enrol requires the recovery identity, keeps the old
        # device revoked, and registers the distinct replacement.
        r = R(self.base["reg"] + "/re_enroll",
              {"actor": "user-blair", "old_device": "device-blair",
               "device": new_device, "token": self.tok}, "POST")
        self.assertEqual(r.get("reason"), "not_permitted")
        r = R(self.base["reg"] + "/re_enroll",
              {"actor": "user-blair", "old_device": "device-blair",
               "device": new_device, "token": rec_tok}, "POST")
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["old_device_still_revoked"])
        policy = R(self.base["reg"] + "/policy")
        self.assertIn("device-blair", policy["revoked"])
        self.assertNotIn(new_device, policy["revoked"])
        # Lost key cannot mint a token; old token is denied at a node.
        breq = tokens.device_proof(self.dev_blair[1].hex(), "user-blair",
                                   "device-blair")
        self.assertEqual(R(self.base["idp"] + "/token", breq,
                           "POST")["status"], "error")
        time.sleep(0.4)  # node-a applies the new policy
        self.assertEqual(R(self.base["na"] + "/read",
                           {"token": self.tokb, "asset": "notes.txt"},
                           "POST")["reason"], "revoked")
        # New device proves the runtime-generated credential, gets a token,
        # and accesses its own protected data.
        new_req = {"identity": "user-blair", "device": new_device,
                   "ttl_s": 300,
                   "enrolment_secret": prov["enrolment_secret"]}
        tok_new = R(self.base["idp"] + "/token", new_req, "POST")["token"]
        time.sleep(2.0)  # all nodes, including the 1.5 s poller, apply it
        read = R(self.base["na"] + "/read",
                 {"token": tok_new, "asset": "notes.txt"}, "POST")
        self.assertEqual(read["decision"], "allow")
        self.assertEqual(read["body"], "blair's own notes")
        # Old device remains denied AFTER the replacement is active.
        self.assertEqual(R(self.base["nc"] + "/read",
                           {"token": self.tokb, "asset": "notes.txt"},
                           "POST")["reason"], "revoked")
        idp_audit = [a["action"] for a in
                     R(self.base["idp"] + "/audit")["audit"]]
        self.assertIn("recover_provision", idp_audit)
        self.assertTrue(R(self.base["reg"] + "/verify_log")["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
