"""Integration tests over REAL localhost sockets.

Each service (registry, IdP, three nodes, messaging endpoint) runs as an
in-process threaded server here (the same code paths as the subprocess
deployment in demo_networked.py, which spawns them as separate OS
processes). Timing assertions use the REAL clock and real poll intervals.
"""

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
                                 "user-alex")
        netutil.serve(msgr.build_routes(cls.recv), ports["recv"])
        cls.REQ = staticmethod(
            lambda url, payload=None, method=None:
                netutil.request(url, payload, method)[1])
        assert netutil.wait_healthy(cls.base["reg"])
        assert netutil.wait_healthy(cls.base["idp"])
        # shared setup: identities, policy, tokens (all tests read-only here)
        R = cls.REQ
        R(cls.base["idp"] + "/register",
          {"identity": "user-alex", "device": "device-alex"}, "POST")
        R(cls.base["idp"] + "/register",
          {"identity": "user-blair", "device": "device-blair"}, "POST")
        R(cls.base["reg"] + "/setup",
          {"owners": {"report.txt": "user-alex"},
           "contents": {"report.txt": "Q3 numbers are green"},
           "grace_seconds": 2.0}, "POST")
        cls.tok = R(cls.base["idp"] + "/token",
                    {"identity": "user-alex"}, "POST")["token"]
        cls.tokb = R(cls.base["idp"] + "/token",
                     {"identity": "user-blair"}, "POST")["token"]
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
        r = R(self.base["reg"] + "/revoke",
              {"actor": "user-blair", "device": "device-blair"}, "POST")
        t0 = time.time()
        # Nodes converge by real polling (node-a: 0.3 s): wait until the
        # revocation is genuinely enforced (reason == "revoked"), not a
        # routine not-owner denial that would pass trivially.
        deadline = t0 + 3.0
        while time.time() < deadline:
            r = R(self.base["na"] + "/read",
                  {"token": self.tokb, "asset": "report.txt"}, "POST")
            if r["decision"] == "deny" and r.get("reason") == "revoked":
                break
            time.sleep(0.05)
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "revoked")
        self.assertLess(time.time() - t0, 3.0)   # enforced within a poll
        r = R(self.base["na"] + "/read",
              {"token": self.tok, "asset": "report.txt"}, "POST")
        self.assertEqual(r["decision"], "allow")  # others unaffected
        # node-c is the slowest poller: it must ALSO enforce (real poll)
        deadline = time.time() + 4.0
        while time.time() < deadline:
            rc = R(self.base["nc"] + "/read",
                   {"token": self.tokb, "asset": "report.txt"}, "POST")
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
                  {"sender": "user-alex"}, "POST")
        sid = offer["sid"]
        ct, ss = crypto.kem_encaps(
            bytes.fromhex(offer["encapsulation_key"]))
        r = R(self.base["recv"] + "/session/establish",
              {"sid": sid, "ciphertext": ct.hex(), "sender": "user-alex"},
              "POST")
        self.assertFalse(r["ephemeral_sk_retained"])   # zeroized in RAM
        key = crypto.hkdf(ss, ("track4-session:%s:%s:%s"
                               % (sid, "user-alex", "user-blair")).encode())

        def envelope(counter, plaintext):
            nonce = crypto.hkdf(key, b"track4-nonce:%d" % counter, 12)
            aad = crypto.canonical({"sid": sid, "sender": "user-alex",
                                    "recipient": "user-blair",
                                    "counter": counter}).encode()
            c = crypto.aead_encrypt(key, nonce, plaintext.encode(), aad)
            return {"sid": sid, "sender": "user-alex",
                    "recipient": "user-blair", "counter": counter,
                    "nonce": nonce.hex(), "ciphertext": c.hex(),
                    "msg_id": crypto.sha256_hex(crypto.canonical(
                        {"sid": sid, "counter": counter}))[:24]}

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
              {"peer": "user-blair"}, "POST")
        token = r["resumption_token"]
        r = R(self.base["recv"] + "/session/resume",
              {"peer": "user-blair", "resumption_token": token}, "POST")
        self.assertEqual(r["decision"], "allow")
        r = R(self.base["recv"] + "/session/resume",
              {"peer": "user-mallory", "resumption_token": token}, "POST")
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "peer_not_bound_to_session")

    def test_06_registry_log_integrity(self):
        r = self.REQ(self.base["reg"] + "/verify_log")
        self.assertTrue(r["valid"])
        self.assertGreater(r["entries"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
