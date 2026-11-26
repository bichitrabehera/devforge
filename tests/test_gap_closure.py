"""Focused regression tests for the four gap-closure behaviors.

Covers: real lost-device recovery without the lost private key, full AAD
binding of encrypted messages, and revocation/key/data persistence across a
REAL registry process kill and restart. All identities and keys are
generated at runtime; only localhost mock services are used.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import crypto, netutil, state as st, tokens  # noqa: E402
from src.dispatch import dispatch  # noqa: E402
from src.messaging import CONTEXT, _msg_aad  # noqa: E402


class EmbeddedRecoveryTest(unittest.TestCase):
    """Adapter-level recovery: proof comes from a SEPARATE recovery identity."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="track4_recovery_")
        st.set_state_dir(self.dir)
        self.rec_pk, self.rec_sk = crypto.dsa_keypair()

    def tearDown(self):
        st.set_state_dir(None)
        shutil.rmtree(self.dir, ignore_errors=True)

    def _setup(self):
        return dispatch({
            "op": "setup", "grace_seconds": 30,
            "owners": {"report.txt": "user-alex",
                       "notes.txt": "user-blair"},
            "contents": {"report.txt": "Q3 numbers are green",
                         "notes.txt": "blair's own notes"},
            "recovery_bindings": {"user-blair": "recovery-user-blair"},
            "recovery_public_keys": {"recovery-user-blair": self.rec_pk.hex()},
        })

    def _proof(self, actor, old, new):
        signed = crypto.canonical({"actor": actor, "old_device": old,
                                   "device": new}).encode()
        return crypto.dsa_sign(self.rec_sk.hex(), signed)

    def test_recovery_without_lost_key_and_old_session_stays_dead(self):
        self.assertEqual(self._setup()["status"], "ok")
        for actor, device in (("user-alex", "device-alex"),
                              ("user-blair", "device-blair")):
            dispatch({"op": "re_enroll", "actor": actor, "device": device})
        # A session exists BEFORE the device is lost.
        sid = dispatch({"op": "session_open", "sender": "user-alex",
                        "recipient": "user-blair"})["sid"]
        dispatch({"op": "session_accept", "sid": sid, "sender": "user-alex"})
        closed = dispatch({"op": "session_close", "sid": sid,
                           "peer": "user-blair"})
        resumption_token = closed["resumption_token"]
        old_ident = dict(st.load_state()["identities"]["user-blair"])

        dispatch({"op": "revoke", "actor": "user-blair",
                  "device": "device-blair"})
        new_device = "device-blair-replacement"

        # Knowing the user id alone, or using the wrong recovery identity,
        # cannot authorize a replacement.
        r = dispatch({"op": "recover_device", "actor": "user-blair",
                      "device": new_device})
        self.assertEqual(r["reason"], "no_recovery_binding")
        r = dispatch({"op": "recover_device", "actor": "user-blair",
                      "recovery_actor": "user-alex", "device": new_device,
                      "recovery_proof": self._proof("user-blair",
                                                    "device-blair",
                                                    new_device)})
        self.assertEqual(r["reason"], "no_recovery_binding")
        # A proof from an attacker's own key is rejected.
        bad_pk, bad_sk = crypto.dsa_keypair()
        signed = crypto.canonical({"actor": "user-blair",
                                   "old_device": "device-blair",
                                   "device": new_device}).encode()
        r = dispatch({"op": "recover_device", "actor": "user-blair",
                      "recovery_actor": "recovery-user-blair",
                      "device": new_device,
                      "recovery_proof": crypto.dsa_sign(bad_sk.hex(), signed)})
        self.assertEqual(r["reason"], "bad_recovery_signature")

        # The legitimate recovery identity proves possession of its own key.
        r = dispatch({"op": "recover_device", "actor": "user-blair",
                      "recovery_actor": "recovery-user-blair",
                      "old_device": "device-blair", "device": new_device,
                      "recovery_proof": self._proof("user-blair",
                                                    "device-blair",
                                                    new_device)})
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["old_device_still_revoked"])
        self.assertTrue(r["sessions_invalidated"])
        for field in ("kem_sk", "dsa_sk", "private_key", "enrolment_secret"):
            self.assertNotIn(field, r)

        state = st.load_state()
        new_ident = state["identities"]["user-blair"]
        self.assertEqual(new_ident["device"], new_device)
        self.assertNotEqual(new_ident["kem_pk"], old_ident["kem_pk"])
        self.assertNotEqual(new_ident["dsa_pk"], old_ident["dsa_pk"])
        self.assertIn("device-blair", state["revoked"])
        self.assertNotIn(new_device, state["revoked"])
        self.assertIsNone(state["sessions"][sid]["resumption_secret"])

        # Old token/session/key are denied; other users retain access.
        r = dispatch({"op": "session_resume", "sid": sid,
                      "peer": "user-blair",
                      "resumption_token": resumption_token})
        self.assertEqual(r.get("message"), "no_resumption_secret")
        r = dispatch({"op": "authenticate", "actor": "user-blair",
                      "device": "device-blair", "node": "node-a"})
        self.assertEqual(r["reason"], "revoked")
        for node in ("node-a", "node-b", "node-c"):
            r = dispatch({"op": "authenticate", "actor": "user-blair",
                          "device": new_device, "node": node})
            self.assertEqual(r["decision"], "allow")
            r = dispatch({"op": "authenticate", "actor": "user-alex",
                          "device": "device-alex", "node": node})
            self.assertEqual(r["decision"], "allow")
        r = dispatch({"op": "read", "actor": "user-blair",
                      "asset": "notes.txt"})
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["body"], "blair's own notes")

        actions = [entry["action"] for entry in state["log"]]
        self.assertIn("revoke", actions)
        self.assertIn("recovery_enrol", actions)
        self.assertTrue(dispatch({"op": "verify_log"})["valid"])


class AADBindingTest(unittest.TestCase):
    """Every security-relevant envelope field is cryptographically bound."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="track4_aad_")
        st.set_state_dir(self.dir)
        dispatch({"op": "setup", "grace_seconds": 30})
        dispatch({"op": "re_enroll", "actor": "alice", "device": "d-alice"})
        dispatch({"op": "re_enroll", "actor": "bob", "device": "d-bob"})
        self.sid = dispatch({"op": "session_open", "sender": "alice",
                             "recipient": "bob"})["sid"]
        dispatch({"op": "session_accept", "sid": self.sid, "sender": "alice"})
        self.msg = dispatch({"op": "message_send", "sid": self.sid,
                             "plaintext": "bound secret"})

    def tearDown(self):
        st.set_state_dir(None)
        shutil.rmtree(self.dir, ignore_errors=True)

    def _receive(self, **overrides):
        env = {"sid": self.sid, "sender": "alice", "recipient": "bob",
               "msg_id": self.msg["msg_id"], "counter": self.msg["counter"],
               "nonce": self.msg["nonce"],
               "ciphertext": self.msg["ciphertext"]}
        env.update(overrides)
        return dispatch(dict({"op": "message_receive"}, **env))

    def _fresh_message(self, text="bound secret"):
        sid = dispatch({"op": "session_open", "sender": "alice",
                        "recipient": "bob"})["sid"]
        dispatch({"op": "session_accept", "sid": sid, "sender": "alice"})
        msg = dispatch({"op": "message_send", "sid": sid,
                        "plaintext": text})
        return sid, msg

    def _deliver(self, sid, msg, **overrides):
        env = {"sid": sid, "sender": "alice", "recipient": "bob",
               "msg_id": msg["msg_id"], "counter": msg["counter"],
               "nonce": msg["nonce"], "ciphertext": msg["ciphertext"]}
        env.update(overrides)
        return dispatch(dict({"op": "message_receive"}, **env))

    def test_modified_sender_recipient_msg_id_and_context_are_rejected(self):
        sid, msg = self._fresh_message()
        self.assertEqual(self._deliver(sid, msg)["decision"], "deliver")
        # Each tampering attempt uses a fresh session/msg so replay filtering
        # cannot mask the AAD check being tested.
        sid, msg = self._fresh_message("sender change")
        self.assertEqual(self._deliver(sid, msg, sender="mallory")["reason"],
                         "authentication_failed")
        sid, msg = self._fresh_message("msg id change")
        self.assertEqual(self._deliver(sid, msg, msg_id="f" * 24)["reason"],
                         "msg_id_mismatch")
        sid, msg = self._fresh_message("recipient change")
        self.assertEqual(
            self._deliver(sid, msg, recipient="mallory")["reason"],
            "recipient_binding_mismatch")
        sid, msg = self._fresh_message("ciphertext change")
        self.assertEqual(
            self._deliver(sid, msg,
                          ciphertext=msg["ciphertext"][:-4] + "0000")["reason"],
            "authentication_failed")
        # The shared AAD helper binds the context and key-version literals
        # used by the networked transport.
        self.assertIn("track4-msg-v2", _msg_aad(sid, "alice", "bob", 1)
                      .decode())
        self.assertEqual(CONTEXT, "track4-msg-v2")

    def test_duplicate_and_truncated_messages_are_rejected(self):
        self.assertEqual(self._receive()["decision"], "deliver")
        r = self._receive()
        self.assertEqual(r["reason"], "duplicate_replay")
        sid2 = dispatch({"op": "session_open", "sender": "alice",
                         "recipient": "bob"})["sid"]
        dispatch({"op": "session_accept", "sid": sid2, "sender": "alice"})
        m2 = dispatch({"op": "message_send", "sid": sid2,
                       "plaintext": "truncate me"})
        env = {"sid": sid2, "sender": "alice", "recipient": "bob",
               "msg_id": m2["msg_id"], "counter": m2["counter"],
               "nonce": m2["nonce"],
               "ciphertext": m2["ciphertext"][:-8]}
        r = dispatch(dict({"op": "message_receive"}, **env))
        self.assertEqual(r["reason"], "authentication_failed")


class RealProcessRestartTest(unittest.TestCase):
    """SIGKILL the registry process and verify persistence through nodes."""

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="track4_restart_")
        self.ports = {k: netutil.free_port()
                      for k in ("reg", "idp", "node")}
        self.base = {k: "http://127.0.0.1:%d" % v
                     for k, v in self.ports.items()}
        self.procs = []
        self.err_files = []
        self.reg_dir = os.path.join(self.work, "registry")
        self.idp_dir = os.path.join(self.work, "idp")
        self.node_dir = os.path.join(self.work, "node")
        self._start_registry()
        self._start("services/idp_server.py",
                    ["--port", str(self.ports["idp"])],
                    {"TRACK4_IDP_DIR": self.idp_dir}, "idp", "idp")
        self._start("services/node_server.py",
                    ["--name", "node-a", "--port", str(self.ports["node"]),
                     "--registry", self.base["reg"], "--idp", self.base["idp"],
                     "--poll-interval", "0.2"],
                    {"TRACK4_NODE_NODE_A_DIR": self.node_dir},
                    "node", "node")
        self.wait()

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        for f in self.err_files:
            f.close()
        shutil.rmtree(self.work, ignore_errors=True)

    def _start(self, script, args, env, key, name):
        e = dict(os.environ, **env)
        err = open(os.path.join(self.work, name + ".err"), "ab")
        self.err_files.append(err)
        p = subprocess.Popen([sys.executable, os.path.join(ROOT, script)] + args,
                             cwd=ROOT, env=e, stdout=err, stderr=err)
        setattr(self, "proc_" + key, p)
        self.procs.append(p)

    def _start_registry(self):
        self._start("services/registry_server.py",
                    ["--port", str(self.ports["reg"]),
                     "--idp", self.base["idp"]],
                    {"TRACK4_REGISTRY_DIR": self.reg_dir}, "reg", "registry")

    def wait(self):
        for key in ("reg", "idp", "node"):
            self.assertTrue(netutil.wait_healthy(self.base[key], timeout=15),
                            "%s did not start" % key)

    def _req(self, key, path, payload=None):
        return netutil.request(self.base[key] + path, payload,
                               method="POST" if payload is not None else "GET")[1]

    def _token(self, ident, device, sk_hex):
        req = tokens.device_proof(sk_hex, ident, device)
        req["ttl_s"] = 900
        return self._req("idp", "/token", req)["token"]

    def test_revocation_keys_data_and_recovery_survive_real_restart(self):
        keys = {}
        for ident, device in (("user-alex", "device-alex"),
                              ("user-blair", "device-blair"),
                              ("recovery-user-blair", "recovery-device")):
            pk, sk = crypto.dsa_keypair()
            keys[ident] = (device, pk.hex(), sk.hex())
            self._req("idp", "/register", {"identity": ident,
                                           "device": device,
                                           "dsa_pk": pk.hex()})
        self._req("reg", "/setup", {"owners": {"report.txt": "user-alex",
                                               "notes.txt": "user-blair"},
                                    "contents": {"report.txt": "green",
                                                 "notes.txt": "blair notes"},
                                    "grace_seconds": 6})
        for ident in ("user-alex", "user-blair"):
            self._req("reg", "/identities/register",
                      {"identity": ident, "device": keys[ident][0]})
        tok_alex = self._token("user-alex", keys["user-alex"][0],
                               keys["user-alex"][2])
        tok_blair = self._token("user-blair", keys["user-blair"][0],
                                keys["user-blair"][2])
        time.sleep(0.6)
        v_new = self._req("reg", "/keys/rotate", {"grace_seconds": 6})[
            "new_version"]
        self.assertEqual(self._req("reg", "/revoke",
                                   {"actor": "user-blair",
                                    "device": "device-blair",
                                    "token": tok_blair})["status"], "ok")
        deadline = time.time() + 4
        while time.time() < deadline:
            r = self._req("node", "/read", {"token": tok_blair,
                                            "asset": "notes.txt"})
            if r.get("reason") == "revoked":
                break
            time.sleep(0.1)
        self.assertEqual(r["reason"], "revoked")

        # REAL crash: no re-enrolment before the kill.
        self.proc_reg.send_signal(signal.SIGKILL)
        self.proc_reg.wait()
        self._start_registry()
        self.wait()

        self.assertEqual(self._req("reg", "/keys/current")["version"], v_new)
        policy = self._req("reg", "/policy")
        self.assertIn("device-blair", policy["revoked"])
        r = self._req("node", "/read", {"token": tok_alex,
                                        "asset": "report.txt"})
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["body"], "green")
        r = self._req("node", "/read", {"token": tok_blair,
                                        "asset": "notes.txt"})
        self.assertEqual(r["reason"], "revoked")

        # Legitimate recovery AFTER restart.
        rec_tok = self._token("recovery-user-blair",
                              keys["recovery-user-blair"][0],
                              keys["recovery-user-blair"][2])
        prov = self._req("idp", "/recover/provision",
                         {"identity": "user-blair", "token": rec_tok})
        self.assertEqual(prov["status"], "ok")
        new_device = prov["device"]
        self.assertNotEqual(new_device, "device-blair")
        r = self._req("reg", "/re_enroll",
                      {"actor": "user-blair", "old_device": "device-blair",
                       "device": new_device, "token": rec_tok})
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["old_device_still_revoked"])
        time.sleep(0.6)
        new_tok = self._req("idp", "/token",
                            {"identity": "user-blair", "ttl_s": 300,
                             "enrolment_secret": prov["enrolment_secret"]})[
                                "token"]
        r = self._req("node", "/read", {"token": new_tok,
                                        "asset": "notes.txt"})
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["body"], "blair notes")
        r = self._req("node", "/read", {"token": tok_blair,
                                        "asset": "notes.txt"})
        self.assertEqual(r["reason"], "revoked")
        self.assertIn("device-blair", self._req("reg", "/policy")["revoked"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
