"""QA gap-fill tests from the full audit.

Covers behaviors the earlier suites did not explicitly assert:
audit-chain mutation classes (deletion/insertion/duplication/reordering),
repeated lateral-movement attempts, concurrency/race conditions,
truncated ciphertexts, path-traversal-ish inputs, error-leak checks, and
revocation enforcement inside live messaging sessions.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import state as st  # noqa: E402
from src.dispatch import dispatch  # noqa: E402
from src.detector import evaluate_labelled  # noqa: E402


def fresh_dir():
    d = tempfile.mkdtemp(prefix="track4_qa_")
    st.set_state_dir(d)
    return d


class QATest(unittest.TestCase):
    def setUp(self):
        self._dir = fresh_dir()
        dispatch({"op": "setup", "owners": {"secret.txt": "victim"},
                  "contents": {"secret.txt": "classified"}})

    def tearDown(self):
        st.set_state_dir(None)
        shutil.rmtree(self._dir, ignore_errors=True)


class TestLogChainMutations(QATest):
    """E: every mutation class of the hash chain must be detectable."""

    def _seed_log(self):
        for i in range(4):
            dispatch({"op": "append_log", "actor": "user-%d" % i,
                      "action": "read", "asset": "a%d" % i, "detail": "d%d" % i})

    def _verify(self):
        return dispatch({"op": "verify_log"})

    def test_untampered_log_valid(self):
        self._seed_log()
        self.assertTrue(self._verify()["valid"])

    def test_entry_deletion_detected(self):
        self._seed_log()
        sp = st.state_path()
        raw = json.load(open(sp))
        raw["log"].pop(1)                      # delete a middle entry
        for i, e in enumerate(raw["log"]):     # renumber to hide the gap
            e["seq"] = i + 1
        raw.pop("state_hash", None)
        raw["state_hash"] = st._state_digest(raw)   # attacker recomputes
        json.dump(raw, open(sp, "w"))
        self.assertFalse(self._verify()["valid"])

    def test_entry_insertion_detected(self):
        self._seed_log()
        sp = st.state_path()
        raw = json.load(open(sp))
        forged = dict(raw["log"][1])           # duplicate a real entry
        forged["seq"] = 5                      # pretend it is new
        forged.pop("hash", None); forged.pop("signature", None)
        forged["actor"] = "attacker"
        raw["log"].append(forged)
        raw.pop("state_hash", None)
        raw["state_hash"] = st._state_digest(raw)
        json.dump(raw, open(sp, "w"))
        self.assertFalse(self._verify()["valid"])

    def test_entry_duplication_detected(self):
        self._seed_log()
        sp = st.state_path()
        raw = json.load(open(sp))
        raw["log"].insert(2, dict(raw["log"][2]))   # exact duplicate entry
        raw.pop("state_hash", None)
        raw["state_hash"] = st._state_digest(raw)
        json.dump(raw, open(sp, "w"))
        self.assertFalse(self._verify()["valid"])

    def test_entry_reordering_detected(self):
        self._seed_log()
        sp = st.state_path()
        raw = json.load(open(sp))
        raw["log"][1], raw["log"][2] = raw["log"][2], raw["log"][1]
        for i, e in enumerate(raw["log"]):     # renumber to hide the swap
            e["seq"] = i + 1
        raw.pop("state_hash", None)
        raw["state_hash"] = st._state_digest(raw)
        json.dump(raw, open(sp, "w"))
        self.assertFalse(self._verify()["valid"])


class TestRepeatedLateralAttempts(QATest):
    """G: repeated unusual-path attempts are flagged, explainably."""

    EVENTS = [
        {"event_id": "r1", "event_time_utc": "2026-01-15T09:00:00.000Z",
         "received_time_utc": "2026-01-15T09:00:01.000Z",
         "source_clock_offset_ms": 0, "actor": "u7",
         "source_service": "portal", "target_service": "billing",
         "action": "read", "role_before": "viewer",
         "role_after": "viewer", "outcome": "allow", "approval_id": "",
         "session_id": "s7", "correlation_id": "c7"},
        {"event_id": "r2", "event_time_utc": "2026-01-15T09:00:02.000Z",
         "received_time_utc": "2026-01-15T09:00:03.000Z",
         "source_clock_offset_ms": 0, "actor": "u7",
         "source_service": "portal", "target_service": "billing",
         "action": "read", "role_before": "viewer",
         "role_after": "viewer", "outcome": "allow", "approval_id": "",
         "session_id": "s7", "correlation_id": "c7"},
        {"event_id": "r3", "event_time_utc": "2026-01-15T09:00:04.000Z",
         "received_time_utc": "2026-01-15T09:00:05.000Z",
         "source_clock_offset_ms": 0, "actor": "u7",
         "source_service": "billing", "target_service": "catalog",
         "action": "read", "role_before": "viewer",
         "role_after": "viewer", "outcome": "allow", "approval_id": "",
         "session_id": "s7", "correlation_id": "c7"},
    ]

    def test_repeated_unknown_edge_access_flagged_with_context(self):
        r = evaluate_labelled(events=self.EVENTS, labels={},
                              approvals={"changes": []})
        alerts = [a for a in r["alerts"] if a["identity"] == "u7"]
        self.assertTrue(alerts)
        a = alerts[0]
        self.assertEqual(a["rule"], "lateral_movement")
        self.assertIn("u7", json.dumps(a))
        self.assertIn("billing", json.dumps(a))   # services named
        self.assertIn("related_events", a)        # event ids named

    def test_normal_path_not_alerted(self):
        e = dict(self.EVENTS[0], target_service="catalog")
        r = evaluate_labelled(events=[e], labels={},
                              approvals={"changes": []})
        self.assertEqual(r["alerts"], [])


class TestConcurrency(QATest):
    """Race conditions: concurrent rotation, revocation, reads, messages."""

    def test_concurrent_ops_keep_invariants(self):
        dispatch({"op": "re_enroll", "device": "da", "actor": "ca"})
        dispatch({"op": "re_enroll", "device": "db", "actor": "cb"})
        errors = []

        def worker(fn, n):
            try:
                for _ in range(n):
                    fn()
            except Exception as exc:          # any crash is a race failure
                errors.append("%s: %s" % (type(exc).__name__, exc))

        def rotate(): dispatch({"op": "rotate_key"})
        def revoke_reenroll():
            dispatch({"op": "revoke", "device": "da"})
            dispatch({"op": "re_enroll", "device": "da", "actor": "ca"})
        def read(): dispatch({"op": "read", "actor": "victim",
                              "asset": "secret.txt"})
        def open_session():
            r = dispatch({"op": "session_open", "sender": "ca",
                          "recipient": "cb"})
            if r.get("sid"):
                dispatch({"op": "session_accept", "sid": r["sid"],
                          "sender": "ca"})
                dispatch({"op": "session_close", "sid": r["sid"],
                          "peer": "cb"})

        threads = [threading.Thread(target=worker, args=(f, 8))
                   for f in (rotate, revoke_reenroll, read, open_session)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], msg="concurrent ops crashed: %s" % errors)
        r = dispatch({"op": "verify_log"})
        self.assertTrue(r["valid"], msg="log chain broken under concurrency")
        state = st.load_state()
        # committed version must be the maximum journaled commit
        floor = st.journal_floor(state["service_dsa_pk"])
        self.assertGreaterEqual(state["active_version"], floor[0])
        self.assertGreaterEqual(state["revocation_epoch"], floor[1])


class TestTruncatedAndTamperedCiphertext(QATest):
    """I: incomplete/tampered ciphertexts are discarded, never crash."""

    def setUp(self):
        super().setUp()
        dispatch({"op": "re_enroll", "device": "d1", "actor": "alice"})
        dispatch({"op": "re_enroll", "device": "d2", "actor": "bob"})
        r = dispatch({"op": "session_open", "sender": "alice",
                      "recipient": "bob"})
        dispatch({"op": "session_accept", "sid": r["sid"], "sender": "alice"})
        self.sid = r["sid"]
        self.msg = dispatch({"op": "message_send", "sid": self.sid,
                             "plaintext": "payload"})

    def _recv(self, **over):
        req = {"sid": self.sid, "recipient": "bob", "sender": "alice",
               "msg_id": self.msg["msg_id"], "counter": self.msg["counter"],
               "nonce": self.msg["nonce"], "ciphertext": self.msg["ciphertext"]}
        req.update(over)
        return dispatch({"op": "message_receive", **req})

    def test_truncated_ciphertext_rejected(self):
        ct = self.msg["ciphertext"]
        r = self._recv(ciphertext=ct[:len(ct) // 4 * 2])   # even hex length
        self.assertEqual(r.get("decision"), "reject")
        self.assertIn(r.get("reason"), ("authentication_failed", "bad_hex"))

    def test_bitflipped_ciphertext_rejected(self):
        ct = bytearray(bytes.fromhex(self.msg["ciphertext"]))
        ct[len(ct) // 2] ^= 0xFF
        r = self._recv(ciphertext=bytes(ct).hex())
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "authentication_failed")

    def test_truncated_nonce_rejected(self):
        r = self._recv(nonce=self.msg["nonce"][:20])
        blob = json.dumps(r)
        self.assertNotIn("payload", blob)      # content never leaks
        self.assertTrue(r.get("decision") == "reject"
                        or r.get("message") in ("bad_hex",),
                        msg=blob)

    def test_counter_shift_is_replay_or_auth_failure(self):
        r = self._recv(counter=self.msg["counter"] + 5)
        self.assertEqual(r["decision"], "reject")


class TestInputValidation(QATest):
    """Malformed / hostile inputs: fail closed, no filesystem effect."""

    def test_path_traversal_asset_is_just_a_key(self):
        r = dispatch({"op": "read", "actor": "victim",
                      "asset": "../../etc/passwd"})
        self.assertEqual(r["decision"], "deny")
        # nothing was written outside the state dir's two files
        self.assertLessEqual(set(os.listdir(self._dir)),
                             {"state.json", "journal.jsonl"})

    def test_unicode_and_control_chars_in_fields(self):
        for actor in ("may\ufffd", "may\\u0000a", "may\\n\\ta", "\\\\u202e"):
            r = dispatch({"op": "read", "actor": actor,
                          "asset": "secret.txt"})
            self.assertEqual(r["decision"], "deny")
        self.assertTrue(dispatch({"op": "verify_log"})["valid"])

    def test_malformed_structures_fail_closed(self):
        cases = [{"op": "read", "actor": {"a": [1]}, "asset": None},
                 {"op": "revoke", "device": [1, 2]},
                 {"op": "append_log", "actor": "u", "action": "x",
                  "asset": "", "detail": {"nested": {"deep": [1]}}},
                 {"op": "protected_read", "actor": "victim",
                  "asset": "secret.txt", "challenge": "c",
                  "public_key": "short"}]
        for req in cases:
            r = dispatch(req)
            self.assertIn(r.get("status"), ("ok", "error"), msg=str(req))
            blob = json.dumps(r)
            if r.get("decision") is not None:
                self.assertNotIn("classified", blob, msg=str(req))


class TestErrorLeaks(QATest):
    """Failures must not leak stack traces, paths, or key material."""

    def test_op_failed_has_no_internal_details(self):
        r = dispatch({"op": "read", "actor": ["bad"], "asset": "secret.txt"})
        blob = json.dumps(r)
        self.assertNotIn("Traceback", blob)
        self.assertNotIn("/", blob.replace("\\/", ""))
        self.assertNotIn("hex", blob.lower())

    def test_responses_never_contain_private_key_material(self):
        state = st.load_state()
        sk = state["service_dsa_sk"]
        for req in ({"op": "read", "actor": "victim", "asset": "secret.txt"},
                    {"op": "rotate_key"},
                    {"op": "revoke", "device": "nope"},
                    {"op": "verify_log"},
                    {"op": "status"}):
            blob = json.dumps(dispatch(req))
            self.assertNotIn(sk[:32], blob, msg=str(req))


class TestRevokedSenderMessaging(QATest):
    """B: revocation reaches live messaging sessions (audit finding)."""

    def setUp(self):
        super().setUp()
        dispatch({"op": "re_enroll", "device": "d1", "actor": "alice"})
        dispatch({"op": "re_enroll", "device": "d2", "actor": "bob"})

    def _session(self):
        r = dispatch({"op": "session_open", "sender": "alice",
                      "recipient": "bob"})
        dispatch({"op": "session_accept", "sid": r["sid"], "sender": "alice"})
        return r["sid"]

    def test_revoked_sender_cannot_keep_sending(self):
        sid = self._session()
        dispatch({"op": "revoke", "device": "d1"})
        r = dispatch({"op": "message_send", "sid": sid, "plaintext": "late"})
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "sender_revoked_or_disabled")

    def test_revoked_recipient_cannot_read(self):
        sid = self._session()
        m = dispatch({"op": "message_send", "sid": sid, "plaintext": "hi"})
        dispatch({"op": "revoke", "device": "d2"})
        r = dispatch({"op": "message_receive", "sid": sid, "recipient": "bob",
                      "sender": "alice", "msg_id": m["msg_id"],
                      "counter": m["counter"], "nonce": m["nonce"],
                      "ciphertext": m["ciphertext"]})
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "recipient_revoked_or_disabled")

    def test_re_enroll_restores_messaging(self):
        sid = self._session()
        dispatch({"op": "revoke", "device": "d1"})
        dispatch({"op": "re_enroll", "device": "d1", "actor": "alice"})
        r = dispatch({"op": "message_send", "sid": sid, "plaintext": "back"})
        self.assertEqual(r["status"], "ok")
        self.assertIn("ciphertext", r)

    def test_revoked_peer_cannot_resume(self):
        sid = self._session()
        r = dispatch({"op": "session_close", "sid": sid, "peer": "bob"})
        tok = r["resumption_token"]
        dispatch({"op": "revoke", "device": "d2"})
        r = dispatch({"op": "session_resume", "sid": sid, "peer": "bob",
                      "resumption_token": tok})
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "peer_revoked_or_disabled")

    def test_disabled_actor_cannot_open_session(self):
        dispatch({"op": "disable", "actor": "alice"})
        r = dispatch({"op": "session_open", "sender": "alice",
                      "recipient": "bob"})
        self.assertEqual(r["message"], "sender_not_active")


if __name__ == "__main__":
    unittest.main(verbosity=2)
