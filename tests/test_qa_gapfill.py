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
import subprocess
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import state as st  # noqa: E402
from src import crypto  # noqa: E402
from src.dispatch import dispatch  # noqa: E402
from src.detector import evaluate_labelled  # noqa: E402
from src.messaging import (_msg_aad, _msg_id, _nonce_for,  # noqa: E402
                           _key_commitment)


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


class TestAdapterEndpoint(unittest.TestCase):
    """The organizer-facing stdin/stdout path: valid JSON always, never a
    traceback, detector op works, concurrent processes serialize."""

    def _run(self, request, state_dir):
        import subprocess
        env = dict(os.environ, TRACK4_STATE_DIR=state_dir)
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "track4_service.py")],
            input=json.dumps(request).encode(), capture_output=True,
            env=env, timeout=120)

    def _fresh(self):
        return tempfile.mkdtemp(prefix="track4_adapter_")

    def test_detector_op_returns_valid_json(self):
        d = self._fresh()
        try:
            p = self._run({"op": "setup", "owners": {},
                           "contents": {}}, d)
            self.assertEqual(json.loads(p.stdout)["status"], "ok")
            ev = os.path.join(ROOT, "practice", "events.csv")
            lb = os.path.join(ROOT, "practice", "labels.csv")
            ap = os.path.join(ROOT, "practice", "approvals.json")
            if not os.path.isfile(ev):
                self.skipTest("practice dataset not present")
            p = self._run({"op": "detector_evaluate", "events_path": ev,
                           "labels_path": lb, "approvals_path": ap}, d)
            self.assertEqual(p.returncode, 0, msg=p.stderr.decode())
            self.assertNotIn("Traceback", p.stderr.decode())
            r = json.loads(p.stdout)      # would raise on non-JSON
            self.assertIn("f1", r)
            self.assertEqual(r["f1"], 1.0)
            # previously crashed on sets: context must be JSON-safe
            self.assertIsInstance(r["context_model"]["role_scopes"]["viewer"],
                                  list)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_no_traceback_on_any_failure(self):
        d = self._fresh()
        import subprocess
        try:
            for req in ("{not json", "", '{"op":"detector_evaluate"}',
                        '{"op":"read","actor":["x"],"asset":123}'):
                p = subprocess.run(
                    [sys.executable, os.path.join(ROOT, "track4_service.py")],
                    input=req.encode(), capture_output=True,
                    env=dict(os.environ, TRACK4_STATE_DIR=d), timeout=60)
                self.assertEqual(p.returncode, 0, msg=req)
                self.assertNotIn("Traceback", p.stderr.decode(), msg=req)
                self.assertNotIn("Traceback", p.stdout.decode(), msg=req)
                json.loads(p.stdout)      # always valid JSON
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_concurrent_processes_serialize(self):
        import subprocess
        d = self._fresh()
        try:
            self._run({"op": "setup", "owners": {"s.txt": "owner"},
                       "contents": {"s.txt": "valuable"}}, d)

            def one(i):
                reqs = [{"op": "read", "actor": "owner", "asset": "s.txt",
                         "request_id": "p%d" % i},
                        {"op": "rotate_key"},
                        {"op": "verify_log"}]
                for req in reqs:
                    p = self._run(req, d)
                    if p.returncode != 0:
                        return "rc=%d" % p.returncode
                    out = p.stdout.decode()
                    if "Traceback" in out or not out.strip():
                        return "bad output: %r" % out[:80]
                    json.loads(out)
                return None

            errs = []

            def run_one(i):
                err = one(i)
                if err:
                    errs.append(err)

            threads = [threading.Thread(target=run_one, args=(i,))
                       for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(errs, [])
            # final state consistent: journal floor satisfied
            from src import state as st
            st.set_state_dir(d)
            try:
                state = st.load_state()
                floor = st.journal_floor(state["service_dsa_pk"])
                self.assertGreaterEqual(state["active_version"], floor[0])
                self.assertTrue(dispatch({"op": "verify_log"})["valid"])
            finally:
                st.set_state_dir(None)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestMsgIdBinding(QATest):
    """msg_id is now derived+authenticated metadata (audit finding)."""

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

    def test_renamed_msg_id_rejected(self):
        r = self._recv(msg_id="a" * 24)
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "msg_id_mismatch")
        self.assertNotIn("payload", json.dumps(r))

    def test_genuine_msg_id_still_delivers_then_duplicates(self):
        r = self._recv()
        self.assertEqual(r["decision"], "deliver")
        self.assertEqual(r["messages"][0]["plaintext"], "payload")
        r = self._recv()      # same envelope again -> duplicate by derived id
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "duplicate_replay")

    def test_cannot_bypass_duplicate_by_renaming(self):
        self._recv()
        r = self._recv(msg_id="b" * 24)   # rename a replay
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "msg_id_mismatch")


class TestAdapterTrustModel(QATest):
    """Second-pass audit reproductions: clock rewind, forged inline
    approvals, pending-session hijack, foreign close/resume."""

    def test_clock_cannot_rewind(self):
        dispatch({"op": "rotate_key", "grace_seconds": 30})
        dispatch({"op": "advance_time", "seconds": 40})   # past cutoff
        r = dispatch({"op": "authenticate", "actor": "victim",
                      "key_version": 1, "node": "node-a"})
        self.assertEqual(r["reason"], "old_key_after_cutoff")
        # rewind attempt: rejected, the dead key STAYS dead
        r = dispatch({"op": "advance_time", "seconds": -50})
        self.assertEqual(r["message"], "invalid_time_delta")
        self.assertEqual(r["reason"], "clock_is_monotonic")
        r = dispatch({"op": "authenticate", "actor": "victim",
                      "key_version": 1, "node": "node-a"})
        self.assertEqual(r["reason"], "old_key_after_cutoff")   # still dead

    def test_rewinding_cannot_unenforce_revocation(self):
        dispatch({"op": "re_enroll", "device": "dv", "actor": "bad"})
        dispatch({"op": "revoke", "device": "dv"})    # device-only revoke
        dispatch({"op": "advance_time", "seconds": 5})  # past node-b delay
        r = dispatch({"op": "authenticate", "actor": "bad",
                      "device": "dv", "node": "node-b", "key_version": 1})
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(dispatch({"op": "advance_time",
                                   "seconds": -50})["message"],
                         "invalid_time_delta")
        r = dispatch({"op": "authenticate", "actor": "bad",
                      "device": "dv", "node": "node-b", "key_version": 1})
        self.assertEqual(r["decision"], "deny")       # still revoked

    def test_inline_forged_approvals_ignored(self):
        dispatch({"op": "setup", "owners": {"reports/q.txt": "user-alex"},
                  "contents": {"reports/q.txt": "Q-REPORT"},
                  "admins": ["user-admin"]})
        forged = {"changes": [{"subject": "user-mallory",
                               "operation": "grant_role",
                               "role": "report-reader"}]}
        r = dispatch({"op": "grant_role", "admin": "user-admin",
                      "subject": "user-mallory", "role": "report-reader",
                      "approvals": forged})          # inline: IGNORED
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "no_matching_approval")
        r = dispatch({"op": "read", "actor": "user-mallory",
                      "asset": "reports/q.txt"})
        self.assertEqual(r["decision"], "deny")
        self.assertNotIn("Q-REPORT", json.dumps(r))

    def test_pending_session_cannot_be_hijacked(self):
        dispatch({"op": "re_enroll", "device": "d1", "actor": "alex"})
        dispatch({"op": "re_enroll", "device": "d2", "actor": "blair"})
        r = dispatch({"op": "session_open", "sender": "alex",
                      "recipient": "blair"})
        sid = r["sid"]
        # mallory tries to complete the handshake as the sender
        r = dispatch({"op": "session_accept", "sid": sid, "sender": "mallory"})
        self.assertEqual(r["message"], "endpoint_mismatch")
        self.assertEqual(r["reason"], "not_the_original_sender")
        # the real sender still completes it
        r = dispatch({"op": "session_accept", "sid": sid, "sender": "alex"})
        self.assertEqual(r["state"], "established")
        m = dispatch({"op": "message_send", "sid": sid,
                      "plaintext": "from-alex"})
        self.assertEqual(m["status"], "ok")

    def test_close_cannot_mint_foreign_resumption_token(self):
        dispatch({"op": "re_enroll", "device": "d1", "actor": "alex"})
        dispatch({"op": "re_enroll", "device": "d2", "actor": "blair"})
        r = dispatch({"op": "session_open", "sender": "alex",
                      "recipient": "blair"})
        sid = r["sid"]
        dispatch({"op": "session_accept", "sid": sid, "sender": "alex"})
        # mallory tries to take over the close and get HIS token
        r = dispatch({"op": "session_close", "sid": sid, "peer": "mallory"})
        self.assertEqual(r["message"], "endpoint_mismatch")
        self.assertEqual(r["reason"], "not_the_session_recipient")
        self.assertNotIn("resumption_token", r)
        # blair closes legitimately and resumes
        r = dispatch({"op": "session_close", "sid": sid, "peer": "blair"})
        self.assertTrue(r["resumption_token"])
        r = dispatch({"op": "session_resume", "sid": sid, "peer": "blair",
                      "resumption_token": r["resumption_token"]})
        self.assertEqual(r["decision"], "allow")

    def test_regular_close_and_accept_unchanged(self):
        dispatch({"op": "re_enroll", "device": "d1", "actor": "alex"})
        dispatch({"op": "re_enroll", "device": "d2", "actor": "blair"})
        r = dispatch({"op": "session_open", "sender": "alex",
                      "recipient": "blair"})
        # accept WITHOUT explicit sender still works (defaults to opener)
        r = dispatch({"op": "session_accept", "sid": r["sid"]})
        self.assertEqual(r["state"], "established")
        r = dispatch({"op": "session_close", "sid": r["sid"]})
        self.assertTrue(r["key_zeroized"])


class TestPracticeProcedureConformance(unittest.TestCase):
    """Conformance to the practice dataset's documented procedure:
    group by actor+session+correlation; exclusive valid_until; keep both
    timestamps in receipt order; labels never enter detection logic."""

    def _ev(self, eid, actor, session, src_svc, tgt, t):
        return {"event_id": eid, "event_time_utc": t,
                "received_time_utc": t, "source_clock_offset_ms": 0,
                "actor": actor, "source_service": src_svc,
                "target_service": tgt, "action": "read",
                "role_before": "viewer", "role_after": "viewer",
                "outcome": "allow", "approval_id": "",
                "session_id": session, "correlation_id": "c"}

    def test_grouping_includes_actor(self):
        # two different actors sharing one session id: separate groups,
        # so a single unknown edge each is NOT a lateral burst
        evs = [self._ev("g1", "alice", "shared", "portal", "billing",
                        "2026-02-01T09:00:00.000Z"),
               self._ev("g2", "bob", "shared", "portal", "billing",
                        "2026-02-01T09:00:01.000Z")]
        r = evaluate_labelled(events=evs, labels=None,
                              approvals={"changes": []})
        self.assertEqual(r["alerts"], [])

    def test_same_actor_burst_still_alerts(self):
        evs = [self._ev("g1", "alice", "shared", "portal", "billing",
                        "2026-02-01T09:00:00.000Z"),
               self._ev("g2", "alice", "shared", "portal", "billing",
                        "2026-02-01T09:00:01.000Z")]
        r = evaluate_labelled(events=evs, labels=None,
                              approvals={"changes": []})
        self.assertEqual(len(r["alerts"]), 2)

    def test_timeline_keeps_receipt_order_and_both_timestamps(self):
        # evt-014-style inversion: the OLDER event arrives LATER
        evs = [self._ev("older", "u", "s", "portal", "catalog",
                        "2026-02-01T09:00:02.000Z"),
               self._ev("newer", "u", "s", "portal", "catalog",
                        "2026-02-01T09:00:01.000Z")]
        r = evaluate_labelled(events=evs, labels=None,
                              approvals={"changes": []})
        self.assertEqual([e["event_id"] for e in r["timeline"]],
                         ["older", "newer"])   # receipt order, not sorted
        row = r["timeline"][0]
        self.assertEqual(row["event_time_utc"], "2026-02-01T09:00:02.000Z")
        self.assertEqual(row["received_time_utc"],
                         "2026-02-01T09:00:02.000Z")
        self.assertIn("estimated_event_time_utc", row)

    def test_valid_until_is_exclusive(self):
        from src.detector import _parse_ts, approval_matches, load_approvals
        approvals = {"changes": [{
            "approval_id": "ap-x", "subject": "maya",
            "operation": "grant_role", "role": "report-reader",
            "valid_from_utc": "2026-02-01T00:00:00Z",
            "valid_until_utc": "2026-02-01T12:00:00Z"}]}
        boundary = _parse_ts("2026-02-01T12:00:00Z")
        ok = approval_matches(load_approvals(None, approvals), {
            "approval_id": "ap-x", "subject": "maya",
            "operation": "grant_role", "role": "report-reader",
            "at": boundary - 1.0})          # 11:59:59Z - inside
        self.assertTrue(ok)
        at_boundary = approval_matches(load_approvals(None, approvals), {
            "approval_id": "ap-x", "subject": "maya",
            "operation": "grant_role", "role": "report-reader",
            "at": boundary})                # exactly AT valid_until
        self.assertFalse(at_boundary)       # exclusive per the dataset spec

    def test_detection_logic_runs_without_labels(self):
        # the practice procedure: load events WITHOUT labels into
        # detection; labels are only used for scoring afterwards
        evs = [self._ev("x1", "u", "s", "admin-console", "billing",
                        "2026-02-01T09:00:00.000Z"),
               self._ev("x2", "u", "s", "admin-console", "billing",
                        "2026-02-01T09:00:01.000Z")]
        r = evaluate_labelled(events=evs, labels=None,
                              approvals={"changes": []})
        self.assertEqual(r["true_positives"], 0)   # no ground truth loaded
        self.assertTrue(r["alerts"])               # rules ran label-free



class TestForwardSecrecyCompromise(QATest):
    """Later compromise of ALL long-term key material must not decrypt
    captured earlier session traffic. The attacker is given everything
    persisted in state.json (service keys, identity KEM/DSA secrets,
    historical key versions) plus the captured ciphertexts."""

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="track4_fs_")
        st.set_state_dir(self._dir)

    def tearDown(self):
        st.set_state_dir(None)
        shutil.rmtree(self._dir, ignore_errors=True)

    def test_captured_traffic_survives_long_term_compromise(self):
        dispatch({"op": "re_enroll", "device": "d1", "actor": "alice"})
        dispatch({"op": "re_enroll", "device": "d2", "actor": "bob"})
        # 1. establish a session and CAPTURE the traffic
        r_open = dispatch({"op": "session_open", "sender": "alice",
                           "recipient": "bob"})
        sid = r_open["sid"]
        r_accept = dispatch({"op": "session_accept", "sid": sid,
                             "sender": "alice"})
        encapsulation = bytes.fromhex(r_accept["ciphertext"])   # KEM ct
        m1 = dispatch({"op": "message_send", "sid": sid,
                       "plaintext": "captured secret one"})
        m2 = dispatch({"op": "message_send", "sid": sid,
                       "plaintext": "captured secret two"})
        envelopes = [(bytes.fromhex(m["nonce"]),
                      bytes.fromhex(m["ciphertext"]), m["counter"])
                     for m in (m1, m2)]
        info = ("track4-session:%s:%s:%s" % (sid, "alice", "bob")).encode()
        # 2. the session ends; keys zeroized
        r = dispatch({"op": "session_close", "sid": sid, "peer": "bob"})
        self.assertTrue(r["key_zeroized"])
        # 3. TOTAL long-term compromise: attacker dumps state.json
        state = st.load_state()
        self.assertIsNone(state["sessions"][sid]["key"])
        self.assertIsNone(state["sessions"][sid]["ephemeral_sk"])
        sk_pool = []
        for ident in state.get("identities", {}).values():
            for f in ("kem_sk", "dsa_sk"):
                if isinstance(ident.get(f), str) and ident[f]:
                    sk_pool.append(ident[f])
        if state.get("service_dsa_sk"):
            sk_pool.append(state["service_dsa_sk"])
        for v in state.get("key_versions", []):
            if v.get("kem_sk"):
                sk_pool.append(v["kem_sk"])
        self.assertGreater(len(sk_pool), 0)   # compromise is real
        # 4. the attacker tries EVERY long-term secret against the
        #    captured encapsulation, then against each captured message
        broke = False
        for sk_hex in sk_pool:
            try:
                ss = crypto.kem_decaps(bytes.fromhex(sk_hex), encapsulation)
            except Exception:
                continue        # wrong key type: no secret recovered
            key = crypto.hkdf(ss, info)
            for nonce, ct, counter in envelopes:
                try:
                    # worst case: the attacker also derives the key-
                    # commitment tag for the candidate key it is trying
                    aad = _msg_aad(sid, "alice", "bob", counter,
                                   key_commitment=_key_commitment(key.hex()))
                    crypto.aead_decrypt(key, nonce, ct, aad)
                    broke = True
                except Exception:
                    pass
        self.assertFalse(broke,
                         "long-term compromise decrypted captured traffic")
        # 5. normal messaging still works with a NEW session after the
        #    compromise (the old captured ciphertext stays undecryptable).
        r_open2 = dispatch({"op": "session_open", "sender": "alice",
                            "recipient": "bob"})
        sid2 = r_open2["sid"]
        dispatch({"op": "session_accept", "sid": sid2, "sender": "alice"})
        fresh = dispatch({"op": "message_send", "sid": sid2,
                          "plaintext": "fresh session works"})
        received = dispatch({"op": "message_receive", "sid": sid2,
                             "sender": "alice", "recipient": "bob",
                             "msg_id": fresh["msg_id"],
                             "counter": fresh["counter"],
                             "nonce": fresh["nonce"],
                             "ciphertext": fresh["ciphertext"]})
        self.assertEqual(received["decision"], "deliver")
        self.assertEqual(received["messages"][0]["plaintext"],
                         "fresh session works")


class TestKeyCommitment(QATest):
    """AES-GCM is not key-committing; the HMAC commitment tag inside the
    AAD must bind every envelope to exactly the session key in use."""

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="track4_kc_")
        st.set_state_dir(self._dir)

    def tearDown(self):
        st.set_state_dir(None)
        shutil.rmtree(self._dir, ignore_errors=True)

    def _established(self):
        dispatch({"op": "re_enroll", "device": "d1", "actor": "alice"})
        dispatch({"op": "re_enroll", "device": "d2", "actor": "bob"})
        r = dispatch({"op": "session_open", "sender": "alice",
                      "recipient": "bob"})
        sid = r["sid"]
        dispatch({"op": "session_accept", "sid": sid, "sender": "alice"})
        return sid

    def _deliver(self, sid, nonce, ct):
        return dispatch({"op": "message_receive", "sid": sid,
                         "sender": "alice", "recipient": "bob",
                         "msg_id": _msg_id(sid, 1), "counter": 1,
                         "nonce": nonce, "ciphertext": ct})

    def test_commitment_binds_envelope_to_the_session_key(self):
        """An envelope encrypted under ANY other key must not deliver,
        even with the right session id/counter - the AAD commitment
        makes the key substitution fail authentication."""
        sid = self._established()
        state = st.load_state()
        session = state["sessions"][sid]
        real_key = bytes.fromhex(session["key"])
        nonce = _nonce_for(real_key, 1)
        plaintext = b"committed message"
        # correct key + correct commitment -> delivers
        aad = _msg_aad(sid, "alice", "bob", 1,
                       key_commitment=_key_commitment(session["key"]))
        ct = crypto.aead_encrypt(real_key, nonce, plaintext, aad)
        r = self._deliver(sid, nonce.hex(), ct.hex())
        self.assertEqual(r["decision"], "deliver")

    def test_wrong_key_with_matching_metadata_fails(self):
        sid = self._established()
        state = st.load_state()
        session = state["sessions"][sid]
        real_key = bytes.fromhex(session["key"])
        # a DIFFERENT key, but commitment tag also derived from that
        # different key (attacker fully controls its own key material)
        rogue_key = crypto.hkdf(b"rogue-shared-secret", b"x")
        nonce = _nonce_for(rogue_key, 1)
        aad = _msg_aad(sid, "alice", "bob", 1,
                       key_commitment=_key_commitment(rogue_key.hex()))
        ct = crypto.aead_encrypt(rogue_key, nonce, b"injected", aad)
        r = self._deliver(sid, nonce.hex(), ct.hex())
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "authentication_failed")
        # and a message encrypted under the REAL key but with the ROGUE
        # commitment in the AAD also fails (commitment is authenticated)
        nonce2 = _nonce_for(real_key, 1)
        aad2 = _msg_aad(sid, "alice", "bob", 1,
                        key_commitment=_key_commitment(rogue_key.hex()))
        ct2 = crypto.aead_encrypt(real_key, nonce2, b"swapped", aad2)
        r2 = self._deliver(sid, nonce2.hex(), ct2.hex())
        self.assertEqual(r2["decision"], "reject")

    def test_commitment_is_deterministic_per_key_and_in_aad(self):
        self.assertEqual(_key_commitment("aa" * 32),
                         _key_commitment("aa" * 32))
        self.assertNotEqual(_key_commitment("aa" * 32),
                            _key_commitment("bb" * 32))
        aad = json.loads(_msg_aad("s", "a", "b", 1,
                                  key_commitment="c0ffee").decode())
        self.assertEqual(aad["key_commitment"], "c0ffee")


if __name__ == "__main__":
    unittest.main(verbosity=2)
