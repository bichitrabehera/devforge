"""Objective-by-objective tests for Track 4.

Each test asserts a graded behavior from the challenge checklist, not just
"status == ok".  State is isolated per test via a private state directory.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import state as st
from src.dispatch import dispatch
from src.detector import evaluate_labelled

PRACTICE = os.path.join(ROOT, "practice")


class ObjectiveTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="track4_test_")
        st.set_state_dir(self._dir)

    def tearDown(self):
        st.set_state_dir(None)
        shutil.rmtree(self._dir, ignore_errors=True)

    # helpers ------------------------------------------------------------
    def setup_service(self, **kw):
        return dispatch({"op": "setup", **kw})


class TestRotationCutoff(ObjectiveTest):
    """Objective: key rotation. Authorized transfers continue during
    rotation; every node rejects the old key after the documented cutoff."""

    def test_transfer_during_rotation_and_cutoff_after(self):
        r = self.setup_service(grace_seconds=30)
        v1 = r["active_version"]
        dispatch({"op": "advance_time", "seconds": 5})
        # rotate -> v2; v1 stays valid until cutoff_at = created + 30s
        r = dispatch({"op": "rotate_key", "grace_seconds": 30})
        self.assertEqual(r["new_version"], v1 + 1)
        self.assertTrue(r["grace_applies"])
        dispatch({"op": "advance_time", "seconds": 10})
        # authorized transfer with OLD version inside the grace window: allowed
        r = dispatch({"op": "authenticate", "actor": "user-alex",
                      "key_version": v1, "node": "node-a"})
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["outcome"], "grace")
        # past cutoff: every node rejects the old version
        dispatch({"op": "advance_time", "seconds": 25})
        for node in ("node-a", "node-b", "node-c"):
            r = dispatch({"op": "authenticate", "actor": "user-alex",
                          "key_version": v1, "node": node})
            self.assertEqual(r["decision"], "deny")
            self.assertEqual(r["reason"], "old_key_after_cutoff")
        # current version keeps working
        r = dispatch({"op": "authenticate", "actor": "user-alex",
                      "node": "node-b"})
        self.assertEqual(r["decision"], "allow")

    def test_grace_period_documented(self):
        r = self.setup_service(grace_seconds=45)
        r = dispatch({"op": "rotate_key"})
        self.assertEqual(r["grace_seconds"], 45.0)
        self.assertIn("cutoff_at", r)


class TestRevocationAcrossNodes(ObjectiveTest):
    """Objective: revocation. Every node rejects a revoked key; time from
    revocation to last-node enforcement is reported; owner re-enrols; other
    users retain access."""

    def test_revoke_propagates_and_reports_timing(self):
        self.setup_service()
        r = dispatch({"op": "revoke", "device": "device-blair"})
        self.assertIn("time_until_last_node_enforces", r)
        self.assertEqual(r["last_node"], "node-c")
        self.assertEqual(r["time_until_last_node_enforces"], 4.0)
        # node-a (no sync delay): instant enforcement
        r = dispatch({"op": "authenticate", "actor": "user-blair",
                      "device": "device-blair", "node": "node-a"})
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "revoked")
        # node-b within its 2s delay: not yet enforced
        r = dispatch({"op": "authenticate", "actor": "user-blair",
                      "device": "device-blair", "node": "node-b"})
        self.assertEqual(r["decision"], "allow")
        # after the delay: enforced
        dispatch({"op": "advance_time", "seconds": 3})
        r = dispatch({"op": "authenticate", "actor": "user-blair",
                      "device": "device-blair", "node": "node-b"})
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "revoked")
        # node-c (4 s delay) is the last node to enforce
        r = dispatch({"op": "authenticate", "actor": "user-blair",
                      "device": "device-blair", "node": "node-c"})
        self.assertEqual(r["decision"], "allow")   # still in propagation
        dispatch({"op": "advance_time", "seconds": 2})
        r = dispatch({"op": "authenticate", "actor": "user-blair",
                      "device": "device-blair", "node": "node-c"})
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "revoked")

    def test_revoke_does_not_break_other_users(self):
        self.setup_service()
        dispatch({"op": "revoke", "device": "device-blair"})
        r = dispatch({"op": "authenticate", "actor": "user-alex",
                      "device": "device-alex", "node": "node-a"})
        self.assertEqual(r["decision"], "allow")

    def test_re_enroll_restores_owner_only(self):
        self.setup_service()
        dispatch({"op": "revoke", "device": "device-blair"})
        r = dispatch({"op": "re_enroll", "device": "device-blair",
                      "actor": "user-blair"})
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["other_users_unaffected"])
        r = dispatch({"op": "authenticate", "actor": "user-blair",
                      "device": "device-blair", "node": "node-b"})
        self.assertEqual(r["decision"], "allow")


class TestCrashRecovery(ObjectiveTest):
    """Objective: crash recovery. After an interrupted rotation the service
    recovers a consistent, authorized key version; revocations survive;
    committed keys and protected data remain available."""

    def test_recover_after_interrupted_rotation(self):
        self.setup_service(grace_seconds=30, owners={"doc.txt": "user-alex"})
        v1 = dispatch({"op": "status"})["active_version"]
        dispatch({"op": "revoke", "device": "device-blair"})
        dispatch({"op": "begin_rotation"})          # journaled, uncommitted
        dispatch({"op": "crash_rotation", "seconds": 1})
        r = dispatch({"op": "recover_state"})
        self.assertTrue(r["recovered"])
        self.assertEqual(r["committed_version"], v1)   # uncommitted discarded
        self.assertIn("device-blair", r["still_revoked"])
        self.assertTrue(r["log_valid"])
        self.assertTrue(r["protected_data_available"])
        # committed key and protected data still work
        r = dispatch({"op": "authenticate", "actor": "user-alex",
                      "device": "device-alex", "node": "node-a"})
        self.assertEqual(r["decision"], "allow")
        r = dispatch({"op": "read", "actor": "user-alex", "asset": "doc.txt"})
        self.assertEqual(r["decision"], "allow")

    def test_recovery_setup_requires_backup_when_identity_lost(self):
        self.setup_service()
        dispatch({"op": "create_backup", "backup_id": "b1"})
        dispatch({"op": "corrupt_state"})           # total disk loss
        r = dispatch({"op": "recover_state"})
        self.assertEqual(r["status"], "error")   # honest failure report
        self.assertEqual(r["message"], "service_identity_lost")
        r = dispatch({"op": "restore_backup", "backup_id": "b1"})
        self.assertTrue(r["restored"])


class TestBackupIntegrity(ObjectiveTest):
    """Objective: backup integrity. Recovery detects a damaged backup and
    reports the failure; only verified key material is used."""

    def test_damaged_backup_rejected_valid_restored(self):
        self.setup_service(grace_seconds=30)
        dispatch({"op": "rotate_key"})
        dispatch({"op": "create_backup", "backup_id": "b1"})
        r = dispatch({"op": "damage_backup", "backup_id": "b1"})
        self.assertTrue(r["damaged"])
        r = dispatch({"op": "restore_backup", "backup_id": "b1"})
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["message"], "backup_integrity_failure")
        self.assertFalse(r["restored"])
        # state untouched: current version still active
        self.assertEqual(dispatch({"op": "status"})["active_version"], 2)
        # a clean backup restores
        dispatch({"op": "create_backup", "backup_id": "b2"})
        r = dispatch({"op": "restore_backup", "backup_id": "b2"})
        self.assertTrue(r["restored"])
        self.assertTrue(r["log_valid"])


class TestLogIntegrity(ObjectiveTest):
    """Objective: log integrity. User text cannot forge a second event or
    change the recorded actor; operators can verify the log."""

    def test_injection_text_stays_one_record(self):
        self.setup_service()
        evil = '"}},"actor":"root","action":"grant_all","seq":99'
        r = dispatch({"op": "append_log", "actor": "mallory",
                      "action": "read", "asset": "x", "detail": evil})
        state = st.load_state()
        entry = state["log"][-1]
        self.assertEqual(entry["actor"], "mallory")   # actor unchanged
        self.assertEqual(entry["detail"], evil)       # text is one string
        self.assertEqual(len(state["log"]),
                         dispatch({"op": "verify_log"})["entries"])
        r = dispatch({"op": "verify_log"})
        self.assertTrue(r["valid"])

    def test_tamper_detected_by_verify(self):
        self.setup_service()
        dispatch({"op": "append_log", "actor": "alice", "action": "read",
                  "asset": "a"})
        dispatch({"op": "append_log", "actor": "bob", "action": "read",
                  "asset": "b"})
        dispatch({"op": "tamper_log", "seq": 2, "field": "actor",
                  "value": "attacker"})
        r = dispatch({"op": "verify_log"})
        self.assertFalse(r["valid"])
        # hash is stale -> detected first
        self.assertEqual(r["reason"], "hash_mismatch")
        # plain-hash rewrite (recomputed SHA-256, forged signature) is still
        # caught because entries are ML-DSA signed
        import hashlib
        state = st.load_state()
        e = state["log"][1]
        e["actor"] = "attacker"
        e["signature"] = "00"
        core = {k: e[k] for k in ("seq", "ts", "actor", "action", "asset",
                                  "decision", "request_id", "detail",
                                  "prev_hash")}
        e["hash"] = hashlib.sha256(
            json.dumps(core, sort_keys=True, separators=(",", ":"))
            .encode()).hexdigest()
        st.save_state(state)
        r = dispatch({"op": "verify_log"})
        self.assertFalse(r["valid"])
        self.assertEqual(r["reason"], "bad_signature")

    def test_log_entries_are_signed(self):
        self.setup_service()
        dispatch({"op": "append_log", "actor": "alice", "action": "read",
                  "asset": "a"})
        entry = st.load_state()["log"][-1]
        self.assertTrue(entry["signature"])
        self.assertGreater(len(bytes.fromhex(entry["signature"])), 2000)


class TestAccessControl(ObjectiveTest):
    """Access control: ownership/role decisions, disabled actors denied,
    every decision logged."""

    def test_owner_reads_and_other_denied(self):
        self.setup_service(owners={"doc.txt": "user-alex"})
        r = dispatch({"op": "read", "actor": "user-alex", "asset": "doc.txt"})
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["body"], "")
        r = dispatch({"op": "read", "actor": "user-blair", "asset": "doc.txt"})
        self.assertEqual(r["decision"], "deny")
        self.assertIn("not_owner:user-alex", r["reasons"])

    def test_disabled_actor_denied_everywhere(self):
        self.setup_service(owners={"doc.txt": "user-alex"})
        dispatch({"op": "disable", "actor": "user-alex"})
        for node in ("node-a", "node-b", "node-c"):
            r = dispatch({"op": "authenticate", "actor": "user-alex",
                          "device": "device-alex", "node": node})
            self.assertEqual(r["decision"], "deny")
            self.assertEqual(r["reason"], "disabled")


class TestDetectorLabelled(ObjectiveTest):
    """Objective: routine vs suspicious activity with metrics on labelled
    logs; lateral movement with explainable alerts; clock differences."""

    def _evaluate(self):
        return evaluate_labelled(
            events_path=os.path.join(PRACTICE, "events.csv"),
            labels_path=os.path.join(PRACTICE, "labels.csv"),
            approvals_path=os.path.join(PRACTICE, "approvals.json"))

    def test_metrics_on_labelled_log(self):
        r = self._evaluate()
        self.assertEqual(r["f1"], 1.0)
        self.assertEqual(r["false_alerts_per_1000_benign"], 0.0)
        self.assertIsNotNone(r["median_time_to_alert_s"])
        self.assertGreater(r["median_time_to_alert_s"], 0)

    def test_alerts_are_explainable(self):
        r = self._evaluate()
        rules = {a["rule"] for a in r["alerts"]}
        self.assertEqual(rules, {"unexpected_role_change",
                                 "review_after_role_change",
                                 "lateral_movement"})
        for a in r["alerts"]:
            self.assertTrue(a["identity"])
            self.assertEqual(len(a["services"]), 2)
            self.assertTrue(a["related_events"])
            self.assertTrue(a["explanation"])
            self.assertGreaterEqual(a["time_to_alert_s"], 0)
        lat = [a for a in r["alerts"] if a["rule"] == "lateral_movement"]
        # svc-report-worker: reports -> billing -> archive -> identity
        self.assertTrue(all(a["identity"] == "svc-report-worker"
                            for a in lat))
        self.assertIn("billing", [s for a in lat for s in a["services"]])
        self.assertEqual([a["event_id"] for a in lat],
                         ["evt-010", "evt-011", "evt-012"])
        # approved administration is NOT alerted
        self.assertNotIn("evt-003", {a["event_id"] for a in r["alerts"]})
        self.assertNotIn("evt-004", {a["event_id"] for a in r["alerts"]})
        self.assertNotIn("evt-016", {a["event_id"] for a in r["alerts"]})

    def test_isolated_unknown_edge_not_alerted(self):
        r = self._evaluate()
        flagged = {a["event_id"] for a in r["alerts"]}
        self.assertNotIn("evt-020", flagged)   # single deny, no burst
        self.assertNotIn("evt-017", flagged)   # routine denial post-revoke
        self.assertNotIn("evt-018", flagged)

    def test_clock_differences_and_out_of_order(self):
        r = self._evaluate()
        notes = {a["event_id"]: a.get("note") for a in r["annotations"]}
        self.assertEqual(notes.get("evt-015"), "clock_offset")
        self.assertEqual(notes.get("evt-013"), "delayed_delivery")
        self.assertEqual(r["supported_offset_range_ms"], 60000)
        self.assertEqual(r["reorder_tolerance_s"], 10.0)

    def test_offset_beyond_range_flagged_uncertain(self):
        events = [{"event_id": "x1", "event_time_utc":
                   "2026-01-15T09:00:00.000Z",
                   "received_time_utc": "2026-01-15T09:02:30.000Z",
                   "source_clock_offset_ms": 120000,
                   "actor": "u", "source_service": "portal",
                   "target_service": "catalog", "action": "read",
                   "role_before": "viewer", "role_after": "viewer",
                   "outcome": "allow", "approval_id": "",
                   "session_id": "s1", "correlation_id": "c1"}]
        r = evaluate_labelled(events=events, labels={},
                              approvals={"changes": []})
        self.assertTrue(any(o["event_id"] == "x1"
                            for o in r["order_uncertain"]))


class TestMessaging(ObjectiveTest):
    """Objectives: replay/recipient binding, forward secrecy, delivery under
    loss/reordering, session resumption."""

    def _establish(self):
        self.setup_service()
        dispatch({"op": "re_enroll", "device": "d-alex", "actor": "user-alex"})
        dispatch({"op": "re_enroll", "device": "d-blair", "actor": "user-blair"})
        r = dispatch({"op": "session_open", "sender": "user-alex",
                      "recipient": "user-blair"})
        sid = r["sid"]
        dispatch({"op": "session_accept", "sid": sid, "sender": "user-alex"})

        def send(text):
            return dispatch({"op": "message_send", "sid": sid,
                             "plaintext": text})
        return sid, send

    def _recv(self, sid, m, recipient="user-blair"):
        return dispatch({"op": "message_receive", "sid": sid,
                         "recipient": recipient, "sender": "user-alex",
                         "msg_id": m["msg_id"], "counter": m["counter"],
                         "nonce": m["nonce"],
                         "ciphertext": m["ciphertext"]})

    def test_replay_and_recipient_binding(self):
        sid, send = self._establish()
        m = send("secret payload")
        r = self._recv(sid, m)
        self.assertEqual(r["decision"], "deliver")
        self.assertEqual(r["messages"][0]["plaintext"], "secret payload")
        # duplicate of the same message -> rejected
        r = self._recv(sid, m)
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "duplicate_replay")
        # wrong recipient -> rejected (authenticated recipient binding)
        m2 = send("second")
        r = self._recv(sid, m2, recipient="user-mallory")
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "recipient_binding_mismatch")
        # tampered ciphertext / AAD -> rejected with failure report
        m3 = send("third")
        bad = dict(m3, ciphertext=m3["ciphertext"][:-4] + "0000")
        r = self._recv(sid, bad)
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "authentication_failed")
        # tampered counter (AAD mismatch) -> rejected
        r = dispatch({"op": "message_receive", "sid": sid,
                      "recipient": "user-blair", "sender": "user-alex",
                      "msg_id": m3["msg_id"], "counter": m3["counter"] + 1,
                      "nonce": m3["nonce"], "ciphertext": m3["ciphertext"]})
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "authentication_failed")

    def test_forward_secrecy(self):
        sid, send = self._establish()
        open_rec = st.load_state()["sessions"][sid]
        # during the session the ephemeral secret is already zeroized
        self.assertIsNone(open_rec["ephemeral_sk"])
        send("past message 1")
        send("past message 2")
        r = dispatch({"op": "session_close", "sid": sid, "peer": "user-blair"})
        self.assertTrue(r["key_zeroized"])
        rec = st.load_state()["sessions"][sid]
        # after close: no session key and no ephemeral secret anywhere
        self.assertIsNone(rec["key"])
        self.assertIsNone(rec["ephemeral_sk"])
        raw = json.dumps(st.load_state())
        # the session key itself is gone from persisted state entirely
        self.assertNotIn('"key": "', raw)
        # the only key material that could decapsulate was the ephemeral
        # secret, which no longer exists -> long-term key exposure cannot
        # reveal the completed session's contents.

    def test_delivery_under_loss_and_reordering(self):
        sid, send = self._establish()
        m1, m2, m3, m4 = send("m1"), send("m2"), send("m3"), send("m4")
        # m3 arrives first (reordering after a loss): buffered
        r = self._recv(sid, m3)
        self.assertEqual(r["decision"], "buffered")
        # m2 fills part of the hole: buffered again
        r = self._recv(sid, m2)
        self.assertEqual(r["decision"], "buffered")
        # m1 fills the hole: m1, m2, m3 delivered in counter order
        r = self._recv(sid, m1)
        self.assertEqual(r["decision"], "deliver")
        self.assertEqual([x["plaintext"] for x in r["messages"]],
                         ["m1", "m2", "m3"])
        self.assertEqual(r["next_deliver"], 4)
        # m4 delivers normally
        r = self._recv(sid, m4)
        self.assertEqual(r["decision"], "deliver")
        # gap beyond the documented window (8) -> delivery failure reported:
        # keep counter 5 undelivered and jump to counter 14
        msgs = {m["counter"]: m for m in
                (send("m%d" % i) for i in range(5, 15))}
        r = self._recv(sid, msgs[14])
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "gap_too_large")
        failures = dispatch({"op": "inbox_drain",
                             "recipient": "user-blair"})["failures"]
        self.assertTrue(any(f["failure"] == "gap_too_large" for f in failures))

    def test_session_resumption_peer_binding(self):
        sid, send = self._establish()
        send("before close")
        r = dispatch({"op": "session_close", "sid": sid, "peer": "user-blair"})
        token = r["resumption_token"]
        # legitimate peer resumes: allowed, key ratcheted
        r = dispatch({"op": "session_resume", "sid": sid,
                      "peer": "user-blair", "resumption_token": token})
        self.assertEqual(r["decision"], "allow")
        self.assertTrue(r["key_replaced"])
        # a different identity presenting the SAME sid + old token: rejected
        r = dispatch({"op": "session_resume", "sid": sid,
                      "peer": "user-mallory", "resumption_token": token})
        self.assertEqual(r["decision"], "reject")
        self.assertEqual(r["reason"], "peer_not_bound_to_session")


class TestServiceAdapter(ObjectiveTest):
    """End-to-end through the JSON stdin/stdout adapter."""

    def test_adapter_roundtrip(self):
        env = dict(os.environ)
        env["TRACK4_STATE_DIR"] = tempfile.mkdtemp(prefix="track4_e2e_")

        def call(req):
            p = subprocess.run(
                [sys.executable, os.path.join(ROOT, "track4_service.py")],
                input=json.dumps(req), capture_output=True, text=True,
                env=env, cwd=ROOT)
            lines = [l for l in p.stdout.splitlines() if l.strip()]
            return json.loads(lines[-1])

        r = call({"op": "setup"})
        self.assertEqual(r["status"], "ok")
        r = call({"op": "append_log", "actor": "alice", "action": "read",
                  "asset": "a"})
        self.assertEqual(r["status"], "ok")
        r = call({"op": "verify_log"})
        self.assertTrue(r["valid"])
        r = call({"op": "bogus_op"})
        self.assertEqual(r["status"], "error")
        self.assertIn("unknown_op", r["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
