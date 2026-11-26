"""Adversarial (red-team) regression tests.

Each test reproduces an attack attempted against the system and asserts the
detect-and-respond behavior. Findings and severities are tracked in
docs/SECURITY_ASSESSMENT.md.
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import crypto, state as st  # noqa: E402
from src.dispatch import dispatch  # noqa: E402
from pqcrypto.kem import ml_kem_768  # noqa: E402


def fresh_dir():
    d = tempfile.mkdtemp(prefix="track4_red_")
    st.set_state_dir(d)
    return d


class AttackTest(unittest.TestCase):
    def setUp(self):
        self._dir = fresh_dir()
        dispatch({"op": "setup", "owners": {"secret.txt": "victim"},
                  "contents": {"secret.txt": "classified"}})

    def tearDown(self):
        st.set_state_dir(None)
        shutil.rmtree(self._dir, ignore_errors=True)


class TestStateTampering(AttackTest):
    """ATTACK 1 (was CRITICAL, now mitigated): rewrite owners on disk."""

    def test_tampered_state_is_quarantined_and_restorable(self):
        # seed a verified backup BEFORE tampering
        dispatch({"op": "create_backup", "backup_id": "clean"})
        # attacker edits state.json: becomes owner of everything
        sp = st.state_path()
        raw = json.load(open(sp))
        raw["owners"]["secret.txt"] = "attacker"
        raw.pop("state_hash", None)
        json.dump(raw, open(sp, "w"))
        r = dispatch({"op": "read", "actor": "attacker",
                      "asset": "secret.txt"})
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["message"], "state_integrity_failure")
        self.assertNotIn("body", r)          # content NOT disclosed
        # every other op refused too
        self.assertEqual(dispatch({"op": "revoke",
                                   "actor": "attacker"})["message"],
                         "state_integrity_failure")
        # recovery path: restore verified material only
        r = dispatch({"op": "restore_backup", "backup_id": "clean"})
        self.assertTrue(r["restored"])
        self.assertTrue(r["log_valid"])
        r = dispatch({"op": "read", "actor": "attacker",
                      "asset": "secret.txt"})
        self.assertEqual(r["decision"], "deny")

    def test_silent_tamper_of_log_region_detected(self):
        sp = st.state_path()
        raw = json.load(open(sp))
        # tamper a committed audit entry inside the state file
        raw["log"][-1]["decision"] = "allow"
        raw.pop("state_hash", None)
        json.dump(raw, open(sp, "w"))
        r = dispatch({"op": "status"})
        self.assertEqual(r["status"], "ok")   # status allowed (read-only)
        r = dispatch({"op": "read", "actor": "victim",
                      "asset": "secret.txt"})
        self.assertEqual(r["message"], "state_integrity_failure")


class TestJournalForgery(AttackTest):
    """ATTACK 2 (was HIGH, now mitigated): forged rotation commit replayed."""

    def test_forged_journal_record_rejected_on_replay(self):
        dispatch({"op": "rotate_key"})          # journal: commit v2 (signed)
        apk, ask = crypto.kem_keypair()
        adsk = crypto.dsa_keypair()[1].hex()    # attacker ML-DSA key
        rec = {"kind": "rotation", "step": "commit", "version": 999,
               "created_at": 1, "cutoff_at": 2, "kem_pk": apk.hex(),
               "kem_sk": ask.hex(), "ts": 1}
        rec["journal_sig"] = crypto.dsa_sign(
            adsk, crypto.canonical(rec).encode())
        with open(st.journal_path(), "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        # also tamper an existing (signed) record -> signature breaks
        lines = open(st.journal_path()).read().splitlines()
        first = json.loads(lines[0])
        first["version"] = 777
        lines[0] = json.dumps(first, sort_keys=True)
        open(st.journal_path(), "w").write("\n".join(lines) + "\n")
        r = dispatch({"op": "recover_state"})
        self.assertTrue(r["recovered"])
        self.assertNotEqual(r["committed_version"], 999)
        self.assertNotEqual(r["committed_version"], 777)
        self.assertGreaterEqual(r["journal_records_rejected"], 1)

    def test_unsigned_journal_record_rejected(self):
        dispatch({"op": "rotate_key"})
        apk, ask = crypto.kem_keypair()
        rec = {"kind": "rotation", "step": "commit", "version": 500,
               "created_at": 1, "cutoff_at": 2, "kem_pk": apk.hex(),
               "kem_sk": ask.hex(), "ts": 1}      # NO journal_sig
        with open(st.journal_path(), "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        r = dispatch({"op": "recover_state"})
        self.assertNotEqual(r["committed_version"], 500)


class TestDecisionOverwrite(AttackTest):
    """ATTACK 3 (was LOW-MED, now mitigated): request_id reuse."""

    def test_first_write_wins(self):
        dispatch({"op": "read", "actor": "victim", "asset": "secret.txt",
                  "request_id": "victim-r1"})
        dispatch({"op": "read", "actor": "attacker", "asset": "secret.txt",
                  "request_id": "victim-r1"})
        r = dispatch({"op": "audit", "request_id": "victim-r1"})
        self.assertEqual(r["decision"], "allow")   # original record intact


class TestBackupSwap(AttackTest):
    """ATTACK 4: attacker replaces the whole backup blob."""

    def test_fully_forged_backup_rejected(self):
        dispatch({"op": "create_backup", "backup_id": "b1"})
        from src.recovery import _backup_path
        bp = _backup_path("b1")
        atk_pk, atk_sk = crypto.dsa_keypair()
        manifest = {"backup_id": "b1", "service_dsa_pk": atk_pk.hex(),
                    "payload_sha256": crypto.sha256_hex("{}")}
        json.dump({"manifest": manifest,
                   "signature": crypto.dsa_sign(
                       atk_sk.hex(), crypto.canonical(manifest).encode()),
                   "payload": "{}"}, open(bp, "w"))
        r = dispatch({"op": "restore_backup", "backup_id": "b1"})
        self.assertEqual(r["message"], "backup_identity_mismatch")
        self.assertFalse(r["restored"])
        # live state untouched: victim still owner, content intact
        r = dispatch({"op": "read", "actor": "victim",
                      "asset": "secret.txt"})
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["body"], "classified")


class TestMessagingAttacks(AttackTest):
    """ATTACKS 5/6/10: cross-session replay, token forgery, session DoS."""

    def setUp(self):
        super().setUp()
        for d, a in (("d1", "a"), ("d2", "b")):
            dispatch({"op": "re_enroll", "device": d, "actor": a})

    def _session(self):
        r = dispatch({"op": "session_open", "sender": "a", "recipient": "b"})
        dispatch({"op": "session_accept", "sid": r["sid"], "sender": "a"})
        return r["sid"]

    def test_cross_session_ciphertext_replay(self):
        s1 = self._session()
        m = dispatch({"op": "message_send", "sid": s1, "plaintext": "x"})
        s2 = self._session()
        r = dispatch({"op": "message_receive", "sid": s2,
                      "recipient": "b", "sender": "a",
                      "msg_id": m["msg_id"], "counter": m["counter"],
                      "nonce": m["nonce"], "ciphertext": m["ciphertext"]})
        self.assertEqual(r["decision"], "reject")
        # derived-msg_id check fires before AEAD (sid differs -> id differs)
        self.assertIn(r["reason"], ("msg_id_mismatch", "authentication_failed"))

    def test_forged_resumption_token(self):
        s = self._session()
        r = dispatch({"op": "session_close", "sid": s, "peer": "b"})
        self.assertTrue(r["resumption_token"])
        for forged in ("f" * 64, r["resumption_token"][:-1] +
                       ("0" if r["resumption_token"][-1] != "0" else "1")):
            r = dispatch({"op": "session_resume", "sid": s, "peer": "b",
                          "resumption_token": forged})
            self.assertEqual(r["decision"], "reject")
            self.assertEqual(r["reason"], "peer_not_bound_to_session")

    def test_session_flood_capped(self):
        created = 0
        for _ in range(400):
            r = dispatch({"op": "session_open", "sender": "a",
                          "recipient": "b"})
            if r.get("message") == "too_many_sessions":
                break
            created += 1
        self.assertLess(created, 400)      # cap enforced
        self.assertGreater(created, 0)     # normal operation before cap


class TestInjectionAndFuzz(AttackTest):
    """ATTACKS 7/8/9: injection, type confusion, fuzzing."""

    def test_log_injection_newline_and_unicode(self):
        evil = '"}}\n,"actor":"root","action":"own-everything"'
        dispatch({"op": "append_log", "actor": "mallory\nROOT",
                  "action": "read", "asset": "x", "detail": evil})
        self.assertTrue(dispatch({"op": "verify_log"})["valid"])
        entry = st.load_state()["log"][-1]
        self.assertEqual(entry["actor"], "mallory\nROOT")  # recorded actor
        self.assertEqual(entry["detail"], evil)            # one string

    def test_protected_read_type_confusion(self):
        pk, sk = crypto.kem_keypair()
        # type-confused challenge with an AUTHORIZED actor
        r = dispatch({"op": "protected_read", "actor": "victim",
                      "asset": "secret.txt",
                      "challenge": {"nested": ["obj", 1]},
                      "public_key": base64.b64encode(pk).decode()})
        self.assertEqual(r["decision"], "allow")   # coerced, no crash
        shared = crypto.kem_decaps(sk, base64.b64decode(r["ciphertext"]))
        # proof must be over the canonicalized challenge + body
        expected = hmac_mod.new(
            shared, (crypto.canonical({"nested": ["obj", 1]}) +
                     "classified").encode(), hashlib.sha256).hexdigest()
        self.assertEqual(r["proof"], expected)

    def test_fuzz_inputs_fail_closed(self):
        cases = [
            {"op": "authenticate", "actor": "victim", "key_version": "abc"},
            {"op": "authenticate", "actor": "victim", "key_version": None},
            {"op": "read", "actor": ["a"], "asset": "secret.txt"},
            {"op": "read", "actor": "victim", "asset": {"a": 1}},
            {"op": "tamper_log", "seq": "x"},
            {"op": "message_receive", "sid": 123, "counter": "x"},
            {"op": "rotate_key", "grace_seconds": "lots"},
            {"op": "protected_read", "actor": "victim",
             "asset": "secret.txt", "challenge": "c",
             "public_key": 12345},
        ]
        for req in cases:
            r = dispatch(req)
            # either a graceful error or a deny - never a crash/allow-leak
            self.assertIn(r.get("status"), ("ok", "error"), msg=str(req))
            if r.get("decision") is not None:
                self.assertNotIn("body", r, msg=str(req))
            self.assertNotIn("classified", json.dumps(r), msg=str(req))

    def test_protected_read_huge_challenge_bounded_output(self):
        pk, _ = crypto.kem_keypair()
        r = dispatch({"op": "protected_read", "actor": "victim",
                      "asset": "secret.txt", "challenge": "A" * 100000,
                      "public_key": base64.b64encode(pk).decode()})
        self.assertEqual(r["decision"], "allow")
        # response stays small: ciphertext + 64-char proof, no challenge echo
        self.assertLess(len(json.dumps(r)), 10000)


class TestDetectorPoisoning(AttackTest):
    """ATTACK 11: crafted events (wild offsets, injection-ish fields)."""

    def test_poisoned_events_flagged_not_crash(self):
        from src.detector import evaluate_labelled
        events = [
            {"event_id": "p1", "event_time_utc": "2026-01-15T09:00:00.000Z",
             "received_time_utc": "2026-01-15T19:00:00.000Z",
             "source_clock_offset_ms": 10 ** 9,
             "actor": 'x","injected":"y', "source_service": "portal",
             "target_service": "billing", "action": "read",
             "role_before": "viewer", "role_after": "viewer",
             "outcome": "allow", "approval_id": "",
             "session_id": "s\n1", "correlation_id": "c"},
            {"event_id": "p2", "event_time_utc": "2026-01-15T09:00:00.000Z",
             "received_time_utc": "2026-01-15T09:00:00.000Z",
             "source_clock_offset_ms": -90_000,
             "actor": "u", "source_service": "portal",
             "target_service": "catalog", "action": "read",
             "role_before": "viewer", "role_after": "viewer",
             "outcome": "allow", "approval_id": "",
             "session_id": "s", "correlation_id": "c"},
        ]
        r = evaluate_labelled(events=events, labels={},
                              approvals={"changes": []})
        ids = {o["event_id"] for o in r["order_uncertain"]}
        self.assertIn("p1", ids)     # offset far beyond supported range
        self.assertIn("p2", ids)     # offset beyond +/-60 s range
        # poisoned identity strings stay opaque values inside alerts
        for a in r["alerts"] + r["annotations"] + r["order_uncertain"]:
            self.assertNotIn('"injected"', json.dumps(a).replace('\\"', '"'))


class TestRollbackSubstitution(AttackTest):
    """CYBER-1: substitute an older-but-VALID state (manifest intact)."""

    def test_stale_snapshot_rolled_forward_by_signed_journal(self):
        dispatch({"op": "create_backup", "backup_id": "clean"})
        sp = st.state_path()
        snapshot = open(sp).read()        # attacker's stale-but-valid copy
        dispatch({"op": "revoke", "device": "dev-att"})
        self.assertEqual(dispatch({"op": "read", "actor": "attacker",
                                   "asset": "secret.txt"})["decision"], "deny")
        open(sp, "w").write(snapshot)     # substitute the stale state
        r = dispatch({"op": "read", "actor": "attacker", "asset": "secret.txt"})
        self.assertEqual(r["decision"], "deny")      # revocation restored
        self.assertNotIn("body", r)
        r2 = dispatch({"op": "authenticate", "actor": "attacker",
                       "device": "dev-att", "node": "node-a",
                       "key_version": 1})
        self.assertEqual(r2["decision"], "deny")

    def test_manifest_plus_rollforward_survives_repeat(self):
        dispatch({"op": "rotate_key"})
        sp = st.state_path()
        snapshot = open(sp).read()
        dispatch({"op": "rotate_key"})    # journal now has a v2 commit
        open(sp, "w").write(snapshot)     # roll back to the v1 state
        r = dispatch({"op": "authenticate", "actor": "victim",
                      "asset": "x", "node": "node-a", "key_version": 2})
        self.assertEqual(r.get("decision"), "allow")   # v2 re-applied
        self.assertEqual(r["key_version"], 2)


class TestNonFiniteClock(AttackTest):
    """CYBER-2: NaN/Infinity clock poisoning defeats revocation cutoffs."""

    def test_nan_and_inf_deltas_rejected(self):
        for bad in (float("nan"), float("inf"), float("-inf"), "nan", None,
                    {"nested": 1}):
            r = dispatch({"op": "advance_time", "seconds": bad})
            self.assertEqual(r["message"], "invalid_time_delta", msg=str(bad))

    def test_nan_clock_cannot_bypass_revocation(self):
        dispatch({"op": "re_enroll", "device": "dv", "actor": "intruder"})
        dispatch({"op": "revoke", "device": "dv"})     # device-only revoke
        dispatch({"op": "advance_time", "seconds": 5})  # past node-b delay
        r = dispatch({"op": "authenticate", "actor": "intruder",
                      "device": "dv", "node": "node-b", "key_version": 1})
        self.assertEqual(r["decision"], "deny")
        # poisoned state: NaN offset written to disk, attacker recomputes
        # the manifest by hand -> the sanitizer must still fail closed
        sp = st.state_path()
        raw = json.load(open(sp))
        raw["clock_offset"] = float("nan")
        raw.pop("state_hash", None)
        raw["state_hash"] = st._state_digest(raw)   # attacker recomputes
        json.dump(raw, open(sp, "w"))
        r = dispatch({"op": "authenticate", "actor": "intruder",
                      "device": "dv", "node": "node-b", "key_version": 1})
        self.assertEqual(r["message"], "state_integrity_failure")   # quarantined
        self.assertNotIn("decision", r)                     # fail-closed
        # verified recovery path repairs the clock and replays revocation
        r = dispatch({"op": "recover_state"})
        self.assertTrue(r["recovered"])
        dispatch({"op": "advance_time", "seconds": 5})  # past node-b delay
        r = dispatch({"op": "authenticate", "actor": "intruder",
                      "device": "dv", "node": "node-b", "key_version": 1})
        self.assertEqual(r["decision"], "deny")


class TestApprovalsInjection(AttackTest):
    """CYBER-3: caller-supplied approvals file outside the repo root."""

    def test_outside_root_approvals_ignored(self):
        dispatch({"op": "setup", "owners": {}, "admins": ["user-admin"],
                  "contents": {}})
        evil = {"changes": [{"approval_id": "evil-1", "subject": "attacker",
                             "operation": "grant_role",
                             "role": "report-reader",
                             "valid_from_utc": "2000-01-01T00:00:00Z",
                             "valid_until_utc": "2099-01-01T00:00:00Z"}]}
        p = os.path.join(self._dir, "evil_approvals.json")
        with open(p, "w") as f:
            json.dump(evil, f)
        r = dispatch({"op": "grant_role", "admin": "user-admin",
                      "subject": "attacker", "role": "report-reader",
                      "approval_id": "evil-1", "approvals_path": p})
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "untrusted_approvals_source")
        # the role was never granted: read stays denied
        r = dispatch({"op": "read", "actor": "attacker",
                      "asset": "reports/q3.txt"})
        self.assertEqual(r["decision"], "deny")


class TestResourceBounds(AttackTest):
    """CYBER-4: multi-megabyte request ids / details bloat the state."""

    def test_huge_request_id_clipped(self):
        r = dispatch({"op": "read", "actor": "victim", "asset": "secret.txt",
                      "request_id": "B" * 5_000_000})
        self.assertEqual(r["decision"], "allow")
        self.assertLess(os.path.getsize(st.state_path()), 512 * 1024)

    def test_huge_detail_clipped(self):
        dispatch({"op": "append_log", "actor": "u", "action": "x",
                  "asset": "", "detail": "D" * 5_000_000})
        self.assertLess(os.path.getsize(st.state_path()), 512 * 1024)
        entry = st.load_state()["log"][-1]
        self.assertTrue(entry["detail"].endswith("\u2026trunc"))


class TestUnconfiguredState(AttackTest):
    """CYBER-5: ops against a never-initialized state must not crash."""

    def test_read_on_unconfigured_state_is_graceful(self):
        d2 = fresh_dir()
        try:
            r = dispatch({"op": "read", "actor": "x", "asset": "y"})
            self.assertEqual(r["status"], "ok")
            self.assertEqual(r["decision"], "deny")
            self.assertTrue(dispatch({"op": "verify_log"})["valid"])
        finally:
            st.set_state_dir(None)
            shutil.rmtree(d2, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
