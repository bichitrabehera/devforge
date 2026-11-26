"""13 unittest tests for Hackathon Track 4.

All 13 tests must pass. Uses track4_service, team_app, detector.
"""

import unittest
import json
import os
import sys
import tempfile

# Add root to path
sys.path.insert(0, "/home/daaku/Desktop/yug")

from team_app import dispatch
from detector import detect_anomalies, detect_lateral_movement


class TestTrack4Goals(unittest.TestCase):
    """13 goals covering all ops, helpers, and detector."""

    def setUp(self):
        """Reset state before each test."""
        state_path = os.path.join(tempfile.gettempdir(), "track4_state.json")
        try:
            os.unlink(state_path)
        except FileNotFoundError:
            pass

    def _make_request(self, op, **kwargs):
        """Helper to build a request dict."""
        return {"op": op, **kwargs}

    # --- Goal 1: setup op produces valid JSON on stdout ---
    def test_goal1_setup_valid_json(self):
        req = self._make_request("setup")
        resp = dispatch(req)
        self.assertIsInstance(resp, dict)
        self.assertEqual(resp["status"], "ok")

    # --- Goal 2: read op ---
    def test_goal2_read_returns_ok(self):
        req = self._make_request("read")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")

    # --- Goal 3: revoke op ---
    def test_goal3_revoke_clears_keys(self):
        req = self._make_request("setup")
        dispatch(req)
        req = self._make_request("revoke")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")
        state = __import__("team_app")._load_state()
        self.assertIsNone(state.get("pk_ml_kem"))
        self.assertIsNone(state.get("sk_ml_kem"))

    # --- Goal 4: audit op ---
    def test_goal4_audit_returns_summary(self):
        req = self._make_request("audit")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")

    # --- Goal 5: protected_read op ---
    def test_goal5_protected_read_no_session(self):
        req = self._make_request("protected_read")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "error")

    # --- Goal 6: rotate_key helper ---
    def test_goal6_rotate_key(self):
        # Setup first
        req = self._make_request("setup")
        dispatch(req)
        # Rotate KEM only - use op="kem" which rotate_key handles
        req = self._make_request("kem")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["kem_rotated"])
        self.assertFalse(resp["dsa_rotated"])

    # --- Goal 7: re_enroll_device helper ---
    def test_goal7_re_enroll_device(self):
        req = self._make_request("re_enroll_device")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")

    # --- Goal 8: recover_state helper ---
    def test_goal8_recover_state(self):
        # Create a backup first
        req = self._make_request("setup")
        dispatch(req)
        req = self._make_request("create_backup", backup_id="test_bak")
        dispatch(req)
        # Now recover
        req = self._make_request("recover_state", backup_id="test_bak")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")

    # --- Goal 9: create_backup helper ---
    def test_goal9_create_backup(self):
        req = self._make_request("setup")
        dispatch(req)
        req = self._make_request("create_backup", backup_id="bak1")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["backup_id"], "bak1")

    # --- Goal 10: restore_backup helper ---
    def test_goal10_restore_backup(self):
        req = self._make_request("setup")
        dispatch(req)
        req = self._make_request("create_backup", backup_id="bak1")
        dispatch(req)
        req = self._make_request("restore_backup", backup_id="bak1")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")

    # --- Goal 11: append_log helper ---
    def test_11_append_log(self):
        req = self._make_request("append_log", entry="test entry", type="general")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")

    # --- Goal 12: verify_log helper ---
    def test_12_verify_log(self):
        # Append a few entries first
        for i in range(3):
            req = self._make_request("append_log", entry=f"entry {i}", type="general")
            dispatch(req)
        req = self._make_request("verify_log")
        resp = dispatch(req)
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["valid"])

    # --- Goal 13: detector anomaly & lateral movement ---
    def test_13_detector_anomalies_and_lateral(self):
        # Ensure some state exists
        req = self._make_request("setup")
        dispatch(req)
        # Detect anomalies
        anomalies = detect_anomalies({"op": "read"})
        self.assertIsInstance(anomalies, list)
        # Detect lateral movement
        lateral = detect_lateral_movement()
        self.assertIsInstance(lateral, list)


if __name__ == "__main__":
    unittest.main()
