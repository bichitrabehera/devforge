"""The standalone verifier must accept clean evidence and reject tampering.

These tests drive the REAL adapter (subprocess per request, isolated state
dir) and then run verifier/track4_verify.py as a separate process, exactly
as an operator who does not trust the service would.
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

VERIFIER = os.path.join(ROOT, "verifier", "track4_verify.py")


def _adapter(req, state_dir):
    env = dict(os.environ, TRACK4_STATE_DIR=state_dir)
    proc = subprocess.run([sys.executable, os.path.join(ROOT,
                                                        "track4_service.py")],
                          input=json.dumps(req), capture_output=True,
                          text=True, env=env, timeout=30)
    return json.loads(proc.stdout)


def _verifier(argv):
    return subprocess.run([sys.executable, VERIFIER] + argv,
                          capture_output=True, text=True, timeout=30)


class TestStandaloneVerifier(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="t4verifier-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        _adapter({"op": "setup",
                  "owners": {"a": "maya"},
                  "contents": {"a": "secret body"},
                  "disabled": [], "key_material": "x"}, self.dir)
        for i in range(3):
            _adapter({"op": "read", "actor": "maya", "asset": "a",
                      "request_id": "r%d" % i}, self.dir)
        with open(os.path.join(self.dir, "state.json")) as f:
            self.state = json.load(f)
        self.pub = self.state["service_dsa_pk"]
        self.head = self.state["log"][-1]["hash"]
        self.state_path = os.path.join(self.dir, "state.json")

    def test_clean_audit_with_recorded_head_is_exit_0(self):
        r = _verifier(["audit", "--state", self.state_path,
                       "--pub", self.pub, "--expect-head", self.head])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("head matches", r.stdout)

    def test_clean_audit_without_head_is_exit_2(self):
        """No recorded head = verified but completeness UNestablished."""
        r = _verifier(["audit", "--state", self.state_path,
                       "--pub", self.pub])
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("completeness NOT established", r.stdout)

    def test_wrong_head_is_exit_1(self):
        r = _verifier(["audit", "--state", self.state_path,
                       "--pub", self.pub,
                       "--expect-head", "aa" * 32])
        self.assertEqual(r.returncode, 1)
        self.assertIn("head mismatch", r.stdout)

    def test_tampered_actor_is_exit_1(self):
        self.state["log"][1]["actor"] = "attacker"
        with open(self.state_path, "w") as f:
            json.dump(self.state, f)
        r = _verifier(["audit", "--state", self.state_path,
                       "--pub", self.pub])
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL", r.stdout)

    def test_truncated_log_is_detected_with_head(self):
        self.state["log"] = self.state["log"][:2]
        with open(self.state_path, "w") as f:
            json.dump(self.state, f)
        r = _verifier(["audit", "--state", self.state_path,
                       "--pub", self.pub, "--expect-head", self.head])
        self.assertEqual(r.returncode, 1)

    def test_state_manifest_detects_modification(self):
        r = _verifier(["state", "--state", self.state_path])
        self.assertEqual(r.returncode, 0, r.stdout)
        self.state["owners"]["a"] = "mallory"      # content-only change
        with open(self.state_path, "w") as f:
            json.dump(self.state, f)
        r = _verifier(["state", "--state", self.state_path])
        self.assertEqual(r.returncode, 1)
        self.assertIn("manifest mismatch", r.stdout)

    def test_journal_signatures(self):
        _adapter({"op": "revoke", "actor": "user-admin"}, self.dir)
        r = _verifier(["journal", "--dir", self.dir, "--pub", self.pub,
                       "--expect-records", "1"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # A forged record must be rejected.
        journal = os.path.join(self.dir, "journal.jsonl")
        with open(journal, "a") as f:
            f.write(json.dumps({"kind": "revocation", "device": "ghost",
                                "epoch": 99}) + "\n")
        r = _verifier(["journal", "--dir", self.dir, "--pub", self.pub])
        self.assertEqual(r.returncode, 1)
        self.assertIn("unsigned", r.stdout)

    def test_backup_verification(self):
        _adapter({"op": "create_backup", "backup_id": "bak1"}, self.dir)
        path = os.path.join(self.dir, "backups", "bak1.json")
        r = _verifier(["backup", "--file", path, "--pub", self.pub])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # Flip one payload byte -> rejected.
        with open(path) as f:
            blob = json.load(f)
        payload = blob["payload"]
        idx = payload.index("secret body")
        blob["payload"] = payload[:idx] + "SECRET BODY" + payload[idx + 11:]
        with open(path, "w") as f:
            json.dump(blob, f)
        r = _verifier(["backup", "--file", path, "--pub", self.pub])
        self.assertEqual(r.returncode, 1)
        self.assertIn("payload hash mismatch", r.stdout)


if __name__ == "__main__":
    unittest.main()
