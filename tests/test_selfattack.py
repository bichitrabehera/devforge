"""The black-box self-attack harness must stay clean.

Runs tools/selfattack.py end-to-end (all 15 items, ~4 s) exactly as an
operator would.  Any FAIL is a regression in the adapter's defenses.
"""

import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class TestSelfAttackHarness(unittest.TestCase):

    def test_full_run_has_no_failures(self):
        r = subprocess.run(
            [sys.executable, "-B", os.path.join(ROOT, "tools",
                                                "selfattack.py"),
             "--report", os.path.join(ROOT, "docs",
                                      "SELFATTACK_REPORT.md")],
            capture_output=True, text=True, timeout=300, cwd=ROOT)
        self.assertEqual(r.returncode, 0,
                         "selfattack found failures:\n%s\n%s"
                         % (r.stdout, r.stderr))
        self.assertIn("0 failed", r.stdout)
        self.assertIn("0 skipped", r.stdout)


if __name__ == "__main__":
    unittest.main()
