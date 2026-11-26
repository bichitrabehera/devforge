"""Adapter contract v1 compliance tests.

Covers: setup reset + disabled + key_material non-disclosure, recorded
audit decisions, and the protected_read KEM interoperability exchange
(verified from the CLIENT side: decapsulate the returned ciphertext and
recompute the HMAC proof). Plus: stdlib HKDF matches `cryptography`'s
HKDF when that package is present.
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import crypto, state as st  # noqa: E402
from src.dispatch import dispatch  # noqa: E402
from pqcrypto.kem import ml_kem_768  # noqa: E402


class ContractTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="track4_contract_")
        st.set_state_dir(self._dir)

    def tearDown(self):
        st.set_state_dir(None)
        shutil.rmtree(self._dir, ignore_errors=True)


class TestSetupReset(ContractTest):
    """setup resets state and honors disabled/key_material."""

    def test_setup_resets_previous_state(self):
        dispatch({"op": "setup", "owners": {"a.txt": "alice"},
                  "contents": {"a.txt": "v1"}})
        dispatch({"op": "revoke", "actor": "alice"})
        self.assertEqual(dispatch({"op": "read", "actor": "alice",
                                   "asset": "a.txt"})["decision"], "deny")
        # setup resets: alice is the owner again, revocation wiped
        r = dispatch({"op": "setup", "owners": {"a.txt": "alice"},
                      "contents": {"a.txt": "v2"}})
        self.assertTrue(r["ready"])
        r = dispatch({"op": "read", "actor": "alice", "asset": "a.txt"})
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["body"], "v2")

    def test_disabled_actors_denied_and_key_material_secret(self):
        marker = "synthetic-key-material-MARKER"
        r = dispatch({"op": "setup", "owners": {"a.txt": "alice"},
                      "contents": {"a.txt": "top"},
                      "disabled": ["mallory"],
                      "key_material": marker})
        self.assertEqual(r["disabled_count"], 1)
        self.assertEqual(r["key_material_stored"], "sha256-digest-only")
        # disabled actor denied everywhere
        r = dispatch({"op": "read", "actor": "mallory", "asset": "a.txt"})
        self.assertEqual(r["decision"], "deny")
        # disabled actor cannot protected_read either
        pk, _ = crypto.kem_keypair()
        r = dispatch({"op": "protected_read", "actor": "mallory",
                      "asset": "a.txt", "challenge": "c",
                      "public_key": base64.b64encode(pk).decode()})
        self.assertEqual(r["decision"], "deny")
        # the material is never stored in plaintext or printed
        raw = open(os.path.join(self._dir, "state.json")).read()
        self.assertNotIn(marker, raw)
        self.assertIn(crypto.sha256_hex(marker), raw)


class TestRecordedAudit(ContractTest):
    """audit returns the RECORDED decision for the request_id."""

    def test_recorded_decision_survives_policy_change(self):
        dispatch({"op": "setup", "owners": {"a.txt": "alice"},
                  "contents": {"a.txt": "x"}})
        r = dispatch({"op": "read", "actor": "alice", "asset": "a.txt",
                      "request_id": "r1"})
        self.assertEqual(r["decision"], "allow")
        # policy changes AFTER the read: actor disabled
        dispatch({"op": "disable", "actor": "alice"})
        r = dispatch({"op": "audit", "request_id": "r1"})
        self.assertEqual(r["decision"], "allow")       # as recorded
        self.assertEqual(r["request_id"], "r1")
        # a denied read is recorded as deny
        r = dispatch({"op": "read", "actor": "bob", "asset": "a.txt",
                      "request_id": "r2"})
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(dispatch({"op": "audit",
                                   "request_id": "r2"})["decision"], "deny")

    def test_unknown_request_id_falls_back(self):
        dispatch({"op": "setup", "owners": {"a.txt": "alice"},
                  "contents": {"a.txt": "x"}})
        r = dispatch({"op": "audit", "request_id": "never-seen",
                      "actor": "alice", "asset": "a.txt"})
        self.assertEqual(r["decision"], "allow")


class TestProtectedRead(ContractTest):
    """The scored KEM-interop exchange, verified from the client side."""

    def setUp(self):
        super().setUp()
        self.r = dispatch({"op": "setup", "owners": {"brief": "maya"},
                           "contents": {"brief": "demo note"}})
        self.client_pk, self.client_sk = crypto.kem_keypair()

    def _protected_read(self, challenge="challenge-123", actor="maya",
                        asset="brief"):
        return dispatch({"op": "protected_read", "actor": actor,
                         "asset": asset, "challenge": challenge,
                         "public_key":
                             base64.b64encode(self.client_pk).decode()})

    def test_roundtrip_verify_proof_and_content(self):
        r = self._protected_read()
        self.assertEqual(r["decision"], "allow")
        ct = base64.b64decode(r["ciphertext"])
        shared = crypto.kem_decaps(self.client_sk, ct)   # client side
        expected = hmac_mod.new(
            shared, ("challenge-123" + "demo note").encode("utf-8"),
            hashlib.sha256).hexdigest()
        self.assertEqual(r["proof"], expected)
        self.assertEqual(r["proof"], r["proof"].lower())

    def test_deny_discloses_nothing(self):
        r = self._protected_read(actor="eve")
        self.assertEqual(r["decision"], "deny")
        self.assertNotIn("ciphertext", r)
        self.assertNotIn("proof", r)
        self.assertNotIn("demo note", json.dumps(r))

    def test_bad_public_key_rejected(self):
        r = dispatch({"op": "protected_read", "actor": "maya",
                      "asset": "brief", "challenge": "c",
                      "public_key": base64.b64encode(b"short").decode()})
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["message"], "invalid_public_key_length")
        r = dispatch({"op": "protected_read", "actor": "maya",
                      "asset": "brief", "challenge": "c",
                      "public_key": "!!!not-base64!!!"})
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["message"], "invalid_public_key_encoding")

    def test_revoked_owner_cannot_protected_read(self):
        dispatch({"op": "revoke", "actor": "maya"})
        r = self._protected_read()
        self.assertEqual(r["decision"], "deny")


class TestHKDFStandard(unittest.TestCase):
    """stdlib HKDF must match `cryptography`'s HKDF when available."""

    def test_matches_cryptography_package(self):
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        except ImportError:
            self.skipTest("cryptography package not installed")
        ikm = bytes(range(32))
        info = b"track4-session:test"
        ours = crypto.hkdf(ikm, info, 32)
        theirs = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                      info=info).derive(ikm)
        self.assertEqual(ours, theirs)


class TestAdapterEndToEnd(ContractTest):
    """Full adapter roundtrip for protected_read through subprocesses."""

    def test_adapter_protected_read_roundtrip(self):
        env = dict(os.environ)
        env["TRACK4_STATE_DIR"] = tempfile.mkdtemp(prefix="track4_e2e2_")

        def call(req):
            p = subprocess.run(
                [sys.executable, os.path.join(ROOT, "track4_service.py")],
                input=json.dumps(req), capture_output=True, text=True,
                env=env, cwd=ROOT)
            return json.loads(p.stdout.strip().splitlines()[-1]), p.stderr

        r, err = call({"op": "setup", "owners": {"brief": "maya"},
                       "contents": {"brief": "demo note"},
                       "key_material": "synthetic-only"})
        self.assertTrue(r["ready"], err)
        self.assertNotIn("synthetic-only", err)
        pk, sk = crypto.kem_keypair()
        r, err = call({"op": "protected_read", "actor": "maya",
                       "asset": "brief", "challenge": "zz-challenge",
                       "public_key": base64.b64encode(pk).decode()})
        self.assertEqual(r["decision"], "allow", err)
        shared = crypto.kem_decaps(sk, base64.b64decode(r["ciphertext"]))
        expected = hmac_mod.new(shared, b"zz-challengedemo note",
                                hashlib.sha256).hexdigest()
        self.assertEqual(r["proof"], expected)
        self.assertNotIn("demo note", json.dumps(r))   # body not disclosed


if __name__ == "__main__":
    unittest.main(verbosity=2)
