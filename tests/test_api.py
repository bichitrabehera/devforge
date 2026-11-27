"""Thin API tests: endpoints must call the existing engine, not reimplement it."""

import os
import sys
import tempfile
import unittest

from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src import crypto, dispatch, state as st  # noqa: E402
from server import engine as adapter  # noqa: E402
from server.main import app  # noqa: E402


class ApiEndpointTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="track4_api_test_")
        st.set_state_dir(self.tmp)
        adapter._SESSIONS.clear()
        adapter._ENVELOPES.clear()
        self.client = TestClient(app)

        self.rec_pk, self.rec_sk = crypto.dsa_keypair()
        dispatch.dispatch({
            "op": "setup", "grace_seconds": 2.0,
            "owners": {"report.txt": "user-alex"},
            "contents": {"report.txt": "alex report"},
            "admins": ["user-admin"],
            "recovery_bindings": {"user-blair": "recovery-user-blair"},
            "recovery_public_keys": {"recovery-user-blair": self.rec_pk.hex()},
        })
        for user, device in (("user-admin", "device-admin"),
                             ("user-alex", "device-alex"),
                             ("user-blair", "device-blair"),
                             ("user-carol", "device-carol"),
                             ("recovery-user-blair", "device-recovery-blair")):
            result = dispatch.dispatch({"op": "re_enroll", "actor": user,
                                        "device": device})
            self.assertEqual(result["status"], "ok")

    def login(self, user, device):
        result = self.client.post("/api/login", json={"username": user,
                                                      "device_id": device})
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()["reference"]

    def recovery_login(self, proof):
        return self.client.post("/api/login", json={
            "username": "recovery-user-blair", "recovery_proof": proof,
        })

    def assert_safe(self, text):
        for marker in ("Traceback", "File \"", "/tmp/", "dsa_sk", "kem_sk",
                       "state_hash", "traceback"):
            self.assertNotIn(marker, text)

    def assert_protected(self, body, identity, device):
        self.assertEqual(body["decision"], "allow")
        self.assertEqual(body["reason"], "authorized")
        self.assertEqual(body["identity"], identity)
        self.assertEqual(body["device"], device)

    def assert_denied(self, body, category):
        self.assertEqual(body["error"], category)
        self.assertEqual(body["decision"], "deny")
        self.assertEqual(body["reason"], adapter.error_reason(category))
        self.assertIn("identity", body)
        self.assertIn("device", body)

    def test_login_status_and_protected_authorization(self):
        admin = self.login("user-admin", "device-admin")
        alex = self.login("user-alex", "device-alex")

        result = self.client.get("/api/status")
        self.assertEqual(result.status_code, 200)
        payload = result.json()
        self.assertIsInstance(payload["users"], list)
        self.assertIn("user-alex", payload["users"])
        self.assertIsInstance(payload["devices"], list)
        self.assertIn("device-alex", payload["devices"])
        self.assertIn("active", payload["key_versions"])
        self.assertIsInstance(payload["key_versions"]["grace_until"], str)
        self.assertIsInstance(payload["key_versions"]["old_key_cutoff"], str)
        self.assertIsInstance(payload["revocations"]["epoch"], int)
        self.assertIsInstance(payload["revocations"]["devices"], list)
        self.assertEqual([n["node"] for n in payload["nodes"]], ["A", "B", "C"])
        for node in payload["nodes"]:
            self.assertIn(node["status"], ("synced", "pending", "uncertain"))
            self.assertIsInstance(node["last_enforced_revocation"], (int, float))
        self.assertEqual(payload["audit"]["integrity_status"], "verified")
        self.assertGreater(payload["audit"]["event_count"], 0)
        metrics = payload["detector_metrics"]
        for key in ("f1", "median_time_to_alert_seconds",
                    "false_alerts_per_1000_benign_events"):
            self.assertIn(key, metrics)

        # Non-admin reference must be refused by the engine's admin policy.
        denied = self.client.post("/api/admin/rotate-key",
                                  json={"token": alex, "target_user": "user-alex"})
        self.assertEqual(denied.status_code, 401)
        denied_body = denied.json()
        self.assert_denied(denied_body, "unauthorized")
        self.assertEqual(denied_body["identity"], "user-alex")
        self.assertEqual(denied_body["device"], "device-alex")

        allowed = self.client.post("/api/admin/rotate-key",
                                   json={"token": admin, "target_user": "user-alex"})
        self.assertEqual(allowed.status_code, 200)
        body = allowed.json()
        self.assert_protected(body, "user-admin", "device-admin")
        self.assertEqual(body["old_version"], 1)
        self.assertEqual(body["new_version"], 2)
        self.assertIsInstance(body["grace_deadline"], str)
        self.assertIsInstance(body["old_key_cutoff"], str)
        self.assert_safe(result.text + denied.text + allowed.text)

    def test_failed_login_reports_attempted_identity_not_previous_session(self):
        admin = self.login("user-admin", "device-admin")
        revoked = self.client.post("/api/admin/revoke-device", json={
            "token": admin, "target_user": "user-blair",
            "target_device": "device-blair"})
        self.assertEqual(revoked.status_code, 200, revoked.text)

        denied = self.client.post("/api/login", json={
            "username": "user-blair", "device_id": "device-blair"})
        self.assertEqual(denied.status_code, 403)
        body = denied.json()
        self.assert_denied(body, "revoked")
        self.assertEqual(body["identity"], "user-blair")
        self.assertEqual(body["device"], "device-blair")

    def test_message_send_and_recipient_only_read(self):
        alex = self.login("user-alex", "device-alex")
        blair = self.login("user-blair", "device-blair")

        sent = self.client.post("/api/messages/send", json={
            "token": alex, "sender": "user-alex", "recipient": "user-blair",
            "plaintext": "operator secret",
        })
        self.assertEqual(sent.status_code, 200, sent.text)
        payload = sent.json()
        self.assertNotIn("plaintext", payload)
        self.assertNotIn("ciphertext", payload)
        self.assertNotIn("session_id", payload)
        self.assert_protected(payload, "user-alex", "device-alex")
        self.assertEqual(payload["status"], "delivered")
        self.assertEqual(payload["route"], ["user-alex", "node-a", "messenger",
                                            "node-b", "node-c", "user-blair"])
        self.assertEqual(payload["policy_decisions"], [
            {"node": "node-a", "decision": "allow"},
            {"node": "node-b", "decision": "allow"},
            {"node": "node-c", "decision": "allow"},
        ])
        msg_id = payload["message_id"]

        wrong = self.client.get(f"/api/messages/{msg_id}",
                                headers={"Authorization": f"Bearer {alex}"},
                                params={"recipient": "user-carol"})
        self.assertEqual(wrong.status_code, 401)
        self.assert_denied(wrong.json(), "unauthorized")

        # A reference in a URL is never accepted as authentication.
        wrong_transport = self.client.get(
            f"/api/messages/{msg_id}",
            params={"recipient": "user-blair", "token": blair})
        self.assertEqual(wrong_transport.status_code, 401)
        self.assert_denied(wrong_transport.json(), "unauthorized")

        read = self.client.get(f"/api/messages/{msg_id}",
                               headers={"Authorization": f"Bearer {blair}"},
                               params={"recipient": "user-blair"})
        self.assertEqual(read.status_code, 200, read.text)
        body = read.json()
        self.assert_protected(body, "user-blair", "device-blair")
        self.assertEqual(body["plaintext"], "operator secret")
        self.assertEqual(body["replay_result"], "accepted")
        self.assertEqual(body["recipient_binding_result"], "accepted")

        duplicate = self.client.get(f"/api/messages/{msg_id}",
                                    headers={"Authorization": f"Bearer {blair}"},
                                    params={"recipient": "user-blair"})
        self.assertEqual(duplicate.status_code, 400)
        self.assert_denied(duplicate.json(), "invalid_message")
        self.assert_safe(sent.text + read.text + duplicate.text)

    def test_revocation_and_recovery_use_recovery_session(self):
        admin = self.login("user-admin", "device-admin")
        lost = self.login("user-blair", "device-blair")
        revoked = self.client.post("/api/admin/revoke-device", json={
            "token": admin, "target_user": "user-blair",
            "target_device": "device-blair",
        })
        self.assertEqual(revoked.status_code, 200, revoked.text)
        revoked_body = revoked.json()
        self.assert_protected(revoked_body, "user-admin", "device-admin")
        self.assertTrue(all(h["denied"] for h in
                            revoked_body["per_node_enforcement"]))
        self.assertGreater(revoked_body["time_until_last_node_enforces"], 0)

        proof = crypto.dsa_sign(
            self.rec_sk.hex(),
            crypto.canonical({"actor": "user-blair",
                              "old_device": "device-blair",
                              "device": "device-blair-new"}).encode())

        # The lost-device session may not enrol its own replacement: the
        # engine re-validates it first and sees the device revocation.
        refused = self.client.post("/api/recovery/enroll-device", json={
            "token": lost, "target_user": "user-blair",
            "new_device": "device-blair-new", "recovery_proof": proof,
        })
        self.assertEqual(refused.status_code, 403)
        self.assert_denied(refused.json(), "revoked")

        bad_proof = crypto.dsa_sign(
            self.rec_sk.hex(),
            crypto.canonical({"actor": "user-blair", "purpose": "wrong"}).encode())
        bad_login = self.recovery_login(bad_proof)
        self.assertEqual(bad_login.status_code, 401)
        self.assert_denied(bad_login.json(), "unauthorized")

        login_proof = crypto.dsa_sign(
            self.rec_sk.hex(),
            crypto.canonical({"actor": "recovery-user-blair",
                              "purpose": "recovery_login"}).encode())
        recovery = self.recovery_login(login_proof)
        self.assertEqual(recovery.status_code, 200, recovery.text)
        recovery_body = recovery.json()
        self.assert_protected(recovery_body, "recovery-user-blair",
                              "device-recovery-blair")
        self.assertEqual(recovery_body["recovery_for"], "user-blair")
        recovery_ref = recovery_body["reference"]

        recovered = self.client.post("/api/recovery/enroll-device", json={
            "token": recovery_ref, "target_user": "user-blair",
            "new_device": "device-blair-new", "recovery_proof": proof,
        })
        self.assertEqual(recovered.status_code, 200, recovered.text)
        body = recovered.json()
        self.assert_protected(body, "recovery-user-blair",
                              "device-recovery-blair")
        self.assertEqual(body["new_device"], "device-blair-new")
        self.assertTrue(body["old_device_still_revoked"])
        self.assertTrue(all(h["old_device_denied"] for h in
                            body["old_device_per_node"]))
        self.assertNotIn("dsa_sk", body)
        self.assertNotIn("recovery_proof", body)
        self.assert_safe(revoked.text + refused.text + recovery.text + recovered.text)

    def test_integrity_detector_and_audit_endpoints(self):
        admin = self.login("user-admin", "device-admin")
        for asset in ("asset-one", "asset-two", "asset-three"):
            dispatch.dispatch({"op": "read", "actor": "user-carol", "asset": asset})
        before = self.client.get("/api/audit/verify").json()["event_count"]

        backup = self.client.post("/api/admin/backup-integrity-test",
                                  json={"token": admin})
        self.assertEqual(backup.status_code, 200, backup.text)
        self.assert_protected(backup.json(), "user-admin", "device-admin")
        self.assertTrue(backup.json()["restore_rejected"])
        self.assertEqual(backup.json()["detection"], "backup_corrupt")

        log = self.client.post("/api/admin/log-integrity-test",
                               json={"token": admin})
        self.assertEqual(log.status_code, 200, log.text)
        self.assert_protected(log.json(), "user-admin", "device-admin")
        self.assertTrue(log.json()["real_log_untouched"])
        self.assertEqual(log.json()["detection"], "log_tampered")
        self.assertEqual(log.json()["mutation_type"], "field_replacement")

        crash = self.client.post("/api/admin/crash-recovery-test", json={
            "token": admin, "target_device": "device-blair",
        })
        self.assertEqual(crash.status_code, 200, crash.text)
        self.assert_protected(crash.json(), "user-admin", "device-admin")
        self.assertTrue(crash.json()["recovered"])
        self.assertIn("recovery_time_s", crash.json())

        detector = self.client.post("/api/detector/run", json={})
        self.assertEqual(detector.status_code, 200)
        self.assertEqual(detector.json()["f1"], 1.0)
        self.assertEqual(detector.json()["dataset_size"], 22)
        self.assertEqual(detector.json()["median_time_to_alert_seconds"], 1.2)

        alerts = self.client.get("/api/detector/alerts")
        self.assertEqual(alerts.status_code, 200)
        self.assertIn("count", alerts.json())
        self.assertGreater(alerts.json()["count"], 0)
        for alert in alerts.json()["alerts"]:
            for key in ("identity", "alert", "services", "event_ids", "rule",
                        "explanation", "timestamp"):
                self.assertIn(key, alert)
            self.assertIsInstance(alert["timestamp"], str)

        audit = self.client.get("/api/audit/verify")
        self.assertTrue(audit.json()["valid"])
        self.assertEqual(audit.json()["integrity_status"], "verified")
        self.assertGreaterEqual(audit.json()["event_count"], before)
        self.assert_safe(backup.text + log.text + crash.text + detector.text
                         + alerts.text + audit.text)


class DemoBootstrapTest(unittest.TestCase):
    """A freshly started API must be demonstrable without manual setup."""

    def setUp(self):
        st.set_state_dir(tempfile.mkdtemp(prefix="track4_demo_bootstrap_"))
        adapter._SESSIONS.clear()
        adapter._ENVELOPES.clear()
        self.client = TestClient(app)

    def test_status_bootstrap_login_proof_and_health(self):
        status = self.client.get("/api/status")
        self.assertEqual(status.status_code, 200)
        self.assertIn("user-alex", status.json()["users"])

        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertEqual(self.client.get("/api/health").status_code, 200)

        login = self.client.post("/api/login", json={
            "username": "user-alex", "device_id": "device-alex"})
        self.assertEqual(login.status_code, 200, login.text)
        self.assertEqual(login.json()["reason"], "authorized")

        proof = self.client.post("/api/demo/recovery-proof", json={
            "purpose": "login",
            "recovery_username": "recovery-user-blair"})
        self.assertEqual(proof.status_code, 200, proof.text)
        self.assertTrue(proof.json()["proof"])

        recovery = self.client.post("/api/login", json={
            "username": "recovery-user-blair",
            "recovery_proof": proof.json()["proof"]})
        self.assertEqual(recovery.status_code, 200, recovery.text)
        self.assertEqual(recovery.json()["recovery_for"], "user-blair")

        enrol = self.client.post("/api/demo/recovery-proof", json={
            "purpose": "enrol", "target_user": "user-blair",
            "new_device": "device-blair-replacement"})
        self.assertEqual(enrol.status_code, 200, enrol.text)
        self.assertTrue(enrol.json()["proof"])

        again = self.client.post("/api/demo/setup")
        self.assertEqual(again.status_code, 200)
        self.assertFalse(again.json()["initialized"])

    def test_reset_clears_stale_revoked_demo_state(self):
        self.client.get("/api/status")  # auto bootstrap
        admin = self.client.post("/api/login", json={
            "username": "user-admin", "device_id": "device-admin"})
        self.assertEqual(admin.status_code, 200, admin.text)
        revoked = self.client.post("/api/admin/revoke-device", json={
            "token": admin.json()["reference"],
            "target_user": "user-blair", "target_device": "device-blair"})
        self.assertEqual(revoked.status_code, 200, revoked.text)

        stale = self.client.post("/api/login", json={
            "username": "user-blair", "device_id": "device-blair"})
        self.assertEqual(stale.status_code, 403, stale.text)
        self.assertEqual(stale.json()["error"], "revoked")

        reset = self.client.post("/api/demo/reset")
        self.assertEqual(reset.status_code, 200, reset.text)
        self.assertTrue(reset.json()["initialized"])

        fresh = self.client.post("/api/login", json={
            "username": "user-blair", "device_id": "device-blair"})
        self.assertEqual(fresh.status_code, 200, fresh.text)


if __name__ == "__main__":
    unittest.main()
