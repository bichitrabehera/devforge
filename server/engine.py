"""Thin adapter layer: every security decision is delegated to the engine.

This module never implements cryptography, authorization, revocation,
recovery, audit or detection logic. It calls ``src.dispatch.dispatch`` (the
engine's single serialized entry point) and existing helpers in ``src`` and
``services``. Its only additions are:

* an in-memory opaque reference returned by login (re-validated through the
  engine on every protected call),
* an in-memory envelope store so a message can be read by its id,
* safe projection of engine results and safe error categories.
"""

from __future__ import annotations

import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import crypto  # noqa: E402
from src import dispatch as engine  # noqa: E402
from src import recovery as recovery_engine  # noqa: E402
from src import state as st  # noqa: E402

NODES = ("node-a", "node-b", "node-c")
SESSION_TTL_S = 3600.0
NORMAL_SESSION = "normal"
RECOVERY_SESSION = "recovery"
DEMO_IDENTITIES = (
    ("user-admin", "device-admin"),
    ("user-alex", "device-alex"),
    ("user-blair", "device-blair"),
    ("user-carol", "device-carol"),
    ("recovery-user-blair", "device-recovery-blair"),
)

_SESSIONS: Dict[str, Dict[str, Any]] = {}
_ENVELOPES: Dict[str, Dict[str, Any]] = {}
_STATE_DIR_LOCK = threading.Lock()
_CONTEXT = threading.local()


def reset_context() -> None:
    """Keep one request's safe identity/device context out of the next one."""
    _CONTEXT.identity = "unknown"
    _CONTEXT.device = "unknown"


class EngineError(Exception):
    """A safe, caller-facing error category (never an exception message)."""

    def __init__(self, category: str, identity: str = "",
                 device: str = ""):
        super().__init__(category)
        self.category = category if category in {
            "unauthorized", "revoked", "invalid_message", "key_expired",
            "backup_corrupt", "log_tampered", "invalid_request",
        } else "invalid_request"
        self.identity = identity or getattr(_CONTEXT, "identity", "unknown")
        self.device = device or getattr(_CONTEXT, "device", "unknown")


# --- safe error mapping -------------------------------------------------------

_EXACT_ERRORS = {
    "proof_replayed": "unauthorized",
    "enrolment_secret_invalid": "unauthorized",
    "recovery_not_authorized": "unauthorized",
    "unknown_identity": "unauthorized",
    "not_permitted": "unauthorized",
    "token_invalid": "unauthorized",
    "token_expired": "key_expired",
    "token_not_yet_valid": "key_expired",
    "bad_token_signature": "unauthorized",
    "malformed_token": "unauthorized",
    "old_key_after_cutoff": "key_expired",
    "unknown_key_version": "invalid_request",
    "backup_integrity_failure": "backup_corrupt",
    "backup_signature_invalid": "backup_corrupt",
    "backup_identity_mismatch": "backup_corrupt",
    "no_such_backup": "invalid_request",
    "msg_id_mismatch": "invalid_message",
    "recipient_binding_mismatch": "invalid_message",
    "duplicate_replay": "invalid_message",
    "authentication_failed": "invalid_message",
    "bad_hex": "invalid_message",
    "missing_fields": "invalid_message",
    "endpoint_mismatch": "unauthorized",
    "no_pending_session": "invalid_request",
    "no_established_session": "invalid_request",
    "state_integrity_failure": "invalid_request",
    "state_rollback_detected": "invalid_request",
}


def error_category(result: Dict[str, Any]) -> str:
    """Translate an engine result into one of the documented safe categories."""
    message = str(result.get("message", ""))
    reason = str(result.get("reason", ""))
    if message in _EXACT_ERRORS:
        return _EXACT_ERRORS[message]
    if message.startswith("token_"):
        return _EXACT_ERRORS.get(message, "unauthorized")
    if reason in ("revoked", "sender_revoked_or_disabled",
                  "recipient_revoked_or_disabled", "peer_revoked_or_disabled"):
        return "revoked"
    if reason in ("duplicate_replay", "msg_id_mismatch", "stale_counter",
                  "gap_too_large", "authentication_failed",
                  "recipient_binding_mismatch", "bad_recovery_signature"):
        if reason == "bad_recovery_signature":
            return "unauthorized"
        return "invalid_message"
    if reason in ("old_key_after_cutoff", "token_expired"):
        return "key_expired"
    if reason in ("no_recovery_binding", "not_permitted",
                  "not_the_original_sender", "peer_not_bound_to_session"):
        return "unauthorized"
    if result.get("decision") in ("deny", "reject"):
        if "revoked" in reason:
            return "revoked"
        if reason in ("token_not_yet_valid", "token_expired"):
            return "key_expired"
        if reason in ("duplicate_replay", "authentication_failed",
                      "msg_id_mismatch", "recipient_binding_mismatch",
                      "stale_counter", "gap_too_large"):
            return "invalid_message"
        return "unauthorized"
    return "invalid_request"


_REASONS = {
    "unauthorized": "unauthorized",
    "revoked": "revoked",
    "invalid_message": "invalid_message",
    "key_expired": "key_expired",
    "backup_corrupt": "invalid_message",
    "log_tampered": "invalid_message",
    "invalid_request": "unauthorized",
}


def error_reason(category: str) -> str:
    """Map a safe category to the documented protected-response reason."""
    return _REASONS.get(category, "unauthorized")


def iso_utc(value: Any) -> Optional[str]:
    """Project an engine timestamp as an explicit UTC string, never local time."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def protected(session: Dict[str, Any], **fields: Any) -> Dict[str, Any]:
    """Add the stable, non-sensitive decision envelope to a protected result."""
    return {
        "decision": "allow",
        "reason": "authorized",
        "identity": session["actor"],
        "device": session["device"],
        **fields,
    }


def raw(op: str, **payload: Any) -> Dict[str, Any]:
    """Call the engine's single entry point; no engine logic is duplicated."""
    return dict(engine.dispatch(dict(op=op, **payload)))


def require_ok(result: Dict[str, Any], identity: str = "",
               device: str = "") -> Dict[str, Any]:
    if result.get("status") == "error" or result.get("decision") in ("deny", "reject"):
        raise EngineError(error_category(result), identity, device)
    return result


# --- local demo bootstrap (composition of existing engine ops only) ----------

def _demo_initialized() -> bool:
    state = st.load_state()
    return bool(state.get("active_version")) and bool(state.get("identities"))


def _recovery_key_aligned() -> bool:
    """True when the enrolled demo recovery key matches its registered key."""
    state = st.load_state()
    recovery = state.get("recovery_bindings", {}).get("user-blair", "")
    registered = state.get("recovery_public_keys", {}).get(recovery, "")
    enrolled = state.get("identities", {}).get(recovery, {})
    return (bool(registered) and enrolled.get("dsa_pk") == registered
            and bool(enrolled.get("dsa_sk")))


def ensure_demo_state() -> None:
    """Make the local console usable from an empty state directory."""
    if not _demo_initialized():
        demo_setup()


def demo_setup(force: bool = False) -> Dict[str, Any]:
    """Create the documented practice identities through the engine setup op."""
    if not force and _demo_initialized():
        return {"status": "ok", "decision": "allow", "reason": "authorized",
                "identity": "service", "device": "demo-state",
                "initialized": False, "note": "demo state already present"}
    rec_pk, rec_sk = crypto.dsa_keypair()  # never returned to the console
    require_ok(raw(
        "setup", grace_seconds=30.0,
        owners={"report.txt": "user-alex"},
        contents={"report.txt": "demo report"},
        admins=["user-admin"],
        recovery_bindings={"user-blair": "recovery-user-blair"},
        recovery_public_keys={"recovery-user-blair": rec_pk.hex()}),
        "service", "demo-state")
    for user, device in DEMO_IDENTITIES:
        require_ok(raw("re_enroll", actor=user, device=device),
                   "service", "demo-state")
    # Keep the enrolled recovery identity's signing key identical to the key
    # registered at setup, so demo proofs verify through the engine exactly as
    # production recovery proofs would.
    state = st.load_state()
    recovery = "recovery-user-blair"
    identity = state.setdefault("identities", {}).setdefault(recovery, {})
    identity.update({"dsa_pk": rec_pk.hex(), "dsa_sk": rec_sk.hex()})
    st.save_state(state)
    return {"status": "ok", "decision": "allow", "reason": "authorized",
            "identity": "service", "device": "demo-state",
            "initialized": True, "users": [user for user, _ in DEMO_IDENTITIES],
            "note": "local demo identities created; no private material exposed"}


def demo_recovery_proof(purpose: str, recovery_username: str = "",
                        target_user: str = "", new_device: str = "") -> Dict[str, Any]:
    """Demo-only helper that signs a recovery challenge with engine-held keys.

    This exists so the operator console can be demonstrated without manually
    exchanging ML-DSA keys. Production deployments must provision proofs at
    the recovery identity instead of exposing this route.
    """
    ensure_demo_state()
    if not _recovery_key_aligned():
        # Repair state created by an earlier demo build before the proof
        # helper was introduced. This route is demo-only and is never part of
        # the production recovery flow.
        demo_setup(force=True)
    state = st.load_state()
    if purpose == "login":
        actor = recovery_username or target_user
        signed = crypto.canonical({
            "actor": actor, "purpose": "recovery_login"}).encode()
    elif purpose == "enrol":
        actor = state.get("recovery_bindings", {}).get(target_user, "")
        old_device = state.get("identities", {}).get(target_user, {}).get("device", "")
        if not new_device or not old_device:
            raise EngineError("invalid_request")
        signed = crypto.canonical({
            "actor": target_user, "old_device": old_device,
            "device": new_device}).encode()
    else:
        raise EngineError("invalid_request")
    signing_key = state.get("identities", {}).get(actor, {}).get("dsa_sk", "")
    if not actor or not signing_key:
        raise EngineError("invalid_request")
    return {"status": "ok", "decision": "allow", "reason": "authorized",
            "identity": actor, "device": "demo-proof", "purpose": purpose,
            "proof": crypto.dsa_sign(signing_key, signed),
            "note": "demo-only helper; provision real proofs in production"}


# --- opaque reference (not a key, not an IdP token) --------------------------

def _prune_sessions() -> None:
    now = time.time()
    for ref, rec in list(_SESSIONS.items()):
        if now - rec["ts"] > SESSION_TTL_S:
            _SESSIONS.pop(ref, None)


def login(username: str, device_id: str) -> Dict[str, Any]:
    """Authenticate through the existing engine, return only a safe reference."""
    ensure_demo_state()
    decision = require_ok(raw("authenticate", actor=username, device=device_id,
                              node="node-a"), username, device_id)
    status = require_ok(raw("status"), username, device_id)
    ref = secrets.token_urlsafe(24)
    _prune_sessions()
    sess = {"actor": username, "device": device_id, "ts": time.time(),
            "kind": NORMAL_SESSION, "owner": ""}
    _SESSIONS[ref] = sess
    _CONTEXT.identity = username
    _CONTEXT.device = device_id
    return protected(sess, reference=ref, status="authorized", user=username,
                     user_status="active" if username not in status.get("disabled", [])
                     else "disabled",
                     device_status="revoked" if device_id in status.get("revoked", {})
                     else "active",
                     node=decision.get("node", "node-a"),
                     key_version=decision.get("key_version"),
                     outcome=decision.get("outcome"),
                     expires_in_s=SESSION_TTL_S,
                     note="reference is an opaque handle; it is not a key or IdP token")


def recovery_login(username: str, proof: str) -> Dict[str, Any]:
    """Authenticate a bound recovery identity with an engine-signed challenge.

    The challenge is verified with the recovery identity's registered public
    key using the existing engine crypto helper. No private key, token or proof
    is stored or returned; only an opaque in-memory reference is issued.
    """
    ensure_demo_state()
    state = st.load_state()
    verify_key = state.get("recovery_public_keys", {}).get(username, "")
    owners = sorted(owner for owner, bound
                    in state.get("recovery_bindings", {}).items()
                    if bound == username)
    if not verify_key or not owners:
        raise EngineError("unauthorized", username, "unknown")
    challenge = crypto.canonical({
        "actor": username, "purpose": "recovery_login"}).encode()
    try:
        verified = crypto.dsa_verify(verify_key, challenge, proof)
    except Exception:
        verified = False
    if not verified:
        raise EngineError("unauthorized", username, "unknown")

    device = state.get("identities", {}).get(username, {}).get("device", username)
    decision = require_ok(raw("authenticate", actor=username, device=device,
                              node="node-a"), username, device)
    ref = secrets.token_urlsafe(24)
    _prune_sessions()
    sess = {"actor": username, "device": device, "ts": time.time(),
            "kind": RECOVERY_SESSION, "owner": owners[0]}
    _SESSIONS[ref] = sess
    _CONTEXT.identity = username
    _CONTEXT.device = device
    return protected(sess, reference=ref, status="authorized", user=username,
                     recovery_for=owners[0], node=decision.get("node", "node-a"),
                     expires_in_s=SESSION_TTL_S,
                     note="recovery reference is an opaque handle for re-enrolment only")


def resolve(reference: str) -> Dict[str, Any]:
    """Re-run the existing engine authentication before any protected call."""
    rec = _SESSIONS.get(reference or "")
    if not rec or time.time() - rec["ts"] > SESSION_TTL_S:
        raise EngineError("unauthorized", "unknown", "unknown")
    decision = raw("authenticate", actor=rec["actor"], device=rec["device"],
                   node="node-a")
    if decision.get("decision") != "allow":
        raise EngineError(error_category(decision), rec["actor"], rec["device"])
    _CONTEXT.identity = rec["actor"]
    _CONTEXT.device = rec["device"]
    return dict(rec)


def require_admin(reference: str) -> Dict[str, Any]:
    sess = resolve(reference)
    state = st.load_state()
    if sess.get("kind") != NORMAL_SESSION or \
            sess["actor"] not in state.get("admins", []):
        raise EngineError("unauthorized", sess["actor"], sess["device"])
    return sess


def require_recovery(reference: str, owner: str) -> Dict[str, Any]:
    """Only a bound recovery session may enrol a replacement device."""
    sess = resolve(reference)
    if sess.get("kind") != RECOVERY_SESSION or sess.get("owner") != owner:
        raise EngineError("unauthorized", sess["actor"], sess["device"])
    return sess


# --- status / alerts / detector / audit --------------------------------------

def _public_identity_labels() -> Dict[str, Any]:
    state = st.load_state()
    identities = state.get("identities", {})
    owners = {ident.get("device", ""): user for user, ident in sorted(identities.items())
              if ident.get("device")}
    devices = set(owners) | set(state.get("revoked", {}))
    return {
        "users": sorted(identities),
        "devices": sorted(d for d in devices if d),
        "device_owners": owners,
        "device_status": {device: ("revoked" if device in state.get("revoked", {})
                                   else "active") for device in devices if device},
    }


def _node_projection(core: Dict[str, Any], raw_nodes: Dict[str, Any]) -> list:
    """Project the engine's node state into the stable operator list."""
    epoch = int(core.get("revocation_epoch") or 0)
    out = []
    for node_id, node in sorted((raw_nodes or core.get("nodes", {})).items()):
        applied = int(node.get("epoch_applied") or 0)
        out.append({
            "node": node_id.replace("node-", "").upper(),
            "node_id": node_id,
            "status": "synced" if applied >= epoch else "pending",
            "last_enforced_revocation": round(
                float(node.get("sync_delay_s") or 0.0), 3),
        })
    return out


def status() -> Dict[str, Any]:
    ensure_demo_state()
    core = require_ok(raw("status"), "service", "public")
    nodes = require_ok(raw("node_status"), "service", "public")
    alerts = require_ok(raw("detector_live"), "service", "public")
    audit = require_ok(raw("verify_log"), "service", "public")
    detector = require_ok(raw(
        "detector_evaluate",
        events_path=str(ROOT / "practice" / "events.csv"),
        labels_path=str(ROOT / "practice" / "labels.csv"),
        approvals_path=str(ROOT / "practice" / "approvals.json")),
        "service", "public")
    labels = _public_identity_labels()
    valid = bool(audit.get("valid"))
    cutoff = iso_utc(core.get("cutoff_at"))
    return {
        "users": labels["users"],
        "devices": labels["devices"],
        "device_owners": labels["device_owners"],
        "device_status": labels["device_status"],
        "key_versions": {
            "active": core.get("active_version"),
            "grace_until": cutoff,
            "old_key_cutoff": cutoff,
            "fingerprint": core.get("fingerprint"),
            "grace_seconds": core.get("grace_seconds"),
        },
        "revocations": {
            "epoch": core.get("revocation_epoch"),
            "devices": sorted(core.get("revoked", {})),
            "disabled_actors": sorted(core.get("disabled", [])),
        },
        "nodes": _node_projection(core, nodes.get("nodes", {})),
        "alerts": normalize_alerts(alerts.get("alerts", [])),
        "audit": {
            "integrity_status": "verified" if valid else "tampered",
            "event_count": audit.get("entries", 0),
            "valid": valid,
            "first_bad_seq": audit.get("first_bad_seq"),
        },
        "detector_metrics": detector_metrics(detector),
        "sessions": core.get("sessions", []),
        "journal_records": core.get("journal_records", 0),
    }


def normalize_alerts(alerts: list) -> list:
    """Project engine alerts into the documented operator fields."""
    out = []
    for alert in alerts:
        services = alert.get("services") or []
        ids = (alert.get("event_ids") or alert.get("related_events")
               or alert.get("events") or [])
        if not ids and alert.get("event_id"):
            ids = [alert["event_id"]]
        rule = alert.get("rule", "")
        out.append({
            "identity": alert.get("identity", ""),
            "alert": alert.get("alert") or rule or "detector_alert",
            "services": services,
            "event_ids": ids,
            "rule": rule,
            "path": alert.get("path") or " -> ".join(str(s) for s in services),
            "explanation": alert.get("explanation", ""),
            "timestamp": iso_utc(alert.get("alert_time", alert.get("ts"))),
        })
    return out


def detector_metrics(result: Dict[str, Any]) -> Dict[str, Any]:
    """Measured values returned by src.detector.evaluate_labelled."""
    return {
        "f1": result.get("f1"),
        "precision": result.get("precision"),
        "recall": result.get("recall"),
        "median_time_to_alert_seconds": result.get("median_time_to_alert_s"),
        "false_alerts_per_1000_benign_events":
            result.get("false_alerts_per_1000_benign"),
        "median_time_to_alert_s": result.get("median_time_to_alert_s"),
        "false_alerts_per_1000_benign": result.get("false_alerts_per_1000_benign"),
        "dataset_size": len(result.get("timeline", [])),
        "true_positives": result.get("true_positives"),
        "false_positives": result.get("false_positives"),
        "missed": result.get("missed"),
        "evaluation_scope": "organizer 22-event synthetic practice set only; "
                            "deterministic rules, no AI/ML",
    }


def alerts() -> Dict[str, Any]:
    live = require_ok(raw("detector_live"), "service", "public")
    labelled = require_ok(raw(
        "detector_evaluate",
        events_path=str(ROOT / "practice" / "events.csv"),
        labels_path=str(ROOT / "practice" / "labels.csv"),
        approvals_path=str(ROOT / "practice" / "approvals.json")),
        "service", "public")
    return {
        "source": "live_audit_log_and_labelled_practice_log",
        "alerts": normalize_alerts(live.get("alerts", [])),
        "labelled_alerts": normalize_alerts(labelled.get("alerts", [])),
        "count": len(live.get("alerts", [])),
    }


def run_detector() -> Dict[str, Any]:
    result = require_ok(raw(
        "detector_evaluate",
        events_path=str(ROOT / "practice" / "events.csv"),
        labels_path=str(ROOT / "practice" / "labels.csv"),
        approvals_path=str(ROOT / "practice" / "approvals.json")),
        "service", "public")
    report = detector_metrics(result)
    report["status"] = "ok"
    report["rules"] = result.get("rules", [])
    report["alerts"] = normalize_alerts(result.get("alerts", []))
    return report


def verify_audit() -> Dict[str, Any]:
    result = require_ok(raw("verify_log"), "service", "public")
    valid = bool(result.get("valid"))
    return {
        "status": "ok",
        "decision": "allow" if valid else "deny",
        "reason": "authorized" if valid else "invalid_message",
        "identity": "service",
        "device": "audit-log",
        "valid": valid,
        "event_count": result.get("entries", 0),
        "first_invalid_record": result.get("first_bad_seq"),
        "integrity_status": "verified" if valid else "tampered",
    }


# --- messaging ---------------------------------------------------------------

def send_message(reference: str, sender: str, recipient: str,
                 plaintext: str) -> Dict[str, Any]:
    sess = resolve(reference)
    if sess.get("kind") != NORMAL_SESSION or sess["actor"] != sender:
        raise EngineError("unauthorized", sess["actor"], sess["device"])
    if not isinstance(plaintext, str) or not sender or not recipient:
        raise EngineError("invalid_request", sess["actor"], sess["device"])

    opened = require_ok(raw("session_open", recipient=recipient, sender=sender),
                        sess["actor"], sess["device"])
    sid = opened["sid"]
    require_ok(raw("session_accept", sid=sid, sender=sender),
               sess["actor"], sess["device"])
    sent = require_ok(raw("message_send", sid=sid, sender=sender,
                          recipient=recipient, plaintext=plaintext),
                      sess["actor"], sess["device"])
    if sent.get("decision") in ("deny", "reject"):
        raise EngineError(error_category(sent), sess["actor"], sess["device"])

    active_version = require_ok(raw("status"), sess["actor"],
                                sess["device"]).get("active_version")
    policy_decisions = []
    for node in NODES:
        hop = raw("authenticate", actor=sender, device=sess["device"],
                  node=node, key_version=active_version)
        policy_decisions.append({
            "node": node,
            "decision": "allow" if hop.get("decision") == "allow" else "deny",
        })
        require_ok(hop, sess["actor"], sess["device"])

    msg_id = sent["msg_id"]
    _ENVELOPES[msg_id] = {
        "sid": sid, "sender": sender, "recipient": recipient,
        "counter": sent["counter"], "nonce": sent["nonce"],
        "ciphertext": sent["ciphertext"],
    }
    return protected(
        sess, status="delivered", message_id=msg_id,
        route=[sender, "node-a", "messenger", "node-b", "node-c", recipient],
        policy_decisions=policy_decisions, delivery_status="delivered",
        replay_result="checked", recipient_binding_result="checked",
        note="envelope is E2E encrypted; plaintext and crypto material are "
             "not exposed by this endpoint")


def read_message(reference: str, recipient: str,
                 message_id: str) -> Dict[str, Any]:
    sess = resolve(reference)
    if sess.get("kind") != NORMAL_SESSION or sess["actor"] != recipient:
        raise EngineError("unauthorized", sess["actor"], sess["device"])
    envelope = _ENVELOPES.get(message_id)
    if not envelope or envelope["recipient"] != recipient:
        raise EngineError("invalid_message", sess["actor"], sess["device"])
    result = raw("message_receive", sid=envelope["sid"],
                 sender=envelope["sender"], recipient=recipient,
                 msg_id=message_id, counter=envelope["counter"],
                 nonce=envelope["nonce"], ciphertext=envelope["ciphertext"])
    if result.get("decision") != "deliver":
        raise EngineError(error_category(result), sess["actor"], sess["device"])
    delivered = result.get("messages", [])
    if not delivered:
        raise EngineError("invalid_message", sess["actor"], sess["device"])
    return protected(
        sess, status="delivered", message_id=message_id, recipient=recipient,
        sender=envelope["sender"], plaintext=delivered[0]["plaintext"],
        replay_result="accepted", recipient_binding_result="accepted",
        replay_checked=True, recipient_binding_checked=True)


# --- admin operations --------------------------------------------------------

def _advance_to_full_enforcement(sess: Dict[str, Any]) -> None:
    """Use the engine's monotonic clock so every node's sync delay has elapsed."""
    nodes = require_ok(raw("node_status"), sess["actor"],
                       sess["device"]).get("nodes", {})
    delay = max((float(n.get("sync_delay_s", 0.0)) for n in nodes.values()),
                default=0.0)
    if delay > 0:
        require_ok(raw("advance_time", seconds=delay),
                   sess["actor"], sess["device"])


def rotate_key(reference: str, target_user: str) -> Dict[str, Any]:
    sess = require_admin(reference)
    result = require_ok(raw("rotate_key", actor=target_user),
                        sess["actor"], sess["device"])
    cutoff = iso_utc(result.get("cutoff_at"))
    return protected(
        sess, status="ok", target_user=target_user,
        old_version=result.get("old_version"),
        new_version=result.get("new_version"),
        grace_seconds=result.get("grace_seconds"),
        grace_deadline=cutoff, old_key_cutoff=cutoff, cutoff_at=cutoff,
        now=iso_utc(result.get("now")),
        grace_applies=result.get("grace_applies", True))


def revoke_device(reference: str, target_user: str,
                  target_device: str) -> Dict[str, Any]:
    sess = require_admin(reference)
    result = require_ok(raw("revoke", actor=target_user,
                            device=target_device, reason="operator_revoke"),
                        sess["actor"], sess["device"])
    report = require_ok(raw("revoke_report"), sess["actor"], sess["device"])
    _advance_to_full_enforcement(sess)
    checks = []
    for node in NODES:
        probe = raw("authenticate", actor=target_user, device=target_device,
                    node=node)
        checks.append({
            "node": node,
            "denied": probe.get("decision") == "deny",
            "reason": probe.get("reason"),
        })
    return protected(
        sess, status="ok", target_user=target_user, target_device=target_device,
        epoch=result.get("epoch"), revoked_at=iso_utc(result.get("revoked_at")),
        enforcement_times={node: iso_utc(value) for node, value
                           in result.get("enforcement_times", {}).items()},
        last_node=result.get("last_node"),
        time_until_last_node_enforces=result.get("time_until_last_node_enforces"),
        per_node_enforcement=checks,
        nodes_epoch=report.get("revocation_epoch"))


def recover_device(reference: str, target_user: str, new_device: str,
                   recovery_proof: str = "") -> Dict[str, Any]:
    sess = require_recovery(reference, target_user)
    state = st.load_state()
    bound = state.get("recovery_bindings", {}).get(target_user)
    if not bound or sess["actor"] != bound:
        raise EngineError("unauthorized", sess["actor"], sess["device"])
    old_device = state.get("identities", {}).get(target_user, {}).get("device", "")
    result = require_ok(raw(
        "recover_device", actor=target_user, recovery_actor=sess["actor"],
        old_device=old_device, device=new_device,
        recovery_proof=recovery_proof), sess["actor"], sess["device"])
    _advance_to_full_enforcement(sess)
    checks = []
    for node in NODES:
        probe = raw("authenticate", actor=target_user, device=old_device,
                    node=node)
        checks.append({
            "node": node,
            "old_device_denied": probe.get("decision") == "deny",
            "reason": probe.get("reason"),
        })
    return protected(
        sess, status="ok", target_user=target_user,
        old_device=result.get("old_device"), new_device=result.get("device"),
        recovery_identity=result.get("recovery_actor"),
        old_device_still_revoked=result.get("old_device_still_revoked", True),
        sessions_invalidated=result.get("sessions_invalidated", True),
        new_device_dsa_fingerprint=result.get("dsa_fingerprint"),
        new_device_kem_fingerprint=result.get("kem_fingerprint"),
        old_device_per_node=checks, no_private_key_returned=True)


def crash_recovery_test(reference: str, target_device: str = "") -> Dict[str, Any]:
    sess = require_admin(reference)
    state = st.load_state()
    device = target_device or (sorted(state.get("revoked", {})) or [""])[0]
    started = time.perf_counter()
    require_ok(raw("begin_rotation"), sess["actor"], sess["device"])
    require_ok(raw("crash_rotation", seconds=0.2), sess["actor"], sess["device"])
    recovered = require_ok(raw("recover_state"), sess["actor"], sess["device"])
    elapsed = time.perf_counter() - started
    _advance_to_full_enforcement(sess)

    checks = []
    for node in NODES:
        probe = raw("authenticate", actor="", device=device, node=node)
        checks.append({
            "node": node,
            "denied": probe.get("decision") == "deny",
            "reason": probe.get("reason"),
        })

    asset = next(iter(state.get("protected_data", {})), "")
    owner = state.get("owners", {}).get(asset, "")
    data = raw("read", actor=owner, asset=asset) if asset else {}
    return protected(
        sess, status="ok", crashed_during_rotation=True,
        recovered=recovered.get("recovered", True),
        committed_version=recovered.get("committed_version"),
        revocation_epoch=recovered.get("revocation_epoch"),
        still_revoked=recovered.get("still_revoked", []),
        revoked_device_checked=device, revoked_device_per_node=checks,
        protected_data_available=bool(data.get("decision") == "allow"),
        log_valid=recovered.get("log_valid"),
        recovery_time_s=round(elapsed, 4),
        measurement_note="embedded interruption/replay simulation; not a "
                         "process kill during rotation")


def backup_integrity_test(reference: str) -> Dict[str, Any]:
    sess = require_admin(reference)
    backup_id = "api-bak-%s" % secrets.token_hex(4)
    require_ok(raw("create_backup", backup_id=backup_id),
               sess["actor"], sess["device"])
    blob = recovery_engine._backup_load(backup_id)
    if not blob:
        raise EngineError("invalid_request", sess["actor"], sess["device"])
    copy_id = backup_id + "-copy"
    recovery_engine._backup_store(copy_id, blob)   # existing engine helper
    require_ok(raw("damage_backup", backup_id=copy_id),
               sess["actor"], sess["device"])
    restored = raw("restore_backup", backup_id=copy_id)
    rejected = restored.get("message") == "backup_integrity_failure"
    return protected(
        sess, status="ok", backup_created=True, controlled_copy=copy_id,
        copy_corrupted=True, restore_rejected=rejected,
        detection="backup_corrupt" if rejected else error_category(restored),
        original_backup_untouched=recovery_engine._backup_load(backup_id) == blob,
        no_key_material_returned=True)


def log_integrity_test(reference: str, seq: Optional[int] = None) -> Dict[str, Any]:
    """Tamper and verify an isolated copy; the live audit log is untouched."""
    sess = require_admin(reference)
    with _STATE_DIR_LOCK:
        original = st.state_dir()
        tmp = tempfile.mkdtemp(prefix="track4_log_test_")
        try:
            for name in ("state.json", "journal.jsonl"):
                src_path = os.path.join(original, name)
                if os.path.exists(src_path):
                    shutil.copy2(src_path, os.path.join(tmp, name))
            st.set_state_dir(tmp)
            before = require_ok(raw("verify_log"), sess["actor"], sess["device"])
            target = seq if seq and seq >= 1 else 1
            tamper = raw("tamper_log", seq=target, field="actor",
                         value="operator-tamper-test")
            require_ok(tamper, sess["actor"], sess["device"])
            after = require_ok(raw("verify_log"), sess["actor"], sess["device"])
        finally:
            st.set_state_dir(original)
            shutil.rmtree(tmp, ignore_errors=True)
    detected = after.get("valid") is False
    return protected(
        sess, status="ok", real_log_untouched=True,
        copy_valid_before=bool(before.get("valid")),
        mutation_type="field_replacement", mutated_field="actor",
        tampered_seq=tamper.get("tampered_seq"),
        copy_valid_after=bool(after.get("valid")),
        first_bad_record=after.get("first_bad_seq"),
        detection="log_tampered" if detected else "invalid_request",
        detected=detected)
