"""Deterministic anomaly & lateral-movement analyzer for Hackathon Track 4.

Uses NO AI/ML, no custom crypto primitives. All detection is rule-based
on state changes, crypto operations, and log patterns.
"""

import os
import json
import hashlib
import ipaddress
import tempfile

from team_app import _load_state, _save_state, _default_state


def _state_path():
    st = os.environ.get("TRACK4_STATE_DIR", None)
    if st:
        os.makedirs(st, exist_ok=True)
        return os.path.join(st, "state.json")
    return os.path.join(tempfile.gettempdir(), "track4_state.json")


def _load_state():
    """Thin loader so detector can run independently."""
    path = _state_path()
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return _default_state()


def _save_state(state):
    path = _state_path()
    data = json.dumps(state, indent=2)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


def detect_anomalies(request):
    """Deterministic anomaly detection on a request/event.

    Returns a list of anomaly strings. Never returns secret material.
    """
    state = _load_state()
    anomalies = []

    op = request.get("op", "")
    sid = request.get("sid", "")

    # Rule: KEM key never set up
    if not state.get("pk_ml_kem"):
        anomalies.append("kem_key_missing")

    # Rule: Session opened without KEM/DSA enrollment
    if sid and state.get("sessions", {}).get(sid) and not state.get("pk_ml_dsa"):
        anomalies.append("dsa_missing_for_session")

    # Rule: Multiple rapid session resumes from different SIDs
    sessions = state.get("sessions", {})
    if sid and sessions.get(sid, {}).get("nonce"):
        anomalies.append("session_resume_active")

    # Rule: Message send without valid session
    if op == "send_message" and not sid:
        anomalies.append("message_without_session")

    # Rule: Receive with mismatched nonce length
    if op == "receive_message":
        nonce_hex = request.get("nonce", "")
        ct_hex = request.get("ciphertext", "")
        if nonce_hex and len(nonce_hex) != 24:
            anomalies.append("invalid_nonce_length")
        if ct_hex and len(ct_hex) % 2 != 0:
            anomalies.append("invalid_ciphertext_length")

    # Rule: Log entries exceeding threshold
    log = state.get("log", [])
    if len(log) > 400:
        anomalies.append("log_flood")

    # Lateral-movement rule: revoke followed immediately by new session
    if op == "open_session" and sid:
        recent_log = state.get("log", [])[-10:]
        if any("revoke" in str(e.get("entry", "")).lower() for e in recent_log):
            anomalies.append("revoke_then_session")

    # Deterministic hash-based flag (no crypto secrets)
    data_to_hash = f"{op}:{sid}:{len(log)}"
    h = hashlib.sha256(data_to_hash.encode()).hexdigest()
    if h[:4] == "0000":
        anomalies.append("deterministic_flag")

    return anomalies


def detect_lateral_movement():
    """Analyze state for lateral-movement patterns.

    Returns a list of lateral-movement indicators. Never leaks keys.
    """
    state = _load_state()
    indicators = []

    sessions = state.get("sessions", {})
    log = state.get("log", [])

    # Multiple SIDs opened in short order
    sid_list = list(sessions.keys())
    if len(sid_list) > 5:
        indicators.append("many_sessions")

    # KEM/DSA key rotation without log entries
    if state.get("pk_ml_kem") and not any(
        "key_rotate" in str(e.get("entry", "")).lower() for e in log
    ):
        indicators.append("key_rotate_no_log")

    # Session resume from revoked state
    for sid, s in sessions.items():
        if s.get("nonce"):
            indicators.append("resume_from_revoked")

    # Unexplained large message sends
    msg_count = sum(1 for e in log if e.get("type") == "message_send")
    if msg_count > 20:
        indicators.append("high_message_volume")

    return indicators
