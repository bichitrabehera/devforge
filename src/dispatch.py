"""Op registry - the single entry point dispatch(request).

Each op loads state, performs its work, appends to the signed audit log
where relevant, and returns a JSON-serializable dict without secret
material.
"""

from . import access, keys, messaging, recovery
from . import state as st


def _op_advance_time(request):
    now = st.advance_clock(float(request.get("seconds", 0)))
    return {"status": "ok", "now": now,
            "clock_offset": st.load_state().get("clock_offset", 0.0)}


def _op_append_log(request):
    from . import audit
    state = st.load_state()
    entry = audit.append(
        state, request.get("actor", "unknown"), request.get("action", "custom"),
        request.get("asset", ""), request.get("decision", "ok"),
        detail=request.get("detail", ""),
        request_id=request.get("request_id", ""))
    st.save_state(state)
    return {"status": "ok", "seq": entry["seq"], "hash": entry["hash"]}


def _op_verify_log(request):
    from . import audit
    state = st.load_state()
    result = audit.verify(state)
    result["status"] = "ok"
    return result


def _op_tamper_log(request):
    """Test helper: modify a committed log entry (attacker simulation)."""
    from . import audit
    state = st.load_state()
    seq = int(request.get("seq", 1))
    if not 1 <= seq <= len(state["log"]):
        return {"status": "error", "message": "no_such_entry"}
    entry = state["log"][seq - 1]
    field = request.get("field", "actor")
    entry[field] = request.get("value", "attacker")
    st.save_state(state)
    return {"status": "ok", "tampered_seq": seq, "field": field,
            "signature_stale": True}


def _op_detector_evaluate(request):
    from .detector import evaluate_labelled
    result = evaluate_labelled(
        events_path=request.get("events_path"),
        labels_path=request.get("labels_path"),
        approvals_path=request.get("approvals_path"),
        events=request.get("events"),
        labels=request.get("labels"),
        approvals=request.get("approvals"))
    result["status"] = "ok"
    return result


def _op_detector_live(request):
    from .detector import evaluate_live
    state = st.load_state()
    result = evaluate_live(state["log"])
    result["status"] = "ok"
    return result


_OPS = {
    # identity / access control
    "setup": keys.op_setup, "status": keys.op_status,
    "advance_time": _op_advance_time,
    "read": access.op_read,
    "audit": access.op_audit,
    "grant_role": access.op_grant_role, "revoke_role": access.op_revoke_role,
    "disable": keys.op_disable,
    # key lifecycle
    "rotate_key": keys.op_rotate_key, "authenticate": keys.op_authenticate,
    "node_status": keys.op_node_status, "node_sync": keys.op_node_sync,
    "revoke": keys.op_revoke, "revoke_report": keys.op_revoke_report,
    "re_enroll": keys.op_re_enroll, "re_enroll_device": keys.op_re_enroll,
    # crash recovery / backups
    "begin_rotation": recovery.op_begin_rotation,
    "crash_rotation": recovery.op_crash_rotation,
    "corrupt_state": recovery.op_corrupt_state,
    "recover_state": recovery.op_recover_state,
    "journal_status": recovery.op_journal_status,
    "create_backup": recovery.op_create_backup,
    "damage_backup": recovery.op_damage_backup,
    "restore_backup": recovery.op_restore_backup,
    # audit log
    "append_log": _op_append_log, "verify_log": _op_verify_log,
    "tamper_log": _op_tamper_log,
    # messaging
    "session_open": messaging.op_session_open,
    "session_accept": messaging.op_session_accept,
    "message_send": messaging.op_message_send,
    "message_receive": messaging.op_message_receive,
    "inbox_drain": messaging.op_inbox_drain,
    "session_resume": messaging.op_session_resume,
    "session_close": messaging.op_session_close,
    # detection
    "detector_evaluate": _op_detector_evaluate,
    "detector_live": _op_detector_live,
    "demo": None,   # wired below to avoid an import cycle
}


def dispatch(request):
    op = request.get("op", "")
    handler = _OPS.get(op)
    if op == "demo":
        from .demo import demo_script
        summary = demo_script()
        summary["status"] = "ok"
        return summary
    if handler is None:
        return {"status": "error", "message": "unknown_op:%s" % op,
                "known_ops": sorted(k for k in _OPS if k != "demo")}
    try:
        return handler(request)
    except Exception as exc:    # never leak internals or key material
        return {"status": "error", "message": "op_failed", "op": op,
                "error_class": type(exc).__name__}
