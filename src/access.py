"""Identity / access control.

Decisions are explainable: every allow/deny carries the reasons that produced
it.  An actor is denied if disabled (revoked identity); an asset read is
allowed for its owner or for a role whose scope includes the asset.
"""

from . import audit
from . import state as st


def access_decision(state, actor, asset):
    """Return (decision, reasons). Deterministic and explainable."""
    if actor in state["disabled"]:
        return "deny", ["actor_is_disabled"]
    if state["owners"].get(asset) == actor:
        return "allow", ["owner"]
    role = state["roles"].get(actor)
    if role == "report-reader" and asset.startswith("reports"):
        return "allow", ["role:report-reader"]
    reasons = []
    owner = state["owners"].get(asset)
    reasons.append("not_owner:%s" % owner if owner else "no_owner_for_asset")
    reasons.append("role:%s" % (role or "none"))
    return "deny", reasons


def op_read(request):
    st_ = st.load_state()
    actor = request.get("actor", "")
    asset = request.get("asset", "")
    decision, reasons = access_decision(st_, actor, asset)
    audit.append(st_, actor, "read", asset, decision,
                 detail=request.get("detail", ""),
                 request_id=request.get("request_id", ""))
    st.save_state(st_)
    resp = {"status": "ok", "decision": decision, "reasons": reasons,
            "actor": actor, "asset": asset,
            "request_id": request.get("request_id", "")}
    if decision == "allow":
        resp["body"] = st_["protected_data"].get(asset, {}).get("body", "")
    return resp


def op_audit(request):
    """Re-evaluate an access decision against the CURRENT state.

    Used by validators/operators to confirm enforcement (e.g. a revoked
    owner must now be denied). Returns decision 'allow' or 'deny'.
    """
    state = st.load_state()
    actor = request.get("actor", "")
    asset = request.get("asset", "")
    decision, reasons = access_decision(state, actor, asset)
    # An actor whose device was revoked (device loss) is denied everywhere,
    # not just at nodes that have applied the epoch.
    device = request.get("device", "")
    if not device:
        ident = state["identities"].get(actor)
        device = ident.get("device", "") if ident else actor
    if device and device in state["revoked"]:
        decision, reasons = "deny", ["revoked_device"]
    audit.append(state, actor, "audit", asset, decision,
                 detail=";".join(reasons),
                 request_id=request.get("request_id", ""))
    st.save_state(state)
    return {"status": "ok", "decision": decision, "reasons": reasons,
            "actor": actor, "asset": asset,
            "request_id": request.get("request_id", "")}


def op_grant_role(request):
    st_ = st.load_state()
    from .detector import approval_matches, load_approvals
    admin = request.get("admin", "")
    subject = request.get("subject", "")
    role = request.get("role", "")
    approval_id = request.get("approval_id", "")
    approvals = load_approvals(request.get("approvals_path"),
                               request.get("approvals"))
    approved = approval_matches(approvals, {
        "approval_id": approval_id, "subject": subject,
        "operation": "grant_role", "role": role, "at": st.now()})
    decision = "allow" if approved and admin in st_["admins"] else "deny"
    reason = "approved_change" if approved else "no_matching_approval"
    if decision == "allow":
        st_["roles"][subject] = role
    audit.append(st_, admin, "grant_role", subject, decision,
                 detail="role=%s approval=%s" % (role, approval_id),
                 request_id=request.get("request_id", ""))
    st.save_state(st_)
    return {"status": "ok", "decision": decision, "reason": reason,
            "subject": subject, "role": role}


def op_revoke_role(request):
    st_ = st.load_state()
    from .detector import approval_matches, load_approvals
    admin = request.get("admin", "")
    subject = request.get("subject", "")
    approval_id = request.get("approval_id", "")
    approvals = load_approvals(request.get("approvals_path"),
                               request.get("approvals"))
    approved = approval_matches(approvals, {
        "approval_id": approval_id, "subject": subject,
        "operation": "revoke_role", "at": st.now()})
    decision = "allow" if approved and admin in st_["admins"] else "deny"
    reason = "approved_change" if approved else "no_matching_approval"
    if decision == "allow":
        st_["roles"][subject] = request.get("new_role", "viewer")
    audit.append(st_, admin, "revoke_role", subject, decision,
                 detail="approval=%s" % approval_id,
                 request_id=request.get("request_id", ""))
    st.save_state(st_)
    return {"status": "ok", "decision": decision, "reason": reason,
            "subject": subject}
