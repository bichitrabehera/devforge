"""Identity / access control.

Decisions are explainable: every allow/deny carries the reasons that produced
it.  An actor is denied if disabled (revoked identity); an asset read is
allowed for its owner or for a role whose scope includes the asset.

Adapter-contract compliance (docs/adapter-v1.md):
* `read` records every decision against the supplied request_id;
* `audit` returns the RECORDED decision for that request_id (not a fresh
  re-evaluation);
* `protected_read` implements the scored KEM-interop exchange: encapsulate
  against the caller's Base64 raw ML-KEM-768 public key and return a
  lowercase-hex HMAC-SHA256 over `challenge + stored_body`, keyed by the
  KEM shared secret, which never leaves the application.
"""

import base64
import hashlib
import hmac
import os

from . import audit
from . import crypto
from . import state as st

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _trusted_approvals(path):
    """A caller-named approvals file is honored ONLY when it lives inside
    the repository root (organizer/operator-controlled policy source).
    Anything else is an injection attempt: return (False, reason)."""
    if not path:
        return True, ""
    try:
        rp = os.path.realpath(str(path))
        root = os.path.realpath(_REPO_ROOT)
        inside = os.path.commonpath([rp, root]) == root
    except (ValueError, TypeError, OSError):
        inside = False
    return inside, "" if inside else "untrusted_approvals_source"


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
    request_id = st.clip(request.get("request_id", ""), 256)
    audit.append(st_, actor, "read", asset, decision,
                 detail=request.get("detail", ""), request_id=request_id)
    # Record the decision against the request id (adapter contract: audit
    # must return the recorded decision, even if policy changes later).
    if request_id:
        decisions = st_.setdefault("decisions", {})
        # First write wins: a later caller reusing the same request_id
        # cannot overwrite an already-recorded decision.
        if request_id not in decisions:
            decisions[request_id] = {"decision": decision, "actor": actor,
                                     "asset": asset, "ts": st.now()}
            if len(decisions) > 1000:   # keep the map bounded
                for old in sorted(decisions,
                                  key=lambda k: decisions[k]["ts"])[:-1000]:
                    decisions.pop(old, None)
    st.save_state(st_)
    resp = {"status": "ok", "decision": decision, "reasons": reasons,
            "actor": actor, "asset": asset, "request_id": request_id}
    if decision == "allow":
        resp["body"] = st_["protected_data"].get(asset, {}).get("body", "")
    return resp


def op_protected_read(request):
    """Adapter contract v1 - protected_read interoperability.

    Request: actor, asset, challenge, public_key (standard Base64 raw
    ML-KEM-768 public key). After authorization: encapsulate against that
    key; return the KEM ciphertext as standard Base64 and proof = lowercase
    hex HMAC-SHA256 keyed by the shared secret over UTF-8 bytes of
    `challenge + stored_body` (no separator). The shared secret never
    leaves the application and is not persisted.
    """
    st_ = st.load_state()
    actor = request.get("actor", "")
    asset = request.get("asset", "")
    challenge = request.get("challenge", "")
    if not isinstance(challenge, str):     # type-confusion hardening
        challenge = crypto.canonical(challenge)
    request_id = st.clip(request.get("request_id", ""), 256)
    decision, reasons = access_decision(st_, actor, asset)
    if request_id:
        decisions = st_.setdefault("decisions", {})
        if request_id not in decisions:      # first write wins
            decisions[request_id] = {
                "decision": decision, "actor": actor, "asset": asset,
                "ts": st.now()}
    if decision != "allow":
        audit.append(st_, actor, "protected_read", asset, "deny",
                     detail=";".join(reasons), request_id=request_id)
        st.save_state(st_)
        return {"status": "ok", "decision": "deny"}   # no protected content
    try:
        peer_pk = base64.b64decode(request.get("public_key", ""),
                                   validate=True)
    except Exception:
        return {"status": "error", "message": "invalid_public_key_encoding"}
    if len(peer_pk) != 1184:    # ML-KEM-768 raw public key size
        return {"status": "error", "message": "invalid_public_key_length",
                "expected_bytes": 1184, "received_bytes": len(peer_pk)}
    ciphertext, shared_secret = crypto.kem_encaps(peer_pk)
    body = st_["protected_data"].get(asset, {}).get("body", "")
    if not isinstance(body, str):          # type-confusion hardening
        body = crypto.canonical(body)
    proof = hmac.new(shared_secret,
                     (challenge + body).encode("utf-8"),
                     hashlib.sha256).hexdigest()
    audit.append(st_, actor, "protected_read", asset, "allow",
                 detail="KEM interoperability proof issued; shared secret "
                        "not disclosed or persisted",
                 request_id=request_id)
    st.save_state(st_)
    return {"status": "ok", "decision": "allow",
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "proof": proof}


def op_audit(request):
    """Adapter contract: return the RECORDED decision for this request_id.

    Falls back to a fresh evaluation (with device-revocation awareness)
    only when the request_id was never recorded.
    """
    st_ = st.load_state()
    request_id = st.clip(request.get("request_id", ""), 256)
    rec = st_.get("decisions", {}).get(request_id)
    if rec is not None:
        decision = rec["decision"]
        reasons = ["recorded"]
        actor = rec.get("actor", "unknown")
        asset = rec.get("asset", "")
    else:
        actor = request.get("actor", "")
        asset = request.get("asset", "")
        decision, reasons = access_decision(st_, actor, asset)
        # An actor whose device was revoked (device loss) is denied
        # everywhere, not just at nodes that have applied the epoch.
        device = request.get("device", "")
        if not device:
            ident = st_["identities"].get(actor)
            device = ident.get("device", "") if ident else actor
        if device and device in st_["revoked"]:
            decision, reasons = "deny", ["revoked_device"]
    audit.append(st_, actor, "audit", asset, decision,
                 detail=";".join(reasons), request_id=request_id)
    st.save_state(st_)
    return {"status": "ok", "decision": decision, "reasons": reasons,
            "actor": actor, "asset": asset, "request_id": request_id}


def op_grant_role(request):
    st_ = st.load_state()
    from .detector import approval_matches, load_approvals
    admin = request.get("admin", "")
    subject = request.get("subject", "")
    role = request.get("role", "")
    approval_id = request.get("approval_id", "")
    trusted, why = _trusted_approvals(request.get("approvals_path"))
    if not trusted:
        audit.append(st_, admin, "grant_role", subject, "deny",
                     detail="approvals_source=%s" % why,
                     request_id=request.get("request_id", ""))
        st.save_state(st_)
        return {"status": "ok", "decision": "deny", "reason": why,
                "subject": subject, "role": role}
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
    trusted, why = _trusted_approvals(request.get("approvals_path"))
    if not trusted:
        audit.append(st_, admin, "revoke_role", subject, "deny",
                     detail="approvals_source=%s" % why,
                     request_id=request.get("request_id", ""))
        st.save_state(st_)
        return {"status": "ok", "decision": "deny", "reason": why,
                "subject": subject}
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
