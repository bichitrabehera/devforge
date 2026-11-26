"""Key lifecycle: rotation with documented cutoff, multi-node revocation,
device re-enrolment.

Rotation model
--------------
Every rotation mints a new ML-KEM-768 version.  The *previous* version stays
valid until `cutoff_at = created_at + grace_seconds` (documented grace period,
default 30 s of simulated time): authorized transfers presented with the old
version keep working inside the window.  After the cutoff every node rejects
old-version requests ("old_key_after_cutoff").

Revocation model
----------------
Revoking a device bumps a global revocation epoch.  Nodes enforce revocations
at `revoked_at + node.sync_delay_s` (node-a: 0 s, node-b: 2 s), so the time
from revocation until the last node enforces is measured and reported.  The
device's owner can re-enrol with fresh key material; no other user or the
service's own keys are affected.
"""

from . import audit, crypto
from . import state as st


def new_key_version(state, grace_seconds=None):
    version = state["active_version"] + 1
    pk, sk = crypto.kem_keypair()
    created = st.now()
    grace = state["grace_seconds"] if grace_seconds is None else grace_seconds
    record = {
        "version": version,
        "created_at": created,
        "cutoff_at": created + grace,
        "kem_pk": pk.hex(),
        "kem_sk": sk.hex(),
        "fingerprint": crypto.fp(pk),
    }
    state["key_versions"] = [v for v in state["key_versions"]
                             if v["version"] != version]
    state["key_versions"].append(record)
    state["active_version"] = version
    return record


def version_record(state, version):
    for v in state["key_versions"]:
        if v["version"] == version:
            return v
    return None


# --- ops --------------------------------------------------------------------

def op_setup(request):
    """Initialize from supplied data. Adapter contract: setup RESETS state
    (a fresh container starts empty; setup resets practice state).

    `key_material` is a synthetic sensitive value: it is stored ONLY as a
    SHA-256 digest and is never returned, logged, or written in plaintext.
    """
    state = st.default_state()      # full reset per the contract
    if request.get("grace_seconds") is not None:
        state["grace_seconds"] = float(request["grace_seconds"])
    pk, sk = crypto.dsa_keypair()
    state["service_dsa_pk"] = pk.hex()
    state["service_dsa_sk"] = sk.hex()
    state["owners"] = dict(request.get("owners", {}) or {})
    state["roles"] = dict(request.get("roles", {}) or {})
    state["admins"] = list(request.get("admins", ["user-admin"]))
    state["disabled"] = list(request.get("disabled", []) or [])
    key_material = request.get("key_material", "")
    if key_material:
        state["key_material_digest"] = crypto.sha256_hex(str(key_material))
        # note: the value itself is never stored, returned, or logged
    for asset, body in (request.get("contents", {}) or {}).items():
        state["protected_data"][asset] = {
            "owner": state["owners"].get(asset, ""), "body": body}
    v = new_key_version(state, grace_seconds=request.get("grace_seconds"))
    for node in state["nodes"].values():
        node["key_version"] = v["version"]
        node["epoch_applied"] = state["revocation_epoch"]
    audit.append(state, "service", "setup", "service", "ok",
                 detail="state reset and initialized; key material kept "
                        "as digest only",
                 request_id=request.get("request_id", ""))
    st.save_state(state)
    return {"status": "ok", "ready": True, "active_version": v["version"],
            "grace_seconds": v["cutoff_at"] - v["created_at"],
            "service_fingerprint": crypto.fp(pk),
            "nodes": list(state["nodes"]),
            "disabled_count": len(state["disabled"]),
            "key_material_stored": "sha256-digest-only"}


def op_status(request):
    state = st.load_state()
    v = version_record(state, state["active_version"])
    return {"status": "ok",
            "active_version": state["active_version"],
            "fingerprint": v["fingerprint"] if v else None,
            "cutoff_at": v["cutoff_at"] if v else None,
            "grace_seconds": state["grace_seconds"],
            "now": st.now(),
            "revocation_epoch": state["revocation_epoch"],
            "revoked": list(state["revoked"]),
            "disabled": list(state["disabled"]),
            "nodes": state["nodes"],
            "log_entries": len(state["log"]),
            "log_valid": audit.verify(state)["valid"],
            "sessions": [sid for sid, s in state["sessions"].items()
                         if s["state"] != "closed"],
            "journal_records": len(st.journal_read())}


def op_rotate_key(request):
    """Rotate the active key version; old version honored until its cutoff."""
    state = st.load_state()
    before = state["active_version"]
    grace = request.get("grace_seconds")
    v = new_key_version(state, grace_seconds=grace)
    st.journal_append({"kind": "rotation", "step": "commit",
                       "version": v["version"], "created_at": v["created_at"],
                       "cutoff_at": v["cutoff_at"], "kem_pk": v["kem_pk"],
                       "kem_sk": v["kem_sk"], "ts": st.now()})
    for node in state["nodes"].values():
        node["key_version"] = v["version"]
        node["epoch_applied"] = state["revocation_epoch"]
    audit.append(state, "service", "rotate_key", "key", "ok",
                 detail="version=%d from=%d" % (v["version"], before),
                 request_id=request.get("request_id", ""))
    st.save_state(state)
    return {"status": "ok", "old_version": before, "new_version": v["version"],
            "cutoff_at": v["cutoff_at"], "now": st.now(),
            "grace_seconds": v["cutoff_at"] - v["created_at"],
            "grace_applies": True,
            "note": "old version accepted until cutoff_at, rejected after"}


def op_authenticate(request):
    """A protected operation presenting a key version at a named node.

    Enforces (a) the documented old-version cutoff, (b) per-node revocation
    with the node's sync delay, (c) disabled actors.  Every decision is
    written to the signed audit log.
    """
    state = st.load_state()
    actor = request.get("actor", "")
    device = request.get("device", actor)
    version = int(request.get("key_version", state["active_version"]))
    node_name = request.get("node", "node-a")
    node = state["nodes"].get(node_name)
    if node is None:
        return {"status": "error", "message": "unknown_node"}
    now = st.now()
    v = version_record(state, version)
    if v is None:
        return {"status": "error", "message": "unknown_key_version",
                "key_version": version}

    if version != state["active_version"]:
        in_grace = (version == state["active_version"] - 1
                    and now < v["cutoff_at"])
        if in_grace:
            outcome = "grace"
        else:
            audit.append(state, actor, "authenticate", "key", "deny",
                         detail="old_key_after_cutoff node=%s version=%d"
                                % (node_name, version),
                         request_id=request.get("request_id", ""))
            st.save_state(state)
            return {"status": "ok", "decision": "deny",
                    "reason": "old_key_after_cutoff", "node": node_name,
                    "key_version": version, "cutoff_at": v["cutoff_at"],
                    "now": now}
    else:
        outcome = "current"

    rev = state["revoked"].get(device)
    if rev is not None:
        enforce_at = rev["revoked_at"] + node["sync_delay_s"]
        node["epoch_applied"] = max(node["epoch_applied"], rev["epoch"])
        if now >= enforce_at:
            audit.append(state, actor, "authenticate", "key", "deny",
                         detail="revoked_device node=%s device=%s"
                                % (node_name, device),
                         request_id=request.get("request_id", ""))
            st.save_state(state)
            return {"status": "ok", "decision": "deny", "reason": "revoked",
                    "node": node_name, "device": device,
                    "enforced_at": enforce_at}
    if actor in state["disabled"]:
        audit.append(state, actor, "authenticate", "key", "deny",
                     detail="disabled_actor node=%s" % node_name,
                     request_id=request.get("request_id", ""))
        st.save_state(state)
        return {"status": "ok", "decision": "deny", "reason": "disabled",
                "node": node_name}

    audit.append(state, actor, "authenticate", "key", "allow",
                 detail="node=%s version=%d outcome=%s"
                        % (node_name, version, outcome),
                 request_id=request.get("request_id", ""))
    st.save_state(state)
    return {"status": "ok", "decision": "allow", "node": node_name,
            "key_version": version, "outcome": outcome}


def op_node_status(request):
    state = st.load_state()
    name = request.get("node")
    nodes = state["nodes"]
    if name:
        if name not in nodes:
            return {"status": "error", "message": "unknown_node"}
        nodes = {name: nodes[name]}
    return {"status": "ok", "nodes": nodes,
            "active_version": state["active_version"],
            "revocation_epoch": state["revocation_epoch"]}


def op_node_sync(request):
    state = st.load_state()
    name = request.get("node")
    if name not in state["nodes"]:
        return {"status": "error", "message": "unknown_node"}
    node = state["nodes"][name]
    node["key_version"] = state["active_version"]
    node["epoch_applied"] = state["revocation_epoch"]
    st.save_state(state)
    return {"status": "ok", "node": name,
            "key_version": node["key_version"],
            "epoch_applied": node["epoch_applied"]}


def op_revoke(request):
    """Revoke a device (device loss) and/or an actor's device.

    Accepts either `device` or `actor` (revoke resolves the actor's
    registered device). The actor's identity is disabled as well, so every
    node denies them immediately; propagation to every node is measured and
    reported. Other users keep access; the owner can re-enrol later.
    """
    state = st.load_state()
    device = request.get("device", "")
    actor = request.get("actor", "") or request.get("user", "") \
        or request.get("subject", "")
    if not device and actor:
        # resolve the actor's device (identity records register one)
        ident = state["identities"].get(actor)
        device = ident.get("device", "") if ident else actor
    if not device:
        device = actor or "unknown-device"
    if actor and actor not in state["disabled"]:
        state["disabled"].append(actor)
    if device not in state["revoked"]:
        state["revocation_epoch"] += 1
        state["revoked"][device] = {"revoked_at": st.now(),
                                    "epoch": state["revocation_epoch"],
                                    "reason": request.get("reason",
                                                          "device_loss")}
        st.journal_append({"kind": "revocation", "device": device,
                           "epoch": state["revocation_epoch"],
                           "revoked_at": state["revoked"][device]["revoked_at"]})
    rev = state["revoked"][device]
    enforcement = {name: rev["revoked_at"] + node["sync_delay_s"]
                   for name, node in state["nodes"].items()}
    last_node = max(enforcement, key=enforcement.get)
    audit.append(state, request.get("admin", "user-admin"), "revoke", device,
                 "ok", detail="epoch=%d actor=%s" % (rev["epoch"], actor),
                 request_id=request.get("request_id", ""))
    st.save_state(state)
    return {"status": "ok", "device": device, "actor": actor,
            "epoch": rev["epoch"], "revoked_at": rev["revoked_at"],
            "enforcement_times": enforcement,
            "last_node": last_node,
            "time_until_last_node_enforces":
                enforcement[last_node] - rev["revoked_at"]}


def op_revoke_report(request):
    state = st.load_state()
    return {"status": "ok", "revoked": state["revoked"],
            "revocation_epoch": state["revocation_epoch"],
            "nodes": state["nodes"],
            "note": "each node enforces a revoked key once its sync delay "
                    "after revoked_at has elapsed"}


def op_re_enroll(request):
    """Re-enrol a device after loss: fresh key material, actor re-enabled,
    other users and the service unaffected."""
    state = st.load_state()
    device = request.get("device", "")
    actor = request.get("actor", device)
    if not device:
        ident = state["identities"].get(actor)
        device = ident.get("device", "") if ident else actor
    if device in state["revoked"]:
        del state["revoked"][device]
        state["revocation_epoch"] += 1
        st.journal_append({"kind": "re_enroll", "device": device,
                           "epoch": state["revocation_epoch"], "ts": st.now()})
    if actor in state["disabled"]:
        state["disabled"].remove(actor)
    pk, sk = crypto.kem_keypair()
    dpk, dsk = crypto.dsa_keypair()
    ident = state["identities"].get(actor, {})
    ident.update({"kem_pk": pk.hex(), "kem_sk": sk.hex(),
                  "dsa_pk": dpk.hex(), "dsa_sk": dsk.hex(),
                  "status": "active", "device": device})
    state["identities"][actor] = ident
    audit.append(state, actor, "re_enroll", device, "ok",
                 detail="fresh key material, epoch=%d"
                        % state["revocation_epoch"],
                 request_id=request.get("request_id", ""))
    st.save_state(state)
    return {"status": "ok", "device": device, "actor": actor,
            "kem_fingerprint": crypto.fp(pk),
            "dsa_fingerprint": crypto.fp(dpk),
            "other_users_unaffected": True}


def op_disable(request):
    """Disable an actor identity entirely (compromised user)."""
    state = st.load_state()
    actor = request.get("actor", "")
    if actor not in state["disabled"]:
        state["disabled"].append(actor)
    audit.append(state, request.get("admin", "user-admin"), "disable", actor,
                 "ok", detail="identity disabled at every node")
    st.save_state(state)
    return {"status": "ok", "actor": actor, "disabled": True}
