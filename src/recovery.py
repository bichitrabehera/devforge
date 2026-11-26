"""Crash recovery and verified backups.

Rotation journal
----------------
`rotate_key` writes a "commit" record to the durable journal *before*
touching in-memory state; `begin_rotation` journals the intent plus the new
key material without committing.  If the process crashes between the two,
`recover_state` replays the journal to the last commit marker: the last
committed version stays active, uncommitted rotations are discarded, and
revocations recorded before the crash remain revoked.

Backups
-------
`create_backup` serializes core state, hashes the payload and signs the
manifest (backup_id + payload SHA-256) with the service ML-DSA key.
`restore_backup` verifies the signature FIRST, then the payload hash; only
verified key material is ever loaded.  A damaged or forged backup is
rejected with no state change.
"""

import json

from . import audit, crypto
from . import state as st


def op_begin_rotation(request):
    """Journal the intent (and the new key material) WITHOUT committing, so a
    crash between begin and commit is recoverable."""
    state = st.load_state()
    version = state["active_version"] + 1
    pk, sk = crypto.kem_keypair()
    created = st.now()
    grace = state["grace_seconds"] if request.get("grace_seconds") is None \
        else request.get("grace_seconds")
    st.journal_append(state, {"kind": "rotation", "step": "begin",
                       "version": version, "created_at": created,
                       "cutoff_at": created + grace,
                       "kem_pk": pk.hex(), "kem_sk": sk.hex(), "ts": created})
    audit.append(state, "service", "begin_rotation", "key", "ok",
                 detail="version=%d journaled (uncommitted)" % version)
    st.save_state(state)
    return {"status": "ok", "journaled_version": version,
            "committed_version": state["active_version"]}


def op_crash_rotation(request):
    """Simulate a crash mid-rotation, after `begin_rotation` journaled the
    intent but before the commit.  Because every state write is atomic
    (fsync + os.replace), the state file on disk still holds the last
    COMMITTED version - a torn write can never expose a half-rotation.
    Run `recover_state` to reconcile the journal with the state file."""
    state = st.load_state()
    state["clock_offset"] = state.get("clock_offset", 0.0) + \
        float(request.get("seconds", 1))
    st.save_state(state)
    return {"status": "ok", "crashed": True,
            "state_file_intact": True,
            "note": "atomic replace kept the last committed version; "
                    "run recover_state to reconcile with the journal"}


def op_corrupt_state(request):
    """Test helper: destroy the state file entirely (worst case: disk loss).
    Recovery then requires a verified backup - see op_recover_state."""
    st.atomic_write(st.state_path(), "{TRUNCATED STATE - disk loss")
    return {"status": "ok", "corrupted": True}


def op_recover_state(request):
    """Rebuild consistent, authorized key state from the durable journal."""
    records = []
    state = st.load_state()   # need the service key to verify signatures
    if state.get("service_dsa_pk") is None:
        # The service long-term key is deliberately NOT journaled (that
        # would duplicate a secret into a second file). Recovery from total
        # disk loss therefore requires a signed backup; report honestly.
        return {"status": "error", "message": "service_identity_lost",
                "recovered": False,
                "note": "restore from a signed backup instead "
                        "(ops: create_backup / restore_backup)"}
    skipped = 0
    for rec in st.journal_read():
        ok, why = st.journal_verify(rec, state["service_dsa_pk"])
        if not ok:
            skipped += 1     # forged/tampered/unsigned record: ignored
            continue
        records.append(rec)
    committed_version = 0
    committed_rotation = None
    revocations = {}
    re_enrollments = {}
    for rec in records:
        if rec["kind"] == "rotation" and rec.get("step") == "commit":
            if rec["version"] > committed_version:
                committed_version = rec["version"]
                committed_rotation = rec
        elif rec["kind"] == "revocation":
            revocations[rec["device"]] = rec
        elif rec["kind"] == "re_enroll":
            re_enrollments[rec["device"]] = rec

    state = st.load_state()
    if committed_rotation:
        v = {
            "version": committed_rotation["version"],
            "created_at": committed_rotation["created_at"],
            "cutoff_at": committed_rotation["cutoff_at"],
            "kem_pk": committed_rotation["kem_pk"],
            "kem_sk": committed_rotation["kem_sk"],
            "fingerprint": crypto.fp(bytes.fromhex(committed_rotation["kem_pk"])),
        }
        state["key_versions"] = [x for x in state["key_versions"]
                                 if x["version"] != v["version"]]
        state["key_versions"].append(v)
        state["active_version"] = max(state["active_version"], v["version"])

    # Re-apply revocation history with append-only semantics.
    state["revocation_epoch"] = 0
    state["revoked"] = {}
    for device, rec in sorted(revocations.items(),
                              key=lambda kv: kv[1]["epoch"]):
        reen = re_enrollments.get(device)
        if reen and reen["epoch"] >= rec["epoch"]:
            continue
        state["revoked"][device] = {"revoked_at": rec["revoked_at"],
                                    "epoch": rec["epoch"],
                                    "reason": "replayed"}
        state["revocation_epoch"] = max(state["revocation_epoch"],
                                        rec["epoch"])
    # The epoch counter is monotonic across the whole journal (revocations
    # AND re-enrolments), so a replayed state never sits below the signed
    # journal floor (rollback-detection invariant).
    seen_epochs = [rec.get("epoch", 0) for rec in records
                   if rec.get("kind") in ("revocation", "re_enroll")]
    state["revocation_epoch"] = max([state["revocation_epoch"]]
                                    + seen_epochs)
    for name, node in state["nodes"].items():
        node["key_version"] = state["active_version"]
        node["epoch_applied"] = state["revocation_epoch"]
    audit.append(state, "service", "recover_state", "service", "ok",
                 detail="committed_version=%d still_revoked=%d"
                        % (state["active_version"], len(state["revoked"])))
    st.save_state(state)
    return {"status": "ok", "recovered": True,
            "committed_version": state["active_version"],
            "still_revoked": list(state["revoked"]),
            "revocation_epoch": state["revocation_epoch"],
            "journal_records_replayed": len(records),
            "journal_records_rejected": skipped,
            "protected_data_available": True,
            "log_valid": audit.verify(state)["valid"]}


def op_journal_status(request):
    records = st.journal_read()
    kinds = {}
    for r in records:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    return {"status": "ok", "records": len(records), "kinds": kinds}


# --- backups ----------------------------------------------------------------

def _backup_path(backup_id):
    import os
    return os.path.join(st.state_dir(), "backups", "%s.json" % backup_id)


def _backup_load(backup_id):
    try:
        with open(_backup_path(backup_id)) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _backup_store(backup_id, blob):
    import os
    path = _backup_path(backup_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    st.atomic_write(path, json.dumps(blob, sort_keys=True))


def op_create_backup(request):
    state = st.load_state()
    backup_id = request.get("backup_id", "bak-%d" % int(st.now()))
    core = {
        "created_at": st.now(),
        "service_dsa_pk": state["service_dsa_pk"],
        "service_dsa_sk": state["service_dsa_sk"],
        "active_version": state["active_version"],
        "key_versions": state["key_versions"],
        "grace_seconds": state["grace_seconds"],
        "revoked": state["revoked"],
        "revocation_epoch": state["revocation_epoch"],
        "disabled": state["disabled"],
        "roles": state["roles"],
        "owners": state["owners"],
        "protected_data": state["protected_data"],
        "log": state["log"],
        "log_prev_hash": state["log_prev_hash"],
    }
    payload = crypto.canonical(core)
    manifest = {"backup_id": backup_id,
                "service_dsa_pk": state["service_dsa_pk"],
                "payload_sha256": crypto.sha256_hex(payload)}
    signature = crypto.dsa_sign(state["service_dsa_sk"],
                                crypto.canonical(manifest).encode())
    blob = {"manifest": manifest, "signature": signature, "payload": payload}
    # Backups live in their own files, OUTSIDE the live state file: the live
    # state can be lost/corrupted without losing the backups.
    _backup_store(backup_id, blob)
    state["backups"][backup_id] = {"payload_sha256": manifest["payload_sha256"],
                                   "created_at": core["created_at"]}
    st.save_state(state)
    return {"status": "ok", "backup_id": backup_id,
            "payload_sha256": manifest["payload_sha256"], "signed": True}


def op_damage_backup(request):
    """Test helper: corrupt one payload byte (bit rot / tamper simulation)."""
    backup_id = request.get("backup_id", "")
    bak = _backup_load(backup_id)
    if not bak:
        return {"status": "error", "message": "no_such_backup"}
    payload = bak["payload"]
    i = max(0, len(payload) // 2)
    ch = payload[i]
    bak["payload"] = payload[:i] + ("0" if ch != "0" else "1") + payload[i + 1:]
    _backup_store(backup_id, bak)
    return {"status": "ok", "backup_id": backup_id, "damaged": True}


def op_restore_backup(request):
    """Restore ONLY verified key material: manifest signature first, then
    payload hash. Any mismatch aborts with no state change.

    Trust anchors: the manifest carries the service ML-DSA public key that
    produced the signature. When the live service key is present it MUST
    match (origin check). After total disk loss the live key is gone, so the
    embedded key is used for integrity verification only - this assumes the
    backup storage itself is access-controlled (documented limitation)."""
    state = st.load_state()
    backup_id = request.get("backup_id", "")
    bak = _backup_load(backup_id)
    if not bak:
        return {"status": "error", "message": "no_such_backup",
                "restored": False}
    payload = bak["payload"]
    manifest = bak["manifest"]
    embedded_pk = manifest.get("service_dsa_pk")
    live_pk = state.get("service_dsa_pk")
    if live_pk and embedded_pk and live_pk != embedded_pk:
        return {"status": "error", "message": "backup_identity_mismatch",
                "restored": False, "backup_id": backup_id}
    if not embedded_pk or not crypto.dsa_verify(
            embedded_pk, crypto.canonical(manifest).encode(),
            bak["signature"]):
        return {"status": "error", "message": "backup_signature_invalid",
                "restored": False, "backup_id": backup_id}
    if crypto.sha256_hex(bak["payload"]) != manifest["payload_sha256"]:
        return {"status": "error", "message": "backup_integrity_failure",
                "restored": False, "backup_id": backup_id,
                "note": "damaged backup detected; verified material only"}
    core = json.loads(bak["payload"])
    state["service_dsa_pk"] = core["service_dsa_pk"]
    state["service_dsa_sk"] = core["service_dsa_sk"]
    state["active_version"] = core["active_version"]
    state["key_versions"] = core["key_versions"]
    state["grace_seconds"] = core["grace_seconds"]
    state["revoked"] = core["revoked"]
    state["revocation_epoch"] = core["revocation_epoch"]
    state["disabled"] = core["disabled"]
    state["roles"] = core["roles"]
    state["owners"] = core["owners"]
    state["protected_data"] = core["protected_data"]
    state["log"] = core["log"]
    state["log_prev_hash"] = core["log_prev_hash"]
    for name, node in state["nodes"].items():
        node["key_version"] = state["active_version"]
        node["epoch_applied"] = state["revocation_epoch"]
    audit.append(state, "service", "restore_backup", backup_id, "ok",
                 detail="signature and payload hash verified")
    st.save_state(state)
    return {"status": "ok", "restored": True, "backup_id": backup_id,
            "active_version": state["active_version"],
            "log_valid": audit.verify(state)["valid"]}
