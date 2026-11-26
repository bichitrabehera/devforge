#!/usr/bin/env python3
"""Track 4 control-plane registry - a REAL separate process.

Holds authoritative state: current key version (+ grace cutoff), revocation
epochs, policy (owners/roles/disabled), identity registry and its own
ML-DSA-signed, hash-chained audit log. Nodes poll /policy over real HTTP;
propagation delay is the real poll interval (no simulated clock).

Persistence (real disk):
  keyfile.json   service ML-DSA keypair, 0600-equivalent, written once
  state.json     authoritative state, atomic writes
  journal.jsonl  durable append-only record of setup/rotations/revocations
  backups/       ML-DSA-signed backup blobs (outside live state)

Crash model: `kill -9` the process. On restart the registry loads the key
file, then state.json; if the state file is corrupt (torn write), it replays
the journal to rebuild a consistent committed state. Revocations recorded
before the crash stay revoked.

Run:  python3 services/registry_server.py --port 8300
Env:  TRACK4_REGISTRY_DIR (default /tmp/track4_registry)
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import crypto, netutil  # noqa: E402
from src import audit  # noqa: E402

REGISTRY_DIR = os.environ.get("TRACK4_REGISTRY_DIR",
                              "/tmp/track4_registry")


# --- persistence ---------------------------------------------------------------

def _path(name):
    os.makedirs(REGISTRY_DIR, exist_ok=True)
    return os.path.join(REGISTRY_DIR, name)


def _atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _journal_append(state, record):
    with open(_path("journal.jsonl"), "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def _journal_read():
    records = []
    path = _path("journal.jsonl")
    if not os.path.exists(path):
        return records
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _default_state():
    return {
        "key_versions": [],
        "active_version": 0,
        "grace_seconds": 10.0,
        "revocation_epoch": 0,
        "revoked": {},
        "disabled": [],
        "identities": {},     # id -> {device}
        "owners": {},
        "roles": {},
        "protected_data": {},
        "log": [],
        "log_prev_hash": "0" * 64,
        "backups": {},
    }


def _load_or_recover():
    """Load state; if the state file is corrupt, replay the journal."""
    keyfile = _path("keyfile.json")
    if not os.path.exists(keyfile):
        pk, sk = crypto.dsa_keypair()
        _atomic_write(keyfile, json.dumps({"dsa_pk": pk.hex(),
                                           "dsa_sk": sk.hex()}, indent=2))
        os.chmod(keyfile, 0o600)
    with open(keyfile) as f:
        keys = json.load(f)

    state = _default_state()
    try:
        with open(_path("state.json")) as f:
            state = json.load(f)
        recovered = False
    except (OSError, json.JSONDecodeError, ValueError):
        # Torn write / total loss: replay the durable journal.
        for rec in _journal_read():
            _apply_record(state, rec)
        recovered = True
        _atomic_write(_path("state.json"),
                      json.dumps(state, indent=2, sort_keys=True))
    state["service_dsa_pk"] = keys["dsa_pk"]
    state["service_dsa_sk"] = keys["dsa_sk"]
    state["recovered_from_journal"] = recovered
    return state


def _apply_record(state, rec):
    kind = rec.get("kind")
    if kind == "setup":
        state["owners"].update(rec.get("owners", {}))
        state["roles"].update(rec.get("roles", {}))
        for asset, body in (rec.get("contents") or {}).items():
            state["protected_data"][asset] = {
                "owner": state["owners"].get(asset, ""), "body": body}
    elif kind == "rotation" and rec.get("step") == "commit":
        if rec["version"] > state["active_version"]:
            state["key_versions"] = [v for v in state["key_versions"]
                                     if v["version"] != rec["version"]]
            state["key_versions"].append(rec)
            state["active_version"] = rec["version"]
    elif kind == "revocation":
        if rec["epoch"] > state.get("revocation_epoch", 0):
            state["revoked"][rec["device"]] = {
                "revoked_at": rec["revoked_at"], "epoch": rec["epoch"],
                "reason": rec.get("reason", "device_loss")}
            state["revocation_epoch"] = rec["epoch"]
            if rec.get("actor") and rec["actor"] not in state["disabled"]:
                state["disabled"].append(rec["actor"])
    elif kind == "re_enroll":
        state["revoked"].pop(rec["device"], None)
        if rec["epoch"] > state.get("revocation_epoch", 0):
            state["revocation_epoch"] = rec["epoch"]
        if rec.get("actor") and rec["actor"] in state["disabled"]:
            state["disabled"].remove(rec["actor"])


def _save(state):
    snapshot = {k: v for k, v in state.items()
                if k not in ("service_dsa_pk", "service_dsa_sk",
                  "recovered_from_journal")}
    _atomic_write(_path("state.json"),
                  json.dumps(snapshot, indent=2, sort_keys=True))


# --- handlers -------------------------------------------------------------------

def new_key_version(state, grace_seconds=None):
    version = state["active_version"] + 1
    pk, sk = crypto.kem_keypair()
    created = time.time()                     # REAL clock
    grace = state["grace_seconds"] if grace_seconds is None else grace_seconds
    rec = {"kind": "rotation", "step": "commit", "version": version,
           "created_at": created, "cutoff_at": created + grace,
           "kem_pk": pk.hex(), "kem_sk": sk.hex()}
    state["key_versions"] = [v for v in state["key_versions"]
                             if v["version"] != version]
    state["key_versions"].append(rec)
    state["active_version"] = version
    return rec


def h_setup(body, state):
    if state["active_version"] == 0:
        rec = {"kind": "setup", "owners": body.get("owners", {}),
               "roles": body.get("roles", {}),
               "contents": body.get("contents", {})}
        _apply_record(state, rec)
        _journal_append(state, rec)
        v = new_key_version(state, body.get("grace_seconds"))
        _journal_append(state, v)
    audit.append(state, "registry", "setup", "registry", "ok", ts=time.time())
    _save(state)
    return {"status": "ok", "ready": True,
            "active_version": state["active_version"],
            "grace_seconds": state["grace_seconds"]}


def h_rotate(body, state):
    before = state["active_version"]
    rec = new_key_version(state, body.get("grace_seconds"))
    _journal_append(state, rec)               # commit is durable first
    audit.append(state, "registry", "rotate_key", "key", "ok",
                 detail="version=%d from=%d" % (rec["version"], before),
                 ts=time.time())
    _save(state)
    return {"status": "ok", "old_version": before,
            "new_version": rec["version"], "cutoff_at": rec["cutoff_at"],
            "grace_seconds": rec["cutoff_at"] - rec["created_at"],
            "now": time.time()}


def h_keys_current(body, state):
    v = next((x for x in state["key_versions"]
              if x["version"] == state["active_version"]), None)
    if v is None:
        return {"status": "error", "message": "no_keys"}
    return {"status": "ok", "version": v["version"], "cutoff_at": v["cutoff_at"],
            "kem_pk": v["kem_pk"], "grace_seconds": state["grace_seconds"]}


def h_policy(body, state):
    """Everything a node needs to enforce locally (nodes poll this)."""
    v = next((x for x in state["key_versions"]
              if x["version"] == state["active_version"]), None)
    return {"status": "ok",
            "registry_time": time.time(),
            "active_version": state["active_version"],
            "cutoff_at": v["cutoff_at"] if v else None,
            "grace_seconds": state["grace_seconds"],
            "revocation_epoch": state["revocation_epoch"],
            "revoked": state["revoked"],
            "disabled": state["disabled"],
            "owners": state["owners"],
            "roles": state["roles"],
            "identities": state["identities"]}


def h_revoke(body, state):
    device = body.get("device", "")
    actor = body.get("actor", "")
    if not device and actor:
        device = state["identities"].get(actor, {}).get("device", actor)
    if not device:
        return {"status": "error", "message": "missing_device_or_actor"}
    if device not in state["revoked"]:
        state["revocation_epoch"] += 1
        state["revoked"][device] = {"revoked_at": time.time(),
                                    "epoch": state["revocation_epoch"],
                                    "reason": body.get("reason",
                                                       "device_loss")}
        _journal_append(state, {"kind": "revocation", "device": device,
                                "actor": actor,
                                "epoch": state["revocation_epoch"],
                                "revoked_at": state["revoked"][device]["revoked_at"]})
    if actor and actor not in state["disabled"]:
        state["disabled"].append(actor)
    rev = state["revoked"][device]
    audit.append(state, "registry", "revoke", device, "ok",
                 detail="epoch=%d actor=%s" % (rev["epoch"], actor),
                 ts=time.time())
    _save(state)
    return {"status": "ok", "device": device, "actor": actor,
            "epoch": rev["epoch"], "revoked_at": rev["revoked_at"],
            "now": time.time()}


def h_re_enroll(body, state):
    actor = body.get("actor", "")
    device = body.get("device", "") or \
        state["identities"].get(actor, {}).get("device", actor)
    if device in state["revoked"]:
        del state["revoked"][device]
    state["revocation_epoch"] += 1
    if actor in state["disabled"]:
        state["disabled"].remove(actor)
    state["identities"].setdefault(actor, {})["device"] = device
    _journal_append(state, {"kind": "re_enroll", "device": device,
                            "actor": actor,
                            "epoch": state["revocation_epoch"]})
    audit.append(state, "registry", "re_enroll", device, "ok",
                 detail="actor=%s" % actor, ts=time.time())
    _save(state)
    return {"status": "ok", "device": device, "actor": actor,
            "epoch": state["revocation_epoch"]}


def h_register_identity(body, state):
    ident = body.get("identity", "")
    if not ident:
        return {"status": "error", "message": "missing_identity"}
    state["identities"].setdefault(ident, {})["device"] = \
        body.get("device", ident)
    _save(state)
    return {"status": "ok", "identity": ident}


def h_backup(body, state):
    backup_id = body.get("backup_id", "bak-%d" % int(time.time()))
    core = {k: state[k] for k in
            ("active_version", "key_versions", "grace_seconds", "revoked",
             "revocation_epoch", "disabled", "owners", "roles",
             "protected_data", "log", "log_prev_hash")}
    payload = crypto.canonical(core)
    manifest = {"backup_id": backup_id, "service_dsa_pk": state["service_dsa_pk"],
                "payload_sha256": crypto.sha256_hex(payload)}
    blob = {"manifest": manifest,
            "signature": crypto.dsa_sign(state["service_dsa_sk"],
                                         crypto.canonical(manifest).encode()),
            "payload": payload}
    os.makedirs(_path("backups"), exist_ok=True)
    _atomic_write(_path(os.path.join("backups", backup_id + ".json")),
                  json.dumps(blob, sort_keys=True))
    state["backups"][backup_id] = {"payload_sha256":
                                   manifest["payload_sha256"]}
    audit.append(state, "registry", "create_backup", backup_id, "ok",
                 ts=time.time())
    _save(state)
    return {"status": "ok", "backup_id": backup_id, "signed": True,
            "payload_sha256": manifest["payload_sha256"]}


def _backup_load(backup_id):
    try:
        with open(_path(os.path.join("backups", backup_id + ".json"))) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def h_damage(body, state):
    backup_id = body.get("backup_id", "")
    blob = _backup_load(backup_id)
    if not blob:
        return {"status": "error", "message": "no_such_backup"}
    payload = blob["payload"]
    i = max(0, len(payload) // 2)
    blob["payload"] = payload[:i] + \
        ("0" if payload[i] != "0" else "1") + payload[i + 1:]
    _atomic_write(_path(os.path.join("backups", backup_id + ".json")),
                  json.dumps(blob, sort_keys=True))
    return {"status": "ok", "backup_id": backup_id, "damaged": True}


def h_restore(body, state):
    backup_id = body.get("backup_id", "")
    blob = _backup_load(backup_id)
    if not blob:
        return {"status": "error", "message": "no_such_backup",
                "restored": False}
    manifest = blob["manifest"]
    live_pk = state.get("service_dsa_pk")
    if live_pk and manifest.get("service_dsa_pk") != live_pk:
        return {"status": "error", "message": "backup_identity_mismatch",
                "restored": False}
    if not crypto.dsa_verify(manifest["service_dsa_pk"],
                             crypto.canonical(manifest).encode(),
                             blob["signature"]):
        return {"status": "error", "message": "backup_signature_invalid",
                "restored": False}
    if crypto.sha256_hex(blob["payload"]) != manifest["payload_sha256"]:
        return {"status": "error", "message": "backup_integrity_failure",
                "restored": False,
                "note": "damaged backup detected; verified material only"}
    core = json.loads(blob["payload"])
    for k in ("active_version", "key_versions", "grace_seconds", "revoked",
              "revocation_epoch", "disabled", "owners", "roles",
              "protected_data", "log", "log_prev_hash"):
        state[k] = core[k]
    audit.append(state, "registry", "restore_backup", backup_id, "ok",
                 ts=time.time())
    _save(state)
    return {"status": "ok", "restored": True, "backup_id": backup_id,
            "log_valid": audit.verify(state)["valid"]}


def h_verify_log(body, state):
    result = audit.verify(state)
    result["status"] = "ok"
    return result


def h_tamper_log(body, state):
    seq = int(body.get("seq", 1))
    if not 1 <= seq <= len(state["log"]):
        return {"status": "error", "message": "no_such_entry"}
    state["log"][seq - 1][body.get("field", "actor")] = \
        body.get("value", "attacker")
    _save(state)
    return {"status": "ok", "tampered_seq": seq}


def h_log(body, state):
    return {"status": "ok", "log": state["log"]}


def h_data(body, state):
    """Protected contents live at the registry (source of data). Access was
    already authorized by the calling node."""
    asset = body.get("asset", "")
    rec = state["protected_data"].get(asset)
    if rec is None:
        return {"status": "error", "message": "no_such_asset"}
    return {"status": "ok", "asset": asset, "body": rec["body"]}


def h_health(body, state):
    return {"status": "ok", "service": "registry",
            "active_version": state["active_version"],
            "revocation_epoch": state["revocation_epoch"],
            "recovered_from_journal": state.get("recovered_from_journal")}


ROUTES = {
    ("GET", "/health"): h_health,
    ("POST", "/setup"): h_setup,
    ("POST", "/keys/rotate"): h_rotate,
    ("GET", "/keys/current"): h_keys_current,
    ("GET", "/policy"): h_policy,
    ("POST", "/revoke"): h_revoke,
    ("POST", "/re_enroll"): h_re_enroll,
    ("POST", "/identities/register"): h_register_identity,
    ("POST", "/backup"): h_backup,
    ("POST", "/damage_backup"): h_damage,
    ("POST", "/restore_backup"): h_restore,
    ("GET", "/verify_log"): h_verify_log,
    ("POST", "/tamper_log"): h_tamper_log,
    ("GET", "/log"): h_log,
    ("POST", "/data"): h_data,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8300)
    args = ap.parse_args()
    state = _load_or_recover()
    netutil.serve(ROUTES, args.port, state=state)
    print("registry listening on 127.0.0.1:%d" % args.port, flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
