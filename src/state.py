"""Persistence and the simulated clock.

State lives in one JSON file written atomically (temp file -> fsync ->
os.replace) and carries an integrity manifest: sha256 over the whole state
minus the manifest field itself.  If the file is tampered with on disk,
load_state() flags it and dispatch() refuses every op except the recovery
paths (restore_backup / recover_state / status) until verified material is
restored.

A durable append-only journal (journal.jsonl, fsync per line) records
rotation commits and revocations; every record is signed with the service's
ML-DSA key and signatures are verified during replay, so a forged journal
record cannot inject key material or revocations (see recovery.py).

All timestamps derive from now() = wall clock + clock_offset stored in state,
so cutoffs, grace windows and propagation delays are deterministic and
testable via the "advance_time" op.
"""

import hashlib
import json
import math
import os
import tempfile
import threading
import time

from . import crypto

_LAST_INTEGRITY = {"tampered": False}
STATE_LOCK = threading.RLock()   # serializes read-modify-write ops


def last_integrity_tampered():
    return _LAST_INTEGRITY["tampered"]


def clip(value, limit, marker="\u2026trunc"):
    """Length-cap attacker-controlled text (resource-bounds)."""
    s = value if isinstance(value, str) else canonical(value)
    if len(s) <= limit:
        return s
    return s[:limit] + marker


def journal_floor(pk_hex):
    """(max_committed_version, max_revocation_epoch) over SIGNATURE-VERIFIED
    journal records.

    The journal is append-only and durable while the state file can be
    atomically REPLACED: an attacker (or a stale snapshot) can substitute an
    older-but-valid state.json whose integrity manifest still verifies. The
    signed journal is the floor: a live state whose active version or
    revocation epoch is below the floor is a rollback, not a legitimate
    state.
    """
    if not pk_hex:
        return None
    max_v = max_e = 0
    for rec in journal_read():
        ok, _ = journal_verify(rec, pk_hex)
        if not ok:
            continue
        if rec.get("kind") == "rotation" and rec.get("step") == "commit":
            max_v = max(max_v, rec.get("version", 0))
        elif rec.get("kind") in ("revocation", "re_enroll"):
            max_e = max(max_e, rec.get("epoch", 0))
    return max_v, max_e


_STATE_DIR = None


def set_state_dir(path):
    """Override the state directory (used by tests and the demo script)."""
    global _STATE_DIR
    _STATE_DIR = path


def state_dir():
    global _STATE_DIR
    if _STATE_DIR is None:
        _STATE_DIR = (os.environ.get("TRACK4_STATE_DIR")
                      or os.path.join(tempfile.gettempdir(), "track4_state"))
    os.makedirs(_STATE_DIR, exist_ok=True)
    return _STATE_DIR


def state_path():
    return os.path.join(state_dir(), "state.json")


def journal_path():
    return os.path.join(state_dir(), "journal.jsonl")


def now():
    """Simulated clock (seconds since epoch). Every timestamp uses this."""
    return time.time() + load_state().get("clock_offset", 0.0)


def advance_clock(seconds):
    state = load_state()
    state["clock_offset"] = state.get("clock_offset", 0.0) + float(seconds)
    save_state(state)
    return now()


def atomic_write(path, data):
    """Atomic replace with a UNIQUE temp name per writer: two threads
    saving concurrently must not clobber each other's temp file."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = "%s.tmp.%s" % (path, os.urandom(6).hex())
    with open(tmp, "w") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def journal_append(state, record):
    """Append one SIGNED JSON line to the durable journal and fsync it.

    The signature (ML-DSA, service key) is verified during journal replay,
    so an attacker who can write to the journal cannot inject key material
    or revocations without the service's private key.
    """
    sk = state.get("service_dsa_sk") if isinstance(state, dict) else None
    if sk:
        record = dict(record)
        record["journal_sig"] = crypto.dsa_sign(
            sk, crypto.canonical(record).encode())
    with open(journal_path(), "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def journal_verify(record, pk_hex):
    """Verify a journal record's signature. Returns (ok, reason)."""
    if not pk_hex:
        return False, "no_verification_key"
    if not record.get("journal_sig"):
        return False, "unsigned"
    core = {k: v for k, v in record.items() if k != "journal_sig"}
    ok = crypto.dsa_verify(pk_hex, crypto.canonical(core).encode(),
                           record["journal_sig"])
    return (ok, None) if ok else (False, "bad_journal_signature")


def journal_read():
    """Read all journal records; a torn tail write yields no record."""
    path = journal_path()
    records = []
    if not os.path.exists(path):
        return records
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def default_state():
    return {
        "clock_offset": 0.0,
        "service_dsa_pk": None,       # hex; long-term service signing key
        "service_dsa_sk": None,       # hex
        "key_versions": [],           # [{version, created_at, cutoff_at, kem_pk, kem_sk, fingerprint}]
        "active_version": 0,
        "grace_seconds": 30.0,        # documented old-key grace period
        "nodes": {                    # enforcement points (embedded) /
                                      # mirrored policy (networked)
            "node-a": {"key_version": 0, "epoch_applied": 0, "sync_delay_s": 0.0},
            "node-b": {"key_version": 0, "epoch_applied": 0, "sync_delay_s": 2.0},
            "node-c": {"key_version": 0, "epoch_applied": 0, "sync_delay_s": 4.0},
        },
        "identities": {},             # id -> {kem/dsa hex keys, status, role, device}
        "revoked": {},                # device -> {revoked_at, epoch, reason}
        "revocation_epoch": 0,
        "disabled": [],               # actors denied everywhere
        "admins": ["user-admin"],
        # Public recovery policy: owner -> separate recovery identity, and
        # recovery identity -> ML-DSA PUBLIC key (no private material).
        "recovery_bindings": {},
        "recovery_public_keys": {},
        "roles": {},                  # actor -> role
        "owners": {},                 # asset -> owner actor
        "protected_data": {},         # asset -> {owner, body}
        "sessions": {},               # sid -> session record
        "seen_msg_ids": {},           # recipient -> [msg ids] (replay rejection)
        "inbox": {},                  # recipient -> [delivery failures]
        "decisions": {},              # request_id -> recorded decision
        "key_material_digest": None,  # sha256 of setup key_material
        "log": [],                    # audit entries (hash chain + signed)
        "log_prev_hash": "0" * 64,
        "backups": {},                # backup_id -> signed backup blob
    }


def _state_digest(state):
    core = {k: v for k, v in state.items() if k != "state_hash"}
    return hashlib.sha256(json.dumps(core, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def load_state():
    try:
        with open(state_path(), "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        _LAST_INTEGRITY["tampered"] = False
        return default_state()
    stored = data.pop("state_hash", None)
    # A state file saved by save_state always carries the manifest; its
    # ABSENCE in an existing file means an attacker removed it.
    _LAST_INTEGRITY["tampered"] = (stored is None or
                                   stored != _state_digest(data))
    # Fail-safe against poisoned numeric fields (NaN/Infinity break every
    # cutoff and revocation-enforcement comparison). A non-finite offset is
    # treated as on-disk tampering: quarantine until verified recovery.
    off = data.get("clock_offset", 0.0)
    if not isinstance(off, (int, float)) or not math.isfinite(off):
        data["clock_offset"] = 0.0
        _LAST_INTEGRITY["tampered"] = True
    return data


def save_state(state):
    state["state_hash"] = _state_digest(state)
    atomic_write(state_path(), json.dumps(state, indent=2, sort_keys=True))
