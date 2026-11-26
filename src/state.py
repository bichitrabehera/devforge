"""Persistence and the simulated clock.

State lives in one JSON file written atomically (temp file -> fsync ->
os.replace).  A durable append-only journal (journal.jsonl, fsync per line)
records rotation commits and revocations so that an interrupted rotation can
be replayed to the last commit marker (see recovery.py).

All timestamps derive from now() = wall clock + clock_offset stored in state,
so cutoffs, grace windows and propagation delays are deterministic and
testable via the "advance_time" op.
"""

import json
import os
import tempfile
import time

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
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def journal_append(record):
    """Append one JSON line to the durable journal and fsync it."""
    with open(journal_path(), "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


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
        "nodes": {                    # simulated enforcement points
            "node-a": {"key_version": 0, "epoch_applied": 0, "sync_delay_s": 0.0},
            "node-b": {"key_version": 0, "epoch_applied": 0, "sync_delay_s": 2.0},
        },
        "identities": {},             # id -> {kem/dsa hex keys, status, role, device}
        "revoked": {},                # device -> {revoked_at, epoch, reason}
        "revocation_epoch": 0,
        "disabled": [],               # actors denied everywhere
        "admins": ["user-admin"],
        "roles": {},                  # actor -> role
        "owners": {},                 # asset -> owner actor
        "protected_data": {},         # asset -> {owner, body}
        "sessions": {},               # sid -> session record
        "seen_msg_ids": {},           # recipient -> [msg ids] (replay rejection)
        "inbox": {},                  # recipient -> [delivery failures]
        "log": [],                    # audit entries (hash chain + signed)
        "log_prev_hash": "0" * 64,
        "backups": {},                # backup_id -> signed backup blob
    }


def load_state():
    try:
        with open(state_path(), "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default_state()


def save_state(state):
    atomic_write(state_path(), json.dumps(state, indent=2, sort_keys=True))
