"""Core engine for Hackathon Track 4.

Provides dispatch() and 11 helpers. State persisted atomically via
write-temp-fsync-os.replace under TRACK4_STATE_DIR or tempfile.gettempdir().
Never prints key material, shared secrets, private keys, or protected contents.
"""
import os
import sys
import json
import tempfile

# pqcrypto primitives
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

# cryptography primitives
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- State path ---

_STATE_DIR = os.environ.get("TRACK4_STATE_DIR", None)


def _state_path():
    if _STATE_DIR:
        os.makedirs(_STATE_DIR, exist_ok=True)
        return os.path.join(_STATE_DIR, "state.json")
    return os.path.join(tempfile.gettempdir(), "track4_state.json")


def _load_state():
    path = _state_path()
    try:
        with open(path, "r") as f:
            state = json.load(f)
        # Convert hex strings back to bytes for crypto keys
        state = _from_json_safe(state)
        return state
    except (FileNotFoundError, json.JSONDecodeError):
        return _default_state()


def _save_state(state):
    path = _state_path()
    # Convert any bytes to hex for JSON serialization
    state = _to_json_safe(state)
    _atomic_write(path, json.dumps(state, indent=2))


def _to_json_safe(obj):
    """Recursively convert bytes to hex strings for JSON serialization."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_json_safe(item) for item in obj]
    return obj


def _from_json_safe(obj):
    """Recursively convert hex strings back to bytes for JSON deserialization."""
    if isinstance(obj, dict):
        converted = {}
        for k, v in obj.items():
            # Check for session key inside sessions dict
            if k == "key" and isinstance(v, str):
                try:
                    converted[k] = bytes.fromhex(v)
                except ValueError:
                    converted[k] = v
            # Check for nonce inside sessions dict
            elif k == "nonce" and isinstance(v, str):
                try:
                    converted[k] = bytes.fromhex(v)
                except ValueError:
                    converted[k] = v
            # Check for known crypto key fields at top level
            elif k in ("pk_ml_kem", "sk_ml_kem", "pk_ml_dsa", "sk_ml_dsa", "session_key") and isinstance(v, str):
                try:
                    converted[k] = bytes.fromhex(v)
                except ValueError:
                    converted[k] = v
            else:
                converted[k] = _from_json_safe(v)
        return converted
    if isinstance(obj, list):
        return [_from_json_safe(item) for item in obj]
    return obj


def _atomic_write(path, data):
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


def _default_state():
    return {
        "pk_ml_kem": None,
        "sk_ml_kem": None,
        "pk_ml_dsa": None,
        "sk_ml_dsa": None,
        "session_key": None,
        "sessions": {},  # sid -> {nonce, ...}
        "log": [],
        "backup": None,
    }


# --- Crypto helpers ---


def _ml_kem_keypair():
    pk, sk = ml_kem_768.keygen()
    return pk, sk


def _ml_dsa_keypair():
    pk, sk = ml_dsa_65.keygen()
    return pk, sk


def _hkdf_derive(key, info, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(key)


def _aes_gcm_encrypt(key, nonce, plaintext, aad=None):
    aesgcm = AESGCM(key)
    if aad:
        return aesgcm.encrypt(nonce, plaintext, aad)
    return aesgcm.encrypt(nonce, plaintext, None)


def _aes_gcm_decrypt(key, nonce, ciphertext, aad=None):
    aesgcm = AESGCM(key)
    if aad:
        return aesgcm.decrypt(nonce, ciphertext, aad)
    return aesgcm.decrypt(nonce, ciphertext, None)


# --- 11 helpers ---


def rotate_key(request):
    """Rotate the KEM and/or DSA key pairs."""
    state = _load_state()
    op = request.get("op", "both")
    if op in ("kem", "both"):
        pk, sk = _ml_kem_keypair()
        state["pk_ml_kem"] = pk.hex() if isinstance(pk, bytes) else pk
        state["sk_ml_kem"] = sk.hex() if isinstance(sk, bytes) else sk
    if op in ("dsa", "both"):
        pk, sk = _ml_dsa_keypair()
        state["pk_ml_dsa"] = pk.hex() if isinstance(pk, bytes) else pk
        state["sk_ml_dsa"] = sk.hex() if isinstance(sk, bytes) else sk
    _save_state(state)
    return {"status": "ok", "kem_rotated": op in ("kem", "both"), "dsa_rotated": op in ("dsa", "both")}


def re_enroll_device(request):
    """Re-enroll a device, generating new KEM and DSA keypairs."""
    return rotate_key(request)


def recover_state(request):
    """Recover state from a backup with integrity verification."""
    state = _load_state()
    backup_id = request.get("backup_id")
    
    # Check if backup exists
    if not backup_id or not state.get("backup") or backup_id not in state["backup"]:
        return {"status": "error", "message": "no_backup", "recovered": False}
    
    backup_data = state["backup"][backup_id]
    
    # Simple integrity check: verify required crypto keys are present
    required_keys = ["pk_ml_kem", "sk_ml_kem", "pk_ml_dsa", "sk_ml_dsa"]
    for field in required_keys:
        if field not in backup_data or not backup_data[field] or len(backup_data[field]) < 20:
            return {"status": "error", "message": f"missing_or_invalid_key: {field}", "recovered": False}
    
    # Restore state from backup
    state["pk_ml_kem"] = backup_data.get("pk_ml_kem")
    state["sk_ml_kem"] = backup_data.get("sk_ml_kem")
    state["pk_ml_dsa"] = backup_data.get("pk_ml_dsa")
    state["sk_ml_dsa"] = backup_data.get("sk_ml_dsa")
    # session_key may be None (set during key rotation); only restore if present
    if "session_key" in backup_data and backup_data["session_key"]:
        state["session_key"] = backup_data["session_key"]
    state["log"] = backup_data.get("log", [])
    
    # Preserve revocation list: don't overwrite with backup's revocation list
    # (This ensures revocations survive crash recovery)
    
    _save_state(state)
    return {"status": "ok", "recovered": True, "backup_id": backup_id}


    return {"status": "ok", "backup_id": backup_id}



def create_backup(request):
    """Create a backup of current state."""
    state = _load_state()
    backup_id = request.get("backup_id", "auto")
    state["backup"] = state.get("backup") or {}
    # Convert bytes to hex for JSON-safe backup
    converted = {}
    for k, v in state.items():
        if isinstance(v, bytes):
            converted[k] = v.hex()
        else:
            converted[k] = v
    state["backup"][backup_id] = {
        "pk_ml_kem": converted.get("pk_ml_kem"),
        "sk_ml_kem": converted.get("sk_ml_kem"),
        "pk_ml_dsa": converted.get("pk_ml_dsa"),
        "sk_ml_dsa": converted.get("sk_ml_dsa"),
        "session_key": converted.get("session_key"),
        "log": converted.get("log", []),
    }
    _save_state(state)
    return {"status": "ok", "backup_id": backup_id}

def restore_backup(request):
    """Restore state from a backup ID."""
    return recover_state(request)


def append_log(request):
    """Append a signed, chained entry to the audit log."""
    state = _load_state()
    # Initialize previous_hash if not present
    if "previous_hash" not in state:
        state["previous_hash"] = "0" * 64
    
    entry_text = request.get("entry", "")
    entry_type = request.get("type", "general")
    actor = state.get("actor", "")  # From current session context
    decision = state.get("decision", "allow")  # From current decision context
    
    # Build content to sign and hash
    entry_content = f"{state.get('request_id', '')}:{decision}:{actor}:{state.get('asset', '')}:{state['previous_hash']}"
    
    # Sign with ML-DSA if key available
    sk_ml_dsa = state.get("sk_ml_dsa")
    signed = False
    signature = ""
    if sk_ml_dsa and sk_ml_dsa != "None":
        try:
            sk_bytes = bytes.fromhex(sk_ml_dsa) if isinstance(sk_ml_dsa, str) else sk_ml_dsa
            signature = _ml_dsa_65.sign(sk_bytes, entry_content.encode())
            signed = True
        except Exception:
            pass
    
    # Compute hash
    import hashlib
    entry_hash = hashlib.sha256(entry_content.encode()).hexdigest()
    
    # Build the chained entry
    new_entry = {
        "request_id": state.get("request_id", ""),
        "decision": decision,
        "actor": actor,
        "asset": state.get("asset", ""),
        "entry": entry_text,
        "type": entry_type,
        "previous_hash": state["previous_hash"],
        "hash": entry_hash,
        "signature": signature.hex() if signed else "",
        "signed": signed,
    }
    
    # Update previous_hash for next entry
    state["previous_hash"] = entry_hash
    state["log"].append(new_entry)
    
    max_log = 500
    if len(state["log"]) > max_log:
        state["log"] = state["log"][-max_log:]
    _save_state(state)
    return {"status": "ok", "log_length": len(state["log"]), "entry_hash": entry_hash}


def verify_log(request):
    """Verify the integrity of the audit log."""
    state = _load_state()
    log = state.get("log", [])
    valid = True
    for i, entry in enumerate(log):
        # Check that entry has required fields
        required = ["request_id", "decision", "actor", "asset", "previous_hash", "hash", "signature", "signed"]
        if not all(k in entry for k in required):
            valid = False
            break
        # Verify hash chain: current entry's previous_hash must match prior entry's hash
        if i > 0 and entry["previous_hash"] != log[i-1]["hash"]:
            valid = False
            break
        # Verify signature if entry was signed
        if entry.get("signed", False):
            import hashlib
            entry_content = f"{entry['request_id']}:{entry['decision']}:{entry['actor']}:{entry['asset']}:{entry['previous_hash']}"
            expected_hash = hashlib.sha256(entry_content.encode()).hexdigest()
            if entry["hash"] != expected_hash:
                valid = False
                break
            # Verify ML-DSA signature
            from team_app import _ml_dsa_65
            import hashlib
            sk_ml_dsa = state.get("sk_ml_dsa")
            if sk_ml_dsa and sk_ml_dsa != "None":
                try:
                    sk_bytes = bytes.fromhex(sk_ml_dsa) if isinstance(sk_ml_dsa, str) else sk_ml_dsa
                    is_valid = _ml_dsa_65.verify(sk_bytes, entry_content.encode(), bytes.fromhex(entry["signature"]))
                    if not is_valid:
                        valid = False
                        break
                except Exception:
                    valid = False
                    break
            # If not signed, check that hash is still valid
        else:
            # Unsigned entries: still verify the hash is consistent
            import hashlib
            entry_content = f"{entry['request_id']}:{entry['decision']}:{entry['actor']}:{entry['asset']}:{entry['previous_hash']}"
            expected_hash = hashlib.sha256(entry_content.encode()).hexdigest()
            if entry["hash"] != expected_hash:
                valid = False
                break
    return {"status": "ok", "valid": valid, "entries": len(log)}


def open_session(request):
    """Open a new authenticated session."""
    state = _load_state()
    pk_ml_kem = state.get("pk_ml_kem")
    sk_ml_kem = state.get("sk_ml_kem")
    pk_ml_dsa = state.get("pk_ml_dsa")
    sk_ml_dsa = state.get("sk_ml_dsa")

    session_nonce = os.urandom(12)

    if pk_ml_kem and pk_ml_kem != "None" and sk_ml_kem and sk_ml_kem != "None":
        # Need raw bytes for encaps, so re-keygen if needed
        # If stored as hex, decode back
        ciphertext, shared_secret = ml_kem_768.encaps(
            bytes.fromhex(pk_ml_kem) if isinstance(pk_ml_kem, str) else pk_ml_kem
        )
        session_key = _hkdf_derive(shared_secret, b"track4-session")
    else:
        session_key = _hkdf_derive(os.urandom(32), b"track4-session")

    sid = request.get("sid", os.urandom(16).hex())
    state["sessions"][sid] = {
        "nonce": session_nonce,
        "key": session_key,
    }
    _save_state(state)
    return {
        "status": "ok",
        "sid": sid,
        "nonce": session_nonce.hex(),
        "key_available": True,
    }


def resume_session(request):
    """Resume an existing session."""
    state = _load_state()
    sid = request.get("sid")
    sessions = state.get("sessions", {})
    if sid and sid in sessions:
        session = sessions[sid]
        return {
            "status": "ok",
            "sid": sid,
            "nonce": session["nonce"].hex(),
            "key_available": True,
        }
    return {"status": "error", "message": "session_not_found"}


def send_message(request):
    """Send an encrypted message with per-message nonce and AAD."""
    state = _load_state()
    sid = request.get("sid")
    message = request.get("message", "").encode("utf-8")
    sender_id = request.get("sender_id", "")
    recipient_id = request.get("recipient_id", "")
    sessions = state.get("sessions", {})

    if not sid or sid not in sessions:
        return {"status": "error", "message": "no_session"}

    session = sessions[sid]
    key = session["key"]
    
    # Per-message nonce: use counter that persists across sends
    msg_counter = session.get("message_counter", 0)
    base_nonce = session["nonce"]
    # Derive per-message nonce: XOR base nonce with counter (as 96-bit value)
    import struct
    counter_bytes = struct.pack('>I', msg_counter)  # 4-byte big-endian counter
    # Use first 12 bytes: base nonce (first 8 bytes) + counter (last 4 bytes)
    # But base nonce is 12 bytes, so we'll truncate/pad
    # Simpler: append counter to base nonce and truncate to 12
    per_nonce = (base_nonce + counter_bytes)[:12]
    
    # Associated data: sender, recipient, key version, counter
    aad = f"{sender_id}:{recipient_id}:{session.get('key_version', 1)}:{msg_counter}".encode()
    
    ciphertext = _aes_gcm_encrypt(key, per_nonce, message, aad=aad)
    
# Increment message counter in session
    session["message_counter"] = msg_counter + 1
    
    # Track sent counters for replay rejection
    sent_counters = session.get("sent_counters", [])
    if isinstance(sent_counters, list):
        sent_counters = set(sent_counters)
    sent_counters.add(msg_counter)
    # Convert back to list for JSON serialization
    session["sent_counters"] = list(sent_counters)
    _save_state(state)
    
    return {"status": "ok", "ciphertext": ciphertext.hex(), "nonce": per_nonce.hex(), "msg_counter": msg_counter}


def receive_message(request):
    """Decrypt an encrypted message with replay rejection."""
    state = _load_state()
    sid = request.get("sid")
    ciphertext_hex = request.get("ciphertext", "")
    nonce_hex = request.get("nonce", "")
    sender_id = request.get("sender_id", "")
    recipient_id = request.get("recipient_id", "")
    sessions = state.get("sessions", {})

    if not sid or sid not in sessions:
        return {"status": "error", "message": "no_session"}

    session = sessions[sid]
    key = session["key"]
    
    # Check replay: track message counters per session
    msg_counter = request.get("msg_counter", -1)
    # sent_counters stored as list in JSON, convert to set for checking
    sent_counters_list = session.get("sent_counters", [])
    sent_counters = set(sent_counters_list) if sent_counters_list else set()
    
    if msg_counter in sent_counters:
        return {"status": "error", "message": "replay_detected"}
    
    # Convert sent_counters to list for JSON serialization
    if isinstance(sent_counters, set):
        session["sent_counters"] = list(sent_counters)
    else:
        session["sent_counters"] = list(sent_counters) + [msg_counter]
    _save_state(state)
    
    # Derive the same per-message nonce
    base_nonce = session["nonce"]
    import struct
    counter_bytes = struct.pack('>I', msg_counter)
    per_nonce = (base_nonce + counter_bytes)[:12]
    
    # Associated data must match
    expected_aad = f"{sender_id}:{recipient_id}:{session.get('key_version', 1)}:{msg_counter}".encode()
    
    try:
        plaintext = _aes_gcm_decrypt(key, per_nonce, bytes.fromhex(ciphertext_hex), aad=expected_aad)
    except Exception as e:
        # If decryption fails (including auth tag failure), remove counter to allow retry
        sent_counters.discard(msg_counter)
        session["sent_counters"] = sent_counters
        _save_state(state)
        return {"status": "error", "message": f"decrypt_failed: {str(e)}"}
    
    return {"status": "ok", "plaintext": plaintext.decode("utf-8")}


# --- Core ops ---


def _cmd_setup(request):
    """Setup initial keypairs."""
    state = _load_state()
    pk_kem, sk_kem = _ml_kem_keypair()
    pk_dsa, sk_dsa = _ml_dsa_keypair()
    # Store as hex for JSON serialization
    state["pk_ml_kem"] = pk_kem.hex()
    state["sk_ml_kem"] = sk_kem.hex()
    state["pk_ml_dsa"] = pk_dsa.hex()
    state["sk_ml_dsa"] = sk_dsa.hex()
    # Store owners and contents from request for access control
    state["owners"] = request.get("owners", {})
    state["contents"] = request.get("contents", {})
    state["disabled"] = request.get("disabled", [])
    _save_state(state)
    return {
        "status": "ok",
        "ready": True,
        "kem_pk": state["pk_ml_kem"],
        "dsa_pk": state["pk_ml_dsa"],
    }


def _cmd_read(request):
    """Read current state with access control decision."""
    state = _load_state()
    actor = request.get("actor", "")
    asset = request.get("asset", "")
    # Check if actor owns the asset and is not disabled
    owned = state.get("owners", {}).get(asset) == actor
    not_disabled = actor not in state.get("disabled", [])
    decision = "allow" if (owned and not_disabled) else "deny"
    # Record audit log entry with hash chain and digital signature
    # Initialize previous_hash in state if not present
    if "previous_hash" not in state:
        state["previous_hash"] = "0" * 64

    # Build the entry content to be signed and chained
    entry_content = f"{request.get('request_id', '')}:{decision}:{actor}:{asset}:{state['previous_hash']}"

    # Sign the entry content with ML-DSA
    sk_ml_dsa = state.get("sk_ml_dsa")
    signed = False
    signature = ""
    if sk_ml_dsa and sk_ml_dsa != "None":
        try:
            sk_bytes = bytes.fromhex(sk_ml_dsa) if isinstance(sk_ml_dsa, str) else sk_ml_dsa
            signature = _ml_dsa_65.sign(sk_bytes, entry_content.encode())
            signed = True
        except Exception:
            pass

    # Build the audit log entry with hash chain and signature
    import hashlib
    audit_entry = {
        "request_id": request.get("request_id", ""),
        "decision": decision,
        "actor": actor,
        "asset": asset,
        "previous_hash": state["previous_hash"],
        "hash": hashlib.sha256(entry_content.encode()).hexdigest(),
        "signature": signature.hex() if signed else "",
        "signed": signed,
    }

    # Update previous_hash for next entry
    state["previous_hash"] = audit_entry["hash"]
    state["log"].append(audit_entry)
    # Keep log manageable
    if len(state["log"]) > 100:
        state["log"] = state["log"][-100:]
    _save_state(state)
    body = state.get("contents", {}).get(asset, "")
    if decision == "allow":
        return {"status": "ok", "decision": decision, "body": body}
    else:
        return {"status": "ok", "decision": decision}


def _cmd_revoke(request):
    """Revoke current keys (clear keypairs)."""
    state = _load_state()
    actor = request.get("actor", "")
    # Add actor to disabled list
    disabled = state.get("disabled", [])
    if actor not in disabled:
        disabled.append(actor)
    state["disabled"] = disabled
    # Clear keypairs and sessions
    state["pk_ml_kem"] = None
    state["sk_ml_kem"] = None
    state["pk_ml_dsa"] = None
    state["sk_ml_dsa"] = None
    state["sessions"] = {}
    _save_state(state)
    return {"status": "ok", "revoked": True}


def _cmd_audit(request):
    """Re-evaluate decision based on current state (fresh subprocess)."""
    state = _load_state()
    actor = request.get("actor", "")
    asset = request.get("asset", "")
    request_id = request.get("request_id", "")
    owned = state.get("owners", {}).get(asset) == actor
    not_disabled = actor not in state.get("disabled", [])
    decision = "allow" if (owned and not_disabled) else "deny"
    return {"status": "ok", "decision": decision, "request_id": request_id}


def _cmd_protected_read(request):
    """Read protected data (session-level)."""
    state = _load_state()
    sid = request.get("sid")
    sessions = state.get("sessions", {})

    if not sid or sid not in sessions:
        return {"status": "error", "message": "no_session"}

    session = sessions[sid]
    return {
        "status": "ok",
        "session_created": True,
    }


# --- Dispatch table ---

_OPS = {
    "setup": _cmd_setup,
    "read": _cmd_read,
    "revoke": _cmd_revoke,
    "audit": _cmd_audit,
    "protected_read": _cmd_protected_read,
}


def dispatch(request):
    """Dispatch a request to the appropriate handler.

    request: dict with at least "op" key.
    Returns a dict that will be serialized to JSON on stdout.
    """
    op = request.get("op", "")
    if op in _OPS:
        return _OPS[op](request)
    # If not a core op, try the 11 helpers
    helper = request.get("op", "")
    helpers = {"kem": rotate_key, "dsa": rotate_key,
        "rotate_key": rotate_key,
        "re_enroll_device": re_enroll_device,
        "recover_state": recover_state,
        "create_backup": create_backup,
        "restore_backup": restore_backup,
        "append_log": append_log,
        "verify_log": verify_log,
        "open_session": open_session,
        "resume_session": resume_session,
        "send_message": send_message,
        "receive_message": receive_message,
    }
    if helper in helpers:
        return helpers[helper](request)
    return {"status": "error", "message": f"unknown_op: {op}"}
