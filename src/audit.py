"""Tamper-evident audit log.

Every entry is a structured JSON object hash-chained to its predecessor and
signed with the service's long-term ML-DSA key:

    entry  = {seq, ts, actor, action, asset, decision, request_id, detail,
              prev_hash, hash, signature}
    digest = SHA-256(canonical(entry without hash/signature))
    hash   = digest
    signature = ML-DSA.sign(service_sk, digest)

Log-injection safety: user-supplied free text is stored ONLY in the "detail"
field as a JSON string value.  The record is serialized with json.dumps of the
whole structure, so text like  "}},"actor":"root""  can never terminate the
record early, forge a second event, or alter the recorded actor/action.
"""

from . import crypto
from . import state as st


def append(state, actor, action, asset, decision, detail="", request_id="",
           ts=None):
    seq = len(state["log"]) + 1
    entry = {
        "seq": seq,
        "ts": st.now() if ts is None else ts,
        "actor": actor,
        "action": action,
        "asset": asset,
        "decision": decision,
        "request_id": request_id,
        "detail": detail,           # free text stays a single JSON string
        "prev_hash": state["log_prev_hash"],
    }
    digest = crypto.sha256_hex(crypto.canonical(entry))
    entry["hash"] = digest
    entry["signature"] = crypto.dsa_sign(state["service_dsa_sk"], digest.encode())
    state["log"].append(entry)
    state["log_prev_hash"] = digest
    return entry


def verify(state):
    """Verify chain links, per-entry hashes and every ML-DSA signature."""
    prev = "0" * 64
    for i, entry in enumerate(state["log"]):
        try:
            core = {k: entry[k] for k in
                    ("seq", "ts", "actor", "action", "asset", "decision",
                     "request_id", "detail", "prev_hash")}
        except KeyError:
            return {"valid": False, "first_bad_seq": entry.get("seq", i + 1),
                    "reason": "malformed_entry"}
        if entry.get("prev_hash") != prev or entry.get("seq") != i + 1:
            return {"valid": False, "first_bad_seq": entry.get("seq", i + 1),
                    "reason": "chain_break"}
        digest = crypto.sha256_hex(crypto.canonical(core))
        if entry.get("hash") != digest:
            return {"valid": False, "first_bad_seq": entry.get("seq", i + 1),
                    "reason": "hash_mismatch"}
        if not crypto.dsa_verify(state["service_dsa_pk"], digest.encode(),
                                 entry.get("signature", "")):
            return {"valid": False, "first_bad_seq": entry.get("seq", i + 1),
                    "reason": "bad_signature"}
        prev = digest
    return {"valid": True, "first_bad_seq": None, "entries": len(state["log"])}
