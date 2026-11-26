"""End-to-end encrypted messaging between identities.

Session establishment (forward secrecy)
---------------------------------------
The recipient opens a session and generates a FRESH EPHEMERAL ML-KEM-768
keypair.  The sender encapsulates against the ephemeral public key; the
session key is HKDF(shared_secret, sid | sender | recipient).  Immediately
after decapsulation/derivation the ephemeral SECRET is deleted and the
session key is zeroized at close.  Consequently, later exposure of the
parties' long-term keys does not reveal earlier completed sessions: the
ephemeral secret needed to recover the session key no longer exists.

Message protection
------------------
AES-256-GCM with:
  * nonce  = HKDF(session_key, "track4-nonce:<counter>")  - unique per message
  * AAD    = canonical({sid, sender, recipient, counter}) - recipient binding
  * msg_id = SHA-256(sid | counter)[:24]                  - replay detection

Delivery semantics
------------------
* duplicate msg_id            -> reject "duplicate_replay"
* stale counter               -> reject "stale_counter"
* gap within window (8)       -> buffer; deliver in counter order when the
                                 hole fills (loss + reordering tolerated)
* gap beyond window           -> reject "gap_too_large" (delivery failure)
* wrong AAD / bad tag         -> reject "authentication_failed"
* AAD recipient != receiver   -> reject "recipient_binding_mismatch"

Resumption
----------
At close (or on demand) the legitimate peer receives
resumption_token = HMAC-SHA256(resumption_secret, peer_id).  Resume requires
a token valid for the CURRENT secret; each resume ratchets the key
(HKDF over the previous resumption secret) and rotates the secret, so a
different identity presenting the same sid cannot inherit the session.
"""

import hashlib
import hmac
import os

from . import audit, crypto
from . import state as st

REORDER_WINDOW = 8      # documented loss/reordering tolerance


MAX_SESSIONS = 256       # DoS bound: capped concurrent session records
MAX_SEEN = 1000          # DoS bound: replay-detection memory per recipient
MAX_FAILURES = 100       # DoS bound: reported delivery failures


def _device_ok(state, actor):
    """A participant must be an active identity whose device is not
    revoked (revocation applies to messaging too, not just access)."""
    ident = state["identities"].get(actor)
    if ident is None or actor in state["disabled"]:
        return False
    return ident.get("device", actor) not in state["revoked"]


def _remember(seen, msg_id):
    seen.append(msg_id)
    if len(seen) > MAX_SEEN:
        del seen[:len(seen) - MAX_SEEN]


def _nonce_for(session_key, counter):
    return crypto.hkdf(session_key, b"track4-nonce:" + str(counter).encode(), 12)


def _msg_aad(sid, sender, recipient, counter):
    return crypto.canonical({"sid": sid, "sender": sender,
                             "recipient": recipient,
                             "counter": counter}).encode()


def _msg_id(sid, counter):
    return hashlib.sha256(crypto.canonical(
        {"sid": sid, "counter": counter}).encode()).hexdigest()[:24]


def _resumption_token(secret_hex, peer):
    return hmac.new(bytes.fromhex(secret_hex), peer.encode(),
                    hashlib.sha256).hexdigest()


# --- ops --------------------------------------------------------------------

def op_session_open(request):
    """Recipient side: fresh ephemeral KEM keypair for this session only."""
    state = st.load_state()
    recipient = request.get("recipient", "")
    sender = request.get("sender", "")
    if recipient not in state["identities"]:
        return {"status": "error", "message": "unknown_recipient"}
    if not _device_ok(state, sender):
        return {"status": "error", "message": "sender_not_active",
                "reason": "revoked_or_disabled"}
    if not _device_ok(state, recipient):
        return {"status": "error", "message": "recipient_not_active",
                "reason": "revoked_or_disabled"}
    # Prune closed sessions, then enforce the session cap (DoS bound).
    state["sessions"] = {sid: s for sid, s in state["sessions"].items()
                         if s["state"] != "closed"}
    if len(state["sessions"]) >= MAX_SESSIONS:
        return {"status": "error", "message": "too_many_sessions",
                "cap": MAX_SESSIONS}
    epk, esk = crypto.kem_keypair()
    sid = os.urandom(16).hex()
    state["sessions"][sid] = {
        "sender": sender, "recipient": recipient, "state": "pending",
        "counter": 0, "created_at": st.now(),
        "ephemeral_pk": epk.hex(), "ephemeral_sk": esk.hex(),
        "key": None, "buffer": {}, "next_deliver": 1,
        "resumption_secret": None, "resume_count": 0,
    }
    audit.append(state, sender, "session_open", sid, "ok",
                 detail="ephemeral KEM offered to %s" % recipient)
    st.save_state(state)
    return {"status": "ok", "sid": sid,
            "encapsulation_key": epk.hex(),   # public material only
            "recipient": recipient, "sender": sender}


def op_session_accept(request):
    """Sender encapsulates; session key derived; ephemeral secret zeroized."""
    state = st.load_state()
    sid = request.get("sid", "")
    session = state["sessions"].get(sid)
    if not session or session["state"] != "pending":
        return {"status": "error", "message": "no_pending_session"}
    sender = request.get("sender", session["sender"])
    recipient = session["recipient"]
    if not _device_ok(state, sender) or not _device_ok(state, recipient):
        return {"status": "error", "message": "participant_not_active",
                "reason": "revoked_or_disabled"}
    ciphertext, shared_secret = crypto.kem_encaps(
        bytes.fromhex(session["ephemeral_pk"]))
    session_key = crypto.hkdf(
        shared_secret,
        ("track4-session:%s:%s:%s" % (sid, sender, recipient)).encode())
    session["key"] = session_key.hex()
    session["sender"] = sender
    session["state"] = "established"
    # Zeroize the ephemeral secret: forward secrecy for this session.
    session["ephemeral_sk"] = None
    session["resumption_secret"] = crypto.hkdf(
        session_key, b"track4-resumption").hex()
    audit.append(state, sender, "session_accept", sid, "ok",
                 detail="key established; ephemeral secret zeroized")
    st.save_state(state)
    return {"status": "ok", "sid": sid, "state": "established",
            "ciphertext": ciphertext.hex(),
            "ephemeral_sk_retained": False,
            "sender": sender, "recipient": recipient}


def op_message_send(request):
    state = st.load_state()
    sid = request.get("sid", "")
    session = state["sessions"].get(sid)
    if not session or session["state"] != "established":
        return {"status": "error", "message": "no_established_session"}
    sender = request.get("sender", session["sender"])
    recipient = request.get("recipient", session["recipient"])
    if sender != session["sender"] or recipient != session["recipient"]:
        return {"status": "error", "message": "endpoint_mismatch"}
    # Revocation applies to live messaging sessions too: a revoked device
    # or disabled actor cannot keep sending.
    if not _device_ok(state, sender):
        audit.append(state, sender, "message_send", sid, "deny",
                     detail="sender_revoked_or_disabled")
        st.save_state(state)
        return {"status": "ok", "decision": "deny",
                "reason": "sender_revoked_or_disabled", "sid": sid}
    if not _device_ok(state, recipient):
        audit.append(state, sender, "message_send", sid, "deny",
                     detail="recipient_revoked_or_disabled")
        st.save_state(state)
        return {"status": "ok", "decision": "deny",
                "reason": "recipient_revoked_or_disabled", "sid": sid}
    counter = session["counter"] + 1
    plaintext = request.get("plaintext", "").encode("utf-8")
    key = bytes.fromhex(session["key"])
    nonce = _nonce_for(key, counter)
    aad = _msg_aad(sid, sender, recipient, counter)
    ct = crypto.aead_encrypt(key, nonce, plaintext, aad)
    session["counter"] = counter
    msg_id = _msg_id(sid, counter)
    audit.append(state, sender, "message_send", sid, "ok",
                 detail="msg_id=%s counter=%d bytes=%d"
                        % (msg_id, counter, len(plaintext)))
    st.save_state(state)
    return {"status": "ok", "msg_id": msg_id, "counter": counter,
            "nonce": nonce.hex(), "ciphertext": ct.hex(), "sid": sid,
            "sender": sender, "recipient": recipient}


def op_message_receive(request):
    """Authenticated, replay-safe, order-tolerant delivery."""
    state = st.load_state()
    sid = request.get("sid", "")
    session = state["sessions"].get(sid)
    if not session or session["state"] != "established":
        return {"status": "error", "message": "no_established_session"}
    recipient = request.get("recipient", "")
    sender = request.get("sender", "")
    msg_id = request.get("msg_id", "")
    counter = int(request.get("counter", 0))
    try:
        key = bytes.fromhex(session["key"])
        nonce = bytes.fromhex(request["nonce"])
        ct = bytes.fromhex(request["ciphertext"])
    except KeyError:
        return {"status": "error", "message": "missing_fields"}
    except ValueError:
        return {"status": "error", "message": "bad_hex"}

    # msg_id is DERIVED metadata: sha256(sid|counter)[:24]. The envelope's
    # sid and counter are inside the AEAD, so a caller-supplied msg_id that
    # disagrees with the derived value is tampered metadata - reject it.
    # The duplicate-replay set is keyed by the DERIVED id, so renaming a
    # replayed envelope cannot bypass duplicate detection.
    derived_id = _msg_id(sid, counter)
    if msg_id != derived_id:
        audit.append(state, recipient or "unknown", "message_receive",
                     sid, "deny", detail="msg_id_mismatch msg=%s" % msg_id)
        st.save_state(state)
        return {"status": "ok", "decision": "reject",
                "reason": "msg_id_mismatch", "msg_id": msg_id}
    msg_id = derived_id

    # Recipient binding: the authenticated AAD must name the receiver.
    if recipient != session["recipient"]:
        audit.append(state, recipient or "unknown", "message_receive", sid,
                     "deny", detail="recipient_binding_mismatch msg=%s" % msg_id)
        st.save_state(state)
        return {"status": "ok", "decision": "reject",
                "reason": "recipient_binding_mismatch", "msg_id": msg_id}
    # A revoked/disabled recipient cannot read (revocation is global).
    if not _device_ok(state, session["recipient"]):
        audit.append(state, session["recipient"], "message_receive", sid,
                     "deny", detail="recipient_revoked_or_disabled")
        st.save_state(state)
        return {"status": "ok", "decision": "reject",
                "reason": "recipient_revoked_or_disabled", "msg_id": msg_id}

    seen = state["seen_msg_ids"].setdefault(session["recipient"], [])
    if msg_id in seen:
        audit.append(state, session["recipient"], "message_receive", sid,
                     "deny", detail="duplicate msg=%s" % msg_id)
        st.save_state(state)
        return {"status": "ok", "decision": "reject",
                "reason": "duplicate_replay", "msg_id": msg_id}
    if counter < session["next_deliver"]:
        audit.append(state, session["recipient"], "message_receive", sid,
                     "deny", detail="stale counter=%d msg=%s"
                                    % (counter, msg_id))
        st.save_state(state)
        return {"status": "ok", "decision": "reject",
                "reason": "stale_counter", "msg_id": msg_id}
    if counter > session["next_deliver"] + REORDER_WINDOW:
        failures = state["inbox"].setdefault(session["recipient"], [])
        if len(failures) < MAX_FAILURES:
            failures.append({"msg_id": msg_id,
                             "failure": "gap_too_large", "counter": counter})
        st.save_state(state)
        return {"status": "ok", "decision": "reject", "reason": "gap_too_large",
                "msg_id": msg_id,
                "note": "delivery failure reported; window=%d" % REORDER_WINDOW}

    try:
        aad = _msg_aad(sid, sender, session["recipient"], counter)
        plaintext = crypto.aead_decrypt(key, nonce, ct, aad)
    except Exception:
        audit.append(state, sender or "unknown", "message_receive", sid,
                     "deny", detail="authentication_failed msg=%s" % msg_id)
        st.save_state(state)
        return {"status": "ok", "decision": "reject",
                "reason": "authentication_failed", "msg_id": msg_id}

    # Buffer while a hole precedes this counter (loss / reordering).
    if counter > session["next_deliver"]:
        session["buffer"][str(counter)] = {
            "msg_id": msg_id, "plaintext": plaintext.decode("utf-8")}
        _remember(seen, msg_id)
        st.save_state(state)
        return {"status": "ok", "decision": "buffered", "msg_id": msg_id,
                "counter": counter,
                "next_deliver": session["next_deliver"],
                "note": "gap before this counter; buffered for in-order delivery"}

    delivered = [{"msg_id": msg_id, "counter": counter,
                  "plaintext": plaintext.decode("utf-8")}]
    session["next_deliver"] = counter + 1
    while str(session["next_deliver"]) in session["buffer"]:
        nxt = session["buffer"].pop(str(session["next_deliver"]))
        nxt["counter"] = session["next_deliver"]
        delivered.append(nxt)
        session["next_deliver"] += 1
    _remember(seen, msg_id)
    audit.append(state, session["recipient"], "message_receive", sid, "allow",
                 detail="delivered msg=%s counter=%d" % (msg_id, counter))
    st.save_state(state)
    return {"status": "ok", "decision": "deliver", "messages": delivered,
            "next_deliver": session["next_deliver"]}


def op_inbox_drain(request):
    state = st.load_state()
    recipient = request.get("recipient", "")
    items = state["inbox"].get(recipient, [])
    state["inbox"][recipient] = []
    st.save_state(state)
    return {"status": "ok", "recipient": recipient, "failures": items}


def op_session_resume(request):
    """Resume bound to the authenticated peer; key is ratcheted."""
    state = st.load_state()
    sid = request.get("sid", "")
    session = state["sessions"].get(sid)
    if not session or session["state"] not in ("established", "closed"):
        return {"status": "error", "message": "no_resumable_session"}
    peer = request.get("peer", "")
    token = request.get("resumption_token", "")
    secret_hex = session.get("resumption_secret") or ""
    if not secret_hex:
        return {"status": "error", "message": "no_resumption_secret"}
    expected = _resumption_token(secret_hex, peer)
    if not hmac.compare_digest(expected, token):
        audit.append(state, peer or "unknown", "session_resume", sid, "deny",
                     detail="identity_not_bound_to_session")
        st.save_state(state)
        return {"status": "ok", "decision": "reject",
                "reason": "peer_not_bound_to_session", "sid": sid,
                "peer": peer}
    if not _device_ok(state, peer):
        audit.append(state, peer, "session_resume", sid, "deny",
                     detail="peer_revoked_or_disabled")
        st.save_state(state)
        return {"status": "ok", "decision": "reject",
                "reason": "peer_revoked_or_disabled", "sid": sid,
                "peer": peer}
    ratchet = int(session.get("resume_count", 0)) + 1
    new_key = crypto.hkdf(bytes.fromhex(secret_hex),
                          ("track4-resume:%s:%d" % (sid, ratchet)).encode())
    session["key"] = new_key.hex()
    session["resume_count"] = ratchet
    session["counter"] = 0
    session["next_deliver"] = 1
    session["buffer"] = {}
    session["state"] = "established"
    session["resumption_secret"] = crypto.hkdf(
        new_key, b"track4-resumption").hex()
    audit.append(state, peer, "session_resume", sid, "ok",
                 detail="ratchet=%d; key replaced" % ratchet)
    st.save_state(state)
    return {"status": "ok", "decision": "allow", "sid": sid, "peer": peer,
            "ratchet": ratchet,
            "next_resumption_token":
                _resumption_token(session["resumption_secret"], peer),
            "key_replaced": True}


def op_session_close(request):
    state = st.load_state()
    sid = request.get("sid", "")
    session = state["sessions"].get(sid)
    if not session:
        return {"status": "error", "message": "no_such_session"}
    peer = request.get("peer", session["recipient"])
    token = ""
    if session.get("resumption_secret"):
        token = _resumption_token(session["resumption_secret"], peer)
    session["state"] = "closed"
    session["key"] = None            # zeroize session key
    session["buffer"] = {}
    audit.append(state, peer, "session_close", sid, "ok",
                 detail="key zeroized; resumption token issued to %s" % peer)
    st.save_state(state)
    return {"status": "ok", "sid": sid, "state": "closed",
            "key_zeroized": True, "peer": peer, "resumption_token": token}
