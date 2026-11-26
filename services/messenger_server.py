#!/usr/bin/env python3
"""Track 4 messaging endpoint - a REAL separate process per endpoint.

Holds ALL session material in process memory only (never written to disk):
the ephemeral ML-KEM keypair, the session key, the receive buffer, seen
message ids and delivered plaintexts. A compromise of this process's disk
yields nothing about any session.

Delivery semantics are identical to the embedded engine (same nonce/AAD/
msg_id derivations, imported from src.messaging):
  duplicate msg_id -> reject; stale counter -> reject; gaps within window
  buffered and delivered in order; gaps beyond window reported as failures;
  wrong recipient binding rejected; AEAD failures reported.

Run:  python3 services/messenger_server.py --name recv-blair --port 8320
Env:  TRACK4_MESSENGER_<NAME>_DIR (only used for its log; keys stay in RAM)
"""

import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import crypto, netutil, tokens  # noqa: E402
from src.messaging import CONTEXT, REORDER_WINDOW  # noqa: E402
from src.messaging import (_msg_aad, _msg_id, _nonce_for,  # noqa: E402
    _key_commitment)


class Endpoint:
    """One messaging endpoint. Every field here lives in RAM only."""

    def __init__(self, name, port, identity, peer_identity, idp=None,
                 registry=None):
        self.name = name
        self.port = port
        self.identity = identity
        self.peer = peer_identity
        self.idp = idp          # required for token-authenticated sessions
        self.registry = registry  # optional: enforce registry revocation
        self._jwks_pk = None
        self._pol_cache = (0.0, {"revoked": {}, "disabled": [],
                                 "identities": {}})
        self.session = {
            "sid": None, "eph_pk": None, "eph_sk": None, "key": None,
            "state": "empty", "counter": 0, "next_deliver": 1,
            "buffer": {}, "seen": [], "delivered": [], "failures": [],
            "resumption": None, "peer": None,
        }
        self.audit = []          # in-memory, non-secret events for the demo
        self.lock = threading.Lock()

    def _event(self, action, decision, detail):
        self.audit.append({"ts": time.time(), "action": action,
                           "decision": decision, "detail": detail})

    def _authenticated_payload(self, body):
        """Return (payload, err). Every security decision uses the IdP
        token's subject AND device, never a client-supplied identity field."""
        if self._jwks_pk is None:
            if not self.idp:
                return None, "idp_unconfigured"
            code, jwks = netutil.request(self.idp + "/jwks.json",
                                         timeout=2.0, retries=1)
            self._jwks_pk = jwks["keys"][0]["x"]
        payload, err = tokens.verify(self._jwks_pk, body.get("token", ""))
        if err:
            return None, "token_" + err
        return payload, None

    def _authenticated_sub(self, body):
        payload, err = self._authenticated_payload(body)
        return (payload.get("sub"), None) if payload else (None, err)

    # --- registry revocation enforcement ---------------------------------------

    def _policy(self):
        """Cached registry policy (0.5 s TTL). Without a configured
        registry the endpoint can only authenticate tokens; with one, a
        revoked device or disabled actor is denied here as well."""
        now = time.time()
        ts, pol = self._pol_cache
        if self.registry and now - ts > 0.5:
            try:
                code, pol = netutil.request(self.registry + "/policy",
                                            timeout=2.0, retries=0)
                if code == 200 and pol.get("status") == "ok":
                    self._pol_cache = (now, pol)
            except Exception:
                pass    # fail with the last known snapshot; snapshot ages
        return self._pol_cache[1]

    def _revocation_ok(self, identity, action, token_device=None):
        """(ok, reason): identity must be known, not disabled, its current
        device must be active, and a token device (when supplied) must still
        be the registered one and must not be revoked."""
        pol = self._policy()
        rec = pol.get("identities", {}).get(identity)
        if rec is None:
            self._event(action, "deny", "unknown_identity=%s" % identity)
            return False, "unknown_identity"
        if identity in pol.get("disabled", []):
            self._event(action, "deny", "disabled_actor=%s" % identity)
            return False, "disabled"
        current = rec.get("device", "")
        if current in pol.get("revoked", {}):
            self._event(action, "deny", "revoked_device=%s" % current)
            return False, "revoked"
        if token_device is not None:
            if token_device != current:
                self._event(action, "deny", "stale_device=%s current=%s"
                            % (token_device, current))
                return False, "stale_device"
            if token_device in pol.get("revoked", {}):
                self._event(action, "deny", "revoked_device=%s" % token_device)
                return False, "revoked"
        return True, ""

    def _failure(self, session, reason, msg_id, counter=0):
        """Record a discarded/invalid message as a delivery failure."""
        if len(session["failures"]) < 100:
            session["failures"].append({"msg_id": msg_id, "counter": counter,
                                        "failure": reason})

    # --- session ---------------------------------------------------------------

    def offer(self, body):
        # The claimed sender must be proven with a valid IdP token; the
        # session binds to the token's subject, not to a caller string.
        payload, err = self._authenticated_payload(body)
        if err:
            self._event("session_offer", "deny", "auth=%s" % err)
            return {"status": "error", "message": "unauthorized",
                    "reason": err}
        sender = payload.get("sub", "")
        token_device = payload.get("device", "")
        ok, why = self._revocation_ok(sender, "session_offer", token_device)
        if not ok:
            return {"status": "error", "message": "sender_not_active",
                    "reason": why}
        epk, esk = crypto.kem_keypair()
        with self.lock:
            self.session = dict(self.session, sid=body.get("sid") or
                                os.urandom(16).hex(), eph_pk=epk,
                                eph_sk=esk, state="pending",
                                counter=0, next_deliver=1, buffer={},
                                seen=[], delivered=[], failures=[],
                                peer=sender, token_device=token_device)
        self._event("session_offer", "ok",
                    "fresh ephemeral ML-KEM keypair; sender=%s" % sender)
        return {"status": "ok", "sid": self.session["sid"],
                "encapsulation_key": epk.hex(),
                "recipient": self.identity, "sender": sender}

    def establish(self, body):
        payload, err = self._authenticated_payload(body)
        if err:
            self._event("session_establish", "deny", "auth=%s" % err)
            return {"status": "error", "message": "unauthorized",
                    "reason": err}
        sender = payload.get("sub", "")
        token_device = payload.get("device", "")
        ok, why = self._revocation_ok(sender, "session_establish", token_device)
        if not ok:
            return {"status": "error", "message": "sender_not_active",
                    "reason": why}
        with self.lock:
            s = self.session
            if s["state"] != "pending" or not s["eph_sk"]:
                return {"status": "error", "message": "no_pending_session"}
            if token_device != s.get("token_device"):
                self._event("session_establish", "deny", "device_mismatch")
                return {"status": "error", "message": "device_mismatch"}
            if sender != s["peer"]:
                self._event("session_establish", "deny",
                            "sender_mismatch offer=%s" % s["peer"])
                return {"status": "error", "message": "sender_mismatch"}
            recipient = self.identity
            shared = crypto.kem_decaps(s["eph_sk"],
                                       bytes.fromhex(body["ciphertext"]))
            key = crypto.hkdf(shared, ("track4-session:%s:%s:%s"
                                       % (s["sid"], sender, recipient)).encode())
            s["key"] = key
            s["state"] = "established"
            s["resumption"] = crypto.hkdf(key, b"track4-resumption")
            s["eph_sk"] = None            # zeroize: forward secrecy
        self._event("session_establish", "ok",
                    "key in RAM; ephemeral secret zeroized")
        return {"status": "ok", "sid": self.session["sid"],
                "state": "established", "ephemeral_sk_retained": False}

    # --- delivery ----------------------------------------------------------------

    def receive(self, body):
        with self.lock:
            s = self.session
            if s["state"] != "established" or not s["key"]:
                return {"status": "error", "message": "no_established_session"}
            recipient = body.get("recipient", "")
            sender = body.get("sender", "")
            msg_id = body.get("msg_id", "")
            try:
                counter = int(body.get("counter", 0))
            except (TypeError, ValueError):
                counter = 0
                self._event("message_receive", "deny", "invalid_counter")
                self._failure(s, "invalid_message", msg_id, counter)
                return {"status": "ok", "decision": "reject",
                        "reason": "invalid_message", "msg_id": msg_id}

            def reject(reason):
                self._event("message_receive", "deny",
                            "%s msg=%s" % (reason, msg_id))
                self._failure(s, reason, msg_id, counter)
                return {"status": "ok", "decision": "reject",
                        "reason": reason, "msg_id": msg_id}

            context = body.get("context")
            if context != CONTEXT:
                return reject("context_mismatch")
            try:
                key_version = int(body.get("key_version", -1))
            except (TypeError, ValueError):
                return reject("key_version_invalid")
            pol = self._policy()
            active = pol.get("active_version", 0)
            cutoff = pol.get("cutoff_at")
            in_grace = (key_version == active - 1 and cutoff is not None
                        and time.time() < cutoff)
            if key_version != active and not in_grace:
                return reject("old_key_after_cutoff")
            # the envelope sender must be the session's AUTHENTICATED
            # sender (bound at offer/establish); spoofing is rejected
            if sender != s["peer"]:
                return reject("sender_mismatch")
            if recipient != self.identity:
                return reject("recipient_binding_mismatch")
            if msg_id != _msg_id(s["sid"], counter):
                return reject("msg_id_mismatch")
            ok, why = self._revocation_ok(sender, "message_receive",
                                          s.get("token_device"))
            if not ok:
                return reject("sender_" + why)
            ok, why = self._revocation_ok(self.identity, "message_receive")
            if not ok:
                return reject("recipient_" + why)
            if msg_id in s["seen"]:
                return reject("duplicate_replay")
            if counter < s["next_deliver"]:
                return reject("stale_counter")
            if counter > s["next_deliver"] + REORDER_WINDOW:
                return reject("gap_too_large")
            try:
                key = s["key"]
                aad = _msg_aad(s["sid"], sender, self.identity, counter,
                               msg_id=msg_id, context=context,
                               key_version=key_version,
                               key_commitment=_key_commitment(key.hex()))
                plaintext = crypto.aead_decrypt(
                    key, bytes.fromhex(body["nonce"]),
                    bytes.fromhex(body["ciphertext"]), aad)
            except Exception:
                return reject("authentication_failed")
            if counter > s["next_deliver"]:
                s["buffer"][str(counter)] = {
                    "msg_id": msg_id, "plaintext": plaintext.decode("utf-8")}
                s["seen"].append(msg_id)
                self._event("message_receive", "buffered",
                            "counter=%d waiting for gap fill" % counter)
                return {"status": "ok", "decision": "buffered",
                        "msg_id": msg_id, "counter": counter,
                        "next_deliver": s["next_deliver"]}
            delivered = [{"msg_id": msg_id, "counter": counter,
                          "plaintext": plaintext.decode("utf-8")}]
            s["next_deliver"] = counter + 1
            while str(s["next_deliver"]) in s["buffer"]:
                nxt = s["buffer"].pop(str(s["next_deliver"]))
                nxt["counter"] = s["next_deliver"]
                delivered.append(nxt)
                s["next_deliver"] += 1
            s["seen"].append(msg_id)
            s["delivered"].extend(delivered)
            self._event("message_receive", "allow",
                        "delivered %d message(s)" % len(delivered))
            return {"status": "ok", "decision": "deliver",
                    "messages": delivered, "next_deliver": s["next_deliver"]}

    # --- resumption ----------------------------------------------------------------

    def close(self, body):
        with self.lock:
            s = self.session
            if s["state"] != "established":
                return {"status": "error", "message": "not_established"}
            peer = body.get("peer", s["peer"])
            import hashlib
            token = hashlib.sha256(
                (s["resumption"] or b"") + peer.encode()).hexdigest() \
                if s["resumption"] else ""
            s["state"] = "closed"
            s["key"] = None             # zeroized in RAM
            s["buffer"] = {}
        self._event("session_close", "ok", "key zeroized")
        return {"status": "ok", "sid": s["sid"], "key_zeroized": True,
                "resumption_token": token}

    def resume(self, body):
        import hashlib
        with self.lock:
            s = self.session
            if s["state"] not in ("established", "closed") or not s["resumption"]:
                return {"status": "error", "message": "no_resumable_session"}
            peer = body.get("peer", "")
            # A lost device must not resume with a captured resumption
            # token: the resuming party must ALSO present a CURRENT IdP
            # token whose device matches the identity's REGISTERED
            # device. After a device loss + rebind the old token names a
            # device that is no longer registered -> rejected.
            payload, err = self._authenticated_payload(body)
            if err:
                self._event("session_resume", "deny", "auth=%s" % err)
                return {"status": "ok", "decision": "reject",
                        "reason": "token_" + err, "peer": peer}
            sub = payload.get("sub", "")
            if sub != peer:
                self._event("session_resume", "deny",
                            "resume_sub_mismatch sub=%s" % sub)
                return {"status": "ok", "decision": "reject",
                        "reason": "resume_sub_mismatch", "peer": peer}
            pol = self._policy()
            cur_device = (pol.get("identities", {}).get(peer) or {}).get(
                "device", "")
            token_device = payload.get("device", "")
            if cur_device and token_device != cur_device:
                self._event("session_resume", "deny",
                            "stale_device peer=%s" % peer)
                return {"status": "ok", "decision": "reject",
                        "reason": "stale_device", "peer": peer}
            ok, why = self._revocation_ok(peer, "session_resume", token_device)
            if not ok:
                return {"status": "ok", "decision": "reject",
                        "reason": "peer_" + why, "peer": peer}
            expected = hashlib.sha256(s["resumption"] + peer.encode()) \
                .hexdigest()
            if expected != body.get("resumption_token", ""):
                self._event("session_resume", "deny",
                            "peer_not_bound_to_session peer=%s" % peer)
                return {"status": "ok", "decision": "reject",
                        "reason": "peer_not_bound_to_session", "peer": peer}
            key = crypto.hkdf(s["resumption"], b"track4-resume:1")
            s["key"] = key
            s["state"] = "established"
            s["counter"] = 0
            s["next_deliver"] = 1
            s["buffer"] = {}
            s["resumption"] = crypto.hkdf(key, b"track4-resumption")
            token = hashlib.sha256(s["resumption"] + peer.encode()) \
                .hexdigest()
        self._event("session_resume", "allow", "ratcheted; bound to %s"
                    % peer)
        return {"status": "ok", "decision": "allow", "peer": peer,
                "ratchet": 1, "next_resumption_token": token}

    # --- inspection ------------------------------------------------------------------

    def messages(self, body):
        with self.lock:
            return {"status": "ok", "delivered": self.session["delivered"],
                    "failures": self.session["failures"],
                    "next_deliver": self.session["next_deliver"]}

    def session_status(self, body):
        with self.lock:
            s = self.session
            return {"status": "ok", "sid": s["sid"], "state": s["state"],
                    "ephemeral_sk_present": s["eph_sk"] is not None,
                    "key_in_ram": s["key"] is not None,
                    "keys_persisted_to_disk": False,
                    "seen": len(s["seen"])}

    def audit(self, body):
        return {"status": "ok", "audit": self.audit}


def build_routes(ep):
    import threading
    _lock = threading.RLock()   # serialize session state mutations

    def _locked(fn):
        def wrapper(body):
            with _lock:
                return fn(body)
        return wrapper

    return {
        ("GET", "/health"): lambda body: {"status": "ok", "endpoint": ep.name,
                                          "identity": ep.identity},
        ("POST", "/session/offer"): _locked(ep.offer),
        ("POST", "/session/establish"): _locked(ep.establish),
        ("POST", "/message/receive"): _locked(ep.receive),
        ("POST", "/session/close"): _locked(ep.close),
        ("POST", "/session/resume"): _locked(ep.resume),
        ("GET", "/messages"): ep.messages,
        ("GET", "/session/status"): ep.session_status,
        ("GET", "/audit"): ep.audit,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--identity", required=True)
    ap.add_argument("--peer", required=True)
    ap.add_argument("--idp", default=None,
                    help="IdP base URL; required for token-authenticated "
                         "sessions")
    ap.add_argument("--registry", default=None,
                    help="registry base URL; enables device-revocation "
                         "enforcement at the messaging endpoint")
    args = ap.parse_args()
    ep = Endpoint(args.name, args.port, args.identity, args.peer,
                  idp=args.idp, registry=args.registry)
    netutil.serve(build_routes(ep), args.port)
    print("endpoint %s (%s) listening on 127.0.0.1:%d"
          % (args.name, args.identity, args.port), flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
