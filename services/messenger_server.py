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

from src import crypto, netutil  # noqa: E402
from src.messaging import REORDER_WINDOW, _msg_aad, _msg_id, _nonce_for  # noqa: E402


class Endpoint:
    """One messaging endpoint. Every field here lives in RAM only."""

    def __init__(self, name, port, identity, peer_identity):
        self.name = name
        self.port = port
        self.identity = identity
        self.peer = peer_identity
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

    # --- session ---------------------------------------------------------------

    def offer(self, body):
        epk, esk = crypto.kem_keypair()
        with self.lock:
            self.session = dict(self.session, sid=body.get("sid") or
                                os.urandom(16).hex(), eph_pk=epk,
                                eph_sk=esk, state="pending",
                                counter=0, next_deliver=1, buffer={},
                                seen=[], delivered=[], failures=[],
                                peer=body.get("sender", self.peer))
        self._event("session_offer", "ok", "fresh ephemeral ML-KEM keypair")
        return {"status": "ok", "sid": self.session["sid"],
                "encapsulation_key": epk.hex(),
                "recipient": self.identity, "sender": self.session["peer"]}

    def establish(self, body):
        with self.lock:
            s = self.session
            if s["state"] != "pending" or not s["eph_sk"]:
                return {"status": "error", "message": "no_pending_session"}
            sender = body.get("sender", s["peer"])
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
            counter = int(body.get("counter", 0))
            if recipient != self.identity:
                self._event("message_receive", "deny",
                            "recipient_binding_mismatch msg=%s" % msg_id)
                return {"status": "ok", "decision": "reject",
                        "reason": "recipient_binding_mismatch",
                        "msg_id": msg_id}
            if msg_id in s["seen"]:
                self._event("message_receive", "deny",
                            "duplicate msg=%s" % msg_id)
                return {"status": "ok", "decision": "reject",
                        "reason": "duplicate_replay", "msg_id": msg_id}
            if counter < s["next_deliver"]:
                self._event("message_receive", "deny",
                            "stale counter=%d" % counter)
                return {"status": "ok", "decision": "reject",
                        "reason": "stale_counter", "msg_id": msg_id}
            if counter > s["next_deliver"] + REORDER_WINDOW:
                s["failures"].append({"msg_id": msg_id,
                                      "failure": "gap_too_large",
                                      "counter": counter})
                return {"status": "ok", "decision": "reject",
                        "reason": "gap_too_large", "msg_id": msg_id}
            try:
                key = s["key"]
                aad = _msg_aad(s["sid"], sender, self.identity, counter)
                plaintext = crypto.aead_decrypt(
                    key, bytes.fromhex(body["nonce"]),
                    bytes.fromhex(body["ciphertext"]), aad)
            except Exception:
                self._event("message_receive", "deny",
                            "authentication_failed msg=%s" % msg_id)
                return {"status": "ok", "decision": "reject",
                        "reason": "authentication_failed", "msg_id": msg_id}
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
    return {
        ("GET", "/health"): lambda body: {"status": "ok", "endpoint": ep.name,
                                          "identity": ep.identity},
        ("POST", "/session/offer"): ep.offer,
        ("POST", "/session/establish"): ep.establish,
        ("POST", "/message/receive"): ep.receive,
        ("POST", "/session/close"): ep.close,
        ("POST", "/session/resume"): ep.resume,
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
    args = ap.parse_args()
    ep = Endpoint(args.name, args.port, args.identity, args.peer)
    netutil.serve(build_routes(ep), args.port)
    print("endpoint %s (%s) listening on 127.0.0.1:%d"
          % (args.name, args.identity, args.port), flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
