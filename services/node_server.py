#!/usr/bin/env python3
"""Track 4 enforcement node - a REAL separate process per node.

Each node:
  * polls the registry's /policy over real HTTP every `--poll-interval`
    seconds; propagation of key versions and revocations is therefore REAL
    network eventual consistency (measured, not simulated);
  * verifies identity tokens against the IdP's /jwks.json with the REAL
    clock (expiry is real);
  * enforces locally: key-version cutoff with grace, revoked devices,
    disabled actors, owners/roles from the last policy snapshot;
  * keeps its own ML-DSA-signed, hash-chained audit log persisted to its
    own directory (verifiable independently).

Run:  python3 services/node_server.py --name node-a --port 8310 \
          --registry http://127.0.0.1:8300 --idp http://127.0.0.1:8400 \
          --poll-interval 0.5
Env:  TRACK4_NODE_<NAME>_DIR or --state-dir
"""

import argparse
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import audit, crypto, netutil, tokens  # noqa: E402
from src.messaging import CONTEXT, _msg_aad, _key_commitment  # noqa: E402


class Node:
    def __init__(self, name, port, registry, idp, poll_interval, state_dir,
                 gossip_next=None, relay_next=None, deliver_to=None):
        self.name = name
        self.port = port
        self.registry = registry
        self.idp = idp
        self.poll_interval = poll_interval
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        # node's own long-term signing key (separate from registry and IdP)
        self.keyfile = os.path.join(state_dir, "node_key.json")
        if not os.path.exists(self.keyfile):
            pk, sk = crypto.dsa_keypair()
            with open(self.keyfile + ".tmp", "w") as f:
                json.dump({"dsa_pk": pk.hex(), "dsa_sk": sk.hex()}, f)
            os.replace(self.keyfile + ".tmp", self.keyfile)
            os.chmod(self.keyfile, 0o600)
        with open(self.keyfile) as f:
            k = json.load(f)
        self.dsa_pk = k["dsa_pk"]
        self.dsa_sk = k["dsa_sk"]
        # local persisted audit log (hash chain rebuilt from disk)
        self.logfile = os.path.join(state_dir, "node_log.json")
        try:
            with open(self.logfile) as f:
                self.log_state = json.load(f)
        except (OSError, json.JSONDecodeError):
            self.log_state = {"log": [], "log_prev_hash": "0" * 64}
        # names align with src.audit expectations
        self.log_state["service_dsa_pk"] = self.dsa_pk
        self.log_state["service_dsa_sk"] = self.dsa_sk
        # in-memory enforcement snapshot (never a source of authority)
        self.policy = {"active_version": 0, "cutoff_at": None,
                       "grace_seconds": 0.0, "revocation_epoch": 0,
                       "revoked": {}, "disabled": [], "owners": {},
                       "roles": {}, "identities": {}}
        self.last_poll = None
        self.last_poll_error = None
        self.enforcement_log = []   # measured real propagation times
        self.jwks = None
        self.lock = threading.Lock()
        self.relay_next = relay_next     # next node's /message/send (relay)
        self.deliver_to = deliver_to     # final recipient's messaging inbox
        self.gossip_next = gossip_next   # peer node's messaging inbox URL
        self._gossiped = None            # (epoch, version) already announced
        self.gossip_log = []             # sent gossip results (for status)
        self._poll_once()

    # --- registry polling (real eventual consistency) ------------------------

    def _poll_once(self):
        try:
            code, policy = netutil.request(self.registry + "/policy",
                                           timeout=2.0, retries=0)
            if code != 200 or policy.get("status") != "ok":
                self.last_poll_error = "registry_error"
                return
            with self.lock:
                prev_epoch = self.policy["revocation_epoch"]
                prev_version = self.policy["active_version"]
                self.policy = policy
                self.last_poll = time.time()
                self.last_poll_error = None
                now = self.last_poll
                for device, rev in policy["revoked"].items():
                    if rev["epoch"] > prev_epoch:
                        self.enforcement_log.append(
                            {"device": device, "epoch": rev["epoch"],
                             "revoked_at": rev["revoked_at"],
                             "enforced_at": now,
                             "propagation_s": round(now - rev["revoked_at"], 3)})
            # Node-to-node gossip: when the applied policy changes, this
            # node PROCESS sends an encrypted, authenticated policy-ack
            # to the next node's messaging endpoint using the same E2E
            # machinery as user messaging (PoP token, ephemeral ML-KEM
            # session, AEAD bound to sid/sender/recipient/counter).
            marker = (policy["revocation_epoch"], policy["active_version"])
            if self.gossip_next and marker != self._gossiped:
                decision = self._gossip_send(policy)
                if decision == "deliver":
                    self._gossiped = marker   # announced; failures retry
                self.gossip_log.append({"epoch": marker[0],
                                        "key_version": marker[1],
                                        "decision": decision,
                                        "ts": now})
        except Exception as exc:
            self.last_poll_error = type(exc).__name__

    def poll_loop(self):
        while True:
            time.sleep(self.poll_interval)
            self._poll_once()

    # --- relayed messaging (policy-checked hops between nodes) ---------------

    def send_message(self, body):
        """One policy-checked relay hop for end-to-end encrypted messages.

        The node NEVER sees plaintext: it verifies the sender's token,
        enforces identity, device state, revocation, key-version (with
        the same grace window as /authenticate) and recipient
        permission/revocation from its current policy snapshot, then
        forwards the opaque envelope to the next hop. The final hop
        delivers to the recipient's messaging endpoint, which enforces
        AEAD binding and replay protection."""
        route = []

        def _deny(reason, actor="unknown"):
            self._log(actor, "send", body.get("recipient", ""), "deny",
                      detail=reason)
            route.append({"node": self.name, "decision": "deny",
                          "reason": reason})
            return {"status": "ok", "decision": "deny", "reason": reason,
                    "route": route, "node": self.name,
                    "delivered": False}

        payload, err = self._verify_token(body.get("token", ""))
        if err:
            return _deny("token_rejected:" + err)
        actor = payload["sub"]
        device = payload.get("device", "")
        recipient = body.get("recipient", "")
        try:
            version = int(body.get("key_version", 0))
        except (TypeError, ValueError):
            return _deny("bad_key_version", actor)
        with self.lock:
            policy = dict(self.policy)
        now = time.time()    # REAL clock against the registry's real cutoff
        # 1. identity known  2. device state  3. disabled actor
        if actor not in policy["identities"]:
            return _deny("unknown_identity", actor)
        if device in policy["revoked"]:
            return _deny("revoked", actor)
        if actor in policy["disabled"]:
            return _deny("disabled", actor)
        # 4. key version: current, or previous version inside the grace window
        if version != policy["active_version"]:
            in_grace = version == policy["active_version"] - 1 and \
                policy["cutoff_at"] is not None and now < policy["cutoff_at"]
            if not in_grace:
                return _deny("old_key_after_cutoff", actor)
        # 5. permission: recipient must be a known identity; the recipient's
        #    device revocation is enforced at the FINAL node below
        if recipient not in policy["identities"]:
            return _deny("recipient_not_active", actor)
        # Recipient-device revocation is enforced at the FINAL node (below),
        # which is the recipient's access-control point; every hop still
        # enforces sender identity/device/key/permission/revocation.
        self._log(actor, "send", recipient, "allow",
                  detail="relay key_version=%d" % version)
        route.append({"node": self.name, "decision": "allow",
                      "actor": actor, "recipient": recipient,
                      "checks": ["token", "identity", "device",
                                 "revocation", "key_version",
                                 "permission"]})
        envelope = {k: body.get(k) for k in
                    ("sid", "sender", "recipient", "counter", "nonce",
                     "ciphertext", "msg_id", "key_version", "context")}
        if self.deliver_to:
            # recipient node: re-check the sender AND the recipient against
            # its latest policy snapshot before allowing delivery.
            rec_device = (policy["identities"].get(recipient) or {}).get(
                "device", "")
            if rec_device in policy["revoked"] or recipient in policy["disabled"]:
                return _deny("recipient_revoked", actor)
            # final hop: hand the envelope to the recipient's messaging
            # endpoint (recipient binding + replay protection live there)
            try:
                code, resp = netutil.request(
                    self.deliver_to + "/message/receive", envelope,
                    method="POST", timeout=3.0, retries=0)
            except Exception:
                return _deny("endpoint_unreachable", actor)
            decision = resp.get("decision", "error")
            route.append({"node": self.name + "/messaging-endpoint",
                          "decision": decision,
                          "reason": resp.get("reason", "")})
            return {"status": "ok", "decision": decision,
                    "reason": resp.get("reason", ""),
                    "delivered_messages": resp.get("messages", []),
                    "route": route, "node": self.name,
                    "delivered": decision == "deliver"}
        if not self.relay_next:
            return _deny("no_next_hop", actor)
        try:
            code, resp = netutil.request(
                self.relay_next + "/message/send", body,
                method="POST", timeout=3.0, retries=0)
        except Exception:
            return _deny("next_hop_unreachable", actor)
        if resp.get("status") != "ok":
            return _deny("relay_error", actor)
        resp["route"] = route + resp.get("route", [])
        return resp

    # --- node-to-node gossip (real messaging between node processes) ----------

    def _gossip_send(self, policy):
        """Send an encrypted, authenticated policy-ack from THIS node
        process to the next node's messaging endpoint. Same E2E machinery
        as user messaging: this node proves possession of its registered
        key (PoP token), opens a fresh ephemeral ML-KEM session, and the
        AEAD is bound to sid/sender/recipient/counter. Gossip failure
        must never break enforcement, so every error is contained."""
        try:
            proof = tokens.device_proof(self.dsa_sk, self.name, self.name)
            proof["ttl_s"] = 60.0
            code, tok = netutil.request(self.idp + "/token", proof,
                                        method="POST", timeout=3.0)
            token = tok["token"]
            code, offer = netutil.request(
                self.gossip_next + "/session/offer",
                {"sender": self.name, "token": token},
                method="POST", timeout=3.0)
            if offer.get("status") != "ok":
                return "offer_rejected"
            sid = offer["sid"]
            peer = offer.get("recipient", "")
            ct, ss = crypto.kem_encaps(
                bytes.fromhex(offer["encapsulation_key"]))
            code, est = netutil.request(
                self.gossip_next + "/session/establish",
                {"sid": sid, "ciphertext": ct.hex(), "sender": self.name,
                 "token": token}, method="POST", timeout=3.0)
            if est.get("status") != "ok":
                return "establish_rejected"
            plaintext = json.dumps(
                {"type": "policy_ack", "node": self.name,
                 "epoch": policy["revocation_epoch"],
                 "key_version": policy["active_version"],
                 "ts": round(time.time(), 3)}).encode()
            key = crypto.hkdf(ss, ("track4-session:%s:%s:%s"
                                   % (sid, self.name, peer)).encode())
            nonce = crypto.hkdf(key, b"track4-nonce:1", 12)
            key_version = policy["active_version"]
            msg_id = crypto.sha256_hex(crypto.canonical(
                {"sid": sid, "counter": 1}).encode())[:24]
            aad = _msg_aad(sid, self.name, peer, 1, msg_id=msg_id,
                           context=CONTEXT, key_version=key_version,
                           key_commitment=_key_commitment(key.hex()))
            env = {"sid": sid, "sender": self.name, "recipient": peer,
                   "counter": 1, "nonce": nonce.hex(),
                   "ciphertext": crypto.aead_encrypt(key, nonce, plaintext,
                                                     aad).hex(),
                   "msg_id": msg_id, "context": CONTEXT,
                   "key_version": key_version}
            code, rec = netutil.request(
                self.gossip_next + "/message/receive", env,
                method="POST", timeout=3.0)
            return rec.get("decision", "error")
        except Exception:
            return "gossip_error"

    # --- local persistence ----------------------------------------------------

    def _persist_log(self):
        tmp = self.logfile + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.log_state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.logfile)

    def _log(self, actor, action, asset, decision, detail=""):
        audit.append(self.log_state, actor, action, asset, decision,
                     detail=detail, ts=time.time())   # REAL clock
        self._persist_log()

    # --- request handling ------------------------------------------------------

    def _verify_token(self, token):
        if self.jwks is None:
            code, jwks = netutil.request(self.idp + "/jwks.json",
                                         timeout=2.0, retries=1)
            self.jwks = jwks["keys"][0]["x"]
        payload, err = tokens.verify(self.jwks, token)   # REAL clock expiry
        return payload, err

    def read(self, body):
        payload, err = self._verify_token(body.get("token", ""))
        if err:
            self._log("unknown", "read", body.get("asset", ""), "deny",
                      detail="token_rejected:%s" % err)
            return {"status": "ok", "decision": "deny",
                    "reason": err, "node": self.name}
        actor = payload["sub"]
        device = payload.get("device", "")
        asset = body.get("asset", "")
        with self.lock:
            policy = dict(self.policy)
        if device in policy["revoked"]:
            self._log(actor, "read", asset, "deny", detail="revoked_device")
            return {"status": "ok", "decision": "deny",
                    "reason": "revoked", "node": self.name}
        if actor in policy["disabled"]:
            self._log(actor, "read", asset, "deny", detail="disabled_actor")
            return {"status": "ok", "decision": "deny",
                    "reason": "disabled", "node": self.name}
        owner = policy["owners"].get(asset)
        role = policy["roles"].get(actor)
        allowed = owner == actor or \
            (role == "report-reader" and asset.startswith("reports"))
        reasons = ["owner"] if owner == actor else \
            (["role:%s" % role] if allowed else
             ["not_owner:%s" % owner, "role:%s" % (role or "none")])
        self._log(actor, "read", asset, "allow" if allowed else "deny",
                  detail=";".join(reasons))
        resp = {"status": "ok", "decision": "allow" if allowed else "deny",
                "reasons": reasons, "node": self.name, "actor": actor,
                "request_id": body.get("request_id", "")}
        if allowed:
            rec = None
            code, reg = netutil.request(self.registry + "/policy",
                                        timeout=2.0, retries=0)
            # protected contents live at the registry (source of data)
            code, data = netutil.request(self.registry + "/data",
                                         {"asset": asset}, method="POST",
                                         timeout=2.0, retries=0)
            if code == 200 and data.get("status") == "ok":
                resp["body"] = data["body"]
        return resp

    def authenticate(self, body):
        payload, err = self._verify_token(body.get("token", ""))
        if err:
            self._log("unknown", "authenticate", "key", "deny",
                      detail="token_rejected:%s" % err)
            return {"status": "ok", "decision": "deny", "reason": err,
                    "node": self.name}
        actor = payload["sub"]
        device = payload.get("device", "")
        version = int(body.get("key_version", 0))
        with self.lock:
            policy = dict(self.policy)
        now = time.time()    # REAL clock against the registry's real cutoff
        if version != policy["active_version"]:
            in_grace = version == policy["active_version"] - 1 and \
                policy["cutoff_at"] is not None and now < policy["cutoff_at"]
            if not in_grace:
                self._log(actor, "authenticate", "key", "deny",
                          detail="old_key_after_cutoff version=%d" % version)
                return {"status": "ok", "decision": "deny",
                        "reason": "old_key_after_cutoff", "node": self.name,
                        "key_version": version, "now": now,
                        "cutoff_at": policy["cutoff_at"]}
            outcome = "grace"
        else:
            outcome = "current"
        if device in policy["revoked"]:
            self._log(actor, "authenticate", "key", "deny",
                      detail="revoked_device")
            return {"status": "ok", "decision": "deny", "reason": "revoked",
                    "node": self.name}
        if actor in policy["disabled"]:
            self._log(actor, "authenticate", "key", "deny",
                      detail="disabled_actor")
            return {"status": "ok", "decision": "deny", "reason": "disabled",
                    "node": self.name}
        self._log(actor, "authenticate", "key", "allow",
                  detail="version=%d outcome=%s" % (version, outcome))
        return {"status": "ok", "decision": "allow", "node": self.name,
                "key_version": version, "outcome": outcome}

    def audit_op(self, body):
        r = self.read(dict(body, _audit=True))
        return r

    def status(self, body):
        with self.lock:
            return {"status": "ok", "node": self.name,
                    "applied_version": self.policy["active_version"],
                    "applied_epoch": self.policy["revocation_epoch"],
                    "last_poll": self.last_poll,
                    "last_poll_error": self.last_poll_error,
                    "poll_interval": self.poll_interval,
                    "enforcement_log": self.enforcement_log,
                    "gossip_log": self.gossip_log,
                    "log_entries": len(self.log_state["log"])}

    def verify_log(self, body):
        result = audit.verify(self.log_state)
        result["status"] = "ok"
        result["node"] = self.name
        return result

    def tamper(self, body):
        seq = int(body.get("seq", 1))
        if not 1 <= seq <= len(self.log_state["log"]):
            return {"status": "error", "message": "no_such_entry"}
        self.log_state["log"][seq - 1][body.get("field", "actor")] = \
            body.get("value", "attacker")
        self._persist_log()
        return {"status": "ok", "tampered_seq": seq}


def build_routes(node):
    import threading
    lock = threading.RLock()   # serialize state mutations per node

    def locked(fn):
        def wrapper(body):
            with lock:
                return fn(body)
        return wrapper

    return {
        ("GET", "/health"): lambda body: {"status": "ok", "node": node.name},
        ("GET", "/status"): node.status,
        ("POST", "/read"): locked(node.read),
        ("POST", "/authenticate"): locked(node.authenticate),
        ("POST", "/message/send"): locked(node.send_message),
        ("POST", "/audit"): locked(node.audit_op),
        ("GET", "/verify_log"): locked(node.verify_log),
        ("POST", "/tamper_log"): locked(node.tamper),
        ("GET", "/log"): locked(lambda body: {"status": "ok",
                                              "log": node.log_state["log"]}),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--idp", required=True)
    ap.add_argument("--poll-interval", type=float, default=1.0)
    ap.add_argument("--state-dir", default=None)
    ap.add_argument("--relay-next", default=None,
                    help="next node's /message/send URL for relayed "
                         "messaging")
    ap.add_argument("--deliver-to", default=None,
                    help="recipient messaging inbox URL (final relay hop)")
    ap.add_argument("--gossip-next", default=None,
                    help="next node's messaging inbox URL for the "
                         "node-to-node policy-ack channel")
    args = ap.parse_args()
    state_dir = args.state_dir or os.environ.get(
        "TRACK4_NODE_%s_DIR" % args.name.upper().replace("-", "_"),
        "/tmp/track4_node_%s" % args.name)
    node = Node(args.name, args.port, args.registry, args.idp,
                args.poll_interval, state_dir, gossip_next=args.gossip_next,
                relay_next=args.relay_next, deliver_to=args.deliver_to)
    routes = build_routes(node)
    if os.environ.get("TRACK4_DEBUG"):
        print("routes:", sorted((m, p) for (m, p) in routes), flush=True)
    netutil.serve(routes, args.port)
    threading.Thread(target=node.poll_loop, daemon=True).start()
    print("node %s listening on 127.0.0.1:%d (poll %.2fs)"
          % (args.name, args.port, args.poll_interval), flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
