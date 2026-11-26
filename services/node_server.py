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


class Node:
    def __init__(self, name, port, registry, idp, poll_interval, state_dir):
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
        except Exception as exc:
            self.last_poll_error = type(exc).__name__

    def poll_loop(self):
        while True:
            time.sleep(self.poll_interval)
            self._poll_once()

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
    return {
        ("GET", "/health"): lambda body: {"status": "ok", "node": node.name},
        ("GET", "/status"): node.status,
        ("POST", "/read"): node.read,
        ("POST", "/authenticate"): node.authenticate,
        ("POST", "/audit"): node.audit_op,
        ("GET", "/verify_log"): node.verify_log,
        ("POST", "/tamper_log"): node.tamper,
        ("GET", "/log"): lambda body: {"status": "ok",
                                       "log": node.log_state["log"]},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--idp", required=True)
    ap.add_argument("--poll-interval", type=float, default=1.0)
    ap.add_argument("--state-dir", default=None)
    args = ap.parse_args()
    state_dir = args.state_dir or os.environ.get(
        "TRACK4_NODE_%s_DIR" % args.name.upper().replace("-", "_"),
        "/tmp/track4_node_%s" % args.name)
    node = Node(args.name, args.port, args.registry, args.idp,
                args.poll_interval, state_dir)
    netutil.serve(build_routes(node), args.port)
    threading.Thread(target=node.poll_loop, daemon=True).start()
    print("node %s listening on 127.0.0.1:%d (poll %.2fs)"
          % (args.name, args.port, args.poll_interval), flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
