#!/usr/bin/env python3
"""Track 4 identity provider - a REAL separate process.

Issues ML-DSA-65-signed identity tokens (post-quantum JWT) and publishes
its public key at /jwks.json. Nodes verify presented tokens against the
JWKS with the REAL clock. This is the external identity integration point:
the nodes and registry hold no signing power over identities; they only
verify.

Run:  python3 services/idp_server.py --port 8400
Env:  TRACK4_IDP_DIR (default /tmp/track4_idp)
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import crypto, netutil, tokens  # noqa: E402

IDP_DIR = os.environ.get("TRACK4_IDP_DIR", "/tmp/track4_idp")


def _path(name):
    os.makedirs(IDP_DIR, exist_ok=True)
    return os.path.join(IDP_DIR, name)


def _load_keys():
    path = _path("idp_key.json")
    if not os.path.exists(path):
        pk, sk = crypto.dsa_keypair()
        with open(path + ".tmp", "w") as f:
            json.dump({"dsa_pk": pk.hex(), "dsa_sk": sk.hex()}, f)
        os.replace(path + ".tmp", path)
        os.chmod(path, 0o600)
    with open(path) as f:
        return json.load(f)


def _load_identities():
    path = _path("identities.json")
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_identities(idents):
    tmp = _path("identities.json.tmp")
    with open(tmp, "w") as f:
        json.dump(idents, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, _path("identities.json"))


KEYS = _load_keys()


def h_health(body):
    return {"status": "ok", "service": "idp"}


def h_register(body):
    ident = body.get("identity", "")
    if not ident:
        return {"status": "error", "message": "missing_identity"}
    idents = _load_identities()
    idents.setdefault(ident, {})["device"] = body.get("device", ident)
    _save_identities(idents)
    return {"status": "ok", "identity": ident}


def h_disable(body):
    ident = body.get("identity", "")
    idents = _load_identities()
    if ident in idents:
        idents[ident]["disabled"] = True
        _save_identities(idents)
    return {"status": "ok", "identity": ident, "disabled": True}


def h_enable(body):
    ident = body.get("identity", "")
    idents = _load_identities()
    if ident in idents:
        idents[ident]["disabled"] = False
        _save_identities(idents)
    return {"status": "ok", "identity": ident, "disabled": False}


def h_token(body):
    ident = body.get("identity", "")
    idents = _load_identities()
    rec = idents.get(ident)
    if rec is None:
        return {"status": "error", "message": "unknown_identity"}
    if rec.get("disabled"):
        return {"status": "error", "message": "identity_disabled"}
    token = tokens.issue(KEYS["dsa_sk"], ident,
                         rec.get("device", ident),
                         ttl_s=body.get("ttl_s", 60.0),
                         skew=body.get("clock_skew", 0.0))
    return {"status": "ok", "token": token, "identity": ident,
            "device": rec.get("device", ident)}


def h_jwks(body):
    return {"status": "ok", "keys": [{"kty": "ML-DSA-65",
                                      "alg": "ML-DSA-65",
                                      "kid": "idp-1",
                                      "x": KEYS["dsa_pk"]}]}


ROUTES = {
    ("GET", "/health"): h_health,
    ("POST", "/register"): h_register,
    ("POST", "/disable"): h_disable,
    ("POST", "/enable"): h_enable,
    ("POST", "/token"): h_token,
    ("GET", "/jwks.json"): h_jwks,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8400)
    args = ap.parse_args()
    netutil.serve(ROUTES, args.port)
    print("idp listening on 127.0.0.1:%d" % args.port, flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
