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
import hmac
import json
import math
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import crypto, netutil, tokens  # noqa: E402

IDP_DIR = os.environ.get("TRACK4_IDP_DIR", "/tmp/track4_idp")

# Device proofs are SINGLE-USE: a captured proof replayed inside the
# freshness window must fail. The IdP keeps a consumed-proof ledger
# (in RAM; entries expire with the window).
import hashlib
import threading

_consumed_proofs = {}          # digest -> consumed_at (monotonic-ish ts)
_consumed_lock = threading.Lock()
MAX_TOKEN_TTL_S = 3600.0       # server-side cap: ttl_s is NOT trusted


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
    # Records may contain SERVICE-HELD device keys (mock HSM): restrict the
    # file to the service account. User-held device private keys are NEVER
    # returned by the service or persisted by it.
    os.chmod(_path("identities.json"), 0o600)


KEYS = _load_keys()


def _audit(action, decision, detail):
    """Append-only JSONL audit of IdP security events (no secrets)."""
    try:
        os.makedirs(IDP_DIR, exist_ok=True)
        with open(os.path.join(IDP_DIR, "audit.jsonl"), "a") as f:
            f.write(json.dumps({"ts": time.time(), "service": "idp",
                                "action": action, "decision": decision,
                                "detail": detail}) + "\n")
    except OSError:
        pass


def h_health(body):
    return {"status": "ok", "service": "idp"}


def h_register(body):
    """Register identity + device + DEVICE PUBLIC KEY (ML-DSA).

    First registration WINS: an existing identity cannot be re-registered
    with a different device or key by an unauthenticated caller. Token
    issuance later REQUIRES proof-of-possession of the registered device
    key, so merely reaching the IdP does not yield someone's token."""
    ident = body.get("identity", "")
    dsa_pk = body.get("dsa_pk", "")
    if not ident or not dsa_pk:
        return {"status": "error",
                "message": "missing_identity_or_device_key"}
    device = body.get("device", ident)
    idents = _load_identities()
    if ident in idents:
        rec = idents[ident]
        if rec.get("device", ident) == device and \
                rec.get("dsa_pk") == dsa_pk:
            return {"status": "ok", "identity": ident}   # idempotent
        return {"status": "error", "message": "identity_exists",
                "note": "device/key changes require authenticated "
                        "re_enrol"}
    idents[ident] = {"device": device, "dsa_pk": dsa_pk}
    _save_identities(idents)
    _audit("register", "ok", "identity=%s device=%s" % (ident, device))
    return {"status": "ok", "identity": ident}


# Recovery administrators: identities allowed to REBIND a device key
# when the owner loses the device's private key (a lost key cannot sign
# a proof, so self-service PoP cannot recover it). Bootstrap admin is
# registered by the demo/deployment; production deployments would map
# this to a real administrator policy.
IDP_ADMINS = {"user-admin"}
# Organizer-approved recovery bindings: identity -> separate recovery
# identity. These are public names, not secrets; the recovery identity must
# prove possession of its own runtime-generated ML-DSA key for every use.
RECOVERY_OF = {"user-blair": "recovery-user-blair"}
DEVICE_PK_BYTES = 1952          # raw ML-DSA-65 public key size
MAX_DEVICE_NAME = 64


def _authorized_recovery(body, identity):
    """Return (payload, reason). Recovery requires a signed IdP token whose
    subject is the bound recovery identity or an organizer admin."""
    payload, err = tokens.verify(KEYS["dsa_pk"], body.get("token", ""))
    if payload is None:
        return None, "token_" + err
    sub = payload.get("sub", "")
    if sub == RECOVERY_OF.get(identity) or sub in IDP_ADMINS:
        return payload, ""
    return None, "not_permitted"


def h_rebind(body):
    """ADMIN re-registration of a device key (lost-key recovery path).

    Requires a valid IdP token whose subject is an administrator. The
    identity's registered device key is replaced: the OLD private key
    can no longer mint proofs, and the owner proves possession of the
    NEW key at /token from then on."""
    ident = body.get("identity", "")
    new_pk = body.get("new_device_pk", "")
    if not ident or not new_pk:
        return {"status": "error",
                "message": "missing_identity_or_device_key"}
    payload, err = tokens.verify(KEYS["dsa_pk"], body.get("token", ""))
    if payload is None:
        _audit("rebind", "deny", "identity=%s token_invalid" % ident)
        return {"status": "error", "message": "token_invalid:" + err}
    if payload.get("sub") not in IDP_ADMINS:
        _audit("rebind", "deny", "identity=%s not_admin sub=%s"
               % (ident, payload.get("sub")))
        return {"status": "error", "message": "not_permitted",
                "note": "only a recovery administrator may rebind a "
                        "device key"}
    idents = _load_identities()
    rec = idents.get(ident)
    if rec is None:
        _audit("rebind", "deny", "identity=%s unknown_identity" % ident)
        return {"status": "error", "message": "unknown_identity"}
    old_device = rec.get("device", ident)
    device = body.get("device", old_device)
    if (not isinstance(device, str) or not device or len(device) > MAX_DEVICE_NAME
            or device == old_device):
        return {"status": "error", "message": "invalid_replacement_device"}
    try:
        if len(bytes.fromhex(new_pk)) != DEVICE_PK_BYTES:
            return {"status": "error", "message": "invalid_device_key_length"}
    except ValueError:
        return {"status": "error", "message": "invalid_device_key_encoding"}
    for other, entry in idents.items():
        if other != ident and entry.get("device") == device:
            return {"status": "error", "message": "device_already_bound"}
    rec["device"] = device
    rec["dsa_pk"] = new_pk
    _save_identities(idents)
    _audit("rebind", "ok", "identity=%s old_device=%s new_device=%s"
           % (ident, old_device, device))
    return {"status": "ok", "identity": ident, "device": device,
            "old_device": old_device,
            "note": "the previous device key can no longer mint proofs; "
                    "the registry keeps the OLD device revoked"}


def h_recover_provision(body):
    """PROVISION A REPLACEMENT after genuine device loss.

    The caller authenticates with a SEPARATE recovery identity (or an
    organizer admin), never with the lost device key. The service generates
    a fresh ML-DSA-65 device keypair at runtime; the private key stays in
    this mock-HSM service (never returned, logged or exposed). The device
    receives a runtime-generated random ENROLMENT CREDENTIAL (stored only as
    a SHA-256 digest) which it uses to obtain its first token. No key
    material appears in the response.
    """
    ident = body.get("identity", "")
    if not ident:
        return {"status": "error", "message": "missing_identity"}
    payload, why = _authorized_recovery(body, ident)
    if payload is None:
        _audit("recover_provision", "deny",
               "identity=%s reason=%s" % (ident, why))
        return {"status": "error", "message": "unauthorized", "reason": why}
    idents = _load_identities()
    rec = idents.get(ident)
    if rec is None:
        _audit("recover_provision", "deny",
               "identity=%s unknown_identity" % ident)
        return {"status": "error", "message": "unknown_identity"}
    old_device = rec.get("device", ident)
    device = body.get("device") or ("device-%s-%s"
                                    % (ident, secrets.token_hex(4)))
    if (not isinstance(device, str) or not device or len(device) > MAX_DEVICE_NAME
            or device == old_device):
        return {"status": "error", "message": "invalid_replacement_device"}
    for other, entry in idents.items():
        if other != ident and entry.get("device") == device:
            return {"status": "error", "message": "device_already_bound"}
    pk, sk = crypto.dsa_keypair()
    credential = secrets.token_urlsafe(32)
    rec["device"] = device
    rec["dsa_pk"] = pk.hex()
    rec["dsa_sk"] = sk.hex()          # service-held mock-HSM key, file 0600
    rec["auth_mode"] = "service_held"
    rec["enrolment_secret_hash"] = crypto.sha256_hex(credential)
    rec["old_devices"] = sorted(set(rec.get("old_devices", [])) | {old_device})
    _save_identities(idents)
    _audit("recover_provision", "ok",
           "identity=%s recovery_sub=%s old_device=%s new_device=%s "
           "pk_fingerprint=%s"
           % (ident, payload.get("sub"), old_device, device, crypto.fp(pk)))
    return {"status": "ok", "identity": ident, "device": device,
            "old_device": old_device, "auth_mode": "service_held",
            "dsa_pk": pk.hex(), "dsa_fingerprint": crypto.fp(pk),
            "enrolment_secret": credential}


def _consume_proof(body):
    """Mark a device proof as used. Returns False if it was ALREADY
    consumed (replay).

    The digest covers ONLY the signed proof fields plus the signature.
    Unsigned request fields such as ttl_s and clock_skew must not change
    the replay identity, otherwise a captured proof can be replayed by
    tweaking them.
    """
    signed = tokens.device_proof_core(body)
    signed["proof"] = body.get("proof", "")
    digest = hashlib.sha256(crypto.canonical(signed).encode()).hexdigest()
    now = time.time()
    with _consumed_lock:
        # prune expired entries (window + slack)
        for d, ts in list(_consumed_proofs.items()):
            if now - ts > 180.0:
                del _consumed_proofs[d]
        if digest in _consumed_proofs:
            return False
        _consumed_proofs[digest] = now
        return True


def h_token(body):
    ident = body.get("identity", "")
    idents = _load_identities()
    rec = idents.get(ident)
    if rec is None:
        return {"status": "error", "message": "unknown_identity"}
    # Proof-of-possession: the caller must sign a fresh challenge with
    # the DEVICE KEY registered for this identity. Reaching the IdP is
    # not enough to obtain someone's token.
    if rec.get("auth_mode") == "service_held":
        # The replacement device holds only a runtime-generated credential;
        # its ML-DSA private key never leaves the service mock HSM.
        secret = body.get("enrolment_secret", "")
        expected = rec.get("enrolment_secret_hash", "")
        if (not isinstance(secret, str) or not secret or not expected
                or not hmac.compare_digest(crypto.sha256_hex(secret), expected)):
            _audit("token", "deny", "identity=%s device=%s bad_credential"
                   % (ident, rec.get("device", ident)))
            return {"status": "error", "message": "enrolment_secret_invalid"}
    else:
        ok, why = tokens.verify_device_proof(rec.get("dsa_pk"), body)
        if not ok:
            return {"status": "error", "message": why}
        # Single-use: a valid proof is burned on first redemption, so a
        # captured proof cannot be replayed inside the freshness window.
        if not _consume_proof(body):
            return {"status": "error", "message": "proof_replayed",
                    "note": "each device proof grants exactly one token"}
    # ttl_s is attacker-controlled input: CAP it server-side. A replayed
    # or stolen proof can never yield an arbitrarily long-lived token.
    try:
        ttl_s = float(body.get("ttl_s", 60.0))
    except (TypeError, ValueError):
        ttl_s = 60.0
    if not math.isfinite(ttl_s):
        ttl_s = 60.0
    ttl_s = min(max(ttl_s, 1.0), MAX_TOKEN_TTL_S)
    # A client-supplied clock_skew is deliberately IGNORED: iat/exp use the
    # IdP's real clock. Verifiers additionally reject future-dated iat.
    token = tokens.issue(KEYS["dsa_sk"], ident,
                         rec.get("device", ident), ttl_s=ttl_s)
    _audit("token", "ok", "identity=%s device=%s auth_mode=%s"
           % (ident, rec.get("device", ident),
              rec.get("auth_mode", "device_pop")))
    return {"status": "ok", "token": token, "identity": ident,
            "device": rec.get("device", ident),
            "ttl_s": ttl_s}


def h_jwks(body):
    return {"status": "ok", "keys": [{"kty": "ML-DSA-65",
                                      "alg": "ML-DSA-65",
                                      "kid": "idp-1",
                                      "x": KEYS["dsa_pk"]}]}


ROUTES = {
    ("GET", "/health"): h_health,
    ("POST", "/register"): h_register,
    ("POST", "/rebind"): h_rebind,
    ("POST", "/recover/provision"): h_recover_provision,
    ("POST", "/token"): h_token,
    ("GET", "/jwks.json"): h_jwks,
    ("GET", "/audit"): lambda body: {
        "status": "ok",
        "audit": [json.loads(line) for line in
                  _read_audit_lines()]},
}


def _read_audit_lines():
    path = os.path.join(IDP_DIR, "audit.jsonl")
    try:
        with open(path) as f:
            return [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return []


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
