"""Identity tokens signed with ML-DSA-65 (a post-quantum JWT).

Compact serialization: base64url(header).base64url(payload).base64url(sig)
where sig = ML-DSA.sign(IdP key, "<h>.<p>"). Nodes fetch the IdP's public
key once from /jwks.json and verify every presented token with the REAL
system clock (expiry is real time, not simulated).
"""

import base64
import json
import os
import time

from . import crypto


# A token whose iat is far ahead of the verifier's real clock is not valid.
# The IdP never applies client-supplied skew; this bound also rejects tokens
# minted by a misconfigured issuer or by a caller of issue(skew=...).
MAX_IAT_FUTURE_S = 60.0


def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _ub64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue(dsa_sk_hex, sub, device, ttl_s=60.0, now=None, skew=0.0):
    """Issue a token for `sub` bound to `device`.

    `skew` exists only for controlled tests of a misconfigured issuer; the
    IdP MUST NOT pass an untrusted client value here. Verifiers reject an
    iat more than MAX_IAT_FUTURE_S ahead of their real clock.
    """
    now = time.time() + skew if now is None else now
    header = {"alg": "ML-DSA-65", "typ": "track4-jwt"}
    payload = {"sub": sub, "device": device, "iat": now, "exp": now + ttl_s,
               "jti": os.urandom(8).hex()}
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    sig = crypto.dsa_sign(dsa_sk_hex, ("%s.%s" % (h, p)).encode())
    return "%s.%s.%s" % (h, p, sig)


def verify(dsa_pk_hex, token, now=None):
    """Returns (payload, None) or (None, reason). Both expiry and an
    unreasonably future-dated iat are checked against the real clock unless
    `now` is given (tests)."""
    try:
        h, p, s = token.split(".")
    except ValueError:
        return None, "malformed_token"
    if not crypto.dsa_verify(dsa_pk_hex, ("%s.%s" % (h, p)).encode(), s):
        return None, "bad_token_signature"
    try:
        payload = json.loads(_ub64(p))
        iat = float(payload["iat"])
        exp = float(payload["exp"])
    except Exception:
        return None, "malformed_token"
    now = time.time() if now is None else now
    if exp < now:
        return None, "token_expired"
    if iat > now + MAX_IAT_FUTURE_S:
        return None, "token_not_yet_valid"
    return payload, None

def device_proof(sk_hex, identity, device, ts=None):
    """Build a device proof-of-possession body: ML-DSA signature over
    canonical({identity, device, ts}) with the device's registered key."""
    import time as _t
    body = {"identity": identity, "device": device,
            "ts": round(_t.time() if ts is None else ts, 3)}
    sig = crypto.dsa_sign(sk_hex, crypto.canonical(body).encode())
    return dict(body, proof=sig)


def device_proof_core(body):
    """The exact fields signed by device_proof().

    Replay ledgers MUST key on these fields plus `proof`, never on the full
    request body: ttl_s/clock_skew are not signed and changing them must not
    turn one captured proof into a fresh token.
    """
    return {k: body.get(k) for k in ("identity", "device", "ts")}


def verify_device_proof(pk_hex, body, max_age=60.0):
    """Returns (ok, reason). Requires a fresh signature from the device
    key registered for this identity - prevents token minting by anyone
    who can merely reach the IdP."""
    if not pk_hex:
        return False, "device_not_registered"
    core = device_proof_core(body)
    if any(v is None for v in core.values()):
        return False, "proof_required"
    try:
        if abs(time.time() - float(core["ts"])) > max_age:
            return False, "proof_stale"
    except (TypeError, ValueError):
        return False, "proof_required"
    ok = crypto.dsa_verify(pk_hex, crypto.canonical(core).encode(),
                           body.get("proof", ""))
    return (True, "") if ok else (False, "bad_proof")
