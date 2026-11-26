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


def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _ub64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue(dsa_sk_hex, sub, device, ttl_s=60.0, now=None, skew=0.0):
    """Issue a token for `sub` bound to `device`. `skew` simulates a
    misconfigured client clock (real seconds added to iat/exp)."""
    now = time.time() + skew if now is None else now
    header = {"alg": "ML-DSA-65", "typ": "track4-jwt"}
    payload = {"sub": sub, "device": device, "iat": now, "exp": now + ttl_s,
               "jti": os.urandom(8).hex()}
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    sig = crypto.dsa_sign(dsa_sk_hex, ("%s.%s" % (h, p)).encode())
    return "%s.%s.%s" % (h, p, sig)


def verify(dsa_pk_hex, token, now=None):
    """Returns (payload, None) or (None, reason). Expiry checked against the
    real clock unless `now` is given (tests)."""
    try:
        h, p, s = token.split(".")
    except ValueError:
        return None, "malformed_token"
    if not crypto.dsa_verify(dsa_pk_hex, ("%s.%s" % (h, p)).encode(), s):
        return None, "bad_token_signature"
    try:
        payload = json.loads(_ub64(p))
    except Exception:
        return None, "malformed_token"
    now = time.time() if now is None else now
    if payload.get("exp", 0) < now:
        return None, "token_expired"
    return payload, None
