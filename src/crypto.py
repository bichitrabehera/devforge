"""Cryptographic primitives - vetted libraries only.

* ML-KEM-768 (FIPS 203) key encapsulation:  pqcrypto.kem.ml_kem_768
* ML-DSA-65 (FIPS 204) signatures:          pqcrypto.sign.ml_dsa_65
* HKDF-SHA256 and AES-256-GCM:              cryptography

No custom cryptographic primitives are implemented anywhere in this project.
Responses never contain secret material; public keys appear only as hex
fingerprints or hex public keys.
"""

import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65


def fp(public_bytes):
    """Short public fingerprint for logs/responses (never secret material)."""
    return hashlib.sha256(public_bytes).hexdigest()[:16]


def kem_keypair():
    return ml_kem_768.keygen()


def kem_encaps(public_key):
    return ml_kem_768.encaps(public_key)   # -> (ciphertext, shared_secret)


def kem_decaps(secret_key, ciphertext):
    return ml_kem_768.decaps(secret_key, ciphertext)


def dsa_keypair():
    return ml_dsa_65.keygen()


def dsa_sign(sk_hex, msg_bytes):
    return ml_dsa_65.sign(bytes.fromhex(sk_hex), msg_bytes).hex()


def dsa_verify(pk_hex, msg_bytes, sig_hex):
    try:
        ml_dsa_65.verify(bytes.fromhex(pk_hex), msg_bytes,
                         bytes.fromhex(sig_hex))
        return True   # pqcrypto returns None on success, raises on failure
    except Exception:
        return False


def hkdf(secret, info, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                info=info).derive(secret)


def aead_encrypt(key, nonce, plaintext, aad):
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key, nonce, ciphertext, aad):
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()
