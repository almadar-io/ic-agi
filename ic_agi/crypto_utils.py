"""
IC-AGI — State-in-Transit Encryption (stdlib-only)
=====================================================

Provides authenticated encryption for state dicts passed between
the Control Plane and remote Worker pods over the network.

SCHEME:
  - HMAC-SHA256 in counter mode as a stream cipher (PRF-based keystream)
  - Encrypt-then-MAC composition (IND-CCA2 secure)
  - 16-byte random nonce per encryption (from ``os.urandom``)

SECURITY RATIONALE:
  - HMAC-SHA256 is a secure PRF → counter-mode keystream is indistinguishable
    from random to any computationally bounded adversary.
  - Encrypt-then-MAC prevents chosen-ciphertext attacks.
  - No external dependencies — uses only Python stdlib.
  - Each call generates a fresh nonce → no keystream reuse.
"""

import base64
import hashlib
import hmac
import json
import os
from typing import Any, Dict


def encrypt_state(state: Dict[str, Any], key: bytes) -> Dict[str, str]:
    """
    Encrypt a state dict for transit between control plane and worker.

    Returns a dict with ``nonce``, ``ciphertext`` (both base64), and ``tag`` (hex).
    """
    plaintext = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(16)

    # Generate keystream from HMAC-SHA256(key, nonce || counter)
    keystream = _generate_keystream(key, nonce, len(plaintext))

    # XOR plaintext with keystream
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))

    # Encrypt-then-MAC: tag covers nonce + ciphertext
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).hexdigest()

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": tag,
    }


def decrypt_state(encrypted: Dict[str, str], key: bytes) -> Dict[str, Any]:
    """
    Decrypt and verify a state dict received from the network.

    Raises ``ValueError`` if the MAC verification fails (tampering detected).
    """
    nonce = base64.b64decode(encrypted["nonce"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])
    tag = encrypted["tag"]

    # Verify MAC first (encrypt-then-MAC → verify before decrypt)
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError(
            "SECURITY: State tampering detected — MAC verification failed. "
            "The state payload was modified in transit."
        )

    # Decrypt
    keystream = _generate_keystream(key, nonce, len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))

    return json.loads(plaintext.decode("utf-8"))


def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate *length* bytes of keystream using HMAC-SHA256 in counter mode."""
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        block = hmac.new(
            key, nonce + counter.to_bytes(4, "big"), hashlib.sha256
        ).digest()
        keystream.extend(block)
        counter += 1
    return bytes(keystream[:length])
