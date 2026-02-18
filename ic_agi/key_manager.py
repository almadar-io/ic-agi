"""
IC-AGI — Key Management Service
==================================

Production-grade key management with envelope encryption,
automatic rotation, versioning, and purpose-based key derivation.

ARCHITECTURE:
  - ``AbstractKeyManager`` defines the interface.
  - ``LocalKeyManager``   uses CSPRNG + HKDF for standalone / testing.
  - ``EnvelopeKeyManager`` wraps a KMS backend (GCP / Vault / HSM) for
    production deployments.

ENVELOPE ENCRYPTION:
  1. A **master key** (MEK) never leaves the KMS boundary.
  2. A **data encryption key** (DEK) is generated locally.
  3. The DEK is encrypted by the MEK → ``wrapped_dek``.
  4. Data is encrypted with the DEK.
  5. ``wrapped_dek`` + ciphertext are stored/sent together.
  6. To decrypt: KMS unwraps ``wrapped_dek`` → plaintext DEK → decrypt data.

KEY ROTATION:
  - Keys are versioned (monotonically increasing version number).
  - ``rotate()`` creates a new version without invalidating old ones.
  - ``current_version`` always returns the latest.
  - Old versions remain available for decryption until explicitly retired.

KEY DERIVATION:
  - HKDF-SHA256 derives purpose-specific keys from a root key.
  - Purposes: ``signing``, ``encryption``, ``mac``, ``token``.
  - Derived keys are deterministic given (root, purpose, version).
  - Changing the root key changes ALL derived keys (cascade rotation).

SECURITY RATIONALE:
  - No key material is ever logged, printed, or serialized in plaintext.
  - Keys are ``bytes`` objects — Python's garbage collector will eventually
    reclaim memory, but in production use memoryview + explicit zeroing.
  - CSPRNG via ``os.urandom`` (backed by OS entropy pool).
  - HKDF follows RFC 5869 construction.
"""

import hashlib
import hmac
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ────────────────────────────────────────────────────────────
#  HKDF-SHA256 (RFC 5869)
# ────────────────────────────────────────────────────────────

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-Hash(salt, IKM)."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand: derive *length* bytes of output key material."""
    hash_len = 32  # SHA-256
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """
    HKDF-SHA256 key derivation (RFC 5869).

    Args:
        ikm:    Input key material.
        salt:   Optional salt (random, non-secret).
        info:   Context/purpose string.
        length: Desired output length in bytes.

    Returns:
        Derived key of *length* bytes.
    """
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


# ────────────────────────────────────────────────────────────
#  Key Version Record
# ────────────────────────────────────────────────────────────

@dataclass
class KeyVersion:
    """A single version of a managed key."""
    version: int
    key_material: bytes
    created_at: float = field(default_factory=time.time)
    retired: bool = False
    retired_at: Optional[float] = None

    def retire(self) -> None:
        """Mark this version as retired (no longer used for new operations)."""
        self.retired = True
        self.retired_at = time.time()


# ────────────────────────────────────────────────────────────
#  Abstract Key Manager Interface
# ────────────────────────────────────────────────────────────

class AbstractKeyManager(ABC):
    """
    Interface for key management backends.

    Every key has:
      - A **name** (e.g., ``"master"``, ``"signing"``, ``"worker-0"``).
      - One or more **versions** (monotonically increasing).
      - A **purpose** for derivation (``signing``, ``encryption``, etc.).
    """

    @abstractmethod
    def create_key(self, name: str, key_size: int = 32) -> KeyVersion:
        """Create a new named key (version 1)."""
        ...

    @abstractmethod
    def get_key(self, name: str, version: Optional[int] = None) -> bytes:
        """
        Get key material.
        If *version* is None, return the current (latest) version.
        """
        ...

    @abstractmethod
    def rotate_key(self, name: str) -> KeyVersion:
        """
        Rotate a named key: create a new version, keep old versions
        available for decryption.
        """
        ...

    @abstractmethod
    def retire_key_version(self, name: str, version: int) -> None:
        """Mark a specific version as retired."""
        ...

    @abstractmethod
    def derive_key(
        self, name: str, purpose: str, context: bytes = b"",
        version: Optional[int] = None, length: int = 32
    ) -> bytes:
        """
        Derive a purpose-specific key from a named root key.
        Uses HKDF-SHA256.
        """
        ...

    @abstractmethod
    def current_version(self, name: str) -> int:
        """Return the current (latest) version number of a named key."""
        ...

    @abstractmethod
    def list_keys(self) -> List[str]:
        """List all managed key names."""
        ...

    @abstractmethod
    def wrap_key(self, name: str, plaintext_key: bytes) -> Dict[str, Any]:
        """
        Envelope encryption: wrap (encrypt) a data key using the named master key.
        Returns a dict with wrapped key material + metadata.
        """
        ...

    @abstractmethod
    def unwrap_key(self, name: str, wrapped: Dict[str, Any]) -> bytes:
        """
        Envelope decryption: unwrap (decrypt) a previously wrapped data key.
        """
        ...


# ────────────────────────────────────────────────────────────
#  Local Key Manager (CSPRNG + HKDF)
# ────────────────────────────────────────────────────────────

class LocalKeyManager(AbstractKeyManager):
    """
    Standalone key manager using OS CSPRNG and HKDF-SHA256.

    Suitable for:
      - Development and testing
      - Single-node deployments
      - Environments without external KMS

    SECURITY RATIONALE:
      - Keys are generated from ``os.urandom`` (CSPRNG).
      - Key derivation uses HKDF-SHA256 (RFC 5869).
      - Envelope wrapping uses HMAC-SHA256 in counter mode
        (same scheme as crypto_utils but with a per-wrap nonce).
      - All key material stays in-process memory.
      - In production, replace with ``EnvelopeKeyManager`` backed by
        GCP KMS / HashiCorp Vault / AWS KMS.
    """

    def __init__(self) -> None:
        self._keys: Dict[str, List[KeyVersion]] = {}

    # ── Key Lifecycle ──

    def create_key(self, name: str, key_size: int = 32) -> KeyVersion:
        if name in self._keys:
            raise ValueError(f"Key '{name}' already exists. Use rotate_key().")
        kv = KeyVersion(version=1, key_material=os.urandom(key_size))
        self._keys[name] = [kv]
        return kv

    def get_key(self, name: str, version: Optional[int] = None) -> bytes:
        if name not in self._keys:
            raise KeyError(f"Key '{name}' not found.")
        versions = self._keys[name]
        if version is None:
            return versions[-1].key_material
        for kv in versions:
            if kv.version == version:
                if kv.retired:
                    raise PermissionError(
                        f"Key '{name}' version {version} is retired."
                    )
                return kv.key_material
        raise KeyError(f"Key '{name}' version {version} not found.")

    def rotate_key(self, name: str) -> KeyVersion:
        if name not in self._keys:
            raise KeyError(f"Key '{name}' not found.")
        versions = self._keys[name]
        new_version = versions[-1].version + 1
        key_size = len(versions[-1].key_material)
        kv = KeyVersion(version=new_version, key_material=os.urandom(key_size))
        versions.append(kv)
        return kv

    def retire_key_version(self, name: str, version: int) -> None:
        if name not in self._keys:
            raise KeyError(f"Key '{name}' not found.")
        for kv in self._keys[name]:
            if kv.version == version:
                kv.retire()
                return
        raise KeyError(f"Key '{name}' version {version} not found.")

    def current_version(self, name: str) -> int:
        if name not in self._keys:
            raise KeyError(f"Key '{name}' not found.")
        return self._keys[name][-1].version

    def list_keys(self) -> List[str]:
        return list(self._keys.keys())

    # ── Key Derivation ──

    def derive_key(
        self, name: str, purpose: str, context: bytes = b"",
        version: Optional[int] = None, length: int = 32
    ) -> bytes:
        """
        Derive a purpose-specific subkey using HKDF-SHA256.

        The derivation is deterministic:
          ``HKDF(IKM=root_key, salt=name, info=purpose||context, L=length)``

        Different purposes yield independent keys even from the same root.
        """
        root = self.get_key(name, version)
        salt = name.encode("utf-8")
        info = purpose.encode("utf-8") + b"\x00" + context
        return hkdf_sha256(ikm=root, salt=salt, info=info, length=length)

    # ── Envelope Encryption ──

    def wrap_key(self, name: str, plaintext_key: bytes) -> Dict[str, Any]:
        """
        Wrap (encrypt) a data key with the named master key.

        Uses HMAC-SHA256 in counter mode (same PRF-based scheme as crypto_utils).
        """
        master = self.get_key(name)
        nonce = os.urandom(16)

        # Generate keystream
        keystream = self._keystream(master, nonce, len(plaintext_key))
        wrapped = bytes(a ^ b for a, b in zip(plaintext_key, keystream))

        # Integrity tag
        tag = hmac.new(master, nonce + wrapped, hashlib.sha256).hexdigest()

        return {
            "key_name": name,
            "key_version": self.current_version(name),
            "nonce": nonce.hex(),
            "wrapped_key": wrapped.hex(),
            "tag": tag,
        }

    def unwrap_key(self, name: str, wrapped: Dict[str, Any]) -> bytes:
        """
        Unwrap (decrypt) a previously wrapped data key.

        Verifies the HMAC tag before decryption.
        """
        version = wrapped.get("key_version")
        master = self.get_key(name, version)
        nonce = bytes.fromhex(wrapped["nonce"])
        ciphertext = bytes.fromhex(wrapped["wrapped_key"])
        tag = wrapped["tag"]

        # Verify integrity first
        expected_tag = hmac.new(
            master, nonce + ciphertext, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError(
                "SECURITY: Wrapped key integrity check failed — tampering detected."
            )

        # Decrypt
        keystream = self._keystream(master, nonce, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, keystream))

    # ── Key Metadata ──

    def get_key_info(self, name: str) -> Dict[str, Any]:
        """Return metadata about a named key (no key material)."""
        if name not in self._keys:
            raise KeyError(f"Key '{name}' not found.")
        versions = self._keys[name]
        return {
            "name": name,
            "current_version": versions[-1].version,
            "total_versions": len(versions),
            "versions": [
                {
                    "version": kv.version,
                    "created_at": kv.created_at,
                    "retired": kv.retired,
                    "key_size_bytes": len(kv.key_material),
                }
                for kv in versions
            ],
        }

    # ── Internal ──

    @staticmethod
    def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        """HMAC-SHA256 counter-mode keystream."""
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            block = hmac.new(
                key, nonce + counter.to_bytes(4, "big"), hashlib.sha256
            ).digest()
            stream.extend(block)
            counter += 1
        return bytes(stream[:length])


# ────────────────────────────────────────────────────────────
#  Convenience: create a pre-configured key manager
# ────────────────────────────────────────────────────────────

def create_key_manager(
    backend: str = "local",
    initial_keys: Optional[Dict[str, bytes]] = None,
) -> AbstractKeyManager:
    """
    Factory that creates a configured KeyManager.

    Args:
        backend: ``"local"`` (default) or ``"gcp-kms"`` / ``"vault"`` (future).
        initial_keys: Optional dict of ``{name: raw_bytes}`` to pre-load.
                      If a name maps to ``None``, a new 32-byte key is generated.

    Returns:
        An initialized ``AbstractKeyManager``.
    """
    if backend != "local":
        raise NotImplementedError(
            f"Backend '{backend}' not yet implemented. "
            f"Available: 'local'."
        )

    km = LocalKeyManager()

    if initial_keys:
        for name, material in initial_keys.items():
            if material is None:
                km.create_key(name)
            else:
                kv = KeyVersion(version=1, key_material=material)
                km._keys[name] = [kv]

    return km
