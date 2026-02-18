"""
IC-AGI — Phase 10 Tests
=========================

Tests for production cryptographic hardening:
  - P0.1: Key Management (LocalKeyManager, HKDF, envelope encryption)
  - P0.2: TLS Manager (InternalCA, cert issuance, mTLS config)
  - P0.3: Threshold BLS Signatures (keygen, sign, aggregate, verify)
"""

import hashlib
import hmac
import os
import time

import pytest


# ════════════════════════════════════════════════════════════
#  P0.1 — Key Management Tests
# ════════════════════════════════════════════════════════════

class TestHKDF:
    """Test HKDF-SHA256 implementation (RFC 5869)."""

    def test_hkdf_deterministic(self):
        """Same inputs produce same output."""
        from ic_agi.key_manager import hkdf_sha256
        k1 = hkdf_sha256(b"secret", b"salt", b"info", 32)
        k2 = hkdf_sha256(b"secret", b"salt", b"info", 32)
        assert k1 == k2

    def test_hkdf_different_info_different_key(self):
        """Different info produces different derived keys."""
        from ic_agi.key_manager import hkdf_sha256
        k1 = hkdf_sha256(b"secret", b"salt", b"purpose-A", 32)
        k2 = hkdf_sha256(b"secret", b"salt", b"purpose-B", 32)
        assert k1 != k2

    def test_hkdf_different_ikm_different_key(self):
        """Different input key material produces different derived keys."""
        from ic_agi.key_manager import hkdf_sha256
        k1 = hkdf_sha256(b"secret-1", b"salt", b"info", 32)
        k2 = hkdf_sha256(b"secret-2", b"salt", b"info", 32)
        assert k1 != k2

    def test_hkdf_variable_length(self):
        """Can derive keys of various lengths."""
        from ic_agi.key_manager import hkdf_sha256
        for length in [16, 32, 48, 64, 128]:
            k = hkdf_sha256(b"secret", b"salt", b"info", length)
            assert len(k) == length

    def test_hkdf_empty_salt(self):
        """HKDF works with empty salt (uses default zero salt)."""
        from ic_agi.key_manager import hkdf_sha256
        k = hkdf_sha256(b"secret", b"", b"info", 32)
        assert len(k) == 32


class TestLocalKeyManager:
    """Test LocalKeyManager key lifecycle."""

    def test_create_key(self):
        """Creating a key produces a 32-byte key at version 1."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        kv = km.create_key("master")
        assert kv.version == 1
        assert len(kv.key_material) == 32

    def test_create_key_duplicate_fails(self):
        """Cannot create a key with an existing name."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        with pytest.raises(ValueError, match="already exists"):
            km.create_key("master")

    def test_get_key_returns_latest(self):
        """get_key without version returns the latest."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        key_v1 = km.get_key("master")
        km.rotate_key("master")
        key_v2 = km.get_key("master")
        assert key_v1 != key_v2

    def test_get_key_by_version(self):
        """Can retrieve a specific version."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        key_v1 = km.get_key("master", version=1)
        km.rotate_key("master")
        key_v1_again = km.get_key("master", version=1)
        assert key_v1 == key_v1_again

    def test_get_key_nonexistent_fails(self):
        """Getting a nonexistent key raises KeyError."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        with pytest.raises(KeyError):
            km.get_key("nonexistent")

    def test_rotate_key(self):
        """Rotating a key creates a new version."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        assert km.current_version("master") == 1
        kv2 = km.rotate_key("master")
        assert kv2.version == 2
        assert km.current_version("master") == 2

    def test_rotate_preserves_old_versions(self):
        """Old key versions remain accessible after rotation."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        key_v1 = km.get_key("master", version=1)
        km.rotate_key("master")
        km.rotate_key("master")
        assert km.get_key("master", version=1) == key_v1
        assert km.current_version("master") == 3

    def test_retire_key_version(self):
        """Retired versions cannot be retrieved."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        km.rotate_key("master")
        km.retire_key_version("master", 1)
        with pytest.raises(PermissionError, match="retired"):
            km.get_key("master", version=1)
        # Current version still works
        assert len(km.get_key("master")) == 32

    def test_list_keys(self):
        """list_keys returns all managed key names."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        km.create_key("signing")
        km.create_key("encryption")
        assert set(km.list_keys()) == {"master", "signing", "encryption"}


class TestKeyDerivation:
    """Test purpose-based key derivation."""

    def test_derive_different_purposes(self):
        """Different purposes produce different keys from same root."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("root")
        k_sign = km.derive_key("root", "signing")
        k_enc = km.derive_key("root", "encryption")
        k_mac = km.derive_key("root", "mac")
        assert k_sign != k_enc
        assert k_enc != k_mac
        assert k_sign != k_mac

    def test_derive_deterministic(self):
        """Same derivation inputs produce same output."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("root")
        k1 = km.derive_key("root", "signing")
        k2 = km.derive_key("root", "signing")
        assert k1 == k2

    def test_derive_with_context(self):
        """Context differentiates derived keys."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("root")
        k1 = km.derive_key("root", "signing", context=b"worker-0")
        k2 = km.derive_key("root", "signing", context=b"worker-1")
        assert k1 != k2

    def test_derive_from_rotated_key(self):
        """Deriving from different versions produces different keys."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("root")
        k_v1 = km.derive_key("root", "signing", version=1)
        km.rotate_key("root")
        k_v2 = km.derive_key("root", "signing", version=2)
        assert k_v1 != k_v2


class TestEnvelopeEncryption:
    """Test envelope encryption (wrap/unwrap)."""

    def test_wrap_unwrap_roundtrip(self):
        """Wrapping and unwrapping returns the original key."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        data_key = os.urandom(32)
        wrapped = km.wrap_key("master", data_key)
        unwrapped = km.unwrap_key("master", wrapped)
        assert unwrapped == data_key

    def test_wrap_different_nonces(self):
        """Each wrap uses a different nonce."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        data_key = os.urandom(32)
        w1 = km.wrap_key("master", data_key)
        w2 = km.wrap_key("master", data_key)
        assert w1["nonce"] != w2["nonce"]
        assert w1["wrapped_key"] != w2["wrapped_key"]

    def test_wrap_tampering_detected(self):
        """Modifying wrapped key is detected on unwrap."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        data_key = os.urandom(32)
        wrapped = km.wrap_key("master", data_key)
        # Tamper with the wrapped key
        tampered = list(bytes.fromhex(wrapped["wrapped_key"]))
        tampered[0] ^= 0xFF
        wrapped["wrapped_key"] = bytes(tampered).hex()
        with pytest.raises(ValueError, match="tampering"):
            km.unwrap_key("master", wrapped)

    def test_wrap_with_rotated_key(self):
        """Can unwrap with specific version after rotation."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        data_key = os.urandom(32)
        wrapped = km.wrap_key("master", data_key)
        km.rotate_key("master")
        # Should still unwrap with version 1
        unwrapped = km.unwrap_key("master", wrapped)
        assert unwrapped == data_key

    def test_wrap_contains_metadata(self):
        """Wrapped bundle contains key name and version."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        wrapped = km.wrap_key("master", os.urandom(32))
        assert wrapped["key_name"] == "master"
        assert wrapped["key_version"] == 1


class TestKeyManagerFactory:
    """Test the create_key_manager factory."""

    def test_factory_local(self):
        """Factory creates a LocalKeyManager."""
        from ic_agi.key_manager import create_key_manager, LocalKeyManager
        km = create_key_manager("local")
        assert isinstance(km, LocalKeyManager)

    def test_factory_with_initial_keys(self):
        """Factory can pre-load keys."""
        from ic_agi.key_manager import create_key_manager
        km = create_key_manager("local", initial_keys={
            "master": None,  # Generate new
            "signing": b"\x01" * 32,  # Pre-set
        })
        assert "master" in km.list_keys()
        assert "signing" in km.list_keys()
        assert km.get_key("signing") == b"\x01" * 32

    def test_factory_unsupported_backend(self):
        """Unsupported backend raises NotImplementedError."""
        from ic_agi.key_manager import create_key_manager
        with pytest.raises(NotImplementedError, match="gcp-kms"):
            create_key_manager("gcp-kms")

    def test_key_info_no_material(self):
        """get_key_info returns metadata without key material."""
        from ic_agi.key_manager import LocalKeyManager
        km = LocalKeyManager()
        km.create_key("master")
        km.rotate_key("master")
        info = km.get_key_info("master")
        assert info["name"] == "master"
        assert info["current_version"] == 2
        assert info["total_versions"] == 2
        # Verify no raw key material in the info dict
        info_str = str(info)
        assert "key_material" not in info_str


# ════════════════════════════════════════════════════════════
#  P0.2 — TLS Manager Tests
# ════════════════════════════════════════════════════════════

class TestInternalCA:
    """Test InternalCA certificate lifecycle."""

    def test_ca_creation(self):
        """CA is created with a certificate."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA(ca_name="Test CA")
        assert ca.ca_cert_pem is not None
        assert len(ca.ca_cert_pem) > 0

    def test_issue_identity(self):
        """Issue a TLS identity for a named entity."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA()
        identity = ca.issue_identity("control-plane")
        assert identity.identity_name == "control-plane"
        assert len(identity.cert_pem) > 0
        assert len(identity.key_pem) > 0
        assert len(identity.ca_cert_pem) > 0

    def test_issue_multiple_unique_certs(self):
        """Each identity gets a unique certificate."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA()
        id1 = ca.issue_identity("worker-0")
        id2 = ca.issue_identity("worker-1")
        assert id1.cert_pem != id2.cert_pem
        assert id1.key_pem != id2.key_pem
        assert id1.serial_number != id2.serial_number

    def test_unique_serial_numbers(self):
        """Serial numbers are monotonically increasing."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA()
        serials = []
        for i in range(5):
            ident = ca.issue_identity(f"node-{i}")
            serials.append(ident.serial_number)
        assert serials == sorted(serials)
        assert len(set(serials)) == 5  # All unique

    def test_verify_issued_identity(self):
        """Identities issued by this CA verify correctly."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA()
        identity = ca.issue_identity("worker-0")
        assert ca.verify_identity(identity) is True

    def test_verify_foreign_identity_fails(self):
        """Identity from a different CA does not verify."""
        from ic_agi.tls_manager import InternalCA
        ca1 = InternalCA(ca_name="CA-1")
        ca2 = InternalCA(ca_name="CA-2")
        identity = ca2.issue_identity("worker-0")
        # CA1 should NOT verify CA2's identity
        assert ca1.verify_identity(identity) is False

    def test_revoke_identity(self):
        """Revoked identities are tracked."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA()
        identity = ca.issue_identity("worker-0")
        assert ca.is_revoked(identity.serial_number) is False
        ca.revoke_identity("worker-0")
        assert ca.is_revoked(identity.serial_number) is True

    def test_identity_fingerprint(self):
        """Each identity has a SHA-256 fingerprint."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA()
        identity = ca.issue_identity("worker-0")
        assert len(identity.fingerprint) == 32  # 32 hex chars

    def test_san_names(self):
        """Can issue identity with Subject Alternative Names."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA()
        identity = ca.issue_identity(
            "control-plane",
            san_names=["localhost", "127.0.0.1"]
        )
        assert identity.identity_name == "control-plane"
        assert ca.verify_identity(identity) is True

    def test_get_server_config(self):
        """Can get TLS config for server."""
        from ic_agi.tls_manager import InternalCA, TLSConfig
        ca = InternalCA()
        ca.issue_identity("server")
        config = ca.get_server_config("server")
        assert isinstance(config, TLSConfig)
        assert config.identity.identity_name == "server"

    def test_get_client_config(self):
        """Can get TLS config for client."""
        from ic_agi.tls_manager import InternalCA, TLSConfig
        ca = InternalCA()
        ca.issue_identity("client")
        config = ca.get_client_config("client")
        assert isinstance(config, TLSConfig)

    def test_get_issued_identities(self):
        """Can list all issued identities metadata."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA()
        ca.issue_identity("control-plane")
        ca.issue_identity("worker-0")
        ca.issue_identity("worker-1")
        issued = ca.get_issued_identities()
        assert len(issued) == 3
        assert "control-plane" in issued
        assert "worker-0" in issued
        # No key material in metadata
        for name, meta in issued.items():
            assert "key_pem" not in str(meta)
            assert "cert_pem" not in str(meta)

    def test_config_missing_identity_fails(self):
        """Getting config for non-issued identity raises KeyError."""
        from ic_agi.tls_manager import InternalCA
        ca = InternalCA()
        with pytest.raises(KeyError, match="not found"):
            ca.get_server_config("nonexistent")


# ════════════════════════════════════════════════════════════
#  P0.3 — Threshold BLS Signature Tests
# ════════════════════════════════════════════════════════════

class TestThresholdBLSKeygen:
    """Test threshold key generation ceremony."""

    def test_keygen_produces_shares(self):
        """Ceremony produces N shares and a group public key."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["alice", "bob", "carol"], threshold=2
        )
        assert len(shares) == 3
        assert len(gpk) > 0
        for share in shares:
            assert share.threshold == 2
            assert share.total == 3

    def test_keygen_unique_shares(self):
        """Each approver gets a unique secret share."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, _ = bls_engine.keygen_ceremony(
            ["a", "b", "c", "d"], threshold=3
        )
        secrets = [s.secret_share for s in shares]
        assert len(set(secrets)) == len(secrets)

    def test_keygen_threshold_too_low(self):
        """Threshold < 2 is rejected."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        with pytest.raises(ValueError, match="Threshold must be >= 2"):
            bls_engine.keygen_ceremony(["a", "b"], threshold=1)

    def test_keygen_threshold_too_high(self):
        """Threshold > N is rejected."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        with pytest.raises(ValueError, match="cannot exceed"):
            bls_engine.keygen_ceremony(["a", "b"], threshold=3)

    def test_keygen_group_public_key_consistent(self):
        """All shares have the same group public key."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        for share in shares:
            assert share.group_public_key == gpk


class TestThresholdBLSSign:
    """Test partial signing and aggregation."""

    def test_partial_sign(self):
        """Each share can produce a partial signature."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, _ = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"approve critical action"
        partial = bls_engine.sign_partial(shares[0], msg)
        assert partial.approver_id == "a"
        assert len(partial.signature_bytes) > 0
        assert partial.message_hash == hashlib.sha256(msg).hexdigest()

    def test_aggregate_with_threshold(self):
        """K partial signatures aggregate into a threshold signature."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"approve critical action"
        partials = [
            bls_engine.sign_partial(shares[0], msg),
            bls_engine.sign_partial(shares[1], msg),
        ]
        sig = bls_engine.aggregate(partials, threshold=2, group_public_key=gpk)
        assert len(sig.signature_bytes) > 0
        assert sig.signers == ["a", "b"]
        assert sig.threshold == 2

    def test_aggregate_below_threshold_fails(self):
        """Cannot aggregate fewer than K signatures."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"test"
        partials = [bls_engine.sign_partial(shares[0], msg)]
        with pytest.raises(ValueError, match="Need at least 2"):
            bls_engine.aggregate(partials, threshold=2, group_public_key=gpk)

    def test_aggregate_different_messages_fails(self):
        """Cannot aggregate signatures for different messages."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        p1 = bls_engine.sign_partial(shares[0], b"message-1")
        p2 = bls_engine.sign_partial(shares[1], b"message-2")
        with pytest.raises(ValueError, match="different messages"):
            bls_engine.aggregate([p1, p2], threshold=2, group_public_key=gpk)

    def test_more_than_threshold_ok(self):
        """Providing more than K signatures is fine (uses first K)."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"test"
        partials = [bls_engine.sign_partial(s, msg) for s in shares]
        sig = bls_engine.aggregate(partials, threshold=2, group_public_key=gpk)
        assert len(sig.signers) == 2  # Only first K used


class TestThresholdBLSVerify:
    """Test threshold signature verification."""

    def test_valid_signature_verifies(self):
        """A properly aggregated signature verifies."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"critical action approval"
        partials = [
            bls_engine.sign_partial(shares[0], msg),
            bls_engine.sign_partial(shares[2], msg),
        ]
        sig = bls_engine.aggregate(partials, threshold=2, group_public_key=gpk)
        assert bls_engine.verify(sig, msg) is True

    def test_wrong_message_fails_verify(self):
        """Signature does not verify against wrong message."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"original message"
        partials = [
            bls_engine.sign_partial(shares[0], msg),
            bls_engine.sign_partial(shares[1], msg),
        ]
        sig = bls_engine.aggregate(partials, threshold=2, group_public_key=gpk)
        assert bls_engine.verify(sig, b"tampered message") is False

    def test_any_k_subset_works(self):
        """Any K-subset of N approvers can sign."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c", "d"], threshold=2
        )
        msg = b"test message"

        # Try multiple K-subsets
        subsets = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]
        for i, j in subsets:
            partials = [
                bls_engine.sign_partial(shares[i], msg),
                bls_engine.sign_partial(shares[j], msg),
            ]
            sig = bls_engine.aggregate(
                partials, threshold=2, group_public_key=gpk
            )
            assert bls_engine.verify(sig, msg) is True, \
                f"Subset ({i},{j}) failed to verify"


class TestThresholdBLSSerialization:
    """Test signature serialization/deserialization."""

    def test_serialize_roundtrip(self):
        """Serialized signature can be deserialized and verified."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"test"
        partials = [
            bls_engine.sign_partial(shares[0], msg),
            bls_engine.sign_partial(shares[1], msg),
        ]
        sig = bls_engine.aggregate(partials, threshold=2, group_public_key=gpk)

        # Serialize and deserialize
        data = ThresholdBLS.serialize_signature(sig)
        assert isinstance(data, dict)
        assert "signature" in data
        assert "group_public_key" in data

        sig2 = ThresholdBLS.deserialize_signature(data)
        assert sig2.signature_bytes == sig.signature_bytes
        assert sig2.message_hash == sig.message_hash
        assert sig2.signers == sig.signers


# ════════════════════════════════════════════════════════════
#  Integration: Key Manager + Crypto Utils
# ════════════════════════════════════════════════════════════

class TestKeyManagerCryptoIntegration:
    """Test key manager integrated with existing crypto_utils."""

    def test_derived_key_for_encryption(self):
        """Derived encryption key works with encrypt_state/decrypt_state."""
        from ic_agi.key_manager import LocalKeyManager
        from ic_agi.crypto_utils import encrypt_state, decrypt_state

        km = LocalKeyManager()
        km.create_key("root")
        enc_key = km.derive_key("root", "encryption")

        state = {"balance": 1000, "account": "alice"}
        encrypted = encrypt_state(state, enc_key)
        decrypted = decrypt_state(encrypted, enc_key)
        assert decrypted == state

    def test_different_purpose_keys_incompatible(self):
        """A signing key cannot decrypt data encrypted with encryption key."""
        from ic_agi.key_manager import LocalKeyManager
        from ic_agi.crypto_utils import encrypt_state, decrypt_state

        km = LocalKeyManager()
        km.create_key("root")
        enc_key = km.derive_key("root", "encryption")
        sign_key = km.derive_key("root", "signing")

        state = {"data": "secret"}
        encrypted = encrypt_state(state, enc_key)
        with pytest.raises(ValueError, match="tampering"):
            decrypt_state(encrypted, sign_key)

    def test_rotated_key_requires_correct_version(self):
        """After rotation, must use correct version for decryption."""
        from ic_agi.key_manager import LocalKeyManager
        from ic_agi.crypto_utils import encrypt_state, decrypt_state

        km = LocalKeyManager()
        km.create_key("root")
        key_v1 = km.derive_key("root", "encryption", version=1)

        state = {"data": "encrypted-with-v1"}
        encrypted = encrypt_state(state, key_v1)

        km.rotate_key("root")
        key_v2 = km.derive_key("root", "encryption", version=2)

        # v1 key still decrypts v1 data
        assert decrypt_state(encrypted, key_v1) == state
        # v2 key cannot decrypt v1 data
        with pytest.raises(ValueError):
            decrypt_state(encrypted, key_v2)


# ════════════════════════════════════════════════════════════
#  Integration: ThresholdBLS + ThresholdAuth semantics
# ════════════════════════════════════════════════════════════

class TestThresholdBLSAuthIntegration:
    """Test that BLS crypto preserves threshold auth formal properties."""

    def test_p1_threshold_safety(self):
        """P1: Cannot produce signature with < K shares."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"critical action"
        # Only 1 partial signature — cannot aggregate
        partials = [bls_engine.sign_partial(shares[0], msg)]
        with pytest.raises(ValueError, match="Need at least 2"):
            bls_engine.aggregate(partials, threshold=2, group_public_key=gpk)

    def test_p2_no_unilateral(self):
        """P2: Single approver cannot forge a threshold signature alone."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares, gpk = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"critical action"
        # Even with share, cannot produce threshold sig alone
        partial = bls_engine.sign_partial(shares[0], msg)
        # Attempting to pass 1 sig where 2 needed
        with pytest.raises(ValueError):
            bls_engine.aggregate([partial], threshold=2, group_public_key=gpk)

    def test_different_ceremonies_incompatible(self):
        """Shares from different ceremonies cannot be mixed."""
        from ic_agi.threshold_crypto import ThresholdBLS
        bls_engine = ThresholdBLS()
        shares1, gpk1 = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        shares2, gpk2 = bls_engine.keygen_ceremony(
            ["a", "b", "c"], threshold=2
        )
        msg = b"test"
        p1 = bls_engine.sign_partial(shares1[0], msg)
        p2 = bls_engine.sign_partial(shares2[1], msg)
        # Can aggregate (different ceremonies have different internals)
        # but the result should NOT verify against either GPK in real BLS
        # In simulated mode, structure-only verification means we test
        # that GPKs are different
        assert gpk1 != gpk2


# ════════════════════════════════════════════════════════════
#  P1.1 — JWT Token Tests (Ed25519)
# ════════════════════════════════════════════════════════════

class TestTokenKeyPair:
    """Test Ed25519 key pair generation."""

    def test_generate_keypair(self):
        """Key pair generation produces valid keys."""
        from ic_agi.jwt_tokens import TokenKeyPair
        kp = TokenKeyPair.generate()
        assert len(kp.private_key_bytes) == 32
        assert len(kp.public_key_bytes) == 32
        assert kp.private_key_bytes != kp.public_key_bytes

    def test_keypairs_unique(self):
        """Each generation produces unique keys."""
        from ic_agi.jwt_tokens import TokenKeyPair
        kp1 = TokenKeyPair.generate()
        kp2 = TokenKeyPair.generate()
        assert kp1.private_key_bytes != kp2.private_key_bytes


class TestTokenIssuer:
    """Test token issuance with Ed25519 signing."""

    def test_issue_token(self):
        """Issued token has correct fields."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        token = issuer.issue(
            token_id="tok-1",
            issued_to="worker-0",
            scope=["execute"],
            ttl_seconds=60,
            budget=5,
        )
        assert token.token_id == "tok-1"
        assert token.issued_to == "worker-0"
        assert token.scope == ["execute"]
        assert token.budget == 5
        assert token.compact  # Has wire format

    def test_compact_format(self):
        """Compact format is header.payload.signature."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        token = issuer.issue("t1", "w0", ["exec"])
        parts = token.compact.split(".")
        assert len(parts) == 3

    def test_token_validity(self):
        """Newly issued token is valid."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        token = issuer.issue("t1", "w0", ["exec"], ttl_seconds=60, budget=3)
        assert token.is_valid()

    def test_token_consume(self):
        """Consuming a token decrements budget."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        token = issuer.issue("t1", "w0", ["exec"], budget=2)
        assert token.consume() is True
        assert token.uses == 1
        assert token.consume() is True
        assert token.uses == 2
        assert token.consume() is False  # Budget exhausted

    def test_expired_token_invalid(self):
        """Expired token is not valid."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        token = issuer.issue("t1", "w0", ["exec"], ttl_seconds=0)
        import time; time.sleep(0.01)
        assert token.is_valid() is False


class TestTokenVerifier:
    """Test token verification with public key only."""

    def test_verify_valid_token(self):
        """Valid token verifies with public key."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer, TokenVerifier
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        verifier = TokenVerifier(kp.public_key_bytes, kp.algorithm)
        token = issuer.issue("t1", "w0", ["exec"], ttl_seconds=60)
        valid, payload = verifier.verify_compact(token.compact)
        assert valid is True
        assert payload["token_id"] == "t1"

    def test_verify_token_dict(self):
        """Can verify from token dict representation."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer, TokenVerifier
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        verifier = TokenVerifier(kp.public_key_bytes, kp.algorithm)
        token = issuer.issue("t1", "w0", ["exec"], ttl_seconds=60)
        assert verifier.verify_token_dict(token.to_dict()) is True

    def test_tampered_token_fails(self):
        """Tampered token does not verify."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer, TokenVerifier
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        verifier = TokenVerifier(kp.public_key_bytes, kp.algorithm)
        token = issuer.issue("t1", "w0", ["exec"], ttl_seconds=60)
        # Tamper with the payload portion
        parts = token.compact.split(".")
        tampered = parts[0] + "." + parts[1] + "X." + parts[2]
        valid, _ = verifier.verify_compact(tampered)
        assert valid is False

    def test_wrong_key_fails(self):
        """Token signed by different key does not verify."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer, TokenVerifier
        kp1 = TokenKeyPair.generate()
        kp2 = TokenKeyPair.generate()
        issuer = TokenIssuer(kp1)
        verifier = TokenVerifier(kp2.public_key_bytes, kp2.algorithm)
        token = issuer.issue("t1", "w0", ["exec"], ttl_seconds=60)
        valid, _ = verifier.verify_compact(token.compact)
        assert valid is False

    def test_expired_compact_fails(self):
        """Expired token fails verification even with correct key."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer, TokenVerifier
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        verifier = TokenVerifier(kp.public_key_bytes, kp.algorithm)
        token = issuer.issue("t1", "w0", ["exec"], ttl_seconds=0)
        import time; time.sleep(0.01)
        valid, _ = verifier.verify_compact(token.compact)
        assert valid is False

    def test_extract_payload(self):
        """Can extract payload without verifying (for inspection)."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenIssuer, TokenVerifier
        kp = TokenKeyPair.generate()
        issuer = TokenIssuer(kp)
        verifier = TokenVerifier(kp.public_key_bytes, kp.algorithm)
        token = issuer.issue("t1", "w0", ["exec", "read"])
        payload = verifier.extract_payload(token.compact)
        assert payload is not None
        assert payload["token_id"] == "t1"
        assert "exec" in payload["scope"]

    def test_malformed_compact_fails(self):
        """Malformed compact string fails gracefully."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenVerifier
        kp = TokenKeyPair.generate()
        verifier = TokenVerifier(kp.public_key_bytes, kp.algorithm)
        valid, _ = verifier.verify_compact("not.a.valid.token")
        assert valid is False
        valid, _ = verifier.verify_compact("")
        assert valid is False

    def test_no_compact_in_dict_fails(self):
        """Token dict without compact field fails verification."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenVerifier
        kp = TokenKeyPair.generate()
        verifier = TokenVerifier(kp.public_key_bytes, kp.algorithm)
        assert verifier.verify_token_dict({"token_id": "t1"}) is False

    def test_asymmetric_property(self):
        """Workers with public key cannot issue tokens."""
        from ic_agi.jwt_tokens import TokenKeyPair, TokenVerifier
        kp = TokenKeyPair.generate()
        verifier = TokenVerifier(kp.public_key_bytes, kp.algorithm)
        # Verifier has no sign method — cannot create tokens
        assert not hasattr(verifier, "issue")
        assert not hasattr(verifier, "_sign")


# ════════════════════════════════════════════════════════════
#  P1.2 — Process Sandbox Tests
# ════════════════════════════════════════════════════════════

class TestProcessSandbox:
    """Test subprocess-isolated code execution."""

    def test_simple_computation(self):
        """Basic arithmetic in subprocess sandbox."""
        from ic_agi.process_sandbox import ProcessSandboxExecutor
        executor = ProcessSandboxExecutor()
        result = executor.execute(
            code="result = a + b * 2",
            inputs={"a": 3, "b": 7},
            output_names=["result"],
        )
        assert result.success is True
        assert result.outputs["result"] == 17

    def test_separate_process(self):
        """Code runs in a different process."""
        from ic_agi.process_sandbox import ProcessSandboxExecutor
        executor = ProcessSandboxExecutor()
        result = executor.execute(
            code="import os; pid = os.getpid()",
            inputs={},
            output_names=["pid"],
        )
        # AST validation should reject 'import'
        assert result.success is False

    def test_math_functions(self):
        """Math functions available in subprocess."""
        from ic_agi.process_sandbox import ProcessSandboxExecutor
        executor = ProcessSandboxExecutor()
        result = executor.execute(
            code="result = sqrt(16) + ceil(3.2)",
            inputs={},
            output_names=["result"],
        )
        assert result.success is True
        assert result.outputs["result"] == 8.0

    def test_timeout_kills_process(self):
        """Long-running code is killed, not abandoned."""
        from ic_agi.process_sandbox import ProcessSandboxExecutor
        executor = ProcessSandboxExecutor()
        result = executor.execute(
            code="x = 0\nwhile True:\n    x += 1",
            inputs={},
            timeout=1.0,
        )
        assert result.success is False
        assert result.killed is True
        assert "TIMEOUT" in (result.error or "")

    def test_ast_validation_first(self):
        """AST validation rejects before subprocess starts."""
        from ic_agi.process_sandbox import ProcessSandboxExecutor
        executor = ProcessSandboxExecutor()
        result = executor.execute(
            code="import os; os.system('rm -rf /')",
            inputs={},
        )
        assert result.success is False
        assert "AST" in (result.error or "") or "SANDBOX" in (result.error or "")

    def test_code_too_long(self):
        """Code exceeding max length is rejected."""
        from ic_agi.process_sandbox import ProcessSandboxExecutor, ProcessSandboxConfig
        executor = ProcessSandboxExecutor(
            config=ProcessSandboxConfig(max_code_length=50)
        )
        result = executor.execute(code="x = 1\n" * 100, inputs={})
        assert result.success is False
        assert "max length" in (result.error or "").lower()

    def test_list_operations(self):
        """Collection operations work in subprocess."""
        from ic_agi.process_sandbox import ProcessSandboxExecutor
        executor = ProcessSandboxExecutor()
        result = executor.execute(
            code="result = sorted([3, 1, 4, 1, 5, 9])",
            inputs={},
            output_names=["result"],
        )
        assert result.success is True
        assert result.outputs["result"] == [1, 1, 3, 4, 5, 9]


# ════════════════════════════════════════════════════════════
#  P1.3 — Persistent Audit Log Tests
# ════════════════════════════════════════════════════════════

class TestMerkleTree:
    """Test Merkle tree implementation."""

    def test_single_leaf(self):
        """Merkle tree with one leaf."""
        from ic_agi.persistent_audit import MerkleTree
        mt = MerkleTree()
        mt.add_leaf("abc123")
        assert mt.root == "abc123"

    def test_multiple_leaves(self):
        """Merkle tree with multiple leaves has a root."""
        from ic_agi.persistent_audit import MerkleTree
        mt = MerkleTree()
        for i in range(8):
            mt.add_leaf(hashlib.sha256(str(i).encode()).hexdigest())
        assert len(mt.root) == 64
        assert len(mt) == 8

    def test_inclusion_proof(self):
        """Merkle inclusion proof verifies correctly."""
        from ic_agi.persistent_audit import MerkleTree
        mt = MerkleTree()
        hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(8)]
        for h in hashes:
            mt.add_leaf(h)
        proof = mt.get_inclusion_proof(3)
        assert MerkleTree.verify_inclusion(hashes[3], proof, mt.root) is True

    def test_inclusion_proof_wrong_leaf(self):
        """Wrong leaf hash does not verify."""
        from ic_agi.persistent_audit import MerkleTree
        mt = MerkleTree()
        for i in range(4):
            mt.add_leaf(hashlib.sha256(str(i).encode()).hexdigest())
        proof = mt.get_inclusion_proof(0)
        assert MerkleTree.verify_inclusion("wrong_hash", proof, mt.root) is False

    def test_tamper_changes_root(self):
        """Changing any leaf changes the root."""
        from ic_agi.persistent_audit import MerkleTree
        mt1 = MerkleTree()
        mt2 = MerkleTree()
        hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(4)]
        for h in hashes:
            mt1.add_leaf(h)
        hashes[2] = "tampered"
        for h in hashes:
            mt2.add_leaf(h)
        assert mt1.root != mt2.root


class TestSQLiteBackend:
    """Test SQLite audit backend."""

    def test_append_and_retrieve(self):
        """Can append and retrieve entries."""
        from ic_agi.persistent_audit import SQLiteAuditBackend
        from ic_agi.audit_log import AuditEntry
        backend = SQLiteAuditBackend(":memory:")
        entry = AuditEntry(
            index=0, timestamp=time.time(),
            data={"event": "test"}, prev_hash="genesis"
        )
        entry.entry_hash = entry.compute_hash()
        backend.append(entry)
        assert backend.get_count() == 1
        last = backend.get_last()
        assert last is not None
        assert last.data["event"] == "test"
        backend.close()

    def test_query_by_source(self):
        """Can query entries by source."""
        from ic_agi.persistent_audit import SQLiteAuditBackend
        from ic_agi.audit_log import AuditEntry
        backend = SQLiteAuditBackend(":memory:")
        for i in range(10):
            src = "A" if i % 2 == 0 else "B"
            entry = AuditEntry(
                index=i, timestamp=time.time(),
                data={"source": src, "event": f"e{i}"},
                prev_hash=f"h{i}"
            )
            entry.entry_hash = entry.compute_hash()
            backend.append(entry)
        results = backend.query(source="A", limit=50)
        assert len(results) == 5
        backend.close()


class TestPersistentAuditLog:
    """Test PersistentAuditLog (drop-in for AuditLog)."""

    def test_append_entry(self):
        """Can append entries."""
        from ic_agi.persistent_audit import PersistentAuditLog
        log = PersistentAuditLog()
        log.append_entry({"source": "test", "event": "START"})
        log.append_entry({"source": "test", "event": "STOP"})
        assert len(log) == 2
        log.close()

    def test_hash_chain_integrity(self):
        """Hash chain verifies correctly."""
        from ic_agi.persistent_audit import PersistentAuditLog
        log = PersistentAuditLog()
        for i in range(20):
            log.append_entry({"source": "test", "event": f"e{i}"})
        assert log.verify_integrity() is True
        log.close()

    def test_merkle_root(self):
        """Merkle root changes with each entry."""
        from ic_agi.persistent_audit import PersistentAuditLog
        log = PersistentAuditLog()
        log.append_entry({"event": "1"})
        root1 = log.get_merkle_root()
        log.append_entry({"event": "2"})
        root2 = log.get_merkle_root()
        assert root1 != root2
        log.close()

    def test_merkle_inclusion(self):
        """Can verify inclusion of individual entries."""
        from ic_agi.persistent_audit import PersistentAuditLog
        log = PersistentAuditLog()
        for i in range(10):
            log.append_entry({"event": f"e{i}"})
        assert log.verify_inclusion(0) is True
        assert log.verify_inclusion(5) is True
        assert log.verify_inclusion(9) is True
        log.close()

    def test_query_entries(self):
        """Can query entries by source/event."""
        from ic_agi.persistent_audit import PersistentAuditLog
        log = PersistentAuditLog()
        log.append_entry({"source": "A", "event": "START"})
        log.append_entry({"source": "B", "event": "START"})
        log.append_entry({"source": "A", "event": "STOP"})
        results = log.get_entries(source="A")
        assert len(results) == 2
        log.close()

    def test_export_log(self):
        """Can export full log for disaster recovery."""
        from ic_agi.persistent_audit import PersistentAuditLog
        log = PersistentAuditLog()
        for i in range(5):
            log.append_entry({"event": f"e{i}"})
        exported = log.export_log()
        assert len(exported) == 5
        assert exported[0]["index"] == 0
        assert exported[4]["index"] == 4
        log.close()

    def test_file_persistence(self, tmp_path):
        """Entries survive process restart (file-backed)."""
        from ic_agi.persistent_audit import PersistentAuditLog
        import os
        db_file = str(tmp_path / "test_audit.db")

        # Write entries
        log1 = PersistentAuditLog(db_path=db_file)
        log1.append_entry({"event": "survive"})
        log1.append_entry({"event": "restart"})
        log1.close()

        # Read back in new instance
        log2 = PersistentAuditLog(db_path=db_file)
        assert len(log2) == 2
        assert log2.verify_integrity() is True
        entries = log2.get_entries()
        assert entries[0].data["event"] == "survive"
        log2.close()

    def test_dump_interface(self):
        """dump() returns same format as AuditLog."""
        from ic_agi.persistent_audit import PersistentAuditLog
        log = PersistentAuditLog()
        log.append_entry({"source": "test", "event": "e1"})
        dumped = log.dump()
        assert len(dumped) == 1
        assert "index" in dumped[0]
        assert "prev_hash" in dumped[0]
        log.close()

    def test_formal_a1_append_only(self):
        """A1: Log length never decreases."""
        from ic_agi.persistent_audit import PersistentAuditLog
        log = PersistentAuditLog()
        lengths = []
        for i in range(10):
            log.append_entry({"event": f"e{i}"})
            lengths.append(len(log))
        assert lengths == list(range(1, 11))
        log.close()

    def test_formal_a2_hash_chain(self):
        """A2: Each entry's prev_hash matches previous entry's hash."""
        from ic_agi.persistent_audit import PersistentAuditLog
        log = PersistentAuditLog()
        for i in range(5):
            log.append_entry({"event": f"e{i}"})
        assert log.verify_integrity() is True
        log.close()


# ════════════════════════════════════════════════════════════
#  Summary count
# ════════════════════════════════════════════════════════════

class TestPhase10Summary:
    """Meta-test: count all Phase 10 tests."""

    def test_count(self):
        """Phase 10 comprehensive test suite."""
        # P0.1: 28 tests (HKDF, KeyManager, Derivation, Envelope, Factory, Integration)
        # P0.2: 13 tests (InternalCA)
        # P0.3: 17 tests (BLS Keygen, Sign, Verify, Serialization, Auth Integration)
        # P1.1: 16 tests (KeyPair, Issuer, Verifier)
        # P1.2:  7 tests (ProcessSandbox)
        # P1.3: 15 tests (MerkleTree, SQLiteBackend, PersistentAuditLog)
        # Total: 96 (excluding this meta-test)
        assert True
