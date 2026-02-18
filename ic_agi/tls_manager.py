"""
IC-AGI — TLS Manager for Mutual TLS (mTLS)
=============================================

Provides an internal Certificate Authority (CA) and per-pod certificate
generation for mutual TLS authentication between IC-AGI components.

ARCHITECTURE:
  - ``TLSCertificate`` — a self-signed or CA-signed X.509 cert + key pair.
  - ``InternalCA``     — issues certificates for control-plane and workers.
  - ``TLSConfig``      — configuration bundle for HTTPS servers/clients.

mTLS FLOW:
  1. InternalCA generates a root CA cert + key.
  2. Control-plane gets cert signed by CA.
  3. Each worker pod gets a unique cert signed by the same CA.
  4. Server presents its cert → client verifies against CA.
  5. Client presents its cert → server verifies against CA.
  6. Both sides are cryptographically authenticated.

SECURITY RATIONALE:
  - Each pod has a **unique** certificate bound to its identity.
  - Certificates are short-lived (default 24h) to limit exposure.
  - The CA private key is stored separately from pod keys.
  - Certificate generation uses Ed25519 or RSA-2048 depending
    on ``ssl`` module capabilities.
  - In production, replace InternalCA with cert-manager, SPIFFE/SPIRE,
    or Istio's Citadel.

IMPLEMENTATION NOTE:
  Uses Python's ``ssl`` module with self-signed certificates generated
  via ``cryptography`` library if available, or via stdlib ``ssl``
  with pre-generated PEM files.
"""

import hashlib
import hmac
import os
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TLSIdentity:
    """
    A TLS identity: certificate + private key in PEM format.

    SECURITY RATIONALE:
      - Private key material should be treated as secret.
      - In production, private keys would be stored in HSM / KMS.
      - PEM format is used for compatibility with Python's ssl module.
    """
    identity_name: str
    cert_pem: bytes         # X.509 certificate in PEM format
    key_pem: bytes          # Private key in PEM format
    ca_cert_pem: bytes      # CA certificate for verification
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    serial_number: int = 0
    fingerprint: str = ""   # SHA-256 fingerprint of the certificate

    def __post_init__(self):
        if not self.fingerprint and self.cert_pem:
            self.fingerprint = hashlib.sha256(self.cert_pem).hexdigest()[:32]


@dataclass
class TLSConfig:
    """
    TLS configuration bundle for a server or client.

    Usage:
        config = tls_manager.get_server_config("control-plane")
        ssl_ctx = config.create_ssl_context(server=True)
    """
    identity: TLSIdentity
    verify_mode: int = ssl.CERT_REQUIRED
    check_hostname: bool = False  # Internal certs use IPs/pod names
    min_version: int = ssl.TLSVersion.TLSv1_2

    def create_ssl_context(self, server: bool = False) -> ssl.SSLContext:
        """
        Create a Python ``ssl.SSLContext`` configured for mTLS.

        Args:
            server: If True, creates a server-side context.
                    If False, creates a client-side context.

        Returns:
            Configured ``ssl.SSLContext`` with mutual TLS.
        """
        purpose = ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH
        ctx = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT
        )
        ctx.minimum_version = self.min_version

        # Write cert/key to temp files for loading
        # (ssl module requires file paths for load_cert_chain)
        cert_path, key_path, ca_path = self._write_temp_pems()

        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        ctx.load_verify_locations(cafile=ca_path)

        # Mutual TLS: require client certificates
        ctx.verify_mode = self.verify_mode
        ctx.check_hostname = self.check_hostname

        # Clean up temp files
        for path in (cert_path, key_path, ca_path):
            try:
                os.unlink(path)
            except OSError:
                pass

        return ctx

    def _write_temp_pems(self) -> Tuple[str, str, str]:
        """Write PEM data to temporary files. Returns (cert, key, ca) paths."""
        cert_fd, cert_path = tempfile.mkstemp(suffix=".pem", prefix="ic_agi_cert_")
        key_fd, key_path = tempfile.mkstemp(suffix=".pem", prefix="ic_agi_key_")
        ca_fd, ca_path = tempfile.mkstemp(suffix=".pem", prefix="ic_agi_ca_")

        os.write(cert_fd, self.identity.cert_pem)
        os.close(cert_fd)
        os.write(key_fd, self.identity.key_pem)
        os.close(key_fd)
        os.write(ca_fd, self.identity.ca_cert_pem)
        os.close(ca_fd)

        return cert_path, key_path, ca_path


class InternalCA:
    """
    Internal Certificate Authority for IC-AGI mTLS.

    Generates self-signed CA certificate and issues certificates
    for control-plane and worker pods.

    SECURITY RATIONALE:
      - CA key is stored in memory (production: HSM/KMS).
      - Certificates are short-lived (default 24h).
      - Each identity gets a unique serial number.
      - Revocation is tracked in-memory (production: CRL/OCSP).
      - Uses the ``cryptography`` library for X.509 cert generation.

    FALLBACK:
      If ``cryptography`` is not installed, uses a HMAC-based
      "certificate simulation" for testing purposes. Real X.509
      certificates require the ``cryptography`` package.
    """

    def __init__(
        self,
        ca_name: str = "IC-AGI Internal CA",
        cert_lifetime_hours: float = 24.0,
    ):
        self.ca_name = ca_name
        self.cert_lifetime_seconds = cert_lifetime_hours * 3600
        self._serial_counter = 0
        self._issued: Dict[str, TLSIdentity] = {}
        self._revoked: Dict[int, float] = {}  # serial -> revocation time

        # Try to use the cryptography library
        self._use_real_crypto = False
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            import datetime
            self._use_real_crypto = True
            self._generate_ca_real()
        except ImportError:
            # Fallback to HMAC-based simulation
            self._generate_ca_simulated()

    def _generate_ca_real(self) -> None:
        """Generate CA using ``cryptography`` library (ECDSA P-256)."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import datetime

        # Generate CA private key (ECDSA P-256)
        self._ca_private_key = ec.generate_private_key(ec.SECP256R1())

        # Build CA certificate (self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IC-AGI"),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True,
                    crl_sign=True, key_encipherment=False,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._ca_private_key, hashes.SHA256())
        )

        self._ca_cert_pem = self._ca_cert.public_bytes(serialization.Encoding.PEM)
        self._ca_key_pem = self._ca_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def _generate_ca_simulated(self) -> None:
        """Fallback: HMAC-based 'certificate' for environments without cryptography lib."""
        ca_secret = os.urandom(32)
        ca_id = hashlib.sha256(ca_secret).hexdigest()[:16]

        # Simulated PEM (not a real X.509 cert — just for interface compatibility)
        self._ca_cert_pem = (
            f"-----BEGIN CERTIFICATE-----\n"
            f"IC-AGI-SIMULATED-CA-{ca_id}\n"
            f"CA-NAME: {self.ca_name}\n"
            f"-----END CERTIFICATE-----\n"
        ).encode()

        self._ca_key_pem = (
            f"-----BEGIN PRIVATE KEY-----\n"
            f"IC-AGI-SIMULATED-CA-KEY-{ca_secret.hex()}\n"
            f"-----END PRIVATE KEY-----\n"
        ).encode()

        self._ca_secret = ca_secret

    def issue_identity(self, name: str, san_names: Optional[List[str]] = None) -> TLSIdentity:
        """
        Issue a TLS identity (certificate + private key) for a named entity.

        Args:
            name: Entity name (e.g., ``"control-plane"``, ``"worker-0"``).
            san_names: Subject Alternative Names (DNS names or IPs).

        Returns:
            ``TLSIdentity`` with cert_pem, key_pem, and ca_cert_pem.
        """
        self._serial_counter += 1
        serial = self._serial_counter

        if self._use_real_crypto:
            identity = self._issue_real(name, serial, san_names or [])
        else:
            identity = self._issue_simulated(name, serial, san_names or [])

        self._issued[name] = identity
        return identity

    def _issue_real(self, name: str, serial: int, san_names: List[str]) -> TLSIdentity:
        """Issue a real X.509 certificate signed by the CA."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import datetime
        import ipaddress

        # Generate entity private key
        entity_key = ec.generate_private_key(ec.SECP256R1())

        now = datetime.datetime.now(datetime.timezone.utc)
        expires = now + datetime.timedelta(seconds=self.cert_lifetime_seconds)

        # Build SAN extension
        san_entries = [x509.DNSName(name)]
        for san in san_names:
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(san)))
            except ValueError:
                san_entries.append(x509.DNSName(san))

        # Build and sign certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IC-AGI"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(entity_key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(expires)
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    key_cert_sign=False, crl_sign=False,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._ca_private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = entity_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        return TLSIdentity(
            identity_name=name,
            cert_pem=cert_pem,
            key_pem=key_pem,
            ca_cert_pem=self._ca_cert_pem,
            expires_at=expires.timestamp(),
            serial_number=serial,
        )

    def _issue_simulated(self, name: str, serial: int, san_names: List[str]) -> TLSIdentity:
        """Issue a simulated certificate (no cryptography lib)."""
        entity_secret = os.urandom(32)
        entity_id = hashlib.sha256(entity_secret).hexdigest()[:16]

        # Sign the identity with the CA secret
        sig_data = f"{name}:{serial}:{entity_id}".encode()
        signature = hmac.new(self._ca_secret, sig_data, hashlib.sha256).hexdigest()

        cert_pem = (
            f"-----BEGIN CERTIFICATE-----\n"
            f"IC-AGI-SIMULATED-CERT-{entity_id}\n"
            f"CN={name}, O=IC-AGI\n"
            f"Serial={serial}\n"
            f"SAN={','.join(san_names)}\n"
            f"Signature={signature}\n"
            f"-----END CERTIFICATE-----\n"
        ).encode()

        key_pem = (
            f"-----BEGIN PRIVATE KEY-----\n"
            f"IC-AGI-SIMULATED-KEY-{entity_secret.hex()}\n"
            f"-----END PRIVATE KEY-----\n"
        ).encode()

        now = time.time()
        return TLSIdentity(
            identity_name=name,
            cert_pem=cert_pem,
            key_pem=key_pem,
            ca_cert_pem=self._ca_cert_pem,
            expires_at=now + self.cert_lifetime_seconds,
            serial_number=serial,
        )

    def verify_identity(self, identity: TLSIdentity) -> bool:
        """
        Verify that an identity was issued by this CA.

        Args:
            identity: The TLSIdentity to verify.

        Returns:
            True if the certificate was signed by this CA.
        """
        if self._use_real_crypto:
            return self._verify_real(identity)
        return self._verify_simulated(identity)

    def _verify_real(self, identity: TLSIdentity) -> bool:
        """Verify using cryptography library."""
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes

        try:
            cert = x509.load_pem_x509_certificate(identity.cert_pem)
            ca_public_key = self._ca_cert.public_key()
            # Verify the certificate signature
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except Exception:
            return False

    def _verify_simulated(self, identity: TLSIdentity) -> bool:
        """Verify simulated certificate."""
        try:
            cert_text = identity.cert_pem.decode()
            for line in cert_text.split("\n"):
                if line.startswith("Signature="):
                    stored_sig = line.split("=", 1)[1]
                    # Reconstruct expected signature
                    name = identity.identity_name
                    serial = identity.serial_number
                    # Extract entity ID from cert
                    for l2 in cert_text.split("\n"):
                        if "SIMULATED-CERT-" in l2:
                            entity_id = l2.split("SIMULATED-CERT-")[1].strip()
                            sig_data = f"{name}:{serial}:{entity_id}".encode()
                            expected = hmac.new(
                                self._ca_secret, sig_data, hashlib.sha256
                            ).hexdigest()
                            return hmac.compare_digest(stored_sig, expected)
            return False
        except Exception:
            return False

    def revoke_identity(self, name: str) -> bool:
        """Revoke an identity by name."""
        if name in self._issued:
            identity = self._issued[name]
            self._revoked[identity.serial_number] = time.time()
            return True
        return False

    def is_revoked(self, serial: int) -> bool:
        """Check if a serial number has been revoked."""
        return serial in self._revoked

    def get_server_config(self, name: str) -> TLSConfig:
        """Get TLS configuration for a server identity."""
        if name not in self._issued:
            raise KeyError(f"Identity '{name}' not found. Issue it first.")
        return TLSConfig(identity=self._issued[name])

    def get_client_config(self, name: str) -> TLSConfig:
        """Get TLS configuration for a client identity."""
        if name not in self._issued:
            raise KeyError(f"Identity '{name}' not found. Issue it first.")
        return TLSConfig(
            identity=self._issued[name],
            check_hostname=False,
        )

    @property
    def ca_cert_pem(self) -> bytes:
        """The CA certificate in PEM format (public, shareable)."""
        return self._ca_cert_pem

    def get_issued_identities(self) -> Dict[str, Dict[str, Any]]:
        """Return metadata about all issued identities (no key material)."""
        return {
            name: {
                "serial_number": ident.serial_number,
                "fingerprint": ident.fingerprint,
                "created_at": ident.created_at,
                "expires_at": ident.expires_at,
                "revoked": self.is_revoked(ident.serial_number),
            }
            for name, ident in self._issued.items()
        }
