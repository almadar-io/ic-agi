"""
IC-AGI — Control Plane (Capability Issuance)
==============================================

The ControlPlane is the authority layer of IC-AGI.
It issues capability tokens, enforces policies, and coordinates
between the ThresholdAuthorizer and the execution workers.

SECURITY RATIONALE:
- The ControlPlane does NOT execute user logic — it only governs.
- Capability tokens have TTL (time-to-live), scope, and budget limits.
- Tokens are short-lived and narrowly scoped by design.
- The ControlPlane logs every issuance and validation event.

SEPARATION OF CONCERNS:
- ControlPlane = WHO can do WHAT and for HOW LONG
- ExecutionPlane (Workers) = HOW things get done
- ThresholdAuthorizer = WHO approves CRITICAL actions

MOCK NOTICE:
Capability tokens are plain dictionaries. Production would use:
  - Signed JWT-like tokens with cryptographic verification
  - Macaroons for delegation and attenuation
  - Hardware-bound tokens (e.g., FIDO2/WebAuthn)
"""

import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional

from dataclasses import dataclass, field

from .audit_log import AuditLog
from .threshold_auth import ThresholdAuthorizer
from .rate_limiter import RateLimiter


@dataclass
class CapabilityToken:
    """
    A capability token authorizing a specific action.
    
    SECURITY RATIONALE:
    - Tokens are scoped: they only permit specific operations.
    - Tokens are time-limited: they expire after TTL seconds.
    - Tokens have budget limits: they can only be used N times.
    - Tokens are non-transferable (in production, cryptographically bound).
    """
    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    issued_to: str = ""            # Worker or entity ID
    scope: List[str] = field(default_factory=list)  # Permitted capability scopes
    issued_at: float = field(default_factory=time.time)
    ttl_seconds: float = 60.0      # Default: 1 minute
    expires_at: float = 0.0
    budget: int = 1                 # Number of allowed uses
    uses: int = 0                   # Current use count
    revoked: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""            # HMAC-SHA256 signature (hex)

    def __post_init__(self):
        if self.expires_at == 0.0:
            self.expires_at = self.issued_at + self.ttl_seconds

    def _signable_payload(self) -> bytes:
        """Canonical byte representation of the token's immutable fields for signing."""
        payload = {
            "token_id": self.token_id,
            "issued_to": self.issued_to,
            "scope": sorted(self.scope),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "budget": self.budget,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, key: bytes) -> None:
        """Sign this token with HMAC-SHA256. Called by ControlPlane at issuance."""
        self.signature = hmac.new(key, self._signable_payload(), hashlib.sha256).hexdigest()

    def verify(self, key: bytes) -> bool:
        """Verify the HMAC-SHA256 signature. Returns False if forged or tampered."""
        if not self.signature:
            return False
        expected = hmac.new(key, self._signable_payload(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def is_valid(self) -> bool:
        """Check if this token is currently valid."""
        if self.revoked:
            return False
        if time.time() > self.expires_at:
            return False
        if self.uses >= self.budget:
            return False
        return True

    def consume(self) -> bool:
        """
        Use one unit of this token's budget.
        Returns True if consumption succeeded, False if token is invalid.
        """
        if not self.is_valid():
            return False
        self.uses += 1
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for passing to workers."""
        return {
            "token_id": self.token_id,
            "issued_to": self.issued_to,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "budget": self.budget,
            "uses": self.uses,
            "revoked": self.revoked,
            "signature": self.signature,
        }


class ControlPlane:
    """
    The authority and governance layer of IC-AGI.
    
    Responsibilities:
    1. Issue capability tokens (with TTL, scope, budget).
    2. Validate capability tokens.
    3. Coordinate with ThresholdAuthorizer for critical actions.
    4. Enforce policies (rate limits, scope checks).
    5. Log all governance events.
    
    SECURITY RATIONALE:
    - The ControlPlane is the ONLY entity that can issue capabilities.
    - It is designed to be replicated (no single point of failure).
    - In production, the ControlPlane would itself require threshold
      approval for policy changes.
    """

    def __init__(
        self,
        threshold_authorizer: ThresholdAuthorizer,
        audit_log: AuditLog,
        default_ttl: float = 60.0,
        default_budget: int = 1,
        signing_key: Optional[bytes] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.authorizer = threshold_authorizer
        self.audit_log = audit_log
        self.default_ttl = default_ttl
        self.default_budget = default_budget
        self._tokens: Dict[str, CapabilityToken] = {}
        self._policies: Dict[str, Any] = {
            "max_ttl_seconds": 3600,      # 1 hour max
            "max_budget": 100,             # 100 uses max
            "critical_requires_approval": True,
        }
        # HMAC-SHA256 signing key — use provided key or generate from CSPRNG
        self._signing_key: bytes = signing_key or secrets.token_bytes(32)
        # Rate limiter — if None, no rate limiting is enforced
        self.rate_limiter: Optional[RateLimiter] = rate_limiter

    def issue_capability(
        self,
        issued_to: str,
        scope: List[str],
        ttl_seconds: Optional[float] = None,
        budget: Optional[int] = None,
        criticality: str = "low",
        approval_request_id: Optional[str] = None
    ) -> CapabilityToken:
        """
        Issue a new capability token.
        
        SECURITY RATIONALE:
        - TTL is capped by policy (cannot issue arbitrarily long tokens).
        - Budget is capped by policy (cannot issue unlimited-use tokens).
        - Critical capabilities require threshold approval.
        - Every issuance is logged to the audit trail.
        
        Args:
            issued_to: The entity receiving the capability.
            scope: List of permitted operation scopes.
            ttl_seconds: Time-to-live (defaults to policy default).
            budget: Number of allowed uses (defaults to policy default).
            criticality: "low", "medium", "high", "critical"
            approval_request_id: Required for critical capabilities.
        
        Returns:
            A CapabilityToken.
        
        Raises:
            PermissionError: If critical action lacks threshold approval.
            ValueError: If parameters violate policy.
        """
        ttl = ttl_seconds or self.default_ttl
        bud = budget or self.default_budget

        # ── Rate Limit Enforcement ──
        if self.rate_limiter:
            scope_key = ",".join(sorted(scope)) if scope else "*"
            if not self.rate_limiter.allow(issued_to, scope_key):
                self.audit_log.append_entry({
                    "source": "ControlPlane",
                    "event": "CAPABILITY_RATE_LIMITED",
                    "issued_to": issued_to,
                    "scope": scope,
                })
                raise PermissionError(
                    f"SECURITY: Rate limit exceeded for '{issued_to}'. "
                    f"Try again later."
                )

        # ── Policy Enforcement ──
        if ttl > self._policies["max_ttl_seconds"]:
            raise ValueError(
                f"POLICY: TTL {ttl}s exceeds maximum {self._policies['max_ttl_seconds']}s"
            )
        if bud > self._policies["max_budget"]:
            raise ValueError(
                f"POLICY: Budget {bud} exceeds maximum {self._policies['max_budget']}"
            )

        # ── Critical Action Gate ──
        if criticality in ("high", "critical") and self._policies["critical_requires_approval"]:
            if approval_request_id is None:
                raise PermissionError(
                    "SECURITY: Critical capabilities require threshold approval. "
                    "Submit an approval request first."
                )
            if not self.authorizer.is_approved(approval_request_id):
                raise PermissionError(
                    f"SECURITY: Approval request {approval_request_id} is not approved."
                )

        # ── Issue Token ──
        token = CapabilityToken(
            issued_to=issued_to,
            scope=scope,
            ttl_seconds=ttl,
            budget=bud,
            metadata={"criticality": criticality}
        )
        # HMAC-SHA256 signature — workers can verify authenticity
        token.sign(self._signing_key)
        self._tokens[token.token_id] = token

        self.audit_log.append_entry({
            "source": "ControlPlane",
            "event": "CAPABILITY_ISSUED",
            "token_id": token.token_id,
            "issued_to": issued_to,
            "scope": scope,
            "ttl": ttl,
            "budget": bud,
            "criticality": criticality
        })

        return token

    def validate_token(self, token_id: str) -> bool:
        """
        Validate a capability token.
        
        SECURITY RATIONALE:
        - Checks existence, expiry, budget, and revocation status.
        """
        if token_id not in self._tokens:
            return False
        return self._tokens[token_id].is_valid()

    def revoke_token(self, token_id: str, reason: str = ""):
        """
        Revoke a capability token immediately.
        
        SECURITY RATIONALE:
        - Revoked tokens are immediately invalid.
        - Revocation is logged to the audit trail.
        - Workers should check revocation status before each use.
        """
        if token_id in self._tokens:
            self._tokens[token_id].revoked = True
            self.audit_log.append_entry({
                "source": "ControlPlane",
                "event": "CAPABILITY_REVOKED",
                "token_id": token_id,
                "reason": reason
            })

    def get_token(self, token_id: str) -> Optional[CapabilityToken]:
        """Retrieve a token by ID."""
        return self._tokens.get(token_id)

    def verify_token_signature(self, token: CapabilityToken) -> bool:
        """Verify the HMAC-SHA256 signature of a capability token."""
        return token.verify(self._signing_key)

    @property
    def signing_key(self) -> bytes:
        """Expose signing key so workers in the same process can verify.
        In production, workers receive the key via a secure channel / HSM."""
        return self._signing_key
