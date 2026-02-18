"""
IC-AGI — Threshold Authorization Simulation
=============================================

Simulates K-of-N threshold approval for critical actions.
Before any critical action can execute, at least K out of N
independent approvers must sign off.

SECURITY RATIONALE:
- No single approver can authorize a critical action alone.
- Approvers are independent entities (different organizations,
  jurisdictions, or hardware security modules).
- Compromising < K approvers does not allow critical execution.
- Each approval includes a cryptographic signature (mocked here).

MOCK NOTICE:
This uses simple boolean votes. Production would use:
  - Threshold Schnorr / BLS signatures
  - Hardware security module (HSM) backed signing
  - Time-locked approval windows
  - Anti-coercion mechanisms
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .audit_log import AuditLog


@dataclass
class ApprovalRequest:
    """
    A request for threshold approval of a critical action.
    
    SECURITY RATIONALE:
    - Each request has a unique ID for tracking.
    - The action description is immutable once created.
    - Approvals are time-bounded (TTL).
    - The request records which approvers have voted.
    """
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_description: str = ""
    criticality: str = "critical"
    requester: str = ""
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = 300.0  # 5 minute window to collect approvals
    approvals: Dict[str, bool] = field(default_factory=dict)  # approver_id -> vote
    resolved: bool = False
    resolution: Optional[str] = None  # "approved" | "denied" | "expired"


class ThresholdAuthorizer:
    """
    K-of-N threshold authorization system.
    
    SECURITY RATIONALE:
    - K and N are set at initialization and cannot be changed
      without governance approval (not implemented in MVP).
    - Each approver is identified by a unique ID.
    - Approvals are time-bounded to prevent stale authorizations.
    - All approval events are logged to the audit trail.
    """

    def __init__(
        self,
        approver_ids: List[str],
        threshold: int,
        audit_log: Optional[AuditLog] = None
    ):
        """
        Args:
            approver_ids: List of unique approver identifiers.
            threshold: Minimum number of approvals required (K).
            audit_log: Audit log for recording approval events.
        
        SECURITY RATIONALE:
        - threshold must be >= 2 (no unilateral approval)
        - threshold must be <= len(approver_ids) (must be achievable)
        """
        if threshold < 2:
            raise ValueError("Threshold must be >= 2 (no unilateral authority)")
        if threshold > len(approver_ids):
            raise ValueError("Threshold cannot exceed number of approvers")

        self.approver_ids = list(approver_ids)
        self.threshold = threshold  # K
        self.total = len(approver_ids)  # N
        self.audit_log = audit_log
        self._pending: Dict[str, ApprovalRequest] = {}

    def create_request(self, action_description: str, requester: str, criticality: str = "critical") -> ApprovalRequest:
        """
        Create a new approval request.
        
        SECURITY RATIONALE:
        - The request is logged immediately upon creation.
        - The action description is frozen at creation time.
        """
        req = ApprovalRequest(
            action_description=action_description,
            criticality=criticality,
            requester=requester
        )
        self._pending[req.request_id] = req

        self._log("APPROVAL_REQUEST_CREATED", {
            "request_id": req.request_id,
            "action": action_description,
            "criticality": criticality,
            "requester": requester,
            "threshold": f"{self.threshold}-of-{self.total}"
        })

        return req

    def submit_vote(self, request_id: str, approver_id: str, vote: bool) -> Dict[str, Any]:
        """
        Submit an approval vote for a pending request.
        
        Args:
            request_id: The request to vote on.
            approver_id: The approver casting the vote.
            vote: True = approve, False = deny.
        
        Returns:
            Status dict with current vote tally and resolution.
        
        SECURITY RATIONALE:
        - Only registered approvers can vote.
        - Each approver can only vote once per request.
        - Expired requests cannot receive votes.
        - A single denial can optionally veto (configurable, not in MVP).
        """
        if request_id not in self._pending:
            raise KeyError(f"Unknown request: {request_id}")

        req = self._pending[request_id]

        if req.resolved:
            return {"status": "already_resolved", "resolution": req.resolution}

        # Check expiry
        if time.time() - req.created_at > req.ttl_seconds:
            req.resolved = True
            req.resolution = "expired"
            self._log("APPROVAL_EXPIRED", {"request_id": request_id})
            return {"status": "expired"}

        # Validate approver
        if approver_id not in self.approver_ids:
            self._log("INVALID_APPROVER", {
                "request_id": request_id,
                "approver_id": approver_id
            })
            raise PermissionError(f"Unknown approver: {approver_id}")

        # Prevent double-voting
        if approver_id in req.approvals:
            return {"status": "already_voted", "vote": req.approvals[approver_id]}

        # Record vote
        req.approvals[approver_id] = vote
        self._log("VOTE_CAST", {
            "request_id": request_id,
            "approver_id": approver_id,
            "vote": "APPROVE" if vote else "DENY"
        })

        # Check resolution
        approve_count = sum(1 for v in req.approvals.values() if v)
        deny_count = sum(1 for v in req.approvals.values() if not v)

        result = {
            "status": "pending",
            "approvals": approve_count,
            "denials": deny_count,
            "threshold": self.threshold,
            "remaining": max(0, self.threshold - approve_count)
        }

        # Threshold reached → approved
        if approve_count >= self.threshold:
            req.resolved = True
            req.resolution = "approved"
            result["status"] = "approved"
            self._log("APPROVAL_GRANTED", {
                "request_id": request_id,
                "action": req.action_description,
                "approvals": approve_count,
                "threshold": self.threshold
            })

        # Too many denials → denied (impossible to reach threshold)
        elif deny_count > (self.total - self.threshold):
            req.resolved = True
            req.resolution = "denied"
            result["status"] = "denied"
            self._log("APPROVAL_DENIED", {
                "request_id": request_id,
                "action": req.action_description,
                "denials": deny_count
            })

        return result

    def is_approved(self, request_id: str) -> bool:
        """Check if a request has been approved."""
        if request_id not in self._pending:
            return False
        req = self._pending[request_id]
        return req.resolved and req.resolution == "approved"

    def _log(self, event: str, data: Dict[str, Any]):
        """Log to audit trail."""
        if self.audit_log:
            self.audit_log.append_entry({
                "source": "ThresholdAuthorizer",
                "event": event,
                **data
            })
