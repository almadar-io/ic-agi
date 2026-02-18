"""
IC-AGI — FastAPI Service Layer
================================

Exposes the IC-AGI distributed execution system as HTTP endpoints.
This is the entry point for the containerized deployment.

MODES:
  - ``full``    — runs control-plane + in-process workers (testing)
  - ``control`` — control-plane only; dispatches segments to remote worker pods
  - ``worker``  — worker node; accepts segments via ``/worker/execute``

Endpoints (all modes):
  GET  /health           — Kubernetes liveness / readiness probe
  GET  /status           — System status

Endpoints (control / full):
  POST /execute          — Execute an IR function through the pipeline
  POST /approval/create  — Create a threshold-approval request
  POST /approval/vote    — Submit a vote on a pending approval
  GET  /audit            — Query the audit trail
  POST /shares/split     — Split a value into Shamir shares
  POST /shares/reconstruct/{key}

Endpoints (worker / full):
  POST /worker/execute   — Receive and execute a single IR segment
"""

import base64
import os
import json
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ic_agi.ir_definition import (
    IRFunction, IRInstruction, IROpCode, IRSegment,
    build_add_function, build_code_function, FUNCTION_CATALOG
)
from ic_agi.share_manager import ShareManager
from ic_agi.audit_log import AuditLog
from ic_agi.threshold_auth import ThresholdAuthorizer
from ic_agi.control_plane import ControlPlane
from ic_agi.worker import Worker
from ic_agi.scheduler import Scheduler
from ic_agi.crypto_utils import encrypt_state, decrypt_state
from ic_agi.rate_limiter import RateLimiter, RateLimitConfig
from ic_agi.anti_oracle import AntiOracleDetector, AntiOracleConfig
from ic_agi.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from ic_agi.sandbox_executor import SandboxExecutor, validate_ast


# ── App Configuration ──

NODE_ID = os.environ.get("IC_AGI_NODE_ID", "node-0")
NODE_ROLE = os.environ.get("IC_AGI_NODE_ROLE", "full")  # "control", "worker", "full"
NUM_WORKERS = int(os.environ.get("IC_AGI_NUM_WORKERS", "3"))
THRESHOLD_K = int(os.environ.get("IC_AGI_THRESHOLD_K", "2"))
THRESHOLD_N = int(os.environ.get("IC_AGI_THRESHOLD_N", "3"))
DISTRIBUTED = os.environ.get("IC_AGI_DISTRIBUTED", "false").lower() == "true"
SIGNING_KEY_B64 = os.environ.get("IC_AGI_SIGNING_KEY", "")

app = FastAPI(
    title="IC-AGI Distributed Execution",
    description="Infrastructure Critical Anti-AGI — Separating Intelligence from Authority",
    version="0.2.0"
)

# ── Initialize Components ──

audit_log = AuditLog()

approver_ids = [f"approver-{i}" for i in range(THRESHOLD_N)]
threshold_auth = ThresholdAuthorizer(
    approver_ids=approver_ids,
    threshold=THRESHOLD_K,
    audit_log=audit_log
)

# If a shared signing key is provided (distributed mode), use it;
# otherwise ControlPlane generates one at random (single-process mode).
_shared_key: Optional[bytes] = None
if SIGNING_KEY_B64:
    _shared_key = base64.b64decode(SIGNING_KEY_B64)

# ── Phase 6: Rate Limiter, Anti-Oracle, Circuit Breaker ──
rate_limiter = RateLimiter(
    config=RateLimitConfig(
        max_requests=int(os.environ.get("IC_AGI_RATE_LIMIT", "50")),
        window_seconds=float(os.environ.get("IC_AGI_RATE_WINDOW", "60")),
        cooldown_seconds=float(os.environ.get("IC_AGI_RATE_COOLDOWN", "30")),
    ),
    audit_log=audit_log,
)

anti_oracle = AntiOracleDetector(
    config=AntiOracleConfig(
        window_seconds=120.0,
        max_identical_queries=int(os.environ.get("IC_AGI_ORACLE_MAX_IDENTICAL", "10")),
        max_similar_queries=int(os.environ.get("IC_AGI_ORACLE_MAX_SIMILAR", "50")),
        suspicion_threshold=0.8,
        alert_threshold=0.5,
    ),
    audit_log=audit_log,
)

circuit_breaker = CircuitBreaker(
    config=CircuitBreakerConfig(
        failure_threshold=int(os.environ.get("IC_AGI_CB_FAILURES", "3")),
        recovery_timeout=float(os.environ.get("IC_AGI_CB_RECOVERY", "30")),
    ),
    audit_log=audit_log,
)

control_plane = ControlPlane(
    threshold_authorizer=threshold_auth,
    audit_log=audit_log,
    default_ttl=120.0,
    default_budget=5,
    signing_key=_shared_key,
    rate_limiter=rate_limiter,
)

# ── Build the worker pool ──
# In distributed mode the control-plane creates RemoteWorker instances
# that send HTTP requests to the StatefulSet worker pods.
# In "full" or "worker" mode we also create a local Worker for the
# /worker/execute endpoint.

if DISTRIBUTED and NODE_ROLE == "control":
    from ic_agi.remote_worker import RemoteWorker
    _worker_base = "ic-agi-worker-{i}.ic-agi-worker-headless.ic-agi.svc.cluster.local"
    workers: list = [
        RemoteWorker(
            worker_id=f"ic-agi-worker-{i}",
            base_url=f"http://{_worker_base.format(i=i)}:8080",
            signing_key=control_plane.signing_key,
            audit_log=audit_log,
        )
        for i in range(NUM_WORKERS)
    ]
else:
    workers = [
        Worker(worker_id=f"worker-{i}", audit_log=audit_log,
               signing_key=control_plane.signing_key)
        for i in range(NUM_WORKERS)
    ]

# Local worker for the /worker/execute endpoint (used by worker pods)
local_worker = Worker(
    worker_id=NODE_ID,
    audit_log=audit_log,
    signing_key=control_plane.signing_key,
)

share_manager = ShareManager(num_nodes=THRESHOLD_N, threshold=THRESHOLD_K)

scheduler = Scheduler(
    control_plane=control_plane,
    workers=workers,
    audit_log=audit_log,
    num_segments=min(NUM_WORKERS, 3),
    circuit_breaker=circuit_breaker,
)

START_TIME = time.time()

audit_log.append_entry({
    "source": "Service",
    "event": "NODE_STARTED",
    "node_id": NODE_ID,
    "role": NODE_ROLE,
    "distributed": DISTRIBUTED,
    "workers": NUM_WORKERS,
    "threshold": f"{THRESHOLD_K}-of-{THRESHOLD_N}"
})


# ── Request / Response Models ──

class ExecuteRequest(BaseModel):
    """Request to execute a function."""
    function_name: str = "add"
    operand_a: float = 3.0
    operand_b: float = 7.0
    criticality: str = "low"
    approval_request_id: Optional[str] = None
    caller_id: str = "anonymous"  # Anti-oracle tracks per caller
    # Phase 7: Support for real code execution
    code: Optional[str] = None              # Custom code (function_name="custom")
    inputs: Optional[Dict[str, Any]] = None  # Arbitrary input bindings
    output_names: Optional[List[str]] = None # Variables to return


class ApprovalVoteRequest(BaseModel):
    """Submit a threshold approval vote."""
    request_id: str
    approver_id: str
    vote: bool


class CreateApprovalRequest(BaseModel):
    """Request threshold approval for a critical action."""
    action_description: str
    requester: str
    criticality: str = "critical"


class AuditQuery(BaseModel):
    """Query parameters for audit log."""
    source: Optional[str] = None
    event: Optional[str] = None
    limit: int = 50


class ShareRequest(BaseModel):
    """Request to split a value into shares."""
    key: str
    value: float


class WorkerExecuteRequest(BaseModel):
    """Inbound request to execute a segment on this worker pod."""
    segment: Dict[str, Any]
    capability_token: Optional[Dict[str, Any]] = None
    encrypted_state: Optional[Dict[str, str]] = None


# ── Endpoints ──

@app.get("/health")
async def health_check():
    """Kubernetes liveness/readiness probe."""
    return {
        "status": "healthy",
        "node_id": NODE_ID,
        "role": NODE_ROLE,
        "distributed": DISTRIBUTED,
        "uptime_seconds": round(time.time() - START_TIME, 2)
    }


@app.get("/status")
async def system_status():
    """Full system status."""
    return {
        "node_id": NODE_ID,
        "role": NODE_ROLE,
        "distributed": DISTRIBUTED,
        "workers": NUM_WORKERS,
        "threshold": f"{THRESHOLD_K}-of-{THRESHOLD_N}",
        "audit_entries": len(audit_log),
        "audit_integrity": audit_log.verify_integrity(),
        "uptime_seconds": round(time.time() - START_TIME, 2)
    }


@app.post("/execute")
async def execute_function(req: ExecuteRequest):
    """
    Execute an IR function through the distributed pipeline.
    
    For MVP, supports 'add' function. In production, this would
    accept arbitrary IR definitions.
    """
    audit_log.append_entry({
        "source": "API",
        "event": "EXECUTE_REQUEST",
        "function": req.function_name,
        "operands": [req.operand_a, req.operand_b],
        "criticality": req.criticality
    })

    # ── Phase 6: Anti-Oracle Detection ──
    oracle_verdict = anti_oracle.check(
        entity=req.caller_id,
        function_name=req.function_name,
        operands=[req.operand_a, req.operand_b],
    )
    if not oracle_verdict["allowed"]:
        raise HTTPException(
            status_code=429,
            detail=f"SECURITY: Request blocked by anti-oracle detector. "
                   f"Reason: {oracle_verdict['reason']}. "
                   f"Flags: {oracle_verdict['flags']}"
        )

    if req.function_name == "add":
        fn = build_add_function(req.operand_a, req.operand_b)
    elif req.function_name in FUNCTION_CATALOG and req.function_name != "add":
        cat = FUNCTION_CATALOG[req.function_name]

        if req.function_name == "custom":
            # Custom code execution — code must be provided
            if not req.code:
                raise HTTPException(
                    status_code=400,
                    detail="function_name='custom' requires the 'code' field."
                )
            # Static validation before building IR
            ast_errors = validate_ast(req.code)
            if ast_errors:
                raise HTTPException(
                    status_code=400,
                    detail=f"SANDBOX_REJECT: {ast_errors}"
                )
            fn = build_code_function(
                code=req.code,
                inputs=req.inputs or {},
                output_names=req.output_names or [],
                name="custom_exec",
                capabilities=["compute.sandbox"],
            )
        else:
            # Catalog function — build from template
            code_template = cat["code"]
            input_names = cat["inputs"]
            output_ns = cat["outputs"]

            # Map request params to function inputs
            input_bindings: Dict[str, Any] = {}
            if req.inputs:
                input_bindings = req.inputs
            else:
                # Fallback: map operand_a / operand_b to first two inputs
                if len(input_names) >= 1:
                    input_bindings[input_names[0]] = req.operand_a
                if len(input_names) >= 2:
                    input_bindings[input_names[1]] = req.operand_b

            fn = build_code_function(
                code=code_template,
                inputs=input_bindings,
                output_names=output_ns,
                name=req.function_name,
                capabilities=cat.get("capabilities", ["compute.sandbox"]),
            )
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown function: {req.function_name}. "
                   f"Available: {list(FUNCTION_CATALOG.keys())}"
        )

    fn.criticality = req.criticality

    # SECURITY: Early gate — reject critical execution requests without approval
    if req.criticality in ("high", "critical") and not req.approval_request_id:
        raise HTTPException(
            status_code=403,
            detail="SECURITY: Critical execution requires threshold approval. "
                   "Create an approval request via /approval/create first."
        )

    try:
        result = scheduler.execute_function(
            fn,
            approval_request_id=req.approval_request_id
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))

    # SECURITY: If the scheduler reports failure (e.g. denied approval),
    # surface it as a proper HTTP error, not a 200.
    if not result.get("success", False):
        status = 403 if "approval" in result.get("error", "").lower() or \
                        "SECURITY" in result.get("error", "") else 500
        raise HTTPException(status_code=status, detail=result.get("error", "Execution failed"))

    return result


@app.post("/approval/create")
async def create_approval(req: CreateApprovalRequest):
    """Create a new threshold approval request."""
    approval = threshold_auth.create_request(
        action_description=req.action_description,
        requester=req.requester,
        criticality=req.criticality
    )
    return {
        "request_id": approval.request_id,
        "action": approval.action_description,
        "threshold": f"{THRESHOLD_K}-of-{THRESHOLD_N}",
        "ttl_seconds": approval.ttl_seconds
    }


@app.post("/approval/vote")
async def submit_vote(req: ApprovalVoteRequest):
    """Submit a vote on a pending approval request."""
    try:
        result = threshold_auth.submit_vote(
            req.request_id, req.approver_id, req.vote
        )
        return result
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))


@app.get("/audit")
async def get_audit(source: Optional[str] = None, event: Optional[str] = None, limit: int = 50):
    """Query the append-only audit trail."""
    entries = audit_log.get_entries(source=source, event=event, limit=limit)
    return {
        "total_entries": len(audit_log),
        "integrity": audit_log.verify_integrity(),
        "entries": [
            {
                "index": e.index,
                "timestamp": e.timestamp,
                "data": e.data,
                "hash": e.entry_hash[:16] + "..."
            }
            for e in entries
        ]
    }


@app.post("/shares/split")
async def split_value(req: ShareRequest):
    """Split a value into distributed shares."""
    shares = share_manager.split(req.key, req.value)
    return {
        "key": req.key,
        "num_shares": len(shares),
        "threshold": share_manager.threshold,
        "shares": [
            {
                "share_id": s.share_id,
                "owner_node": s.owner_node,
                "share_index": s.share_index,
                # NOTE: In production, share values would NOT be exposed via API
                "value_preview": f"{s.value:.4f}..."
            }
            for s in shares
        ]
    }


@app.post("/shares/reconstruct/{key}")
async def reconstruct_value(key: str):
    """Reconstruct a value from its shares (requires threshold)."""
    try:
        value = share_manager.reconstruct(key)
        return {"key": key, "reconstructed_value": value}
    except (KeyError, PermissionError) as e:
        raise HTTPException(status_code=403, detail=str(e))


# ── Worker Execution Endpoint (served by worker pods) ──

@app.post("/worker/execute")
async def worker_execute(req: WorkerExecuteRequest):
    """
    Execute a single IR segment on this worker pod.

    SECURITY:
      - Decrypts inbound state, validates the HMAC tag.
      - Validates the capability token (HMAC signature + expiry + scope).
      - Executes the segment in a sandboxed register machine.
      - Encrypts the result state before returning.

    This endpoint is called by the control-plane's RemoteWorker client.
    """
    # ── Deserialize segment ──
    segment = IRSegment.from_dict(req.segment)

    # ── Decrypt inbound state ──
    initial_state: Dict[str, Any] = {}
    if req.encrypted_state:
        try:
            initial_state = decrypt_state(
                req.encrypted_state, control_plane.signing_key
            )
        except ValueError as ve:
            raise HTTPException(status_code=403, detail=str(ve))

    # ── Execute locally ──
    result = local_worker.execute_segment(
        segment=segment,
        capability_token=req.capability_token,
        initial_state=initial_state,
    )

    # ── Encrypt outbound state ──
    encrypted_out = None
    if result.success:
        encrypted_out = encrypt_state(result.state, control_plane.signing_key)

    return {
        "worker_id": local_worker.worker_id,
        "segment_id": result.segment_id,
        "success": result.success,
        "error": result.error,
        "execution_time_ms": result.execution_time_ms,
        "state": result.state if not encrypted_out else None,
        "encrypted_state": encrypted_out,
    }


# ── Phase 6: Security Monitoring Endpoints ──

@app.get("/security/rate-limit/{entity}")
async def rate_limit_status(entity: str):
    """Query rate-limit status for an entity."""
    return rate_limiter.get_status(entity)


@app.post("/security/rate-limit/{entity}/reset")
async def rate_limit_reset(entity: str):
    """Admin: reset rate-limit counters for an entity."""
    rate_limiter.reset(entity)
    return {"reset": True, "entity": entity}


@app.get("/security/oracle/{entity}")
async def oracle_status(entity: str):
    """Query anti-oracle suspicion score for an entity."""
    return anti_oracle.get_status(entity)


@app.post("/security/oracle/{entity}/block")
async def oracle_block(entity: str):
    """Admin: manually block an entity suspected of oracle attacks."""
    anti_oracle.block(entity, duration=300.0)
    return {"blocked": True, "entity": entity, "duration_seconds": 300}


@app.post("/security/oracle/{entity}/unblock")
async def oracle_unblock(entity: str):
    """Admin: unblock an entity."""
    anti_oracle.unblock(entity)
    return {"unblocked": True, "entity": entity}


@app.get("/security/circuit-breaker")
async def circuit_breaker_status_all():
    """Query circuit-breaker status for all workers."""
    return {"workers": circuit_breaker.get_all_status()}


@app.get("/security/circuit-breaker/{worker_id}")
async def circuit_breaker_status(worker_id: str):
    """Query circuit-breaker status for a specific worker."""
    return circuit_breaker.get_status(worker_id)


@app.post("/security/circuit-breaker/{worker_id}/trip")
async def circuit_breaker_trip(worker_id: str):
    """Admin: manually trip a worker's circuit breaker."""
    circuit_breaker.force_open(worker_id, reason="manual_trip_via_api")
    return {"tripped": True, "worker_id": worker_id}


@app.post("/security/circuit-breaker/{worker_id}/reset")
async def circuit_breaker_reset(worker_id: str):
    """Admin: manually close a worker's circuit breaker."""
    circuit_breaker.force_close(worker_id)
    return {"reset": True, "worker_id": worker_id}


@app.get("/security/summary")
async def security_summary():
    """Full security subsystem status."""
    return {
        "rate_limiter": {
            "config": {
                "max_requests": rate_limiter.config.max_requests,
                "window_seconds": rate_limiter.config.window_seconds,
                "cooldown_seconds": rate_limiter.config.cooldown_seconds,
            }
        },
        "anti_oracle": {
            "config": {
                "max_identical_queries": anti_oracle.config.max_identical_queries,
                "max_similar_queries": anti_oracle.config.max_similar_queries,
                "suspicion_threshold": anti_oracle.config.suspicion_threshold,
            }
        },
        "circuit_breaker": {
            "workers": circuit_breaker.get_all_status(),
            "healthy_workers": circuit_breaker.healthy_workers(),
        },
    }


# ── Phase 7: Function Catalog & Code Validation Endpoints ──

class ValidateCodeRequest(BaseModel):
    """Request to statically validate code before execution."""
    code: str


@app.get("/functions")
async def list_functions():
    """List all available functions in the catalog."""
    catalog_info = {}
    for name, spec in FUNCTION_CATALOG.items():
        catalog_info[name] = {
            "description": spec["description"],
            "capabilities": spec.get("capabilities", []),
        }
        if "inputs" in spec:
            catalog_info[name]["inputs"] = spec["inputs"]
        if "outputs" in spec:
            catalog_info[name]["outputs"] = spec["outputs"]
    return {"functions": catalog_info}


@app.post("/validate")
async def validate_code(req: ValidateCodeRequest):
    """
    Static AST validation of code without executing it.
    Returns any security rejections found by the sandbox.
    """
    errors = validate_ast(req.code)
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "code_length": len(req.code),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
