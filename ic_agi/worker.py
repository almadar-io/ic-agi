"""
IC-AGI — Worker Execution Stub
================================

Workers execute IR segments in a sandboxed environment.
Each worker:
  1. Receives an IR segment from the Scheduler.
  2. Validates that it holds a valid capability token.
  3. Executes each instruction in the segment.
  4. Returns the resulting state to the ControlPlane.

SECURITY RATIONALE:
- Workers only see their assigned segment, never the full function.
- Workers must present a valid, unexpired capability token.
- All execution is logged to the append-only audit trail.
- Workers operate in an execution sandbox (in production, this would
  be a memory-isolated, network-restricted container).

MOCK NOTICE:
This stub simulates execution with a simple register machine.
Production workers would run in hardware-isolated enclaves
(e.g., SGX, TrustZone, or confidential VMs).
"""

from typing import Any, Dict, Optional
from dataclasses import dataclass, field
import uuid
import time

from .ir_definition import IRInstruction, IRSegment, IROpCode
from .audit_log import AuditLog
from .sandbox_executor import SandboxExecutor, SandboxConfig


@dataclass
class WorkerResult:
    """Result of executing an IR segment on a worker."""
    worker_id: str
    segment_id: str
    success: bool
    state: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time_ms: float = 0.0


class Worker:
    """
    A distributed execution worker.
    
    SECURITY RATIONALE:
    - Each worker has a unique ID for audit tracking.
    - Workers validate capability tokens before execution.
    - Execution is time-bounded to prevent resource exhaustion.
    - State is isolated per-segment execution.
    """

    def __init__(self, worker_id: Optional[str] = None, audit_log: Optional[AuditLog] = None, signing_key: Optional[bytes] = None):
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.audit_log = audit_log
        self._signing_key = signing_key  # HMAC key for token verification
        self._registers: Dict[str, Any] = {}  # Virtual register file
        self._sandbox = SandboxExecutor()  # Phase 7: real code execution

    def execute_segment(
        self,
        segment: IRSegment,
        capability_token: Optional[Dict] = None,
        initial_state: Optional[Dict[str, Any]] = None
    ) -> WorkerResult:
        """
        Execute an IR segment.
        
        SECURITY RATIONALE:
        - Capability token is validated before any instruction executes.
        - Each instruction is executed in isolation within the register file.
        - Execution time is measured for anomaly detection.
        
        Args:
            segment: The IR segment to execute.
            capability_token: The capability token authorizing this execution.
            initial_state: Any pre-loaded state (e.g., from a previous segment).
        
        Returns:
            WorkerResult with the output state.
        """
        start_time = time.time()

        # ── Capability Validation ──
        # SECURITY: No execution without a valid capability token
        if capability_token is None:
            self._log("REJECTED", segment.segment_id, "No capability token provided")
            return WorkerResult(
                worker_id=self.worker_id,
                segment_id=segment.segment_id,
                success=False,
                error="SECURITY: Execution rejected — no capability token"
            )

        if not self._validate_capability(capability_token, segment):
            self._log("REJECTED", segment.segment_id, "Invalid capability token")
            return WorkerResult(
                worker_id=self.worker_id,
                segment_id=segment.segment_id,
                success=False,
                error="SECURITY: Execution rejected — invalid/expired capability"
            )

        # ── Initialize Register State ──
        self._registers = {}
        if initial_state:
            self._registers.update(initial_state)

        self._log("EXEC_START", segment.segment_id, f"Executing {len(segment.instructions)} instructions")

        # ── Execute Instructions ──
        try:
            for instr in segment.instructions:
                self._execute_instruction(instr)
        except Exception as e:
            self._log("EXEC_ERROR", segment.segment_id, str(e))
            return WorkerResult(
                worker_id=self.worker_id,
                segment_id=segment.segment_id,
                success=False,
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )

        elapsed = (time.time() - start_time) * 1000
        self._log("EXEC_COMPLETE", segment.segment_id, f"Completed in {elapsed:.2f}ms")

        return WorkerResult(
            worker_id=self.worker_id,
            segment_id=segment.segment_id,
            success=True,
            state=dict(self._registers),
            execution_time_ms=elapsed
        )

    def _execute_instruction(self, instr: IRInstruction):
        """
        Execute a single IR instruction.
        
        SECURITY RATIONALE:
        - Only whitelisted opcodes are supported.
        - Division by zero is checked.
        - Unknown opcodes raise an error (fail-safe).
        """
        op = instr.opcode

        if op == IROpCode.CONST:
            # Load a constant value into a register
            self._registers[instr.output] = instr.operands[0]

        elif op == IROpCode.ADD:
            a = self._resolve(instr.operands[0])
            b = self._resolve(instr.operands[1])
            self._registers[instr.output] = a + b

        elif op == IROpCode.SUB:
            a = self._resolve(instr.operands[0])
            b = self._resolve(instr.operands[1])
            self._registers[instr.output] = a - b

        elif op == IROpCode.MUL:
            a = self._resolve(instr.operands[0])
            b = self._resolve(instr.operands[1])
            self._registers[instr.output] = a * b

        elif op == IROpCode.DIV:
            a = self._resolve(instr.operands[0])
            b = self._resolve(instr.operands[1])
            if b == 0:
                raise ArithmeticError("SECURITY: Division by zero blocked")
            self._registers[instr.output] = a / b

        elif op == IROpCode.LOAD:
            var_name = instr.operands[0]
            if var_name not in self._registers:
                raise KeyError(f"SECURITY: Attempted to load undefined variable: {var_name}")
            self._registers[instr.output] = self._registers[var_name]

        elif op == IROpCode.STORE:
            value = self._resolve(instr.operands[0])
            self._registers[instr.output] = value

        elif op == IROpCode.RETURN:
            # Mark the return value
            var_name = instr.operands[0]
            self._registers["__return__"] = self._resolve(var_name)

        elif op == IROpCode.COMPARE:
            a = self._resolve(instr.operands[0])
            b = self._resolve(instr.operands[1])
            self._registers[instr.output] = (a == b)

        elif op == IROpCode.BRANCH:
            # MOCK: branches are no-ops in linear segment execution
            pass

        elif op == IROpCode.EXEC_CODE:
            # Phase 7: Execute real Python code in the sandbox
            code_str = instr.operands[0]
            output_names = instr.operands[1] if len(instr.operands) > 1 else []
            embedded_inputs = instr.operands[2] if len(instr.operands) > 2 else {}

            # Merge: embedded inputs take priority, then register state
            sandbox_inputs = dict(self._registers)
            if isinstance(embedded_inputs, dict):
                sandbox_inputs.update(embedded_inputs)

            self._log("SANDBOX_EXEC", "n/a",
                      f"Executing {len(code_str)} chars of sandboxed code")

            sb_result = self._sandbox.execute(
                code=code_str,
                inputs=sandbox_inputs,
                output_names=output_names or None,
            )

            if not sb_result.success:
                raise RuntimeError(
                    f"SANDBOX_FAILED: {sb_result.error}; "
                    f"rejects={sb_result.rejected_constructs}"
                )

            # Merge sandbox outputs back into registers
            self._registers.update(sb_result.outputs)

        else:
            raise ValueError(f"SECURITY: Unknown opcode rejected: {op}")

    def _resolve(self, operand: Any) -> Any:
        """Resolve an operand — either a register reference or a literal value."""
        if isinstance(operand, str) and operand in self._registers:
            return self._registers[operand]
        return operand

    def _validate_capability(self, token: Dict, segment: IRSegment) -> bool:
        """
        Validate a capability token against the segment requirements.
        
        SECURITY RATIONALE:
        - HMAC-SHA256 signature is verified (forgery detection).
        - Tokens must not be expired (TTL check).
        - Token scope must include the required capabilities.
        - Token must not have been revoked.
        """
        # ── HMAC Signature Verification ──
        if self._signing_key and "signature" in token:
            from .control_plane import CapabilityToken as CT
            temp = CT(
                token_id=token.get("token_id", ""),
                issued_to=token.get("issued_to", ""),
                scope=token.get("scope", []),
                issued_at=token.get("issued_at", 0),
                expires_at=token.get("expires_at", 0),
                budget=token.get("budget", 0),
                signature=token.get("signature", ""),
            )
            if not temp.verify(self._signing_key):
                return False

        # Check expiry
        if "expires_at" in token:
            if time.time() > token["expires_at"]:
                return False

        # Check scope
        if "scope" in token:
            for req_cap in segment.required_capabilities:
                if req_cap not in token["scope"]:
                    return False

        # Check revocation
        if token.get("revoked", False):
            return False

        return True

    def _log(self, event_type: str, segment_id: str, detail: str):
        """Log an event to the audit trail."""
        if self.audit_log:
            self.audit_log.append_entry({
                "source": "Worker",
                "worker_id": self.worker_id,
                "event": event_type,
                "segment_id": segment_id,
                "detail": detail,
            })
