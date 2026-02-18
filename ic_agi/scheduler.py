"""
IC-AGI — Scheduler for Routing IR Segments
=============================================

The Scheduler is responsible for:
  1. Taking an IR function and splitting it into segments.
  2. Assigning segments to available workers.
  3. Requesting capability tokens from the ControlPlane.
  4. Orchestrating execution and collecting results.
  5. Reassembling the final result from worker outputs.

SECURITY RATIONALE:
- The Scheduler coordinates but does NOT execute logic.
- It requests capabilities on behalf of workers (principle of least privilege).
- It enforces that critical functions go through threshold approval.
- Segment assignment can be randomized to prevent targeted attacks.

SEPARATION OF CONCERNS:
- Scheduler = WHEN and WHERE segments execute
- ControlPlane = WHO is authorized
- Workers = HOW instructions execute
"""

import random
from typing import Any, Dict, List, Optional

from .ir_definition import IRFunction, IRSegment
from .worker import Worker, WorkerResult
from .control_plane import ControlPlane, CapabilityToken
from .audit_log import AuditLog
from .circuit_breaker import CircuitBreaker


class Scheduler:
    """
    Distributed execution scheduler.
    
    Orchestrates the full lifecycle:
    IR Function → Segments → Capability Issuance → Worker Assignment → Execution → Result Assembly
    
    SECURITY RATIONALE:
    - Workers are selected from a pool (can be randomized).
    - Each worker gets only the capability needed for its segment.
    - Results are collected and merged — no single worker sees the full output.
    """

    def __init__(
        self,
        control_plane: ControlPlane,
        workers: List[Worker],
        audit_log: AuditLog,
        num_segments: int = 2,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ):
        self.control_plane = control_plane
        self.workers = workers
        self.audit_log = audit_log
        self.num_segments = num_segments
        self.circuit_breaker = circuit_breaker
        # Register workers with circuit breaker
        if self.circuit_breaker:
            for w in self.workers:
                self.circuit_breaker.register_worker(w.worker_id)

    def execute_function(
        self,
        ir_function: IRFunction,
        approval_request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute an IR function through the distributed pipeline.
        
        Steps:
        1. Split function into segments.
        2. For each segment, issue a capability token.
        3. Assign segments to workers.
        4. Execute each segment.
        5. Merge results.
        6. Return final state.
        
        Args:
            ir_function: The IR function to execute.
            approval_request_id: Required if function is critical.
        
        Returns:
            Dict with execution results, including the return value.
        """
        self.audit_log.append_entry({
            "source": "Scheduler",
            "event": "EXECUTION_PIPELINE_START",
            "function_id": ir_function.function_id,
            "function_name": ir_function.name,
            "criticality": ir_function.criticality,
            "num_instructions": len(ir_function.instructions),
            "num_segments": self.num_segments
        })

        # ── Step 1: Split into segments ──
        segments = ir_function.segment(self.num_segments)
        self.audit_log.append_entry({
            "source": "Scheduler",
            "event": "FUNCTION_SEGMENTED",
            "function_id": ir_function.function_id,
            "segments_created": len(segments)
        })

        # ── Step 2-4: Assign, authorize, and execute each segment ──
        results: List[WorkerResult] = []
        merged_state: Dict[str, Any] = {}

        # Shuffle workers for non-deterministic assignment (anti-targeting)
        available_workers = list(self.workers)
        random.shuffle(available_workers)

        # Filter out workers with tripped circuit breakers
        if self.circuit_breaker:
            healthy = [
                w for w in available_workers
                if self.circuit_breaker.allow(w.worker_id)
            ]
            if not healthy:
                self.audit_log.append_entry({
                    "source": "Scheduler",
                    "event": "ALL_WORKERS_CIRCUIT_OPEN",
                    "function_id": ir_function.function_id,
                })
                return {
                    "success": False,
                    "error": "SECURITY: All workers are circuit-broken. "
                             "System is in protective isolation.",
                    "stage": "worker_selection",
                }
            available_workers = healthy

        for i, segment in enumerate(segments):
            # Select worker (round-robin from shuffled pool)
            worker = available_workers[i % len(available_workers)]
            segment.assigned_worker = worker.worker_id

            self.audit_log.append_entry({
                "source": "Scheduler",
                "event": "SEGMENT_ASSIGNED",
                "segment_id": segment.segment_id,
                "segment_index": segment.segment_index,
                "worker_id": worker.worker_id
            })

            # Issue capability token for this segment
            try:
                token = self.control_plane.issue_capability(
                    issued_to=worker.worker_id,
                    scope=segment.required_capabilities,
                    ttl_seconds=30.0,  # Short-lived token
                    budget=1,          # Single use
                    criticality=segment.criticality,
                    approval_request_id=approval_request_id
                )
            except PermissionError as e:
                self.audit_log.append_entry({
                    "source": "Scheduler",
                    "event": "CAPABILITY_DENIED",
                    "segment_id": segment.segment_id,
                    "error": str(e)
                })
                return {
                    "success": False,
                    "error": str(e),
                    "stage": "capability_issuance",
                    "segment_index": i
                }

            # Execute segment on worker
            result = worker.execute_segment(
                segment=segment,
                capability_token=token.to_dict(),
                initial_state=merged_state  # Pass accumulated state
            )
            results.append(result)

            # Record result with circuit breaker
            if self.circuit_breaker:
                if result.success:
                    self.circuit_breaker.record_success(worker.worker_id)
                else:
                    self.circuit_breaker.record_failure(
                        worker.worker_id, result.error or "unknown"
                    )

            if not result.success:
                self.audit_log.append_entry({
                    "source": "Scheduler",
                    "event": "SEGMENT_EXECUTION_FAILED",
                    "segment_id": segment.segment_id,
                    "worker_id": worker.worker_id,
                    "error": result.error
                })
                return {
                    "success": False,
                    "error": result.error,
                    "stage": "execution",
                    "segment_index": i
                }

            # Merge state from this segment into accumulated state
            merged_state.update(result.state)

            # Consume the token (mark as used)
            token.consume()

        # ── Step 5: Assemble final result ──
        return_value = merged_state.get("__return__", None)

        self.audit_log.append_entry({
            "source": "Scheduler",
            "event": "EXECUTION_PIPELINE_COMPLETE",
            "function_id": ir_function.function_id,
            "function_name": ir_function.name,
            "segments_executed": len(results),
            "all_succeeded": all(r.success for r in results),
            "return_value": return_value
        })

        return {
            "success": True,
            "return_value": return_value,
            "state": merged_state,
            "segments_executed": len(results),
            "worker_results": [
                {
                    "worker_id": r.worker_id,
                    "segment_id": r.segment_id,
                    "success": r.success,
                    "execution_time_ms": r.execution_time_ms
                }
                for r in results
            ]
        }
