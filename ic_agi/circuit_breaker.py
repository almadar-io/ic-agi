"""
IC-AGI — Circuit Breaker for Workers
======================================

Implements the *circuit breaker* pattern for distributed worker pods.

SECURITY RATIONALE:
  A compromised or malfunctioning worker can:
    - Return incorrect results (Byzantine fault).
    - Hang indefinitely (DoS).
    - Leak or corrupt state.

  The circuit breaker protects the system by tracking per-worker error
  rates and automatically *isolating* workers that exceed a failure
  threshold.  Isolated workers receive NO new segments until:
    1. A configurable recovery timeout elapses, AND
    2. A "half-open" probe succeeds.

  This is the standard *Closed → Open → Half-Open* state machine:

    ┌────────┐  failure rate > threshold  ┌────────┐
    │ CLOSED │ ──────────────────────────→ │  OPEN  │
    │ (ok)   │                             │ (block)│
    └────────┘                             └───┬────┘
         ↑                                     │ recovery_timeout
         │  probe succeeds                     ↓
         │                               ┌───────────┐
         └─────────────────────────────── │ HALF_OPEN │
                                          │ (probe 1) │
                probe fails → OPEN        └───────────┘

AUDIT:
  Every state transition is logged so that operators can identify which
  workers had problems and when.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .audit_log import AuditLog


class CircuitState(str, Enum):
    CLOSED = "CLOSED"        # healthy — requests flow normally
    OPEN = "OPEN"            # unhealthy — all requests blocked
    HALF_OPEN = "HALF_OPEN"  # probing — one request allowed


@dataclass
class CircuitBreakerConfig:
    """Tuneable knobs for the circuit breaker."""
    failure_threshold: int = 3          # consecutive failures to trip
    success_threshold: int = 2          # consecutive successes to close
    recovery_timeout: float = 30.0      # seconds before half-open probe
    error_rate_window: float = 120.0    # sliding window for error rate
    error_rate_threshold: float = 0.5   # 50 % failure rate → trip


@dataclass
class _WorkerCircuit:
    """Per-worker circuit state."""
    worker_id: str
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    total_requests: int = 0
    total_failures: int = 0
    last_failure_time: float = 0.0
    opened_at: float = 0.0              # when the circuit tripped
    last_transition_time: float = field(default_factory=time.time)
    # Recent results for error-rate calculation  (True=ok, False=fail)
    _recent: List[tuple] = field(default_factory=list)   # (timestamp, bool)

    def error_rate(self, window: float) -> float:
        now = time.time()
        cutoff = now - window
        recent = [(t, ok) for t, ok in self._recent if t > cutoff]
        self._recent = recent      # prune in-place
        if not recent:
            return 0.0
        fails = sum(1 for _, ok in recent if not ok)
        return fails / len(recent)


class CircuitBreaker:
    """
    Manages per-worker circuit breakers.

    USAGE (inside the Scheduler / service layer):
        if not breaker.allow(worker_id):
            # skip this worker, pick another
            ...

        result = worker.execute_segment(...)

        if result.success:
            breaker.record_success(worker_id)
        else:
            breaker.record_failure(worker_id, result.error)
    """

    def __init__(
        self,
        config: Optional[CircuitBreakerConfig] = None,
        audit_log: Optional[AuditLog] = None,
    ):
        self.config = config or CircuitBreakerConfig()
        self.audit_log = audit_log
        self._circuits: Dict[str, _WorkerCircuit] = {}

    # ── public ──

    def register_worker(self, worker_id: str):
        """Pre-register a worker (optional — auto-registered on first call)."""
        if worker_id not in self._circuits:
            self._circuits[worker_id] = _WorkerCircuit(worker_id=worker_id)

    def allow(self, worker_id: str) -> bool:
        """
        Can this worker receive a new request?

        Returns True for CLOSED and HALF_OPEN (the probe request).
        Returns False for OPEN (unless recovery timeout has elapsed).
        """
        c = self._get(worker_id)
        now = time.time()

        if c.state == CircuitState.CLOSED:
            return True

        if c.state == CircuitState.OPEN:
            # Has recovery timeout elapsed?
            if now - c.opened_at >= self.config.recovery_timeout:
                self._transition(c, CircuitState.HALF_OPEN)
                return True     # allow the probe
            return False        # still blocked

        if c.state == CircuitState.HALF_OPEN:
            # Only one probe at a time — if already probing, block
            return True

        return False  # pragma: no cover

    def record_success(self, worker_id: str):
        """Record a successful execution."""
        c = self._get(worker_id)
        now = time.time()
        c.total_requests += 1
        c.consecutive_failures = 0
        c.consecutive_successes += 1
        c._recent.append((now, True))

        if c.state == CircuitState.HALF_OPEN:
            if c.consecutive_successes >= self.config.success_threshold:
                self._transition(c, CircuitState.CLOSED)

    def record_failure(self, worker_id: str, error: str = ""):
        """Record a failed execution."""
        c = self._get(worker_id)
        now = time.time()
        c.total_requests += 1
        c.total_failures += 1
        c.consecutive_failures += 1
        c.consecutive_successes = 0
        c.last_failure_time = now
        c._recent.append((now, False))

        if c.state == CircuitState.HALF_OPEN:
            # Probe failed — go back to OPEN
            self._transition(c, CircuitState.OPEN)
            return

        if c.state == CircuitState.CLOSED:
            # Check consecutive failures
            if c.consecutive_failures >= self.config.failure_threshold:
                self._transition(c, CircuitState.OPEN)
                return
            # Check error rate
            rate = c.error_rate(self.config.error_rate_window)
            if c.total_requests >= 5 and rate >= self.config.error_rate_threshold:
                self._transition(c, CircuitState.OPEN)

    def force_open(self, worker_id: str, reason: str = "admin"):
        """Manually trip a circuit (e.g., suspected compromise)."""
        c = self._get(worker_id)
        self._transition(c, CircuitState.OPEN)
        self._log(worker_id, "CIRCUIT_FORCE_OPEN", reason)

    def force_close(self, worker_id: str):
        """Manually close a circuit (admin override)."""
        c = self._get(worker_id)
        c.consecutive_failures = 0
        c.consecutive_successes = 0
        self._transition(c, CircuitState.CLOSED)

    def get_state(self, worker_id: str) -> str:
        return self._get(worker_id).state.value

    def get_status(self, worker_id: str) -> Dict[str, Any]:
        c = self._get(worker_id)
        return {
            "worker_id": worker_id,
            "state": c.state.value,
            "consecutive_failures": c.consecutive_failures,
            "consecutive_successes": c.consecutive_successes,
            "total_requests": c.total_requests,
            "total_failures": c.total_failures,
            "error_rate": round(c.error_rate(self.config.error_rate_window), 4),
            "last_failure_time": c.last_failure_time,
        }

    def get_all_status(self) -> List[Dict[str, Any]]:
        return [self.get_status(wid) for wid in self._circuits]

    def healthy_workers(self) -> List[str]:
        """Return IDs of workers whose circuits allow traffic."""
        return [wid for wid in self._circuits if self.allow(wid)]

    def reset_all(self):
        self._circuits.clear()

    # ── private ──

    def _get(self, worker_id: str) -> _WorkerCircuit:
        if worker_id not in self._circuits:
            self._circuits[worker_id] = _WorkerCircuit(worker_id=worker_id)
        return self._circuits[worker_id]

    def _transition(self, c: _WorkerCircuit, new_state: CircuitState):
        old = c.state
        c.state = new_state
        c.last_transition_time = time.time()
        if new_state == CircuitState.OPEN:
            c.opened_at = time.time()
        if new_state == CircuitState.CLOSED:
            c.consecutive_failures = 0
        self._log(c.worker_id, "CIRCUIT_TRANSITION",
                  f"{old.value} → {new_state.value}")

    def _log(self, worker_id: str, event: str, detail: str):
        if self.audit_log:
            self.audit_log.append_entry({
                "source": "CircuitBreaker",
                "event": event,
                "worker_id": worker_id,
                "detail": detail,
            })
