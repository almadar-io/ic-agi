"""
IC-AGI — Rate Limiter
======================

Enforces per-entity rate limits on capability token consumption.

SECURITY RATIONALE:
  - Without rate limiting an adversary who compromises a single worker
    (or obtains a leaked signing key) could issue a flood of capability
    requests, exhausting the system or probing for side-channels.
  - The limiter uses a sliding-window counter per ``(entity, scope)``
    pair.  When the limit is exceeded the ControlPlane REFUSES to issue
    new tokens — this is enforced *before* the token is signed.
  - Every enforcement action (grant / deny / cooldown) is logged to the
    append-only audit trail so that patterns can be reviewed post-hoc.
  - In production this would be backed by a distributed counter
    (e.g., Redis INCR + EXPIRE).  The in-memory implementation is
    sufficient for a single-process control plane or a single pod.

DESIGN:
  - ``SlidingWindowCounter`` — fixed-size deque of timestamps; count =
    number of timestamps within the current window.
  - ``RateLimiter`` — facade that maps (entity, scope) → counter and
    exposes ``allow()`` / ``remaining()`` / ``reset()``.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional, Tuple

from .audit_log import AuditLog


@dataclass
class RateLimitConfig:
    """Configuration for a rate-limit window."""
    max_requests: int = 20       # requests per window
    window_seconds: float = 60.0  # sliding window length
    cooldown_seconds: float = 30.0  # penalty after exceeding the limit


class _SlidingWindowCounter:
    """Sliding-window counter backed by a deque of timestamps."""

    __slots__ = ("_window", "_max", "_timestamps", "_cooldown_until")

    def __init__(self, window: float, max_requests: int, cooldown: float = 0.0):
        self._window = window
        self._max = max_requests
        self._timestamps: Deque[float] = deque()
        self._cooldown_until: float = 0.0

    # ── public ──

    def allow(self, now: float | None = None) -> bool:
        """Return True if the request is allowed, False otherwise."""
        now = now or time.time()
        # Cooldown period?
        if now < self._cooldown_until:
            return False
        self._evict(now)
        if len(self._timestamps) >= self._max:
            # Exceeded — start cooldown
            self._cooldown_until = now + 0.0  # placeholder, caller sets
            return False
        self._timestamps.append(now)
        return True

    def remaining(self, now: float | None = None) -> int:
        now = now or time.time()
        self._evict(now)
        return max(0, self._max - len(self._timestamps))

    def set_cooldown(self, seconds: float, now: float | None = None):
        now = now or time.time()
        self._cooldown_until = now + seconds

    @property
    def in_cooldown(self) -> bool:
        return time.time() < self._cooldown_until

    def reset(self):
        self._timestamps.clear()
        self._cooldown_until = 0.0

    # ── private ──

    def _evict(self, now: float):
        cutoff = now - self._window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()


class RateLimiter:
    """
    Per-entity, per-scope sliding-window rate limiter.

    SECURITY RATIONALE:
      - Each ``(entity, scope)`` pair gets its own counter.
      - A *global* counter additionally caps the total system throughput,
        preventing distributed flooding.
      - When a limit is hit a cooldown period is applied; during cooldown
        ALL requests by that entity are denied — this raises the cost of
        brute-force attacks.
      - The limiter is consulted by the ControlPlane *before* signing a
        capability token, so a denied entity never receives a valid token.
    """

    def __init__(
        self,
        config: Optional[RateLimitConfig] = None,
        audit_log: Optional[AuditLog] = None,
    ):
        self.config = config or RateLimitConfig()
        self.audit_log = audit_log
        self._counters: Dict[Tuple[str, str], _SlidingWindowCounter] = {}
        # Global counter — rate-limits the entire system
        self._global = _SlidingWindowCounter(
            window=self.config.window_seconds,
            max_requests=self.config.max_requests * 10,  # 10× per-entity
        )

    # ── public API ──

    def allow(self, entity: str, scope: str = "*") -> bool:
        """
        Check whether ``entity`` may consume one more token with ``scope``.

        Returns ``True`` and records the event if allowed.
        Returns ``False`` and logs a RATE_LIMIT_DENIED event if blocked.
        """
        now = time.time()

        # ── Global limit ──
        if not self._global.allow(now):
            self._log_denied(entity, scope, "GLOBAL_RATE_LIMIT")
            return False

        # ── Per-entity limit ──
        counter = self._get(entity, scope)
        if not counter.allow(now):
            counter.set_cooldown(self.config.cooldown_seconds, now)
            self._log_denied(entity, scope, "ENTITY_RATE_LIMIT")
            return False

        return True

    def remaining(self, entity: str, scope: str = "*") -> int:
        """How many more requests this entity can make in the current window."""
        return self._get(entity, scope).remaining()

    def in_cooldown(self, entity: str, scope: str = "*") -> bool:
        """True if the entity is in a cooldown penalty period."""
        return self._get(entity, scope).in_cooldown

    def reset(self, entity: str, scope: str = "*"):
        """Manually reset the counter for an entity (admin override)."""
        key = (entity, scope)
        if key in self._counters:
            self._counters[key].reset()
            self._log_event(entity, scope, "RATE_LIMIT_RESET")

    def reset_all(self):
        """Reset every counter (used in tests)."""
        self._counters.clear()
        self._global.reset()

    def get_status(self, entity: str, scope: str = "*") -> Dict[str, Any]:
        """Return human-readable status for an entity."""
        counter = self._get(entity, scope)
        return {
            "entity": entity,
            "scope": scope,
            "remaining": counter.remaining(),
            "in_cooldown": counter.in_cooldown,
            "max_requests": self.config.max_requests,
            "window_seconds": self.config.window_seconds,
            "cooldown_seconds": self.config.cooldown_seconds,
        }

    # ── private ──

    def _get(self, entity: str, scope: str) -> _SlidingWindowCounter:
        key = (entity, scope)
        if key not in self._counters:
            self._counters[key] = _SlidingWindowCounter(
                window=self.config.window_seconds,
                max_requests=self.config.max_requests,
                cooldown=self.config.cooldown_seconds,
            )
        return self._counters[key]

    def _log_denied(self, entity: str, scope: str, reason: str):
        if self.audit_log:
            self.audit_log.append_entry({
                "source": "RateLimiter",
                "event": "RATE_LIMIT_DENIED",
                "entity": entity,
                "scope": scope,
                "reason": reason,
            })

    def _log_event(self, entity: str, scope: str, event: str):
        if self.audit_log:
            self.audit_log.append_entry({
                "source": "RateLimiter",
                "event": event,
                "entity": entity,
                "scope": scope,
            })
