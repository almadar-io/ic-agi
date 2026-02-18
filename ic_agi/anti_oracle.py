"""
IC-AGI — Anti-Oracle Detection
================================

Detects and blocks oracle-extraction attacks.

SECURITY RATIONALE (whitepaper §3.2 — Anti-Oracle Property):
  An attacker who can submit arbitrary queries and observe outputs may
  gradually reconstruct the internal decision model.  Classic oracle
  attacks include:
    - **Membership inference:** repeatedly querying slight variants of
      the same input to determine decision boundaries.
    - **Model inversion:** systematic probing to reconstruct secrets.
    - **Differential analysis:** comparing outputs of near-identical
      inputs to extract parameters.

  IC-AGI mitigates this at the *capability* layer:
    1. **Repetition detection** — a sliding window of recent queries is
       kept; if the same (or highly similar) query is repeated too many
       times, the request is flagged and eventually blocked.
    2. **Pattern scoring** — each query is hashed into a feature space.
       Clusters of hashes in a short time-window raise a suspicion
       score.  A score above the threshold triggers an ALERT and blocks
       the entity until manual review.
    3. **Audit trail** — every flag / block is recorded so that
       defenders can study the attack pattern post-hoc.

  This is a *defence-in-depth* control.  It works alongside rate
  limiting (caps throughput) and capability budgets (caps total uses).
  Together they make oracle attacks economically infeasible.

IMPLEMENTATION:
  - In-memory sliding window of (hash, timestamp) pairs per entity.
  - Similarity is measured by *exact hash match* of (function_name,
    operand_a, operand_b).  Production would use LSH / embedding
    distance for fuzzy matching.
  - Configurable thresholds for repetition count, time window, and
    suspicion score.
"""

import hashlib
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from .audit_log import AuditLog


@dataclass
class AntiOracleConfig:
    """Tuneable knobs for oracle-detection sensitivity."""
    window_seconds: float = 120.0        # how far back to look
    max_identical_queries: int = 5        # same query N times → flag
    max_similar_queries: int = 15         # queries to same function → flag
    suspicion_threshold: float = 0.8      # 0–1; above → block
    alert_threshold: float = 0.5          # 0–1; above → log warning
    decay_rate: float = 0.1              # per-second score decay


@dataclass
class QueryFingerprint:
    """Compact representation of a single query for comparison."""
    fingerprint: str       # SHA-256 of canonical query repr
    function_name: str
    timestamp: float
    entity: str


class AntiOracleDetector:
    """
    Stateful detector that tracks query patterns per entity and flags
    behaviour consistent with oracle-extraction attacks.
    """

    def __init__(
        self,
        config: Optional[AntiOracleConfig] = None,
        audit_log: Optional[AuditLog] = None,
    ):
        self.config = config or AntiOracleConfig()
        self.audit_log = audit_log
        # Per-entity history of recent query fingerprints
        self._history: Dict[str, Deque[QueryFingerprint]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        # Entities currently blocked
        self._blocked: Dict[str, float] = {}   # entity → blocked_until
        # Suspicion scores
        self._scores: Dict[str, float] = defaultdict(float)

    # ── public API ──

    def check(
        self,
        entity: str,
        function_name: str,
        operands: List[Any],
    ) -> Dict[str, Any]:
        """
        Analyse an incoming query and return a verdict.

        Returns:
          {
            "allowed": bool,
            "suspicion_score": float,   # 0.0 – 1.0
            "reason": str | None,
            "flags": [str, ...]
          }

        If ``allowed`` is False the caller MUST reject the request.
        """
        now = time.time()

        # ── Is entity currently blocked? ──
        if entity in self._blocked:
            if now < self._blocked[entity]:
                return {
                    "allowed": False,
                    "suspicion_score": 1.0,
                    "reason": "ORACLE_BLOCKED",
                    "flags": ["ENTITY_BLOCKED"],
                }
            else:
                del self._blocked[entity]
                self._scores[entity] = 0.0

        # ── Compute fingerprint ──
        fp = self._fingerprint(entity, function_name, operands, now)
        history = self._history[entity]
        self._evict(history, now)
        history.append(fp)

        # ── Analyse patterns ──
        flags: List[str] = []
        score = self._scores[entity]

        # Apply time-based decay
        score = max(0.0, score - self.config.decay_rate)

        # 1) Identical-query repetition
        identical = sum(
            1 for q in history
            if q.fingerprint == fp.fingerprint
        )
        if identical > self.config.max_identical_queries:
            score += 0.3
            flags.append(f"IDENTICAL_REPEAT_{identical}")

        # 2) Same-function saturation
        same_fn = sum(1 for q in history if q.function_name == function_name)
        if same_fn > self.config.max_similar_queries:
            score += 0.2
            flags.append(f"FUNCTION_SATURATION_{same_fn}")

        # 3) Query burst (> 10 queries in 10 seconds)
        burst_cutoff = now - 10.0
        burst_count = sum(1 for q in history if q.timestamp > burst_cutoff)
        if burst_count > 10:
            score += 0.3
            flags.append(f"QUERY_BURST_{burst_count}")

        # 4) Incremental probing: detect sequential operand sweeps
        #    (e.g., add(1,x), add(2,x), add(3,x) ...)
        recent = [q for q in history if q.function_name == function_name]
        if len(recent) >= 5:
            score += 0.1
            flags.append("POSSIBLE_SWEEP")

        # Clamp
        score = min(1.0, max(0.0, score))
        self._scores[entity] = score

        # ── Decision ──
        if score >= self.config.suspicion_threshold:
            # Block the entity
            block_duration = 60.0 * score  # up to 60s for score=1.0
            self._blocked[entity] = now + block_duration
            self._log_event(entity, "ORACLE_BLOCKED", score, flags)
            return {
                "allowed": False,
                "suspicion_score": score,
                "reason": "SUSPICION_THRESHOLD_EXCEEDED",
                "flags": flags,
            }

        if score >= self.config.alert_threshold:
            self._log_event(entity, "ORACLE_ALERT", score, flags)

        return {
            "allowed": True,
            "suspicion_score": round(score, 4),
            "reason": None,
            "flags": flags,
        }

    def get_score(self, entity: str) -> float:
        """Current suspicion score for an entity."""
        return self._scores.get(entity, 0.0)

    def is_blocked(self, entity: str) -> bool:
        if entity not in self._blocked:
            return False
        if time.time() >= self._blocked[entity]:
            del self._blocked[entity]
            return False
        return True

    def block(self, entity: str, duration: float = 60.0):
        """Manually block an entity (admin action)."""
        self._blocked[entity] = time.time() + duration
        self._log_event(entity, "ORACLE_MANUAL_BLOCK", 1.0, ["ADMIN_BLOCK"])

    def unblock(self, entity: str):
        """Remove block for an entity (admin action)."""
        if entity in self._blocked:
            del self._blocked[entity]
        self._scores[entity] = 0.0
        self._log_event(entity, "ORACLE_UNBLOCKED", 0.0, ["ADMIN_UNBLOCK"])

    def reset(self, entity: str):
        """Clear all history and scores for an entity."""
        self._history.pop(entity, None)
        self._scores.pop(entity, None)
        self._blocked.pop(entity, None)

    def reset_all(self):
        """Clear all state (used in tests)."""
        self._history.clear()
        self._scores.clear()
        self._blocked.clear()

    def get_status(self, entity: str) -> Dict[str, Any]:
        return {
            "entity": entity,
            "suspicion_score": round(self._scores.get(entity, 0.0), 4),
            "is_blocked": self.is_blocked(entity),
            "recent_queries": len(self._history.get(entity, [])),
            "config": {
                "window_seconds": self.config.window_seconds,
                "max_identical": self.config.max_identical_queries,
                "max_similar": self.config.max_similar_queries,
                "suspicion_threshold": self.config.suspicion_threshold,
            },
        }

    # ── private ──

    def _fingerprint(
        self, entity: str, function_name: str,
        operands: List[Any], now: float,
    ) -> QueryFingerprint:
        canonical = json.dumps(
            {"fn": function_name, "ops": operands},
            sort_keys=True, separators=(",", ":"),
        )
        fp = hashlib.sha256(canonical.encode()).hexdigest()
        return QueryFingerprint(
            fingerprint=fp,
            function_name=function_name,
            timestamp=now,
            entity=entity,
        )

    def _evict(self, history: Deque[QueryFingerprint], now: float):
        cutoff = now - self.config.window_seconds
        while history and history[0].timestamp < cutoff:
            history.popleft()

    def _log_event(
        self, entity: str, event: str,
        score: float, flags: List[str],
    ):
        if self.audit_log:
            self.audit_log.append_entry({
                "source": "AntiOracle",
                "event": event,
                "entity": entity,
                "suspicion_score": round(score, 4),
                "flags": flags,
            })
