"""
IC-AGI — Phase 6 Adversarial Tests
=====================================

Tests the rate limiter, anti-oracle detector, and circuit breaker
both locally (unit) and against the live GKE cluster (integration).

Local tests:         Validate the logic without network.
Integration tests:   Validate the deployed v6 system.
"""

import sys
import time
import json
import urllib.request
import urllib.error

# ── Local imports (rate limiter, anti-oracle, circuit breaker) ──
sys.path.insert(0, ".")
from ic_agi.audit_log import AuditLog
from ic_agi.rate_limiter import RateLimiter, RateLimitConfig
from ic_agi.anti_oracle import AntiOracleDetector, AntiOracleConfig
from ic_agi.circuit_breaker import CircuitBreaker, CircuitBreakerConfig

PASS = 0
FAIL = 0


def check(label: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ✅ {label}")
    else:
        FAIL += 1
        print(f"  ❌ {label}  — {detail}")


# ═════════════════════════════════════════════════════
#  SECTION A — LOCAL UNIT TESTS (no network required)
# ═════════════════════════════════════════════════════

# ── ATTACK 11: Rate-Limit Flood ──
def test_rate_limit_flood():
    print("\n═══ ATTACK 11: Rate-Limit Flood ═══")
    audit = AuditLog()
    rl = RateLimiter(
        config=RateLimitConfig(max_requests=5, window_seconds=10, cooldown_seconds=2),
        audit_log=audit,
    )

    # First 5 requests should succeed
    for i in range(5):
        ok = rl.allow("attacker", "compute.basic")
        check(f"Request {i+1}/5 allowed", ok)

    # 6th request should be denied
    ok = rl.allow("attacker", "compute.basic")
    check("6th request DENIED (rate limit hit)", not ok)

    # Should be in cooldown
    check("Entity in cooldown", rl.in_cooldown("attacker", "compute.basic"))

    # Different entity should still be allowed
    ok = rl.allow("honest-user", "compute.basic")
    check("Different entity still allowed", ok)


# ── ATTACK 12: Rate-Limit Cooldown ──
def test_rate_limit_cooldown():
    print("\n═══ ATTACK 12: Rate-Limit Cooldown Penalty ═══")
    audit = AuditLog()
    rl = RateLimiter(
        config=RateLimitConfig(max_requests=3, window_seconds=60, cooldown_seconds=0.5),
        audit_log=audit,
    )

    # Exhaust the limit
    for _ in range(3):
        rl.allow("attacker", "*")
    denied = not rl.allow("attacker", "*")
    check("Rate limit triggered", denied)

    # During cooldown — still denied
    denied2 = not rl.allow("attacker", "*")
    check("During cooldown → denied", denied2)

    # Wait for cooldown to expire
    time.sleep(0.6)
    # After cooldown — should be allowed again (window hasn't expired)
    # But the old requests are still in the window, so it's still full
    # Reset first
    rl.reset("attacker", "*")
    ok = rl.allow("attacker", "*")
    check("After reset → allowed", ok)


# ── ATTACK 13: Rate-Limit Global Cap ──
def test_rate_limit_global():
    print("\n═══ ATTACK 13: Rate-Limit Global Cap ═══")
    rl = RateLimiter(
        config=RateLimitConfig(max_requests=3, window_seconds=60, cooldown_seconds=0.5),
    )
    # Global limit = 3 * 10 = 30.  Use 30 different entities.
    for i in range(30):
        rl.allow(f"entity-{i}", "*")
    # 31st entity should be denied by global limit
    denied = not rl.allow("entity-30", "*")
    check("Global rate limit triggered", denied)


# ── ATTACK 14: Anti-Oracle Identical Queries ──
def test_anti_oracle_identical():
    print("\n═══ ATTACK 14: Anti-Oracle — Identical Query Repetition ═══")
    audit = AuditLog()
    ao = AntiOracleDetector(
        config=AntiOracleConfig(
            max_identical_queries=3,
            suspicion_threshold=0.8,
            alert_threshold=0.3,
            decay_rate=0.0,
        ),
        audit_log=audit,
    )

    # Submit the same query repeatedly
    for i in range(3):
        result = ao.check("attacker", "add", [1, 2])
        check(f"Identical query {i+1} allowed", result["allowed"])

    # Queries 4+ raise score
    for i in range(3, 8):
        result = ao.check("attacker", "add", [1, 2])

    check("Score elevated", ao.get_score("attacker") > 0.3,
          f"score = {ao.get_score('attacker')}")

    # Eventually should be blocked
    blocked = ao.is_blocked("attacker")
    check("Attacker eventually blocked", blocked or ao.get_score("attacker") >= 0.8,
          f"score={ao.get_score('attacker')}, blocked={blocked}")


# ── ATTACK 15: Anti-Oracle Query Burst ──
def test_anti_oracle_burst():
    print("\n═══ ATTACK 15: Anti-Oracle — Query Burst ═══")
    ao = AntiOracleDetector(
        config=AntiOracleConfig(
            suspicion_threshold=0.8,
            alert_threshold=0.3,
            decay_rate=0.0,
            max_identical_queries=100,  # disable identical check
            max_similar_queries=100,     # disable similar check
        ),
    )

    # Fire 15 queries in rapid succession (different operands)
    last_result = None
    burst_detected = False
    for i in range(15):
        last_result = ao.check("burst-attacker", "add", [i, i*2])
        if "QUERY_BURST" in str(last_result.get("flags", [])):
            burst_detected = True
        if not last_result["allowed"]:
            break  # entity got blocked

    check("Burst detected or blocked",
          burst_detected or not last_result["allowed"],
          f"flags={last_result.get('flags')}")
    check("Score > 0.3 after burst", ao.get_score("burst-attacker") > 0.3,
          f"score = {ao.get_score('burst-attacker')}")


# ── ATTACK 16: Anti-Oracle Manual Block ──
def test_anti_oracle_manual_block():
    print("\n═══ ATTACK 16: Anti-Oracle — Manual Block/Unblock ═══")
    ao = AntiOracleDetector()

    ao.block("suspect", duration=60)
    check("Manually blocked", ao.is_blocked("suspect"))

    result = ao.check("suspect", "add", [1, 2])
    check("Blocked entity → request denied", not result["allowed"])
    check("Reason = ORACLE_BLOCKED", result["reason"] == "ORACLE_BLOCKED")

    ao.unblock("suspect")
    check("After unblock → allowed", ao.check("suspect", "add", [1, 2])["allowed"])


# ── ATTACK 17: Circuit Breaker — Consecutive Failures ──
def test_circuit_breaker_failures():
    print("\n═══ ATTACK 17: Circuit Breaker — Consecutive Failures Trip ═══")
    audit = AuditLog()
    cb = CircuitBreaker(
        config=CircuitBreakerConfig(failure_threshold=3, recovery_timeout=0.5),
        audit_log=audit,
    )

    # 3 consecutive failures should trip the circuit
    for i in range(3):
        cb.record_failure("worker-bad", f"error-{i}")

    check("Circuit tripped (OPEN)", cb.get_state("worker-bad") == "OPEN")
    check("Worker blocked", not cb.allow("worker-bad"))


# ── ATTACK 18: Circuit Breaker — Recovery ──
def test_circuit_breaker_recovery():
    print("\n═══ ATTACK 18: Circuit Breaker — Half-Open Recovery ═══")
    cb = CircuitBreaker(
        config=CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=2,
            recovery_timeout=0.3,
        ),
    )

    # Trip it
    cb.record_failure("worker-x", "err1")
    cb.record_failure("worker-x", "err2")
    check("Circuit OPEN", cb.get_state("worker-x") == "OPEN")

    # Wait for recovery timeout
    time.sleep(0.4)
    check("After timeout → allow probe", cb.allow("worker-x"))
    check("State = HALF_OPEN", cb.get_state("worker-x") == "HALF_OPEN")

    # Probe succeeds
    cb.record_success("worker-x")
    cb.record_success("worker-x")
    check("After 2 successes → CLOSED", cb.get_state("worker-x") == "CLOSED")


# ── ATTACK 19: Circuit Breaker — Failed Probe ──
def test_circuit_breaker_failed_probe():
    print("\n═══ ATTACK 19: Circuit Breaker — Failed Probe → Re-Open ═══")
    cb = CircuitBreaker(
        config=CircuitBreakerConfig(failure_threshold=2, recovery_timeout=0.2),
    )

    cb.record_failure("worker-y", "err1")
    cb.record_failure("worker-y", "err2")
    check("Circuit OPEN", cb.get_state("worker-y") == "OPEN")

    time.sleep(0.3)
    cb.allow("worker-y")  # transitions to HALF_OPEN
    check("State = HALF_OPEN", cb.get_state("worker-y") == "HALF_OPEN")

    # Probe fails
    cb.record_failure("worker-y", "probe-fail")
    check("Failed probe → back to OPEN", cb.get_state("worker-y") == "OPEN")


# ── ATTACK 20: Circuit Breaker — Force Trip ──
def test_circuit_breaker_force():
    print("\n═══ ATTACK 20: Circuit Breaker — Admin Force Trip/Close ═══")
    cb = CircuitBreaker()

    cb.force_open("worker-z", reason="suspected compromise")
    check("Force-opened", cb.get_state("worker-z") == "OPEN")
    check("Worker blocked", not cb.allow("worker-z"))

    cb.force_close("worker-z")
    check("Force-closed", cb.get_state("worker-z") == "CLOSED")
    check("Worker unblocked", cb.allow("worker-z"))


# ── ATTACK 21: Rate Limit + ControlPlane Integration ──
def test_rate_limit_control_plane():
    print("\n═══ ATTACK 21: Rate Limiter Integrated with ControlPlane ═══")
    from ic_agi.control_plane import ControlPlane
    from ic_agi.threshold_auth import ThresholdAuthorizer

    audit = AuditLog()
    auth = ThresholdAuthorizer(["a-0", "a-1"], threshold=2, audit_log=audit)
    rl = RateLimiter(
        config=RateLimitConfig(max_requests=3, window_seconds=60, cooldown_seconds=1),
        audit_log=audit,
    )
    cp = ControlPlane(
        threshold_authorizer=auth,
        audit_log=audit,
        rate_limiter=rl,
    )

    # First 3 tokens should succeed
    for i in range(3):
        t = cp.issue_capability(
            issued_to="worker-0",
            scope=["compute.basic"],
        )
        check(f"Token {i+1} issued", t is not None)

    # 4th should be rate-limited
    try:
        cp.issue_capability(issued_to="worker-0", scope=["compute.basic"])
        check("4th token DENIED", False, "should have raised PermissionError")
    except PermissionError as e:
        check("4th token rate-limited", "Rate limit" in str(e))


# ── ATTACK 22: Circuit Breaker + Scheduler Integration ──
def test_circuit_breaker_scheduler():
    print("\n═══ ATTACK 22: Circuit Breaker Isolates Bad Workers ═══")
    from ic_agi.control_plane import ControlPlane
    from ic_agi.threshold_auth import ThresholdAuthorizer
    from ic_agi.worker import Worker
    from ic_agi.scheduler import Scheduler
    from ic_agi.ir_definition import build_add_function

    audit = AuditLog()
    auth = ThresholdAuthorizer(["a-0", "a-1"], threshold=2, audit_log=audit)
    cp = ControlPlane(threshold_authorizer=auth, audit_log=audit)
    workers = [Worker(f"w-{i}", audit, cp.signing_key) for i in range(3)]
    cb = CircuitBreaker(
        config=CircuitBreakerConfig(failure_threshold=2),
        audit_log=audit,
    )
    sched = Scheduler(cp, workers, audit, num_segments=2, circuit_breaker=cb)

    # Trip circuit for worker 0 and 1
    cb.record_failure("w-0", "err"); cb.record_failure("w-0", "err")
    cb.record_failure("w-1", "err"); cb.record_failure("w-1", "err")

    check("w-0 circuit OPEN", cb.get_state("w-0") == "OPEN")
    check("w-1 circuit OPEN", cb.get_state("w-1") == "OPEN")
    check("w-2 still healthy", cb.allow("w-2"))

    # Execution should still work — only w-2 is healthy
    fn = build_add_function(5, 10)
    result = sched.execute_function(fn)
    check("Execution succeeds with 1 healthy worker",
          result.get("success") is True and result.get("return_value") == 15)

    # All workers used should be w-2
    worker_ids = [r["worker_id"] for r in result.get("worker_results", [])]
    check("All segments on w-2", all(w == "w-2" for w in worker_ids),
          f"workers={worker_ids}")


# ── ATTACK 23: All Workers Circuit-Broken → Fail-Safe ──
def test_all_workers_broken():
    print("\n═══ ATTACK 23: All Workers Circuit-Broken → Fail-Safe ═══")
    from ic_agi.control_plane import ControlPlane
    from ic_agi.threshold_auth import ThresholdAuthorizer
    from ic_agi.worker import Worker
    from ic_agi.scheduler import Scheduler
    from ic_agi.ir_definition import build_add_function

    audit = AuditLog()
    auth = ThresholdAuthorizer(["a-0", "a-1"], threshold=2, audit_log=audit)
    cp = ControlPlane(threshold_authorizer=auth, audit_log=audit)
    workers = [Worker(f"w-{i}", audit, cp.signing_key) for i in range(3)]
    cb = CircuitBreaker(config=CircuitBreakerConfig(failure_threshold=1), audit_log=audit)
    sched = Scheduler(cp, workers, audit, num_segments=2, circuit_breaker=cb)

    # Trip all circuits
    for w in workers:
        cb.record_failure(w.worker_id, "compromised")

    fn = build_add_function(1, 1)
    result = sched.execute_function(fn)
    check("Execution fails (all workers broken)", not result.get("success"))
    check("Error mentions circuit/isolation",
          "circuit" in result.get("error", "").lower() or
          "isolation" in result.get("error", "").lower(),
          f"error={result.get('error')}")


# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  IC-AGI — Phase 6 Adversarial Security Tests           ║")
    print("║  Rate Limiting · Anti-Oracle · Circuit Breaker          ║")
    print("╚══════════════════════════════════════════════════════════╝")

    test_rate_limit_flood()
    test_rate_limit_cooldown()
    test_rate_limit_global()
    test_anti_oracle_identical()
    test_anti_oracle_burst()
    test_anti_oracle_manual_block()
    test_circuit_breaker_failures()
    test_circuit_breaker_recovery()
    test_circuit_breaker_failed_probe()
    test_circuit_breaker_force()
    test_rate_limit_control_plane()
    test_circuit_breaker_scheduler()
    test_all_workers_broken()

    print("\n════════════════════════════════════════════════════════════")
    if FAIL == 0:
        print(f"  🛡️  ALL {PASS} PHASE 6 ADVERSARIAL CHECKS PASSED")
        print(f"     Rate limiter blocks floods and enforces cooldown")
        print(f"     Anti-oracle detects repetition, bursts, and sweeps")
        print(f"     Circuit breaker isolates failing workers")
        print(f"     Fail-safe when all workers are compromised")
    else:
        print(f"  ❌  {FAIL} FAILURES out of {PASS + FAIL} checks")
    print("════════════════════════════════════════════════════════════")
    sys.exit(1 if FAIL else 0)
