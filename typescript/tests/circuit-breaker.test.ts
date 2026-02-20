// TLA+ property coverage (DistributedExecution.tla):
//   P12 CircuitBreakerSafety: circuit-broken workers receive no segments — OPEN state blocks requests
//
// State machine coverage:
//   CLOSED → OPEN:      consecutive failure threshold triggers trip
//   OPEN → HALF_OPEN:   recovery timeout allows probe request
//   HALF_OPEN → CLOSED: consecutive successes meet success threshold
//   HALF_OPEN → OPEN:   any failure during probe trips immediately
//
// Additional coverage:
//   - Error rate guard: trips when rate >= threshold AND totalRequests >= 5
//   - Error rate minimum sample: no trip when totalRequests < 5 (avoids noisy startup)
//   - Entity isolation: independent circuits per worker (w1 OPEN does not affect w2)
//   - Stats tracking: totalRequests, totalFailures, consecutiveFailures

import { CircuitBreaker, CircuitState } from '../src/circuit-breaker.js';

describe('CircuitBreaker', () => {
  // --- State: CLOSED (initial) ---

  it('starts in CLOSED state', () => {
    const cb = new CircuitBreaker();
    expect(cb.getState('worker-1')).toBe(CircuitState.CLOSED);
  });

  it('allows requests in CLOSED state', () => {
    const cb = new CircuitBreaker();
    expect(cb.allow('w1')).toBe(true);
  });

  // --- Failure threshold → OPEN ---

  it('opens after reaching failure threshold (consecutive failures)', () => {
    const cb = new CircuitBreaker({ failureThreshold: 3 });
    cb.recordFailure('w1');
    expect(cb.getState('w1')).toBe(CircuitState.CLOSED);
    cb.recordFailure('w1');
    expect(cb.getState('w1')).toBe(CircuitState.CLOSED);
    cb.recordFailure('w1');
    expect(cb.getState('w1')).toBe(CircuitState.OPEN);
  });

  it('blocks requests in OPEN state', () => {
    const cb = new CircuitBreaker({ failureThreshold: 2 });
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    expect(cb.getState('w1')).toBe(CircuitState.OPEN);
    expect(cb.allow('w1')).toBe(false);
  });

  it('resets consecutive failure count on a success', () => {
    const cb = new CircuitBreaker({ failureThreshold: 3 });
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    cb.recordSuccess('w1');
    // One more failure — counter was reset so we're only at 1 now
    cb.recordFailure('w1');
    expect(cb.getState('w1')).toBe(CircuitState.CLOSED);
  });

  // --- OPEN → HALF_OPEN (recovery timeout) ---

  it('transitions OPEN → HALF_OPEN after recovery timeout', () => {
    const cb = new CircuitBreaker({ failureThreshold: 2, recoveryTimeoutSeconds: 0 });
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    expect(cb.getState('w1')).toBe(CircuitState.OPEN);
    // recoveryTimeoutSeconds = 0, so allow() should immediately transition
    expect(cb.allow('w1')).toBe(true);
    expect(cb.getState('w1')).toBe(CircuitState.HALF_OPEN);
  });

  it('stays OPEN when recovery timeout has not elapsed', () => {
    const cb = new CircuitBreaker({ failureThreshold: 2, recoveryTimeoutSeconds: 9999 });
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    expect(cb.allow('w1')).toBe(false);
    expect(cb.getState('w1')).toBe(CircuitState.OPEN);
  });

  // --- HALF_OPEN → CLOSED (success reset) ---

  it('closes from HALF_OPEN after enough consecutive successes', () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      successThreshold: 2,
      recoveryTimeoutSeconds: 0,
    });
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    cb.allow('w1'); // trigger OPEN → HALF_OPEN
    expect(cb.getState('w1')).toBe(CircuitState.HALF_OPEN);

    cb.recordSuccess('w1');
    expect(cb.getState('w1')).toBe(CircuitState.HALF_OPEN); // not closed yet
    cb.recordSuccess('w1');
    expect(cb.getState('w1')).toBe(CircuitState.CLOSED);
  });

  it('stays HALF_OPEN until success threshold is met', () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      successThreshold: 3,
      recoveryTimeoutSeconds: 0,
    });
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    cb.allow('w1');
    cb.recordSuccess('w1');
    cb.recordSuccess('w1');
    expect(cb.getState('w1')).toBe(CircuitState.HALF_OPEN);
  });

  // --- HALF_OPEN → OPEN (failure in probe) ---

  it('re-opens immediately on failure in HALF_OPEN state', () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      recoveryTimeoutSeconds: 0,
    });
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    cb.allow('w1'); // OPEN → HALF_OPEN
    cb.recordFailure('w1'); // should trip back
    expect(cb.getState('w1')).toBe(CircuitState.OPEN);
  });

  // --- Error rate guard ---

  it('trips on error rate when totalRequests >= 5', () => {
    const cb = new CircuitBreaker({
      failureThreshold: 99, // high threshold so only error rate matters
      errorRateThreshold: 0.5,
      errorRateWindow: 120,
    });
    // 3 failures, 2 successes → 60% error rate, >= 5 requests
    cb.recordSuccess('w1');
    cb.recordSuccess('w1');
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    expect(cb.getState('w1')).toBe(CircuitState.CLOSED); // only 4 requests
    cb.recordFailure('w1'); // 5th request, rate = 3/5 = 60% → trip
    expect(cb.getState('w1')).toBe(CircuitState.OPEN);
  });

  it('does not trip on error rate when totalRequests < 5', () => {
    const cb = new CircuitBreaker({
      failureThreshold: 99,
      errorRateThreshold: 0.5,
    });
    // 4 requests all failures — rate 100% but < 5 total
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    expect(cb.getState('w1')).toBe(CircuitState.CLOSED);
  });

  // --- getStats ---

  it('getStats tracks totals correctly', () => {
    const cb = new CircuitBreaker({ failureThreshold: 99 });
    cb.recordSuccess('w1');
    cb.recordSuccess('w1');
    cb.recordFailure('w1');
    const stats = cb.getStats('w1');
    expect(stats.totalRequests).toBe(3);
    expect(stats.totalFailures).toBe(1);
    expect(stats.consecutiveFailures).toBe(1);
    expect(stats.state).toBe(CircuitState.CLOSED);
  });

  // --- Circuit isolation (separate workers) ---

  it('maintains independent circuits per worker', () => {
    const cb = new CircuitBreaker({ failureThreshold: 2 });
    cb.recordFailure('w1');
    cb.recordFailure('w1');
    expect(cb.getState('w1')).toBe(CircuitState.OPEN);
    expect(cb.getState('w2')).toBe(CircuitState.CLOSED);
    expect(cb.allow('w2')).toBe(true);
    expect(cb.allow('w1')).toBe(false);
  });
});
