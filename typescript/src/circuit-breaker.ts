/**
 * CircuitBreaker — Fault isolation state machine per worker/session.
 *
 * TypeScript port of saezbaldo/ic-agi `ic_agi/circuit_breaker.py`.
 * See: https://github.com/saezbaldo/ic-agi
 *
 * State machine:
 *   CLOSED → OPEN         when consecutive failures >= threshold OR error rate >= 50%
 *   OPEN   → HALF_OPEN    after recovery timeout (probe request allowed through)
 *   HALF_OPEN → CLOSED    when consecutive successes >= success threshold
 *   HALF_OPEN → OPEN      on any failure (immediate trip)
 *
 * Error rate guard only fires when totalRequests >= 5 to prevent
 * tripping on a single noisy startup failure.
 */

import type { AuditLog } from './audit-log.js';

export enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN',
}

export interface CircuitBreakerConfig {
  /** Consecutive failures before tripping. Default: 3 */
  failureThreshold?: number;
  /** Consecutive successes in HALF_OPEN before closing. Default: 2 */
  successThreshold?: number;
  /** Seconds in OPEN before allowing a probe request. Default: 30 */
  recoveryTimeoutSeconds?: number;
  /** Window in seconds for error-rate calculation. Default: 120 */
  errorRateWindow?: number;
  /** Error rate threshold (0–1) to trigger OPEN. Default: 0.5 */
  errorRateThreshold?: number;
}

interface WorkerCircuit {
  workerId: string;
  state: CircuitState;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  totalRequests: number;
  totalFailures: number;
  lastFailureTime: number;
  openedAt: number;
  lastTransitionTime: number;
  /** Sliding window of (timestamp, success) pairs. */
  recent: Array<{ timestamp: number; success: boolean }>;
}

export class CircuitBreaker {
  private readonly circuits = new Map<string, WorkerCircuit>();
  private readonly config: Required<CircuitBreakerConfig>;
  private readonly auditLog?: AuditLog;

  constructor(config: CircuitBreakerConfig = {}, auditLog?: AuditLog) {
    this.config = {
      failureThreshold: config.failureThreshold ?? 3,
      successThreshold: config.successThreshold ?? 2,
      recoveryTimeoutSeconds: config.recoveryTimeoutSeconds ?? 30,
      errorRateWindow: config.errorRateWindow ?? 120,
      errorRateThreshold: config.errorRateThreshold ?? 0.5,
    };
    this.auditLog = auditLog;
  }

  private getOrCreate(workerId: string): WorkerCircuit {
    if (!this.circuits.has(workerId)) {
      this.circuits.set(workerId, {
        workerId,
        state: CircuitState.CLOSED,
        consecutiveFailures: 0,
        consecutiveSuccesses: 0,
        totalRequests: 0,
        totalFailures: 0,
        lastFailureTime: 0,
        openedAt: 0,
        lastTransitionTime: Date.now() / 1000,
        recent: [],
      });
    }
    return this.circuits.get(workerId)!;
  }

  /** Compute error rate for the worker within the configured window. Prunes stale entries. */
  private errorRate(circuit: WorkerCircuit, now = Date.now() / 1000): number {
    const cutoff = now - this.config.errorRateWindow;
    circuit.recent = circuit.recent.filter(r => r.timestamp >= cutoff);
    if (circuit.recent.length === 0) return 0;
    const failures = circuit.recent.filter(r => !r.success).length;
    return failures / circuit.recent.length;
  }

  private transition(circuit: WorkerCircuit, newState: CircuitState): void {
    const oldState = circuit.state;
    circuit.state = newState;
    circuit.lastTransitionTime = Date.now() / 1000;
    if (newState === CircuitState.OPEN) circuit.openedAt = circuit.lastTransitionTime;
    if (newState === CircuitState.CLOSED) circuit.consecutiveFailures = 0;
    this.auditLog?.append({
      event: 'CIRCUIT_TRANSITION',
      workerId: circuit.workerId,
      from: oldState,
      to: newState,
    });
  }

  /**
   * Check whether the worker is allowed to proceed.
   * - CLOSED: always allowed
   * - OPEN:   blocked until recovery timeout, then transitions to HALF_OPEN
   * - HALF_OPEN: probe allowed through
   */
  allow(workerId: string): boolean {
    const now = Date.now() / 1000;
    const c = this.getOrCreate(workerId);

    if (c.state === CircuitState.CLOSED) return true;

    if (c.state === CircuitState.OPEN) {
      if (now - c.openedAt >= this.config.recoveryTimeoutSeconds) {
        this.transition(c, CircuitState.HALF_OPEN);
        return true;
      }
      return false;
    }

    // HALF_OPEN — probe request
    return true;
  }

  recordSuccess(workerId: string): void {
    const now = Date.now() / 1000;
    const c = this.getOrCreate(workerId);
    c.consecutiveFailures = 0;
    c.consecutiveSuccesses++;
    c.totalRequests++;
    c.recent.push({ timestamp: now, success: true });

    if (
      c.state === CircuitState.HALF_OPEN &&
      c.consecutiveSuccesses >= this.config.successThreshold
    ) {
      this.transition(c, CircuitState.CLOSED);
    }
  }

  recordFailure(workerId: string): void {
    const now = Date.now() / 1000;
    const c = this.getOrCreate(workerId);
    c.consecutiveFailures++;
    c.consecutiveSuccesses = 0;
    c.totalRequests++;
    c.totalFailures++;
    c.lastFailureTime = now;
    c.recent.push({ timestamp: now, success: false });

    // HALF_OPEN: any failure trips immediately
    if (c.state === CircuitState.HALF_OPEN) {
      this.transition(c, CircuitState.OPEN);
      return;
    }

    if (c.state === CircuitState.CLOSED) {
      // Consecutive failure threshold
      if (c.consecutiveFailures >= this.config.failureThreshold) {
        this.transition(c, CircuitState.OPEN);
        return;
      }
      // Error rate guard — only fires when >= 5 total requests
      if (
        c.totalRequests >= 5 &&
        this.errorRate(c, now) >= this.config.errorRateThreshold
      ) {
        this.transition(c, CircuitState.OPEN);
      }
    }
  }

  getState(workerId: string): CircuitState {
    return this.getOrCreate(workerId).state;
  }

  getStats(workerId: string): Pick<WorkerCircuit, 'state' | 'consecutiveFailures' | 'totalRequests' | 'totalFailures'> {
    const c = this.getOrCreate(workerId);
    return {
      state: c.state,
      consecutiveFailures: c.consecutiveFailures,
      totalRequests: c.totalRequests,
      totalFailures: c.totalFailures,
    };
  }
}
