/**
 * RateLimiter — Sliding window per-entity rate limiting.
 *
 * TypeScript port of saezbaldo/ic-agi `ic_agi/rate_limiter.py`.
 * See: https://github.com/saezbaldo/ic-agi
 *
 * Two-layer design:
 *   1. Global counter (10x per-entity limit) — system-wide protection
 *   2. Per-(entity, scope) counter — fine-grained per-caller limits
 *
 * Cooldown note: when a per-entity counter is exceeded, a cooldown
 * period is applied. The global counter does not apply cooldown.
 */

import type { AuditLog } from './audit-log.js';

/** Sliding window counter for a single (entity, scope) pair. */
class SlidingWindowCounter {
  private timestamps: number[] = [];
  private cooldownUntil = 0;

  constructor(
    private readonly max: number,
    private readonly windowSeconds: number,
    private readonly cooldownSeconds: number,
  ) {}

  allow(now = Date.now() / 1000): boolean {
    if (now < this.cooldownUntil) return false;
    this.evict(now);
    if (this.timestamps.length >= this.max) {
      this.cooldownUntil = now + this.cooldownSeconds;
      return false;
    }
    this.timestamps.push(now);
    return true;
  }

  remaining(now = Date.now() / 1000): number {
    this.evict(now);
    return Math.max(0, this.max - this.timestamps.length);
  }

  get inCooldown(): boolean {
    return Date.now() / 1000 < this.cooldownUntil;
  }

  reset(): void {
    this.timestamps = [];
    this.cooldownUntil = 0;
  }

  private evict(now: number): void {
    const cutoff = now - this.windowSeconds;
    while (this.timestamps.length > 0 && (this.timestamps[0] ?? 0) < cutoff) {
      this.timestamps.shift();
    }
  }
}

export interface RateLimitConfig {
  /** Maximum requests per window. Default: 20 */
  maxRequests?: number;
  /** Sliding window duration in seconds. Default: 60 */
  windowSeconds?: number;
  /** Cooldown duration in seconds after limit exceeded. Default: 30 */
  cooldownSeconds?: number;
}

export class RateLimiter {
  private readonly counters = new Map<string, SlidingWindowCounter>();
  private readonly global: SlidingWindowCounter;
  private readonly config: Required<RateLimitConfig>;
  private readonly auditLog?: AuditLog;

  constructor(config: RateLimitConfig = {}, auditLog?: AuditLog) {
    this.config = {
      maxRequests: config.maxRequests ?? 20,
      windowSeconds: config.windowSeconds ?? 60,
      cooldownSeconds: config.cooldownSeconds ?? 30,
    };
    // Global counter is 10x the per-entity limit
    this.global = new SlidingWindowCounter(
      this.config.maxRequests * 10,
      this.config.windowSeconds,
      this.config.cooldownSeconds,
    );
    this.auditLog = auditLog;
  }

  /**
   * Check whether the (entity, scope) pair is allowed to proceed.
   * Checks the global counter first, then the per-entity counter.
   */
  allow(entity: string, scope = '*'): boolean {
    if (!this.global.allow()) {
      this.auditLog?.append({ event: 'GLOBAL_RATE_LIMIT', entity, scope });
      return false;
    }
    const key = `${entity}:${scope}`;
    if (!this.counters.has(key)) {
      this.counters.set(
        key,
        new SlidingWindowCounter(
          this.config.maxRequests,
          this.config.windowSeconds,
          this.config.cooldownSeconds,
        ),
      );
    }
    const counter = this.counters.get(key)!;
    if (!counter.allow()) {
      this.auditLog?.append({ event: 'ENTITY_RATE_LIMIT', entity, scope });
      return false;
    }
    return true;
  }

  remaining(entity: string, scope = '*'): number {
    const key = `${entity}:${scope}`;
    return this.counters.get(key)?.remaining() ?? this.config.maxRequests;
  }

  inCooldown(entity: string, scope = '*'): boolean {
    const key = `${entity}:${scope}`;
    return this.counters.get(key)?.inCooldown ?? false;
  }

  reset(entity: string, scope = '*'): void {
    const key = `${entity}:${scope}`;
    this.counters.get(key)?.reset();
    this.auditLog?.append({ event: 'RATE_LIMIT_RESET', entity, scope });
  }

  /** Reset all counters including global (test utility). */
  resetAll(): void {
    this.counters.clear();
    this.global.reset();
  }
}
