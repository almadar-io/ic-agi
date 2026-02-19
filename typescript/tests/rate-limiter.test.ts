import { RateLimiter } from '../src/rate-limiter.js';

describe('RateLimiter', () => {
  // --- Basic rate limiting ---

  it('allows requests within the limit', () => {
    const rl = new RateLimiter({ maxRequests: 3, windowSeconds: 60 });
    expect(rl.allow('agent-1')).toBe(true);
    expect(rl.allow('agent-1')).toBe(true);
    expect(rl.allow('agent-1')).toBe(true);
  });

  it('blocks requests that exceed the per-entity limit', () => {
    const rl = new RateLimiter({ maxRequests: 2, windowSeconds: 60, cooldownSeconds: 10 });
    expect(rl.allow('agent-1')).toBe(true);
    expect(rl.allow('agent-1')).toBe(true);
    expect(rl.allow('agent-1')).toBe(false); // exceeded
  });

  // --- remaining() ---

  it('remaining() returns full limit before any calls', () => {
    const rl = new RateLimiter({ maxRequests: 5, windowSeconds: 60 });
    expect(rl.remaining('agent-1')).toBe(5);
  });

  it('remaining() decrements with each allowed request', () => {
    const rl = new RateLimiter({ maxRequests: 5, windowSeconds: 60 });
    rl.allow('agent-1');
    rl.allow('agent-1');
    expect(rl.remaining('agent-1')).toBe(3);
  });

  it('remaining() does not go below 0', () => {
    const rl = new RateLimiter({ maxRequests: 2, windowSeconds: 60, cooldownSeconds: 0 });
    rl.allow('agent-1');
    rl.allow('agent-1');
    rl.allow('agent-1'); // blocked
    expect(rl.remaining('agent-1')).toBe(0);
  });

  // --- Cooldown after limit exceeded ---

  it('enters cooldown after limit is exceeded', () => {
    const rl = new RateLimiter({ maxRequests: 1, windowSeconds: 60, cooldownSeconds: 30 });
    expect(rl.allow('agent-1')).toBe(true);
    expect(rl.allow('agent-1')).toBe(false); // trips cooldown
    expect(rl.inCooldown('agent-1')).toBe(true);
    // while in cooldown, all subsequent calls are blocked
    expect(rl.allow('agent-1')).toBe(false);
  });

  it('inCooldown() is false before limit is hit', () => {
    const rl = new RateLimiter({ maxRequests: 5, windowSeconds: 60 });
    rl.allow('agent-1');
    expect(rl.inCooldown('agent-1')).toBe(false);
  });

  // --- reset() ---

  it('reset() clears entity counter and cooldown', () => {
    const rl = new RateLimiter({ maxRequests: 1, windowSeconds: 60, cooldownSeconds: 30 });
    rl.allow('agent-1'); // consume limit
    rl.allow('agent-1'); // enter cooldown
    rl.reset('agent-1', '*');
    expect(rl.inCooldown('agent-1')).toBe(false);
    expect(rl.allow('agent-1')).toBe(true);
  });

  // --- Scope isolation ---

  it('limits are independent per scope', () => {
    const rl = new RateLimiter({ maxRequests: 1, windowSeconds: 60, cooldownSeconds: 0 });
    expect(rl.allow('agent-1', 'execute')).toBe(true);
    expect(rl.allow('agent-1', 'execute')).toBe(false); // 'execute' exhausted
    expect(rl.allow('agent-1', 'read')).toBe(true);    // 'read' is independent
  });

  it('default scope is * when none provided', () => {
    const rl = new RateLimiter({ maxRequests: 1, windowSeconds: 60, cooldownSeconds: 0 });
    rl.allow('agent-1');           // scope = '*'
    expect(rl.allow('agent-1', '*')).toBe(false); // same bucket
  });

  // --- Entity isolation ---

  it('limits are independent per entity', () => {
    const rl = new RateLimiter({ maxRequests: 1, windowSeconds: 60, cooldownSeconds: 0 });
    expect(rl.allow('agent-1')).toBe(true);
    expect(rl.allow('agent-1')).toBe(false);
    expect(rl.allow('agent-2')).toBe(true); // separate entity, unaffected
  });

  // --- Global counter (10x per-entity limit) ---

  it('global counter blocks when system-wide limit is reached', () => {
    // maxRequests=2 → global limit = 20; use 10 distinct entities (2 each) to exhaust it
    const rl = new RateLimiter({ maxRequests: 2, windowSeconds: 60, cooldownSeconds: 0 });
    for (let i = 0; i < 10; i++) {
      rl.allow(`entity-${i}`);
      rl.allow(`entity-${i}`);
    }
    // Global counter is now at capacity (20). A new entity should be blocked.
    expect(rl.allow('new-entity')).toBe(false);
  });

  // --- resetAll() ---

  it('resetAll() clears all counters including global', () => {
    const rl = new RateLimiter({ maxRequests: 2, windowSeconds: 60, cooldownSeconds: 0 });
    // Exhaust global limit
    for (let i = 0; i < 10; i++) {
      rl.allow(`entity-${i}`);
      rl.allow(`entity-${i}`);
    }
    rl.resetAll();
    expect(rl.allow('new-entity')).toBe(true);
  });

  // --- Burst requests (multiple entities hitting limit quickly) ---

  it('handles burst requests across entities without cross-contamination', () => {
    const rl = new RateLimiter({ maxRequests: 3, windowSeconds: 60 });
    for (let i = 0; i < 3; i++) {
      expect(rl.allow('burst-a')).toBe(true);
      expect(rl.allow('burst-b')).toBe(true);
    }
    // Both should now be at their limit
    expect(rl.allow('burst-a')).toBe(false);
    expect(rl.allow('burst-b')).toBe(false);
    // A third entity should still be allowed (global not exhausted)
    expect(rl.allow('burst-c')).toBe(true);
  });
});
