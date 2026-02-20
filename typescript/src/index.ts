/**
 * @almadar/agent security layer — IC-AGI TypeScript port.
 *
 * Ported from: https://github.com/saezbaldo/ic-agi
 * Fork:        https://github.com/almadar-io/ic-agi
 */

export { AuditLog } from './audit-log.js';
export type { AuditEntry } from './audit-log.js';

export {
  issueToken,
  verifyToken,
  isTokenValid,
  consumeToken,
  revokeToken,
} from './capability-token.js';
export type { CapabilityToken, TokenParams } from './capability-token.js';

export { ThresholdAuthorizer } from './threshold-auth.js';
export type { ApprovalRequest, VoteResult } from './threshold-auth.js';

export { RateLimiter } from './rate-limiter.js';
export type { RateLimitConfig } from './rate-limiter.js';

export { CircuitBreaker, CircuitState } from './circuit-breaker.js';
export type { CircuitBreakerConfig } from './circuit-breaker.js';

export { SegmentExecutionEngine } from './distributed-execution.js';
export type { SegmentState, WorkerState, IntegrityState } from './distributed-execution.js';
