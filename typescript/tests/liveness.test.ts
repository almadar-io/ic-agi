// TLA+ liveness property coverage:
//
//   L1 EventualResolution (ThresholdAuth_TLC.tla):
//     [](AllVoted => resolved = TRUE)
//     Once all approvers have voted, the request is resolved.
//     Reference: ic_agi/formal/ThresholdAuth_TLC.tla lines 113-116
//
//   L2 EventualExpiry (CapabilityTokens_TLC.tla):
//     [](clock >= TTL => ~TokenValid)
//     A token past its TTL is eventually invalid.
//     Reference: ic_agi/formal/CapabilityTokens_TLC.tla lines 119-120
//
//   L4 CircuitRecovery (DistributedExecution_TLC.tla):
//     \A w \in Workers: [](circuitOpen[w] = TRUE => <>(circuitOpen[w] = FALSE))
//     An open circuit eventually recovers (under strong fairness).
//     Reference: ic_agi/formal/DistributedExecution_TLC.tla lines 180-182
//
// Liveness properties are temporal (they describe "eventually" behaviors).
// In unit tests we model them by simulating time progression and verifying
// that the system reaches the expected state.

import { ThresholdAuthorizer } from '../src/threshold-auth.js';
import {
  issueToken,
  isTokenValid,
  consumeToken,
} from '../src/capability-token.js';
import { CircuitBreaker, CircuitState } from '../src/circuit-breaker.js';

const approvers = ['alice', 'bob', 'charlie'];
const signingKey = Buffer.from('liveness-test-signing-key-32b!!!', 'utf8');

describe('Liveness properties', () => {
  // ═══════════════════════════════════════════
  //  L1 — EventualResolution
  //  TLA+: [](AllVoted => resolved = TRUE)
  //  ThresholdAuth_TLC.tla: once all approvers have voted, the request is resolved.
  // ═══════════════════════════════════════════

  describe('L1 EventualResolution', () => {
    it('all-approve resolves immediately', () => {
      const auth = new ThresholdAuthorizer(2, approvers);
      const req = auth.createRequest('action', 'agent');
      auth.submitVote(req.requestId, 'alice', true);
      // After 2nd vote, threshold reached → resolved
      const result = auth.submitVote(req.requestId, 'bob', true);
      expect(result.status).toBe('approved');
      expect(auth.getRequest(req.requestId)!.resolved).toBe(true);
    });

    it('all-deny resolves immediately', () => {
      const auth = new ThresholdAuthorizer(2, approvers);
      const req = auth.createRequest('action', 'agent');
      auth.submitVote(req.requestId, 'alice', false);
      // After 2nd deny, threshold unreachable → resolved as denied
      const result = auth.submitVote(req.requestId, 'bob', false);
      expect(result.status).toBe('denied');
      expect(auth.getRequest(req.requestId)!.resolved).toBe(true);
    });

    it('mixed votes: once all vote, request is resolved', () => {
      const auth = new ThresholdAuthorizer(2, approvers);
      const req = auth.createRequest('action', 'agent');
      auth.submitVote(req.requestId, 'alice', true);
      auth.submitVote(req.requestId, 'bob', false);
      // After charlie votes approve, threshold (2) is reached → resolved
      const result = auth.submitVote(req.requestId, 'charlie', true);
      expect(result.status).toBe('approved');
      expect(auth.getRequest(req.requestId)!.resolved).toBe(true);
    });

    it('all deny with K=2 N=3: 2 denials resolve (deny > N-K)', () => {
      // N-K = 3-2 = 1. After 2 denials (> 1), resolved as denied.
      const auth = new ThresholdAuthorizer(2, approvers);
      const req = auth.createRequest('action', 'agent');
      auth.submitVote(req.requestId, 'alice', false);
      const result = auth.submitVote(req.requestId, 'bob', false);
      expect(result.status).toBe('denied');
      // charlie's vote is irrelevant — already resolved
      expect(auth.getRequest(req.requestId)!.resolved).toBe(true);
    });

    it('resolution is reached for every possible vote permutation (exhaustive K=2 N=3)', () => {
      // Exhaustively test all 2^3 = 8 vote combinations for 3 approvers
      const votePatterns = [
        [true, true, true],
        [true, true, false],
        [true, false, true],
        [true, false, false],
        [false, true, true],
        [false, true, false],
        [false, false, true],
        [false, false, false],
      ];

      for (const pattern of votePatterns) {
        const auth = new ThresholdAuthorizer(2, approvers);
        const req = auth.createRequest('action', 'agent');
        for (let i = 0; i < approvers.length; i++) {
          try {
            auth.submitVote(req.requestId, approvers[i]!, pattern[i]!);
          } catch {
            // already resolved — expected for some patterns
          }
        }
        // L1: after all votes, request MUST be resolved
        expect(auth.getRequest(req.requestId)!.resolved).toBe(true);
      }
    });
  });

  // ═══════════════════════════════════════════
  //  L2 — EventualExpiry
  //  TLA+: [](clock >= TTL => ~TokenValid)
  //  CapabilityTokens_TLC.tla: a token past its TTL is invalid.
  // ═══════════════════════════════════════════

  describe('L2 EventualExpiry', () => {
    it('token becomes invalid after TTL expires', () => {
      // Issue token with TTL already in the past
      const token = issueToken(
        { issuedTo: 'w1', scope: ['execute'], ttlSeconds: -1 },
        signingKey,
      );
      // clock >= TTL → ~TokenValid
      expect(isTokenValid(token)).toBe(false);
    });

    it('expired token cannot be consumed', () => {
      const token = issueToken(
        { issuedTo: 'w1', scope: ['execute'], ttlSeconds: -1 },
        signingKey,
      );
      expect(consumeToken(token)).toBe(false);
      expect(token.uses).toBe(0); // uses frozen
    });

    it('token is valid before TTL and invalid after', () => {
      // Issue with 60s TTL — should be valid now
      const token = issueToken(
        { issuedTo: 'w1', scope: ['execute'], ttlSeconds: 60 },
        signingKey,
      );
      expect(isTokenValid(token)).toBe(true);

      // Simulate time passing: manually set expiresAt to the past
      token.expiresAt = Date.now() / 1000 - 1;
      expect(isTokenValid(token)).toBe(false);
      expect(consumeToken(token)).toBe(false);
    });

    it('expiry is permanent — no re-validation after TTL', () => {
      const token = issueToken(
        { issuedTo: 'w1', scope: ['execute'], ttlSeconds: -1 },
        signingKey,
      );
      expect(isTokenValid(token)).toBe(false);
      // Even with remaining budget, expired token stays invalid
      expect(token.uses).toBe(0);
      expect(token.budget).toBeGreaterThan(0);
      expect(consumeToken(token)).toBe(false);
    });
  });

  // ═══════════════════════════════════════════
  //  L4 — CircuitRecovery
  //  TLA+: \A w \in Workers: [](circuitOpen[w] = TRUE => <>(circuitOpen[w] = FALSE))
  //  DistributedExecution_TLC.tla: an open circuit eventually recovers.
  // ═══════════════════════════════════════════

  describe('L4 CircuitRecovery', () => {
    it('OPEN circuit recovers to HALF_OPEN after timeout', () => {
      const cb = new CircuitBreaker({
        failureThreshold: 2,
        recoveryTimeoutSeconds: 0, // immediate recovery for testing
      });
      cb.recordFailure('w1');
      cb.recordFailure('w1');
      expect(cb.getState('w1')).toBe(CircuitState.OPEN);

      // After recovery timeout (0s), allow() transitions OPEN → HALF_OPEN
      expect(cb.allow('w1')).toBe(true);
      expect(cb.getState('w1')).toBe(CircuitState.HALF_OPEN);
    });

    it('HALF_OPEN circuit recovers to CLOSED after success threshold', () => {
      const cb = new CircuitBreaker({
        failureThreshold: 2,
        successThreshold: 2,
        recoveryTimeoutSeconds: 0,
      });
      // Trip the circuit
      cb.recordFailure('w1');
      cb.recordFailure('w1');
      expect(cb.getState('w1')).toBe(CircuitState.OPEN);

      // Transition OPEN → HALF_OPEN
      cb.allow('w1');
      expect(cb.getState('w1')).toBe(CircuitState.HALF_OPEN);

      // Recover HALF_OPEN → CLOSED
      cb.recordSuccess('w1');
      cb.recordSuccess('w1');
      expect(cb.getState('w1')).toBe(CircuitState.CLOSED);
    });

    it('full recovery cycle: CLOSED → OPEN → HALF_OPEN → CLOSED', () => {
      const cb = new CircuitBreaker({
        failureThreshold: 2,
        successThreshold: 1,
        recoveryTimeoutSeconds: 0,
      });

      // Start CLOSED
      expect(cb.getState('w1')).toBe(CircuitState.CLOSED);
      expect(cb.allow('w1')).toBe(true);

      // Trip to OPEN
      cb.recordFailure('w1');
      cb.recordFailure('w1');
      expect(cb.getState('w1')).toBe(CircuitState.OPEN);
      expect(cb.allow('w1')).toBe(true); // transitions to HALF_OPEN

      // Recover to CLOSED
      expect(cb.getState('w1')).toBe(CircuitState.HALF_OPEN);
      cb.recordSuccess('w1');
      expect(cb.getState('w1')).toBe(CircuitState.CLOSED);

      // Worker is fully recovered and operational
      expect(cb.allow('w1')).toBe(true);
    });

    it('recovery applies independently per worker', () => {
      const cb = new CircuitBreaker({
        failureThreshold: 2,
        successThreshold: 1,
        recoveryTimeoutSeconds: 0,
      });

      // Trip both workers
      cb.recordFailure('w1');
      cb.recordFailure('w1');
      cb.recordFailure('w2');
      cb.recordFailure('w2');
      expect(cb.getState('w1')).toBe(CircuitState.OPEN);
      expect(cb.getState('w2')).toBe(CircuitState.OPEN);

      // Recover w1 only
      cb.allow('w1'); // OPEN → HALF_OPEN
      cb.recordSuccess('w1'); // HALF_OPEN → CLOSED
      expect(cb.getState('w1')).toBe(CircuitState.CLOSED);
      expect(cb.getState('w2')).toBe(CircuitState.OPEN); // w2 still open
    });

    it('repeated trip and recovery cycle (fairness)', () => {
      const cb = new CircuitBreaker({
        failureThreshold: 2,
        successThreshold: 1,
        recoveryTimeoutSeconds: 0,
      });

      for (let cycle = 0; cycle < 3; cycle++) {
        // Trip
        cb.recordFailure('w1');
        cb.recordFailure('w1');
        expect(cb.getState('w1')).toBe(CircuitState.OPEN);

        // Recover
        cb.allow('w1');
        cb.recordSuccess('w1');
        expect(cb.getState('w1')).toBe(CircuitState.CLOSED);
      }
      // After 3 trip-recovery cycles, worker is still operational
      expect(cb.allow('w1')).toBe(true);
    });
  });
});
