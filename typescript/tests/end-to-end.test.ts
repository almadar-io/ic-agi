// TLA+ property coverage (EndToEnd_TLC.tla):
//   C1 NoExecWithoutPipeline:  execution requires ALL gates passed (approval + token + assignment)
//   C2 PipelineOrder:          correct sequencing — token after approval, assignment after token, execution after assignment
//   C3 TokenRequiresApproval:  critical tokens need threshold approval before issuance
//   C4 ComposedThreshold:      P1 + P11 composed — execution requires K approvals AND a token
//   C5 ComposedAntiReplay:     P5 preserved in composition — token uses never exceed budget
//   C6 ComposedRevocation:     P7 preserved in composition — revoked token blocks execution
//   C7 EventualCompletion:     under fairness, pipeline eventually reaches "done" or "denied"
//
// Pipeline phases (from EndToEnd_TLC.tla):
//   "voting" → "token" → "assigning" → "executing" → "done"
//                                                    → "denied" (early denial path)
//
// This test composes ThresholdAuthorizer, CapabilityToken, CircuitBreaker, and AuditLog
// into the full end-to-end pipeline modelled by EndToEnd_TLC.tla.
//
// Reference: ic_agi/formal/EndToEnd_TLC.tla lines 186-225

import { ThresholdAuthorizer } from '../src/threshold-auth.js';
import {
  issueToken,
  verifyToken,
  isTokenValid,
  consumeToken,
  revokeToken,
} from '../src/capability-token.js';
import type { CapabilityToken } from '../src/capability-token.js';
import { CircuitBreaker, CircuitState } from '../src/circuit-breaker.js';
import { AuditLog } from '../src/audit-log.js';

const approvers = ['alice', 'bob', 'charlie'];
const signingKey = Buffer.from('end-to-end-signing-key-32bytes!!', 'utf8');

/**
 * Helper: run the full pipeline and return the state at each phase.
 * Models the EndToEnd_TLC.tla pipeline: voting → token → assigning → executing → done.
 */
function runPipeline(opts: {
  votes: Array<{ approver: string; approve: boolean }>;
  workerIds?: string[];
  targetWorker?: string;
  revokeBeforeExec?: boolean;
  tripCircuitBeforeExec?: boolean;
  budget?: number;
}) {
  const auditLog = new AuditLog();
  const auth = new ThresholdAuthorizer(2, approvers, auditLog);
  const cb = new CircuitBreaker({ failureThreshold: 3 }, auditLog);
  const workers = opts.workerIds ?? ['w1', 'w2'];
  const worker = opts.targetWorker ?? 'w1';

  // Phase 1: Voting
  const req = auth.createRequest('end-to-end test action', 'agent-1');
  let lastVote;
  for (const v of opts.votes) {
    try {
      lastVote = auth.submitVote(req.requestId, v.approver, v.approve);
    } catch {
      // already resolved
    }
  }

  const approved = auth.isApproved(req.requestId);
  const denied = auth.isDenied(req.requestId);

  // Phase 2: Token issuance (only if approved)
  let token: CapabilityToken | null = null;
  if (approved) {
    token = issueToken(
      { issuedTo: worker, scope: ['execute'], budget: opts.budget ?? 1 },
      signingKey,
    );
    auditLog.append({ event: 'TOKEN_ISSUED', tokenId: token.tokenId });
  }

  // Adversarial: revoke token
  if (opts.revokeBeforeExec && token) {
    revokeToken(token);
    auditLog.append({ event: 'TOKEN_REVOKED', tokenId: token.tokenId });
  }

  // Adversarial: trip circuit
  if (opts.tripCircuitBeforeExec) {
    for (let i = 0; i < 3; i++) cb.recordFailure(worker);
    auditLog.append({ event: 'CIRCUIT_TRIPPED', workerId: worker });
  }

  // Phase 3: Assignment check (worker must be healthy)
  const assigned = token && cb.allow(worker);

  // Phase 4: Execution (all guards must pass)
  let executed = false;
  if (token && assigned && isTokenValid(token) && verifyToken(token, signingKey)) {
    executed = consumeToken(token);
    if (executed) {
      auditLog.append({ event: 'SEGMENT_EXECUTED', workerId: worker });
    }
  }

  return {
    approved,
    denied,
    token,
    assigned,
    executed,
    auditLog,
    auth,
    req,
    approveCount: lastVote?.approvals ?? 0,
  };
}

describe('EndToEnd composition', () => {
  // ═══════════════════════════════════════════
  //  C1 — NoExecWithoutPipeline
  //  TLA+: executed = TRUE => resolution = "approved" /\ tokenIssued = TRUE /\ assigned /= "unassigned"
  // ═══════════════════════════════════════════

  describe('C1 NoExecWithoutPipeline', () => {
    it('execution requires approval + token + assignment', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
        ],
      });
      expect(result.executed).toBe(true);
      expect(result.approved).toBe(true);
      expect(result.token).not.toBeNull();
      expect(result.assigned).toBe(true);
    });

    it('no execution without approval', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: false },
          { approver: 'bob', approve: false },
        ],
      });
      expect(result.executed).toBe(false);
      expect(result.approved).toBe(false);
      expect(result.token).toBeNull();
    });

    it('no execution with only partial approval (1 of 2 needed)', () => {
      const result = runPipeline({
        votes: [{ approver: 'alice', approve: true }],
      });
      // Only 1 approval, threshold is 2 — not approved yet
      expect(result.approved).toBe(false);
      expect(result.executed).toBe(false);
    });
  });

  // ═══════════════════════════════════════════
  //  C2 — PipelineOrder
  //  TLA+: (tokenIssued => resolved) /\ (assigned /= "unassigned" => tokenIssued) /\ (executed => assigned)
  // ═══════════════════════════════════════════

  describe('C2 PipelineOrder', () => {
    it('token is only issued after approval', () => {
      // Denied request — no token
      const denied = runPipeline({
        votes: [
          { approver: 'alice', approve: false },
          { approver: 'bob', approve: false },
        ],
      });
      expect(denied.token).toBeNull();
      expect(denied.denied).toBe(true);

      // Approved request — token issued
      const approved = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
        ],
      });
      expect(approved.token).not.toBeNull();
      expect(approved.approved).toBe(true);
    });

    it('assignment requires token', () => {
      // No approval → no token → no assignment
      const result = runPipeline({
        votes: [{ approver: 'alice', approve: true }], // only 1, need 2
      });
      expect(result.token).toBeNull();
      expect(result.assigned).toBeFalsy();
    });

    it('execution requires assignment', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
        ],
        tripCircuitBeforeExec: true, // assignment fails due to open circuit
      });
      expect(result.assigned).toBe(false);
      expect(result.executed).toBe(false);
    });
  });

  // ═══════════════════════════════════════════
  //  C3 — TokenRequiresApproval
  //  TLA+: tokenIssued = TRUE => resolution = "approved"
  // ═══════════════════════════════════════════

  describe('C3 TokenRequiresApproval', () => {
    it('token issuance requires threshold approval', () => {
      // Pipeline only issues token when approved
      const approved = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
        ],
      });
      expect(approved.approved).toBe(true);
      expect(approved.token).not.toBeNull();

      const denied = runPipeline({
        votes: [
          { approver: 'alice', approve: false },
          { approver: 'bob', approve: false },
        ],
      });
      expect(denied.approved).toBe(false);
      expect(denied.token).toBeNull();
    });
  });

  // ═══════════════════════════════════════════
  //  C4 — ComposedThreshold (P1 + P11)
  //  TLA+: executed = TRUE => ApproveCount >= K /\ tokenIssued = TRUE
  // ═══════════════════════════════════════════

  describe('C4 ComposedThreshold', () => {
    it('execution requires both K approvals AND a token', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
        ],
      });
      expect(result.executed).toBe(true);
      // P1: approvals >= K (2 >= 2)
      expect(result.approveCount).toBeGreaterThanOrEqual(2);
      // P11: token was issued
      expect(result.token).not.toBeNull();
    });

    it('1 approval is insufficient for K=2', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: false },
          { approver: 'charlie', approve: false },
        ],
      });
      expect(result.executed).toBe(false);
      expect(result.denied).toBe(true);
    });
  });

  // ═══════════════════════════════════════════
  //  C5 — ComposedAntiReplay (P5 preserved)
  //  TLA+: tokenUses <= Budget
  // ═══════════════════════════════════════════

  describe('C5 ComposedAntiReplay', () => {
    it('token uses never exceed budget in composed pipeline', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
        ],
        budget: 2,
      });
      expect(result.executed).toBe(true);
      expect(result.token!.uses).toBe(1);

      // Consume again (still within budget)
      expect(consumeToken(result.token!)).toBe(true);
      expect(result.token!.uses).toBe(2);

      // Budget exhausted — anti-replay blocks further use
      expect(consumeToken(result.token!)).toBe(false);
      expect(result.token!.uses).toBe(2); // never exceeds budget
      expect(result.token!.uses).toBeLessThanOrEqual(result.token!.budget);
    });
  });

  // ═══════════════════════════════════════════
  //  C6 — ComposedRevocation (P7 preserved)
  //  TLA+: (tokenRevoked = TRUE /\ phase = "executing") => executed = FALSE
  // ═══════════════════════════════════════════

  describe('C6 ComposedRevocation', () => {
    it('revoked token blocks execution in composed pipeline', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
        ],
        revokeBeforeExec: true,
      });
      expect(result.approved).toBe(true);
      expect(result.token).not.toBeNull();
      expect(result.token!.revoked).toBe(true);
      expect(result.executed).toBe(false); // revocation blocked execution
    });

    it('revocation is permanent — cannot un-revoke', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
        ],
        revokeBeforeExec: true,
      });
      // Token is revoked — consuming should fail
      expect(consumeToken(result.token!)).toBe(false);
      // "Un-revoking" is not possible through the API (P7)
      expect(result.token!.revoked).toBe(true);
    });
  });

  // ═══════════════════════════════════════════
  //  C7 — EventualCompletion
  //  TLA+: [](AllApproved => <>(phase \in {"done", "denied"}))
  //  Tested as: if all approvers vote, the pipeline reaches a terminal state.
  // ═══════════════════════════════════════════

  describe('C7 EventualCompletion', () => {
    it('all-approve path reaches "done"', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
          { approver: 'charlie', approve: true },
        ],
      });
      // Pipeline completed: approval → token → assignment → execution → done
      expect(result.executed).toBe(true);
    });

    it('all-deny path reaches "denied"', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: false },
          { approver: 'bob', approve: false },
          { approver: 'charlie', approve: false },
        ],
      });
      expect(result.denied).toBe(true);
      expect(result.executed).toBe(false);
    });

    it('mixed votes resolve to a terminal state', () => {
      // 2 approve, 1 deny → approved (K=2 reached)
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: false },
          { approver: 'charlie', approve: true },
        ],
      });
      expect(result.approved).toBe(true);
      expect(result.executed).toBe(true);
    });

    it('audit log records all pipeline phases (A4 Completeness)', () => {
      const result = runPipeline({
        votes: [
          { approver: 'alice', approve: true },
          { approver: 'bob', approve: true },
        ],
      });
      const events = result.auditLog.getEntries().map(
        e => e.data['event'] as string,
      );
      // Pipeline generates events at each phase
      expect(events).toContain('APPROVAL_REQUEST_CREATED');
      expect(events).toContain('VOTE_SUBMITTED');
      expect(events).toContain('REQUEST_APPROVED');
      expect(events).toContain('TOKEN_ISSUED');
      expect(events).toContain('SEGMENT_EXECUTED');
      // Audit chain integrity preserved throughout (A2)
      expect(result.auditLog.verify()).toBe(true);
    });
  });
});
