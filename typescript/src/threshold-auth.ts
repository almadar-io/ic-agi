/**
 * ThresholdAuthorizer — K-of-N approval voting for critical agent actions.
 *
 * TypeScript port of saezbaldo/ic-agi `ic_agi/threshold_auth.py`.
 * See: https://github.com/saezbaldo/ic-agi
 *
 * TLA+ properties verified in ThresholdAuth.tla:
 *   P1 ThresholdSafety:       executed => approvals >= K
 *   P2 NoUnilateralAuthority: K >= 2 enforced in constructor
 *   P3 DenialFinality:        once denied, resolution immutable
 *   P4 ResolutionImmutability: resolved => resolution never changes
 *
 * Early-denial formula: deny_count > (N - K)
 * Once enough denials make threshold mathematically unreachable,
 * the request is immediately resolved as denied.
 */

import { randomUUID } from 'crypto';
import type { AuditLog } from './audit-log.js';

export interface ApprovalRequest {
  requestId: string;
  actionDescription: string;
  criticality: string;
  requester: string;
  /** Unix epoch seconds. */
  createdAt: number;
  ttlSeconds: number;
  /** Map of approverId → vote (true = approve, false = deny). */
  approvals: Map<string, boolean>;
  resolved: boolean;
  resolution: 'approved' | 'denied' | 'expired' | null;
}

export interface VoteResult {
  status: 'approved' | 'denied' | 'pending';
  approvals: number;
  denials: number;
  threshold: number;
  /** Remaining approvals needed to reach threshold. */
  remaining: number;
}

export class ThresholdAuthorizer {
  private requests = new Map<string, ApprovalRequest>();
  private readonly k: number;
  private readonly n: number;
  private readonly approverIds: Set<string>;
  private readonly auditLog?: AuditLog;

  /**
   * @param k         Minimum approvals required (must be >= 2, P2)
   * @param approverIds List of registered approver IDs (length >= k)
   * @param auditLog  Optional audit chain for all voting events
   */
  constructor(k: number, approverIds: string[], auditLog?: AuditLog) {
    if (k < 2) throw new Error('Threshold must be >= 2 — no unilateral authority (P2)');
    if (k > approverIds.length) throw new Error('Threshold cannot exceed number of approvers');
    this.k = k;
    this.n = approverIds.length;
    this.approverIds = new Set(approverIds);
    this.auditLog = auditLog;
  }

  /**
   * Create a new approval request for a critical action.
   * The request window is 5 minutes (300s).
   */
  createRequest(
    actionDescription: string,
    requester: string,
    criticality = 'critical',
  ): ApprovalRequest {
    const req: ApprovalRequest = {
      requestId: randomUUID(),
      actionDescription,
      criticality,
      requester,
      createdAt: Date.now() / 1000,
      ttlSeconds: 300,
      approvals: new Map(),
      resolved: false,
      resolution: null,
    };
    this.requests.set(req.requestId, req);
    this.auditLog?.append({
      event: 'APPROVAL_REQUEST_CREATED',
      requestId: req.requestId,
      action: actionDescription,
      requester,
      criticality,
    });
    return req;
  }

  /**
   * Submit a vote for a pending request.
   * Auto-resolves the request when threshold is reached (approve)
   * or when threshold becomes mathematically unreachable (deny).
   *
   * @throws if request not found, already resolved, expired, approver not registered, or double-vote
   */
  submitVote(requestId: string, approverId: string, vote: boolean): VoteResult {
    const req = this.requests.get(requestId);
    if (!req) throw new Error(`Request ${requestId} not found`);
    if (req.resolved) throw new Error(`Request ${requestId} already resolved (P4)`);
    if (this.isExpired(requestId)) {
      req.resolved = true;
      req.resolution = 'expired';
      this.auditLog?.append({ event: 'REQUEST_EXPIRED', requestId });
      throw new Error(`Request ${requestId} has expired`);
    }
    if (!this.approverIds.has(approverId)) {
      throw new Error(`Approver ${approverId} is not registered`);
    }
    if (req.approvals.has(approverId)) {
      throw new Error(`Approver ${approverId} has already voted`);
    }

    req.approvals.set(approverId, vote);
    this.auditLog?.append({ event: 'VOTE_SUBMITTED', requestId, approverId, vote });

    const yesVotes = [...req.approvals.values()].filter(Boolean).length;
    const noVotes = [...req.approvals.values()].filter(v => !v).length;

    // P1: auto-approve once threshold reached
    if (yesVotes >= this.k) {
      req.resolved = true;
      req.resolution = 'approved';
      this.auditLog?.append({ event: 'REQUEST_APPROVED', requestId, approvals: yesVotes });
    }

    // P3: early denial — deny_count > (N - K) means threshold is unreachable
    if (!req.resolved && noVotes > this.n - this.k) {
      req.resolved = true;
      req.resolution = 'denied';
      this.auditLog?.append({ event: 'REQUEST_DENIED', requestId, denials: noVotes });
    }

    return {
      status: req.resolved ? (req.resolution as 'approved' | 'denied') : 'pending',
      approvals: yesVotes,
      denials: noVotes,
      threshold: this.k,
      remaining: Math.max(0, this.k - yesVotes),
    };
  }

  /** Returns true iff the request is resolved and approved (P1). */
  isApproved(requestId: string): boolean {
    const req = this.requests.get(requestId);
    return !!req?.resolved && req.resolution === 'approved';
  }

  /** Returns true iff the request is resolved and denied (P3). */
  isDenied(requestId: string): boolean {
    const req = this.requests.get(requestId);
    return !!req?.resolved && req.resolution === 'denied';
  }

  isExpired(requestId: string): boolean {
    const req = this.requests.get(requestId);
    if (!req) return true;
    return Date.now() / 1000 > req.createdAt + req.ttlSeconds;
  }

  getRequest(requestId: string): ApprovalRequest | undefined {
    return this.requests.get(requestId);
  }
}
