/**
 * SegmentExecutionEngine — Distributed segment execution with isolation guarantees.
 *
 * TypeScript implementation of the DistributedExecution.tla formal model.
 * See: ic_agi/formal/DistributedExecution.tla
 *
 * TLA+ properties enforced:
 *   P10 SegmentIsolation:    no worker sees ALL segments
 *   P11 CapabilityGate:      executed => tokenIssued
 *   P12 CircuitBreakerSafety: circuit-open worker receives no segments
 *   P13 HMACIntegrity:       executed => stateIntegrity != "tampered"
 *   P14 ShamirThreshold:     any (K-1) workers see < totalSegments collectively
 *
 * MODEL:
 *   - One function split into S segments, each assigned to a worker
 *   - Each segment requires a capability token before execution
 *   - State integrity is verified via HMAC between segments
 *   - Circuit-broken workers are excluded from assignment and execution
 */

import { createHmac } from 'crypto';

export type IntegrityState = 'unchecked' | 'intact' | 'tampered';

export interface SegmentState {
  segmentId: string;
  assignedTo: string | null;
  tokenIssued: boolean;
  executed: boolean;
  integrity: IntegrityState;
  /** HMAC-SHA256 hex digest of the segment state payload. */
  hmac: string;
}

export interface WorkerState {
  workerId: string;
  circuitOpen: boolean;
  /** Set of segment IDs this worker has executed (its "view"). */
  viewedSegments: Set<string>;
}

export class SegmentExecutionEngine {
  private readonly segments: Map<string, SegmentState>;
  private readonly workers: Map<string, WorkerState>;
  private readonly totalSegments: number;
  private readonly kShares: number;
  private readonly hmacKey: Buffer;

  /**
   * @param segmentIds  Set of segment identifiers (e.g. ["s1","s2","s3"])
   * @param workerIds   Set of worker identifiers (e.g. ["w1","w2","w3"])
   * @param kShares     Shamir threshold — minimum shares to reconstruct
   * @param hmacKey     Secret key for state integrity HMACs
   */
  constructor(segmentIds: string[], workerIds: string[], kShares: number, hmacKey: Buffer) {
    this.totalSegments = segmentIds.length;
    this.kShares = kShares;
    this.hmacKey = hmacKey;

    this.segments = new Map();
    for (const id of segmentIds) {
      this.segments.set(id, {
        segmentId: id,
        assignedTo: null,
        tokenIssued: false,
        executed: false,
        integrity: 'unchecked',
        hmac: this.computeHmac(id),
      });
    }

    this.workers = new Map();
    for (const id of workerIds) {
      this.workers.set(id, {
        workerId: id,
        circuitOpen: false,
        viewedSegments: new Set(),
      });
    }
  }

  private computeHmac(segmentId: string): string {
    return createHmac('sha256', this.hmacKey)
      .update(segmentId)
      .digest('hex');
  }

  /**
   * Assign a segment to a worker.
   *
   * Guards (from DistributedExecution.tla Assign action):
   *   - Segment must be unassigned
   *   - Worker circuit must be closed (P12)
   *   - Worker must not end up with ALL segments (P10 isolation guard)
   */
  assign(segmentId: string, workerId: string): boolean {
    const seg = this.segments.get(segmentId);
    const worker = this.workers.get(workerId);
    if (!seg || !worker) return false;
    if (seg.assignedTo !== null) return false;
    if (worker.circuitOpen) return false;

    // P10 isolation guard: worker must not end up with ALL segments
    const currentCount = [...this.segments.values()]
      .filter(s => s.assignedTo === workerId).length;
    if (currentCount + 1 >= this.totalSegments) return false;

    seg.assignedTo = workerId;
    return true;
  }

  /**
   * Issue a capability token for an assigned segment.
   *
   * Guards (from DistributedExecution.tla IssueToken action):
   *   - Segment must be assigned
   *   - Token must not already be issued
   */
  issueToken(segmentId: string): boolean {
    const seg = this.segments.get(segmentId);
    if (!seg) return false;
    if (seg.assignedTo === null) return false;
    if (seg.tokenIssued) return false;

    seg.tokenIssued = true;
    return true;
  }

  /**
   * Execute a segment.
   *
   * Guards (from DistributedExecution.tla ExecuteSeg action):
   *   - Segment must be assigned
   *   - Token must be issued (P11 CapabilityGate)
   *   - Segment must not already be executed
   *   - State integrity must not be "tampered" (P13 HMACIntegrity)
   *   - Worker circuit must be closed (P12)
   *
   * Side effects:
   *   - Marks segment as executed
   *   - Adds segment to worker's view (workerView)
   */
  execute(segmentId: string): boolean {
    const seg = this.segments.get(segmentId);
    if (!seg) return false;
    if (seg.assignedTo === null) return false;
    if (!seg.tokenIssued) return false;
    if (seg.executed) return false;
    if (seg.integrity === 'tampered') return false;

    const worker = this.workers.get(seg.assignedTo);
    if (!worker) return false;
    if (worker.circuitOpen) return false;

    seg.executed = true;
    worker.viewedSegments.add(segmentId);
    return true;
  }

  /**
   * Adversary action: tamper with segment state.
   * Only works on "unchecked" segments (matching TLA+ TamperState guard).
   */
  tamperState(segmentId: string): boolean {
    const seg = this.segments.get(segmentId);
    if (!seg) return false;
    if (seg.integrity !== 'unchecked') return false;

    seg.integrity = 'tampered';
    seg.hmac = 'tampered-invalid';
    return true;
  }

  /**
   * Verify segment state integrity via HMAC.
   * Recomputes the expected HMAC and compares. Sets integrity to "intact"
   * or "tampered" accordingly.
   */
  verifyIntegrity(segmentId: string): boolean {
    const seg = this.segments.get(segmentId);
    if (!seg) return false;

    const expected = this.computeHmac(segmentId);
    if (seg.hmac === expected) {
      seg.integrity = 'intact';
      return true;
    }
    seg.integrity = 'tampered';
    return false;
  }

  /** Trip a worker's circuit breaker (P12). */
  tripCircuit(workerId: string): boolean {
    const worker = this.workers.get(workerId);
    if (!worker) return false;
    if (worker.circuitOpen) return false;

    worker.circuitOpen = true;
    return true;
  }

  /** Reset a worker's circuit breaker (supports L4 CircuitRecovery). */
  resetCircuit(workerId: string): boolean {
    const worker = this.workers.get(workerId);
    if (!worker) return false;
    if (!worker.circuitOpen) return false;

    worker.circuitOpen = false;
    return true;
  }

  // ═══════════════════════════════════════════
  //  PROPERTY CHECKERS
  // ═══════════════════════════════════════════

  /** P10: No worker sees ALL segments. */
  checkSegmentIsolation(): boolean {
    for (const worker of this.workers.values()) {
      if (worker.viewedSegments.size >= this.totalSegments) return false;
    }
    return true;
  }

  /** P11: executed => tokenIssued for every segment. */
  checkCapabilityGate(): boolean {
    for (const seg of this.segments.values()) {
      if (seg.executed && !seg.tokenIssued) return false;
    }
    return true;
  }

  /** P13: executed => integrity !== "tampered" for every segment. */
  checkHmacIntegrity(): boolean {
    for (const seg of this.segments.values()) {
      if (seg.executed && seg.integrity === 'tampered') return false;
    }
    return true;
  }

  /**
   * P14: Any (K-1) workers collectively see fewer than totalSegments.
   * Checks all subsets of workers with size < kShares.
   */
  checkShamirThreshold(): boolean {
    const workerList = [...this.workers.values()];
    for (let size = 1; size < this.kShares; size++) {
      for (const subset of combinations(workerList, size)) {
        const union = new Set<string>();
        for (const w of subset) {
          for (const seg of w.viewedSegments) union.add(seg);
        }
        if (union.size >= this.totalSegments) return false;
      }
    }
    return true;
  }

  // ═══════════════════════════════════════════
  //  ACCESSORS
  // ═══════════════════════════════════════════

  getSegment(segmentId: string): SegmentState | undefined {
    return this.segments.get(segmentId);
  }

  getWorker(workerId: string): WorkerState | undefined {
    return this.workers.get(workerId);
  }

  getWorkerView(workerId: string): ReadonlySet<string> {
    return this.workers.get(workerId)?.viewedSegments ?? new Set();
  }

  getTotalSegments(): number {
    return this.totalSegments;
  }

  getKShares(): number {
    return this.kShares;
  }
}

/** Generate all combinations of size k from an array. */
function* combinations<T>(arr: T[], k: number): Generator<T[]> {
  if (k === 0) { yield []; return; }
  for (let i = 0; i <= arr.length - k; i++) {
    for (const rest of combinations(arr.slice(i + 1), k - 1)) {
      yield [arr[i]!, ...rest];
    }
  }
}
