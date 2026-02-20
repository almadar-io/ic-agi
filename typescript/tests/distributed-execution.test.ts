// TLA+ property coverage (DistributedExecution.tla / DistributedExecution_TLC.tla):
//   P10 SegmentIsolation:     no worker sees ALL segments — isolation guard tests
//   P11 CapabilityGate:       executed => tokenIssued — token gate tests
//   P13 HMACIntegrity:        executed => stateIntegrity != "tampered" — integrity tests
//   P14 ShamirThreshold:      any (K-1) workers see < totalSegments — threshold tests
//
// TLA+ actions modelled:
//   Assign(s, w)   — assign segment to healthy worker (isolation guard + circuit guard)
//   IssueToken(s)  — issue capability token for assigned segment
//   ExecuteSeg(s)  — execute segment (all guards: token, integrity, circuit)
//   TamperState(s) — adversary tampers segment state
//   VerifyState(s) — HMAC integrity verification
//   TripCircuit(w) — trip worker circuit breaker
//
// Reference: ic_agi/formal/DistributedExecution.tla lines 113-138

import { SegmentExecutionEngine } from '../src/distributed-execution.js';

const hmacKey = Buffer.from('test-hmac-key-for-segment-state!', 'utf8');

describe('SegmentExecutionEngine', () => {
  // ═══════════════════════════════════════════
  //  P10 — SegmentIsolation
  //  TLA+: \A w \in Workers: Cardinality(workerView[w]) < TotalSegments
  // ═══════════════════════════════════════════

  describe('P10 SegmentIsolation', () => {
    it('prevents assigning ALL segments to a single worker', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2', 's3'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      // w1 can take s1 and s2 (2 of 3), but not s3
      expect(engine.assign('s1', 'w1')).toBe(true);
      expect(engine.assign('s2', 'w1')).toBe(true);
      expect(engine.assign('s3', 'w1')).toBe(false); // isolation guard blocks
      expect(engine.checkSegmentIsolation()).toBe(true);
    });

    it('no worker sees all segments after execution', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2', 's3'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      // Distribute segments across workers
      engine.assign('s1', 'w1');
      engine.assign('s2', 'w1');
      engine.assign('s3', 'w2');

      // Issue tokens and execute
      engine.issueToken('s1');
      engine.issueToken('s2');
      engine.issueToken('s3');
      engine.execute('s1');
      engine.execute('s2');
      engine.execute('s3');

      // w1 sees {s1, s2}, w2 sees {s3} — neither sees all 3
      expect(engine.getWorkerView('w1').size).toBeLessThan(3);
      expect(engine.getWorkerView('w2').size).toBeLessThan(3);
      expect(engine.checkSegmentIsolation()).toBe(true);
    });

    it('isolation holds with many workers and segments', () => {
      const segments = ['s1', 's2', 's3', 's4', 's5'];
      const workers = ['w1', 'w2', 'w3'];
      const engine = new SegmentExecutionEngine(segments, workers, 2, hmacKey);

      // Assign round-robin
      engine.assign('s1', 'w1');
      engine.assign('s2', 'w2');
      engine.assign('s3', 'w3');
      engine.assign('s4', 'w1');
      // w1 already has 2 segments — trying a 5th total, but w1 has 2 of 5
      // Can it take a 3rd? 2+1=3 < 5, so yes. Can it take a 4th? 3+1=4 < 5, yes.
      // But it can't get all 5 (4+1 >= 5 blocked)
      engine.assign('s5', 'w2');

      for (const s of segments) engine.issueToken(s);
      for (const s of segments) engine.execute(s);

      expect(engine.checkSegmentIsolation()).toBe(true);
    });
  });

  // ═══════════════════════════════════════════
  //  P11 — CapabilityGate
  //  TLA+: \A s \in Segments: executed[s] = TRUE => tokenIssued[s] = TRUE
  // ═══════════════════════════════════════════

  describe('P11 CapabilityGate', () => {
    it('blocks execution without token', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      engine.assign('s1', 'w1');
      // No token issued — execution must fail
      expect(engine.execute('s1')).toBe(false);
      expect(engine.getSegment('s1')!.executed).toBe(false);
      expect(engine.checkCapabilityGate()).toBe(true);
    });

    it('allows execution with token', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      engine.assign('s1', 'w1');
      engine.issueToken('s1');
      expect(engine.execute('s1')).toBe(true);
      expect(engine.getSegment('s1')!.executed).toBe(true);
      expect(engine.checkCapabilityGate()).toBe(true);
    });

    it('cannot issue token for unassigned segment', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      expect(engine.issueToken('s1')).toBe(false);
    });

    it('maintains gate invariant across multiple segments', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2', 's3'],
        ['w1', 'w2', 'w3'],
        2,
        hmacKey,
      );
      engine.assign('s1', 'w1');
      engine.assign('s2', 'w2');
      engine.assign('s3', 'w3');

      // Only issue token for s1 and s2
      engine.issueToken('s1');
      engine.issueToken('s2');

      expect(engine.execute('s1')).toBe(true);
      expect(engine.execute('s2')).toBe(true);
      expect(engine.execute('s3')).toBe(false); // no token

      // Invariant: every executed segment has a token
      expect(engine.checkCapabilityGate()).toBe(true);
    });
  });

  // ═══════════════════════════════════════════
  //  P13 — HMACIntegrity
  //  TLA+: \A s \in Segments: executed[s] = TRUE => stateIntegrity[s] /= "tampered"
  // ═══════════════════════════════════════════

  describe('P13 HMACIntegrity', () => {
    it('blocks execution of tampered segment', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      engine.assign('s1', 'w1');
      engine.issueToken('s1');
      engine.tamperState('s1');

      expect(engine.execute('s1')).toBe(false);
      expect(engine.getSegment('s1')!.executed).toBe(false);
      expect(engine.checkHmacIntegrity()).toBe(true);
    });

    it('allows execution after integrity verification passes', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      engine.assign('s1', 'w1');
      engine.issueToken('s1');
      engine.verifyIntegrity('s1'); // sets integrity to "intact"

      expect(engine.execute('s1')).toBe(true);
      expect(engine.checkHmacIntegrity()).toBe(true);
    });

    it('detects tampered HMAC during verification', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      engine.tamperState('s1');
      expect(engine.verifyIntegrity('s1')).toBe(false);
      expect(engine.getSegment('s1')!.integrity).toBe('tampered');
    });

    it('tamper only works on unchecked segments (TLA+ guard)', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      engine.verifyIntegrity('s1'); // now "intact"
      expect(engine.tamperState('s1')).toBe(false); // guard blocks
    });

    it('executed segments are never tampered (invariant holds)', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2', 's3'],
        ['w1', 'w2', 'w3'],
        2,
        hmacKey,
      );
      // Tamper s2 before execution pipeline
      engine.tamperState('s2');

      engine.assign('s1', 'w1');
      engine.assign('s2', 'w2');
      engine.assign('s3', 'w3');
      engine.issueToken('s1');
      engine.issueToken('s2');
      engine.issueToken('s3');

      engine.execute('s1'); // succeeds (unchecked, not tampered)
      engine.execute('s2'); // blocked (tampered)
      engine.execute('s3'); // succeeds

      expect(engine.getSegment('s1')!.executed).toBe(true);
      expect(engine.getSegment('s2')!.executed).toBe(false);
      expect(engine.getSegment('s3')!.executed).toBe(true);
      expect(engine.checkHmacIntegrity()).toBe(true);
    });
  });

  // ═══════════════════════════════════════════
  //  P14 — ShamirThreshold
  //  TLA+: \A S_sub \in SUBSET Workers:
  //           Cardinality(S_sub) < K_shares =>
  //             Cardinality(UNION {workerView[w] : w \in S_sub}) < TotalSegments
  // ═══════════════════════════════════════════

  describe('P14 ShamirThreshold', () => {
    it('K-1 workers cannot reconstruct the full function', () => {
      // 3 segments, 3 workers, K=2
      // Each worker gets exactly 1 segment → any single worker sees < 3
      const engine = new SegmentExecutionEngine(
        ['s1', 's2', 's3'],
        ['w1', 'w2', 'w3'],
        2,
        hmacKey,
      );
      engine.assign('s1', 'w1');
      engine.assign('s2', 'w2');
      engine.assign('s3', 'w3');
      engine.issueToken('s1');
      engine.issueToken('s2');
      engine.issueToken('s3');
      engine.execute('s1');
      engine.execute('s2');
      engine.execute('s3');

      // Any single worker (K-1 = 1) sees only 1 segment out of 3
      expect(engine.getWorkerView('w1').size).toBe(1);
      expect(engine.getWorkerView('w2').size).toBe(1);
      expect(engine.getWorkerView('w3').size).toBe(1);
      expect(engine.checkShamirThreshold()).toBe(true);
    });

    it('K workers together may see all segments (but K-1 cannot)', () => {
      // 3 segments, 3 workers, K=3
      // Each worker gets 1 segment. K-1=2 workers see 2 of 3 segments.
      const engine = new SegmentExecutionEngine(
        ['s1', 's2', 's3'],
        ['w1', 'w2', 'w3'],
        3,
        hmacKey,
      );
      engine.assign('s1', 'w1');
      engine.assign('s2', 'w2');
      engine.assign('s3', 'w3');
      engine.issueToken('s1');
      engine.issueToken('s2');
      engine.issueToken('s3');
      engine.execute('s1');
      engine.execute('s2');
      engine.execute('s3');

      // Any 2 workers (K-1) see at most 2 of 3 segments
      expect(engine.checkShamirThreshold()).toBe(true);
    });

    it('isolation guard prevents threshold violation with 2 workers', () => {
      // 3 segments, 2 workers, K=2
      // Without isolation guard, w1 could get all 3 → K-1=1 worker sees all
      // Isolation guard limits each worker to < totalSegments
      const engine = new SegmentExecutionEngine(
        ['s1', 's2', 's3'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      engine.assign('s1', 'w1');
      engine.assign('s2', 'w1');
      // w1 already has 2 of 3 — isolation guard blocks 3rd
      expect(engine.assign('s3', 'w1')).toBe(false);

      engine.assign('s3', 'w2');
      engine.issueToken('s1');
      engine.issueToken('s2');
      engine.issueToken('s3');
      engine.execute('s1');
      engine.execute('s2');
      engine.execute('s3');

      // w1 sees {s1,s2}, w2 sees {s3} — any single worker < 3
      expect(engine.checkShamirThreshold()).toBe(true);
    });

    it('threshold property holds with higher K', () => {
      // 4 segments, 4 workers, K=3
      // Each worker gets 1 segment. Any 2 workers see 2 of 4.
      const segments = ['s1', 's2', 's3', 's4'];
      const workers = ['w1', 'w2', 'w3', 'w4'];
      const engine = new SegmentExecutionEngine(segments, workers, 3, hmacKey);

      engine.assign('s1', 'w1');
      engine.assign('s2', 'w2');
      engine.assign('s3', 'w3');
      engine.assign('s4', 'w4');
      for (const s of segments) engine.issueToken(s);
      for (const s of segments) engine.execute(s);

      // Any 2 workers (K-1=2) see at most 2 of 4 segments
      expect(engine.checkShamirThreshold()).toBe(true);
    });
  });

  // ═══════════════════════════════════════════
  //  Cross-property integration
  // ═══════════════════════════════════════════

  describe('Cross-property integration', () => {
    it('all invariants hold after a full execution pipeline', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2', 's3'],
        ['w1', 'w2', 'w3'],
        2,
        hmacKey,
      );

      // Full pipeline: assign → issueToken → verify → execute
      engine.assign('s1', 'w1');
      engine.assign('s2', 'w2');
      engine.assign('s3', 'w3');
      engine.issueToken('s1');
      engine.issueToken('s2');
      engine.issueToken('s3');
      engine.verifyIntegrity('s1');
      engine.verifyIntegrity('s2');
      engine.verifyIntegrity('s3');
      engine.execute('s1');
      engine.execute('s2');
      engine.execute('s3');

      expect(engine.checkSegmentIsolation()).toBe(true);   // P10
      expect(engine.checkCapabilityGate()).toBe(true);      // P11
      expect(engine.checkHmacIntegrity()).toBe(true);       // P13
      expect(engine.checkShamirThreshold()).toBe(true);     // P14
    });

    it('circuit-broken worker blocks both assignment and execution (P12)', () => {
      const engine = new SegmentExecutionEngine(
        ['s1', 's2'],
        ['w1', 'w2'],
        2,
        hmacKey,
      );
      engine.tripCircuit('w1');

      // Cannot assign to circuit-broken worker
      expect(engine.assign('s1', 'w1')).toBe(false);

      // Assign and token via w2, then trip w2 before execution
      engine.assign('s1', 'w2');
      engine.issueToken('s1');
      engine.tripCircuit('w2');
      expect(engine.execute('s1')).toBe(false);
    });
  });
});
