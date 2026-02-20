// TLA+ property coverage (AuditLog_TLC.tla):
//   A1 AppendOnly:         log length never decreases — append & index test
//   A2 HashChain:          every entry links to predecessor's hash — integrity verification test
//   A3 Immutability:       existing entries never change — tamper detection test
//   A4 Completeness:       every action generates a log entry — implicit in all append tests
//   A5 GrowthMonotonicity: log length monotonically non-decreasing — append ordering test
//
// Additional coverage:
//   - Timestamp immutability: caller-supplied timestamps are rejected (server-authoritative time)
//   - Filter correctness: event-type filtering returns correct subsets

import { AuditLog } from '../src/audit-log.js';

describe('AuditLog', () => {
  it('appends entries and maintains index', () => {
    const log = new AuditLog();
    const e1 = log.append({ event: 'TEST', source: 'unit' });
    const e2 = log.append({ event: 'TEST2', source: 'unit' });
    expect(e1.index).toBe(0);
    expect(e2.index).toBe(1);
    expect(log.length).toBe(2);
  });

  it('passes integrity verification on unmodified chain', () => {
    const log = new AuditLog();
    log.append({ event: 'A' });
    log.append({ event: 'B' });
    log.append({ event: 'C' });
    expect(log.verify()).toBe(true);
  });

  it('fails integrity verification if entry is tampered', () => {
    const log = new AuditLog();
    log.append({ event: 'A' });
    log.append({ event: 'B' });
    const entries = log.getEntries();
    // Tamper with first entry's data
    (entries[0] as { data: Record<string, unknown> }).data['event'] = 'TAMPERED';
    expect(log.verify()).toBe(false);
  });

  it('filters by event type', () => {
    const log = new AuditLog();
    log.append({ event: 'FOO' });
    log.append({ event: 'BAR' });
    log.append({ event: 'FOO' });
    expect(log.getEntries({ event: 'FOO' })).toHaveLength(2);
    expect(log.getEntries({ event: 'BAR' })).toHaveLength(1);
  });

  it('does not accept caller-supplied timestamps', () => {
    const log = new AuditLog();
    const before = Date.now() / 1000;
    const entry = log.append({ event: 'X', timestamp: 0 });
    const after = Date.now() / 1000;
    expect(entry.timestamp).toBeGreaterThanOrEqual(before);
    expect(entry.timestamp).toBeLessThanOrEqual(after);
  });
});
