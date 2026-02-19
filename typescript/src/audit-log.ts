/**
 * AuditLog — Hash-chained append-only audit ledger.
 *
 * TypeScript port of saezbaldo/ic-agi `ic_agi/audit_log.py`.
 * See: https://github.com/saezbaldo/ic-agi
 *
 * Each entry is cryptographically linked to the previous one via
 * SHA-256 chaining. Any tampering with historical entries will
 * break chain verification.
 */

import { createHash } from 'crypto';

// Genesis sentinel — hardcoded string matching the Python implementation
const GENESIS_HASH = createHash('sha256').update('IC-AGI-GENESIS').digest('hex');

/**
 * Produce a deterministic JSON string: sorted keys, no spaces.
 * Matches Python's json.dumps(sort_keys=True, separators=(',', ':'), default=str).
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) ?? 'null';
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => `${JSON.stringify(k)}:${stableStringify(obj[k])}`);
  return `{${pairs.join(',')}}`;
}

export interface AuditEntry {
  /** Zero-based position in the chain. */
  index: number;
  /** Unix epoch seconds — set by append(), never caller-supplied. */
  timestamp: number;
  /** Arbitrary event data. */
  data: Record<string, unknown>;
  /** SHA-256 of the previous entry (or GENESIS_HASH for the first entry). */
  prevHash: string;
  /** SHA-256 of this entry's canonical form. */
  entryHash: string;
}

/**
 * Hash payload uses snake_case keys (`prev_hash`) intentionally to match the Python IC-AGI
 * implementation. Do NOT rename to camelCase (`prevHash`) — doing so would change the SHA-256
 * digest and break cross-language audit log verification.
 */
function computeEntryHash(entry: Omit<AuditEntry, 'entryHash'>): string {
  const content = stableStringify({
    data: entry.data,
    index: entry.index,
    prev_hash: entry.prevHash,
    timestamp: entry.timestamp,
  });
  return createHash('sha256').update(content).digest('hex');
}

export class AuditLog {
  private entries: AuditEntry[] = [];

  /**
   * Append a new entry to the chain.
   * The timestamp is set here — callers cannot supply it.
   */
  append(data: Record<string, unknown>): AuditEntry {
    const prevHash =
      this.entries.length > 0
        ? this.entries[this.entries.length - 1].entryHash
        : GENESIS_HASH;

    const partial: Omit<AuditEntry, 'entryHash'> = {
      index: this.entries.length,
      timestamp: Date.now() / 1000,
      data,
      prevHash,
    };
    const entry: AuditEntry = { ...partial, entryHash: computeEntryHash(partial) };
    this.entries.push(entry);
    return entry;
  }

  /**
   * Verify the integrity of the entire chain.
   * Recomputes every entry hash and checks chain linkage.
   * Returns false immediately on the first mismatch.
   */
  verify(): boolean {
    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];
      if (entry.entryHash !== computeEntryHash(entry)) return false;
      const expectedPrev = i === 0 ? GENESIS_HASH : this.entries[i - 1].entryHash;
      if (entry.prevHash !== expectedPrev) return false;
    }
    return true;
  }

  /** Return entries, optionally filtered by source, event type, or count limit. */
  getEntries(filter?: { source?: string; event?: string; limit?: number }): AuditEntry[] {
    let results = this.entries;
    if (filter?.source) results = results.filter(e => e.data['source'] === filter.source);
    if (filter?.event) results = results.filter(e => e.data['event'] === filter.event);
    if (filter?.limit) results = results.slice(-filter.limit);
    return results;
  }

  getEntry(index: number): AuditEntry | undefined {
    return this.entries[index];
  }

  get length(): number {
    return this.entries.length;
  }
}
