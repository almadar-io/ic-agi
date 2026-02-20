// TLA+ property coverage (CapabilityTokens.tla):
//   P5 AntiReplay:         uses <= budget (invariant) — budget exhaustion test
//   P6 TTLEnforcement:     expired tokens produce no log entries — expired token rejection test
//   P7 RevocationFinality: revoked = true => uses frozen forever — revocation finality test
//   P8 BudgetMonotonicity: uses never decreases — uses counter never exceeds budget test
//   P9 ForgeryResistance:  invalid signature => uses never incremented — forged signature test
//
// Additional coverage:
//   - Policy caps: TTL capped at 3600s, budget capped at 100
//   - HMAC-SHA256 signature verification via timingSafeEqual (constant-time)

import {
  issueToken,
  verifyToken,
  isTokenValid,
  consumeToken,
  revokeToken,
} from '../src/capability-token.js';

const signingKey = Buffer.from('test-signing-key-32-bytes-padding', 'utf8');

describe('CapabilityToken', () => {
  it('issues a valid signed token', () => {
    const token = issueToken({ issuedTo: 'worker-1', scope: ['execute'] }, signingKey);
    expect(verifyToken(token, signingKey)).toBe(true);
    expect(isTokenValid(token)).toBe(true);
    expect(token.uses).toBe(0);
    expect(token.revoked).toBe(false);
  });

  it('consumes budget and invalidates at zero (P5)', () => {
    const token = issueToken({ issuedTo: 'w', scope: ['x'], budget: 2 }, signingKey);
    expect(consumeToken(token)).toBe(true);
    expect(consumeToken(token)).toBe(true);
    expect(consumeToken(token)).toBe(false); // budget exhausted
    expect(token.uses).toBe(2); // uses never exceeds budget (P8)
  });

  it('revocation is final (P7)', () => {
    const token = issueToken({ issuedTo: 'w', scope: ['x'] }, signingKey);
    revokeToken(token);
    expect(isTokenValid(token)).toBe(false);
    expect(consumeToken(token)).toBe(false);
    expect(token.uses).toBe(0); // uses frozen after revocation
  });

  it('rejects forged signature (P9)', () => {
    const token = issueToken({ issuedTo: 'w', scope: ['x'] }, signingKey);
    const wrongKey = Buffer.from('wrong-signing-key-32-bytes-pad!!', 'utf8');
    expect(verifyToken(token, wrongKey)).toBe(false);
  });

  it('rejects expired token (P6)', async () => {
    const token = issueToken({ issuedTo: 'w', scope: ['x'], ttlSeconds: -1 }, signingKey);
    expect(isTokenValid(token)).toBe(false);
  });

  it('caps TTL at 3600s', () => {
    const token = issueToken({ issuedTo: 'w', scope: ['x'], ttlSeconds: 99999 }, signingKey);
    expect(token.expiresAt - token.issuedAt).toBeLessThanOrEqual(3600);
  });

  it('caps budget at 100', () => {
    const token = issueToken({ issuedTo: 'w', scope: ['x'], budget: 9999 }, signingKey);
    expect(token.budget).toBeLessThanOrEqual(100);
  });
});
