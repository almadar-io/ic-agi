/**
 * CapabilityToken — HMAC-SHA256 signed scoped token with budget + TTL.
 *
 * TypeScript port of saezbaldo/ic-agi `ic_agi/control_plane.py`.
 * See: https://github.com/saezbaldo/ic-agi
 *
 * TLA+ properties verified in CapabilityTokens.tla:
 *   P5 AntiReplay:         uses <= budget (invariant)
 *   P6 TTLEnforcement:     expired tokens produce no log entries
 *   P7 RevocationFinality: revoked = true => uses frozen forever
 *   P8 BudgetMonotonicity: uses never decreases
 *   P9 ForgeryResistance:  invalid signature => uses never incremented
 */

import { createHmac, randomUUID, timingSafeEqual } from 'crypto';

const MAX_TTL_SECONDS = 3600;
const MAX_BUDGET = 100;

export interface CapabilityToken {
  tokenId: string;
  issuedTo: string;
  /** Sorted alphabetically for determinism. */
  scope: string[];
  /** Unix epoch seconds. */
  issuedAt: number;
  /** Unix epoch seconds. */
  expiresAt: number;
  budget: number;
  uses: number;
  revoked: boolean;
  metadata: Record<string, unknown>;
  /** HMAC-SHA256 hex digest over the immutable fields. */
  signature: string;
}

export interface TokenParams {
  issuedTo: string;
  scope: string[];
  ttlSeconds?: number;
  budget?: number;
  criticality?: 'low' | 'medium' | 'high' | 'critical';
  metadata?: Record<string, unknown>;
}

/**
 * Canonical signable payload.
 * - Mutable fields (uses, revoked) are intentionally excluded.
 * - Snake_case keys match Python IC-AGI for upstream PR compatibility.
 * - Scope is sorted for determinism.
 */
function signablePayload(
  token: Pick<
    CapabilityToken,
    'tokenId' | 'issuedTo' | 'scope' | 'issuedAt' | 'expiresAt' | 'budget'
  >,
): Buffer {
  const payload = JSON.stringify({
    budget: token.budget,
    expires_at: token.expiresAt,
    issued_at: token.issuedAt,
    issued_to: token.issuedTo,
    scope: [...token.scope].sort(),
    token_id: token.tokenId,
  });
  return Buffer.from(payload);
}

/** Issue a new signed capability token. TTL and budget are policy-capped. */
export function issueToken(params: TokenParams, signingKey: Buffer): CapabilityToken {
  const issuedAt = Date.now() / 1000;
  const ttl = Math.min(params.ttlSeconds ?? 60, MAX_TTL_SECONDS);
  const budget = Math.min(params.budget ?? 1, MAX_BUDGET);

  const token: CapabilityToken = {
    tokenId: randomUUID(),
    issuedTo: params.issuedTo,
    scope: [...(params.scope)].sort(),
    issuedAt,
    expiresAt: issuedAt + ttl,
    budget,
    uses: 0,
    revoked: false,
    metadata: params.metadata ?? {},
    signature: '',
  };

  token.signature = createHmac('sha256', signingKey)
    .update(signablePayload(token))
    .digest('hex');

  return token;
}

/** Verify the token's HMAC signature. Uses constant-time comparison (P9). */
export function verifyToken(token: CapabilityToken, signingKey: Buffer): boolean {
  if (!token.signature) return false;
  const expected = createHmac('sha256', signingKey)
    .update(signablePayload(token))
    .digest('hex');
  const a = Buffer.from(token.signature, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Check if the token can be used (not revoked, not expired, has remaining budget). */
export function isTokenValid(token: CapabilityToken): boolean {
  return !token.revoked && Date.now() / 1000 <= token.expiresAt && token.uses < token.budget;
}

/**
 * Consume one use from the token.
 * Returns false without mutating if the token is invalid (P5, P8).
 */
export function consumeToken(token: CapabilityToken): boolean {
  if (!isTokenValid(token)) return false;
  token.uses++;
  return true;
}

/** Permanently revoke a token. Immutable once set (P7). */
export function revokeToken(token: CapabilityToken): void {
  token.revoked = true;
}
