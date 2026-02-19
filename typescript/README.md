# IC-AGI TypeScript

TypeScript port of [IC-AGI](https://github.com/saezbaldo/ic-agi) — cryptographic authority guarantees for AI agents.

Ported and maintained by [Almadar](https://almadar.io). Contributions welcome back to the upstream repo.

## Modules

| Module | Description |
|--------|-------------|
| `AuditLog` | SHA-256 hash-chained append-only ledger. Tamper-evident. Genesis sentinel `"IC-AGI-GENESIS"`. |
| `CapabilityToken` | HMAC-SHA256 signed scoped tokens with budget + TTL. TLA+ properties P5–P9. |
| `ThresholdAuthorizer` | K-of-N approval voting. Early denial. TLA+ properties P1–P4. K≥2 enforced. |
| `RateLimiter` | Sliding window with global + per-entity layers and cooldown periods. |
| `CircuitBreaker` | CLOSED → OPEN → HALF_OPEN state machine with consecutive failure + error rate guards. |

## Install

```bash
npm install @ic-agi/typescript
```

## Usage

### AuditLog

```typescript
import { AuditLog } from '@ic-agi/typescript';

const log = new AuditLog();
log.append({ event: 'TOOL_CALL', tool: 'execute', command: 'npm install' });
log.append({ event: 'TOOL_COMPLETE', tool: 'execute', exitCode: 0 });

console.log(log.verify()); // true — chain intact
```

### CapabilityToken

```typescript
import { issueToken, verifyToken, consumeToken } from '@ic-agi/typescript';
import { randomBytes } from 'crypto';

const signingKey = randomBytes(32);

// Issue a token: agent may call "execute" up to 10 times, valid for 5 minutes
const token = issueToken({
  issuedTo: 'agent-session-abc',
  scope: ['execute'],
  ttlSeconds: 300,
  budget: 10,
}, signingKey);

// Before each tool call:
if (consumeToken(token)) {
  // execute the tool
} else {
  // token exhausted or expired
}
```

### ThresholdAuthorizer (K-of-N)

```typescript
import { ThresholdAuthorizer } from '@ic-agi/typescript';

// Require 2 of 3 approvals for critical actions
const auth = new ThresholdAuthorizer(2, ['alice', 'bob', 'charlie']);

const req = auth.createRequest('git push origin main', 'agent-1');

// Both alice and bob must approve:
auth.submitVote(req.requestId, 'alice', true);
const result = auth.submitVote(req.requestId, 'bob', true);

if (auth.isApproved(req.requestId)) {
  // proceed with the action
}
```

## Threshold-Gated Actions (Almadar defaults)

| Action | Gate |
|--------|------|
| `pnpm publish` / `npm publish` | 2-of-2 |
| `git push` to `main` / production deploy | 2-of-2 |
| `rm -rf` / destructive file ops | 2-of-2 |
| Database migrations / delete-all | 2-of-2 |
| Read/write `.env`, secrets | 2-of-2 |
| Cross-user data operations | 2-of-2 |
| Routine: compile, validate, read files | None |

## TLA+ Properties

Verified in the original IC-AGI formal model:

**CapabilityToken:**
- P5 AntiReplay: `uses ≤ budget` (invariant)
- P6 TTLEnforcement: expired tokens produce no log entries
- P7 RevocationFinality: `revoked = true ⇒ □(uses' = uses)`
- P8 BudgetMonotonicity: uses never decreases
- P9 ForgeryResistance: invalid signature ⇒ uses never incremented

**ThresholdAuthorizer:**
- P1 ThresholdSafety: executed ⇒ approvals ≥ K
- P2 NoUnilateralAuthority: K ≥ 2 (constructor precondition)
- P3 DenialFinality: once denied, resolution immutable
- P4 ResolutionImmutability: resolved ⇒ resolution never changes

## Cross-Language Compatibility Notes

### Constructor Parameter Order: ThresholdAuthorizer

The parameter order for `ThresholdAuthorizer` differs intentionally between the Python and TypeScript implementations:

| Implementation | Signature |
|----------------|-----------|
| Python | `ThresholdAuthorizer(approver_ids, threshold)` |
| TypeScript | `ThresholdAuthorizer(k, approverIds)` |

The TypeScript version places the threshold `k` first because it is the more constrained, policy-critical value — putting it first makes call sites read naturally ("require **2** of these approvers") and aligns with common TypeScript API conventions where the primary configuration value leads. This is an intentional ergonomic improvement and is **not** a bug.

When cross-referencing between the Python and TypeScript implementations, note this reversal so argument order is not accidentally swapped.

## License

MIT

