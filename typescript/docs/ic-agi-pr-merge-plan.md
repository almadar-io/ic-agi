# IC-AGI TypeScript Port - PR Merge Plan

Based on feedback from the author's review of the TypeScript implementation port.

## Overview

The TypeScript implementation is nearly ready for merging upstream. The following tasks address the author's feedback and will make the PR merge-ready.

## Implementation Plan

### 1. Add Missing Test Coverage

**CircuitBreaker Tests**
- Create comprehensive test suite covering:
  - State transitions (open → half-open → closed)
  - Failure threshold tracking
  - Success reset logic
  - Timeout behavior
- Location: `typescript/tests/circuit-breaker.test.ts`

**RateLimiter Tests**
- Create comprehensive test suite covering:
  - Rate limiting enforcement
  - Token bucket replenishment
  - Time window behavior
  - Edge cases (burst requests, concurrent calls)
- Location: `typescript/tests/rate-limiter.test.ts`

**Status**: Currently 3 of 5 modules have test coverage. These additions will complete the test suite.

### 2. Update README Documentation

Add a new section explaining **constructor parameter order differences** between Python and TypeScript:

- Python implementation: `ThresholdAuthorizer(approver_ids, threshold)`
- TypeScript implementation: `ThresholdAuthorizer(k, approverIds)`
- Clarify that the parameter reordering is intentional and improves TypeScript ergonomics
- Helps future contributors cross-reference between language implementations

**Location**: `typescript/README.md`

### 3. Add Code Comments for Hash Compatibility

Add explanatory comments in the codebase explaining why **snake_case keys are used in hash payloads**:

- Intent: Ensure cross-language hash compatibility (Python ↔ TypeScript)
- Prevents future contributors from "fixing" it to camelCase and breaking hash verification
- Impacts: `prev_hash`, `issued_to`, and similar fields in hash payload generation

**Rationale**: This is a critical detail for maintaining HMAC verification (property P9/forgery resistance) across language implementations.

**Locations**:
- `typescript/src/threshold-auth.ts` (hash payload generation)
- `typescript/src/capability-token.ts` (hash payload generation)
- `typescript/src/audit-log.ts` (if applicable)

### 4. Verification & Submission

Before creating the PR:
- ✅ Run all tests to ensure coverage is complete
- ✅ Verify no hash compatibility is broken
- ✅ Ensure code follows existing patterns
- ✅ Confirm TLA+ property preservation (P1-P9) is maintained
- ✅ Review crypto implementation (timingSafeEqual, stableStringify)

## What's Already Great

Per the author's review:
- ✅ TLA+ property preservation is solid (P1-P9 correctly mapped)
- ✅ Crypto implementation is correct (timingSafeEqual for HMAC, canonical JSON)
- ✅ Zero external dependencies maintained
- ✅ Clean TypeScript idioms and strict mode compliance
- ✅ Proper ESM exports and type safety

## PR Submission Notes

Once these tasks are complete, the PR will be ready to merge upstream with the following highlights:
1. Complete test coverage for all 5 modules
2. Clear documentation of design decisions and language-specific differences
3. Maintained cryptographic security properties across implementations
4. Ready for integration into IC-AGI deployment pipelines at Almadar
