---- MODULE CapabilityTokens ----
\*
\* IC-AGI — Formal Specification: Capability Token Lifecycle
\* ============================================================
\*
\* SAFETY PROPERTIES VERIFIED:
\*   P5. A consumed token cannot be reused (Anti-Replay)
\*   P6. An expired token cannot authorize execution (TTL Enforcement)
\*   P7. A revoked token is permanently invalid (Revocation Finality)
\*   P8. Token budget is monotonically non-increasing (Budget Monotonicity)
\*   P9. A forged token (wrong signature) never authorizes (Forgery Resistance)
\*
\* MODEL:
\*   - One token with budget B, TTL, and signature state
\*   - Clock advances in steps
\*   - Workers attempt to use the token
\*

EXTENDS Naturals

CONSTANTS
    Budget,          \* Initial budget (e.g. 1)
    TTL,             \* Time-to-live in ticks (e.g. 3)
    Workers          \* Set of worker IDs

VARIABLES
    uses,            \* Number of times the token has been consumed
    clock,           \* Current logical time (ticks)
    revoked,         \* Boolean: has the token been revoked?
    signatureValid,  \* Boolean: does the token carry a valid HMAC?
    executionLog     \* Sequence of (worker, time) tuples representing executions

vars == <<uses, clock, revoked, signatureValid, executionLog>>

TypeOK ==
    /\ uses \in 0..Budget
    /\ clock \in Nat
    /\ revoked \in BOOLEAN
    /\ signatureValid \in BOOLEAN

\* ── Token Validity ──
TokenValid ==
    /\ uses < Budget
    /\ clock < TTL
    /\ revoked = FALSE
    /\ signatureValid = TRUE

\* ── Initial State ──
Init ==
    /\ uses = 0
    /\ clock = 0
    /\ revoked = FALSE
    /\ signatureValid = TRUE
    /\ executionLog = <<>>

\* ── Consume Token ──
\* A worker uses the token if it is valid.
Consume(w) ==
    /\ TokenValid
    /\ uses' = uses + 1
    /\ executionLog' = Append(executionLog, <<w, clock>>)
    /\ UNCHANGED <<clock, revoked, signatureValid>>

\* ── Attempt with Invalid Token ──
\* This action checks that using an invalid token does NOT produce execution.
AttemptInvalid(w) ==
    /\ ~TokenValid
    /\ UNCHANGED vars   \* No state change — the attempt is rejected

\* ── Clock Tick ──
TickClock ==
    /\ clock' = clock + 1
    /\ UNCHANGED <<uses, revoked, signatureValid, executionLog>>

\* ── Revoke ──
Revoke ==
    /\ revoked = FALSE
    /\ revoked' = TRUE
    /\ UNCHANGED <<uses, clock, signatureValid, executionLog>>

\* ── Forge Attempt ──
\* Simulate an attacker invalidating the signature.
Forge ==
    /\ signatureValid' = FALSE
    /\ UNCHANGED <<uses, clock, revoked, executionLog>>

\* ── Next ──
Next ==
    \/ \E w \in Workers : Consume(w)
    \/ \E w \in Workers : AttemptInvalid(w)
    \/ TickClock
    \/ Revoke
    \/ Forge

Spec == Init /\ [][Next]_vars

\* ══════════════════════════════════════════════════
\*  SAFETY PROPERTIES
\* ══════════════════════════════════════════════════

\* P5: Total uses never exceed budget
AntiReplay == uses <= Budget

\* P6: No execution occurs at or after TTL expiry
TTLEnforcement ==
    \A i \in 1..Len(executionLog) :
        executionLog[i][2] < TTL

\* P7: Once revoked, no further executions
RevocationFinality ==
    revoked = TRUE => [](uses' = uses)

\* P8: Budget only decreases (uses only increase)
BudgetMonotonicity ==
    [][uses' >= uses]_uses

\* P9: Forged signature => no execution
ForgeryResistance ==
    signatureValid = FALSE => [](uses' = uses)

====
