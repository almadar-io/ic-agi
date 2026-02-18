---- MODULE CapabilityTokens_TLC ----
\*
\* IC-AGI — Capability Token Lifecycle (TLC-verified version)
\* ============================================================
\*
\* INVARIANTS:
\*   P5. AntiReplay:          uses <= Budget
\*   P6. TTLEnforcement:      no execution at or after TTL
\*   P8. BudgetMonotonicity:  uses only increases (never resets)
\*   P9. ForgeryBlock:        forged token => 0 additional uses
\*   TypeOK:                  type invariant
\*
\* TEMPORAL:
\*   P7. RevocationFinality:  once revoked, uses never increases
\*

EXTENDS Naturals, Sequences

CONSTANTS
    Budget,          \* Max uses (e.g. 2)
    TTL,             \* Ticks before expiry (e.g. 3)
    MaxClock         \* Upper bound on clock for finite state space (e.g. 5)

VARIABLES
    uses,            \* Nat: how many times consumed
    clock,           \* Nat: current time tick
    revoked,         \* BOOLEAN
    signatureValid,  \* BOOLEAN
    executionLog     \* Sequence of <<clock_at_execution>> values

vars == <<uses, clock, revoked, signatureValid, executionLog>>

TypeOK ==
    /\ uses \in 0..Budget
    /\ clock \in 0..MaxClock
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

\* ── Actions ──
Consume ==
    /\ TokenValid
    /\ uses' = uses + 1
    /\ executionLog' = Append(executionLog, clock)
    /\ UNCHANGED <<clock, revoked, signatureValid>>

TickClock ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ UNCHANGED <<uses, revoked, signatureValid, executionLog>>

Revoke ==
    /\ revoked = FALSE
    /\ revoked' = TRUE
    /\ UNCHANGED <<uses, clock, signatureValid, executionLog>>

Forge ==
    /\ signatureValid = TRUE
    /\ signatureValid' = FALSE
    /\ UNCHANGED <<uses, clock, revoked, executionLog>>

Next ==
    \/ Consume
    \/ TickClock
    \/ Revoke
    \/ Forge

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* ══════════════════════════════════════════════════
\*  INVARIANTS
\* ══════════════════════════════════════════════════

\* P5: Total uses never exceed budget
AntiReplay == uses <= Budget

\* P6: Every execution occurred before TTL
TTLEnforcement ==
    \A i \in 1..Len(executionLog) :
        executionLog[i] < TTL

\* P7: Once revoked, the token cannot be consumed (uses frozen)
\* Expressed as state invariant: revoked => no valid consume path
RevocationFinality ==
    revoked = TRUE => ~TokenValid

\* P9: If signature is invalid, uses has not increased since forging
\* (encoded as: invalid sig => no valid consume path)
ForgeryBlock ==
    signatureValid = FALSE => ~TokenValid

\* ══════════════════════════════════════════════════
\*  TEMPORAL PROPERTIES
\* ══════════════════════════════════════════════════

\* P8: uses is monotonically non-decreasing
BudgetMonotonicity ==
    [][uses' >= uses]_uses

\* ══════════════════════════════════════════════════
\*  LIVENESS PROPERTIES
\* ══════════════════════════════════════════════════

\* L2: A token past TTL is eventually invalid
EventualExpiry ==
    [](clock >= TTL => ~TokenValid)

====
