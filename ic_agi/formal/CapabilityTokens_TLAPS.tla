---- MODULE CapabilityTokens_TLAPS ----
\*
\* IC-AGI — Capability Tokens (TLAPS proof for P5 AntiReplay)
\* ============================================================
\*
\* Machine-checked proof that uses ≤ Budget for ANY Budget ∈ ℕ.
\*
\* THEOREM:
\*   Thm_AntiReplay — □(uses ≤ Budget)
\*

EXTENDS Naturals, Sequences, TLAPS

CONSTANTS
    Budget,          \* Any natural number ≥ 1
    TTL,             \* Any natural number ≥ 1
    MaxClock         \* Bound for clock (≥ TTL)

ASSUME Assumption_Budget ==
    /\ Budget \in Nat
    /\ Budget >= 1
    /\ TTL \in Nat
    /\ TTL >= 1
    /\ MaxClock \in Nat
    /\ MaxClock >= TTL

VARIABLES
    uses,            \* Nat: how many times consumed
    clock,           \* Nat: current time tick
    revoked,         \* BOOLEAN
    signatureValid,  \* BOOLEAN
    executionLog     \* Sequence of clock values at execution

vars == <<uses, clock, revoked, signatureValid, executionLog>>

TypeOK ==
    /\ uses \in 0..Budget
    /\ clock \in 0..MaxClock
    /\ revoked \in BOOLEAN
    /\ signatureValid \in BOOLEAN

TokenValid ==
    /\ uses < Budget
    /\ clock < TTL
    /\ revoked = FALSE
    /\ signatureValid = TRUE

Init ==
    /\ uses = 0
    /\ clock = 0
    /\ revoked = FALSE
    /\ signatureValid = TRUE
    /\ executionLog = <<>>

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

Spec == Init /\ [][Next]_vars

\* ══════════════════════════════════════════════════
\*  INVARIANT: P5 AntiReplay
\* ══════════════════════════════════════════════════

AntiReplay == uses <= Budget

\* Stronger inductive invariant: TypeOK implies AntiReplay
\* because TypeOK constrains uses ∈ 0..Budget
InductiveInv ==
    /\ TypeOK
    /\ (revoked = TRUE => ~TokenValid)

\* ══════════════════════════════════════════════════
\*  TLAPS PROOFS
\* ══════════════════════════════════════════════════

THEOREM Thm_TypeOK_Init == Init => TypeOK
<1>1. SUFFICES ASSUME Init PROVE TypeOK
    OBVIOUS
<1>2. uses = 0 /\ clock = 0 /\ revoked = FALSE /\ signatureValid = TRUE
    BY <1>1 DEF Init
<1>3. uses \in 0..Budget
    BY <1>2, Assumption_Budget
<1>4. clock \in 0..MaxClock
    BY <1>2, Assumption_Budget
<1>5. QED
    BY <1>2, <1>3, <1>4 DEF TypeOK

THEOREM Thm_TypeOK_Next == TypeOK /\ [Next]_vars => TypeOK'
<1>1. SUFFICES ASSUME TypeOK, [Next]_vars PROVE TypeOK'
    OBVIOUS
<1>2. CASE UNCHANGED vars
    BY <1>2, <1>1 DEF TypeOK, vars
<1>3. CASE Consume
    \* Consume requires uses < Budget (via TokenValid)
    \* So uses' = uses + 1 ≤ Budget
    <2>1. uses < Budget
        BY <1>3 DEF Consume, TokenValid
    <2>2. uses' = uses + 1
        BY <1>3 DEF Consume
    <2>3. uses' <= Budget
        BY <2>1, <2>2, <1>1 DEF TypeOK
    <2>4. uses' \in 0..Budget
        BY <2>3, <1>1 DEF TypeOK
    <2>5. UNCHANGED <<clock, revoked, signatureValid>>
        BY <1>3 DEF Consume
    <2>6. QED
        BY <2>4, <2>5, <1>1 DEF TypeOK
<1>4. CASE TickClock
    BY <1>4, <1>1 DEF TypeOK, TickClock
<1>5. CASE Revoke
    BY <1>5, <1>1 DEF TypeOK, Revoke
<1>6. CASE Forge
    BY <1>6, <1>1 DEF TypeOK, Forge
<1>7. QED
    BY <1>2, <1>3, <1>4, <1>5, <1>6 DEF Next

\* ── Main Theorem: AntiReplay holds universally ──
THEOREM Thm_AntiReplay == Spec => []AntiReplay
<1>1. TypeOK => AntiReplay
    BY DEF TypeOK, AntiReplay
<1>2. Init => TypeOK
    BY Thm_TypeOK_Init
<1>3. TypeOK /\ [Next]_vars => TypeOK'
    BY Thm_TypeOK_Next
<1>4. QED
    BY <1>1, <1>2, <1>3, PTL DEF Spec

====
