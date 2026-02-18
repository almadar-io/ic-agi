---- MODULE ThresholdAuth_TLAPS ----
\*
\* IC-AGI — Threshold Authorization (TLAPS proofs)
\* =================================================
\*
\* Machine-checked proofs that P1 and P2 hold for ANY N ≥ K ≥ 2.
\* Unlike TLC (bounded), TLAPS proves these universally.
\*
\* THEOREMS:
\*   Thm_TypeOK_Inductive     — TypeOK is inductive
\*   Thm_ThresholdSafety      — P1: executed ⇒ approvals ≥ K
\*   Thm_NoUnilateralAuthority — P2: no single approver can authorize
\*

EXTENDS Naturals, FiniteSets, TLAPS

CONSTANTS
    Approvers,       \* Any finite set
    K                \* Threshold ≥ 2

ASSUME Assumption_K ==
    /\ K \in Nat
    /\ K >= 2
    /\ K <= Cardinality(Approvers)
    /\ IsFiniteSet(Approvers)

VARIABLES
    votes,           \* [Approvers -> {"approve", "deny", "none"}]
    resolved,        \* BOOLEAN
    resolution,      \* "pending" | "approved" | "denied"
    executed         \* BOOLEAN

vars == <<votes, resolved, resolution, executed>>

N == Cardinality(Approvers)

ApproveCount == Cardinality({a \in Approvers : votes[a] = "approve"})
DenyCount    == Cardinality({a \in Approvers : votes[a] = "deny"})

TypeOK ==
    /\ votes \in [Approvers -> {"approve", "deny", "none"}]
    /\ resolved \in BOOLEAN
    /\ resolution \in {"pending", "approved", "denied"}
    /\ executed \in BOOLEAN

Init ==
    /\ votes = [a \in Approvers |-> "none"]
    /\ resolved = FALSE
    /\ resolution = "pending"
    /\ executed = FALSE

CastApprove(a) ==
    /\ resolved = FALSE
    /\ votes[a] = "none"
    /\ votes' = [votes EXCEPT ![a] = "approve"]
    /\ LET newApproveCount == Cardinality({x \in Approvers : votes'[x] = "approve"})
       IN IF newApproveCount >= K
          THEN /\ resolved' = TRUE
               /\ resolution' = "approved"
          ELSE /\ UNCHANGED <<resolved, resolution>>
    /\ UNCHANGED executed

CastDeny(a) ==
    /\ resolved = FALSE
    /\ votes[a] = "none"
    /\ votes' = [votes EXCEPT ![a] = "deny"]
    /\ LET newDenyCount == Cardinality({x \in Approvers : votes'[x] = "deny"})
       IN IF newDenyCount > (N - K)
          THEN /\ resolved' = TRUE
               /\ resolution' = "denied"
          ELSE /\ UNCHANGED <<resolved, resolution>>
    /\ UNCHANGED executed

Execute ==
    /\ resolution = "approved"
    /\ executed = FALSE
    /\ executed' = TRUE
    /\ UNCHANGED <<votes, resolved, resolution>>

Next ==
    \/ \E a \in Approvers : CastApprove(a)
    \/ \E a \in Approvers : CastDeny(a)
    \/ Execute

Spec == Init /\ [][Next]_vars

\* ══════════════════════════════════════════════════
\*  INVARIANTS
\* ══════════════════════════════════════════════════

\* The key inductive invariant linking resolution to vote counts.
\* This is stronger than P1 alone, but needed for inductiveness.
InductiveInv ==
    /\ TypeOK
    /\ (resolution = "approved" => ApproveCount >= K)
    /\ (executed = TRUE => resolution = "approved")
    /\ (resolved = FALSE => resolution = "pending")
    /\ (resolution /= "pending" => resolved = TRUE)

\* P1: No execution without K approvals
ThresholdSafety ==
    executed = TRUE => ApproveCount >= K

\* P2: No single approver can authorize alone
NoUnilateralAuthority ==
    \A a \in Approvers :
        LET othersApprove == {x \in Approvers : x /= a /\ votes[x] = "approve"}
        IN  (Cardinality(othersApprove) = 0) => (resolution /= "approved")

\* ══════════════════════════════════════════════════
\*  TLAPS PROOFS
\* ══════════════════════════════════════════════════

\* ── Theorem 1: TypeOK is inductive ──
\* Init establishes TypeOK, and every Next step preserves it.

THEOREM Thm_TypeOK_Init == Init => TypeOK
<1>1. SUFFICES ASSUME Init PROVE TypeOK
    OBVIOUS
<1>2. votes = [a \in Approvers |-> "none"]
    BY <1>1 DEF Init
<1>3. votes \in [Approvers -> {"approve", "deny", "none"}]
    BY <1>2
<1>4. resolved = FALSE /\ resolution = "pending" /\ executed = FALSE
    BY <1>1 DEF Init
<1>5. QED
    BY <1>3, <1>4 DEF TypeOK

THEOREM Thm_TypeOK_Next == TypeOK /\ [Next]_vars => TypeOK'
<1>1. SUFFICES ASSUME TypeOK, [Next]_vars PROVE TypeOK'
    OBVIOUS
<1>2. CASE UNCHANGED vars
    BY <1>2, <1>1 DEF TypeOK, vars
<1>3. CASE \E a \in Approvers : CastApprove(a)
    BY <1>3, <1>1 DEF TypeOK, CastApprove
<1>4. CASE \E a \in Approvers : CastDeny(a)
    BY <1>4, <1>1 DEF TypeOK, CastDeny
<1>5. CASE Execute
    BY <1>5, <1>1 DEF TypeOK, Execute
<1>6. QED
    BY <1>2, <1>3, <1>4, <1>5 DEF Next

\* ── Theorem 2: InductiveInv is inductive ──
\* This is the core: proves the link between resolution and vote counts.

THEOREM Thm_Inv_Init == Init => InductiveInv
<1>1. SUFFICES ASSUME Init PROVE InductiveInv
    OBVIOUS
<1>2. votes = [a \in Approvers |-> "none"]
    BY <1>1 DEF Init
<1>3. ApproveCount = 0
    BY <1>2 DEF ApproveCount
<1>4. resolution = "pending" /\ resolved = FALSE /\ executed = FALSE
    BY <1>1 DEF Init
<1>5. QED
    BY <1>1, <1>2, <1>3, <1>4, Thm_TypeOK_Init DEF InductiveInv

THEOREM Thm_Inv_Next == InductiveInv /\ [Next]_vars => InductiveInv'
<1>1. SUFFICES ASSUME InductiveInv, [Next]_vars PROVE InductiveInv'
    OBVIOUS
<1>2. CASE UNCHANGED vars
    BY <1>2, <1>1 DEF InductiveInv, vars, TypeOK, ApproveCount
<1>3. CASE \E a \in Approvers : CastApprove(a)
    \* CastApprove only sets resolution' = "approved" when newApproveCount >= K
    <2>1. PICK a \in Approvers : CastApprove(a)
        BY <1>3
    <2>2. votes' = [votes EXCEPT ![a] = "approve"]
        BY <2>1 DEF CastApprove
    <2>3. CASE Cardinality({x \in Approvers : votes'[x] = "approve"}) >= K
        \* resolution' = "approved", and ApproveCount' >= K — invariant preserved
        BY <2>1, <2>2, <2>3, <1>1 DEF CastApprove, InductiveInv, TypeOK, ApproveCount
    <2>4. CASE ~(Cardinality({x \in Approvers : votes'[x] = "approve"}) >= K)
        \* resolution unchanged — invariant trivially preserved
        BY <2>1, <2>2, <2>4, <1>1 DEF CastApprove, InductiveInv, TypeOK, ApproveCount
    <2>5. QED
        BY <2>3, <2>4
<1>4. CASE \E a \in Approvers : CastDeny(a)
    \* CastDeny never sets resolution = "approved", so P1 link preserved
    <2>1. PICK a \in Approvers : CastDeny(a)
        BY <1>4
    <2>2. UNCHANGED executed
        BY <2>1 DEF CastDeny
    <2>3. resolution' \in {"pending", "denied"} \/ resolution' = resolution
        BY <2>1, <1>1 DEF CastDeny, InductiveInv
    <2>4. QED
        BY <2>1, <2>2, <2>3, <1>1 DEF CastDeny, InductiveInv, TypeOK, ApproveCount, N
<1>5. CASE Execute
    \* Execute requires resolution = "approved" which implies ApproveCount >= K
    <2>1. resolution = "approved"
        BY <1>5 DEF Execute
    <2>2. ApproveCount >= K
        BY <2>1, <1>1 DEF InductiveInv
    <2>3. UNCHANGED <<votes, resolved, resolution>>
        BY <1>5 DEF Execute
    <2>4. ApproveCount' = ApproveCount
        BY <2>3 DEF ApproveCount
    <2>5. QED
        BY <1>5, <2>1, <2>2, <2>3, <2>4, <1>1 DEF Execute, InductiveInv, TypeOK
<1>6. QED
    BY <1>2, <1>3, <1>4, <1>5 DEF Next

\* ── Theorem 3: P1 ThresholdSafety holds for all reachable states ──
THEOREM Thm_ThresholdSafety == Spec => []ThresholdSafety
<1>1. InductiveInv => ThresholdSafety
    BY DEF InductiveInv, ThresholdSafety
<1>2. Init => InductiveInv
    BY Thm_Inv_Init
<1>3. InductiveInv /\ [Next]_vars => InductiveInv'
    BY Thm_Inv_Next
<1>4. QED
    BY <1>1, <1>2, <1>3, PTL DEF Spec

\* ── Theorem 4: P2 NoUnilateralAuthority holds for all reachable states ──
\* Key insight: K ≥ 2, so approved requires ≥ 2 approve votes,
\* meaning at least one OTHER approver must have voted approve.
THEOREM Thm_NoUnilateral == Spec => []NoUnilateralAuthority
<1>1. SUFFICES ASSUME InductiveInv PROVE NoUnilateralAuthority
    BY Thm_Inv_Init, Thm_Inv_Next, PTL DEF Spec
<1>2. TAKE a \in Approvers
<1>3. ASSUME Cardinality({x \in Approvers : x /= a /\ votes[x] = "approve"}) = 0
       PROVE  resolution /= "approved"
    <2>1. {x \in Approvers : votes[x] = "approve"} \subseteq {a}
        BY <1>3
    <2>2. ApproveCount <= 1
        BY <2>1, Assumption_K DEF ApproveCount
    <2>3. K >= 2
        BY Assumption_K
    <2>4. ApproveCount < K
        BY <2>2, <2>3
    <2>5. QED
        BY <2>4, <1>1 DEF InductiveInv
<1>4. QED
    BY <1>3 DEF NoUnilateralAuthority

====
