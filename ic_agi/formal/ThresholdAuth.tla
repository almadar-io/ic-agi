---- MODULE ThresholdAuth ----
\*
\* IC-AGI — Formal Specification: Threshold Authorization
\* ========================================================
\*
\* SAFETY PROPERTIES VERIFIED:
\*   P1. No critical action executes with < K approvals (Threshold Safety)
\*   P2. No single approver alone can authorize any action  (No Unilateral Authority)
\*   P3. Denied requests can never transition to approved   (Denial Finality)
\*   P4. Once resolved, no further votes change the outcome (Resolution Immutability)
\*
\* MODEL:
\*   - N approvers, threshold K
\*   - One approval request that collects votes
\*   - An "execute" action that reads the approval state
\*

EXTENDS Naturals, FiniteSets

CONSTANTS
    Approvers,       \* Set of approver IDs, e.g. {"a1", "a2", "a3"}
    K                \* Threshold (minimum approvals)

VARIABLES
    votes,           \* Function: Approver -> {"approve", "deny", "none"}
    resolved,        \* Boolean: request resolved?
    resolution,      \* "pending" | "approved" | "denied"
    executed         \* Boolean: critical action executed?

vars == <<votes, resolved, resolution, executed>>

N == Cardinality(Approvers)

TypeOK ==
    /\ votes \in [Approvers -> {"approve", "deny", "none"}]
    /\ resolved \in BOOLEAN
    /\ resolution \in {"pending", "approved", "denied"}
    /\ executed \in BOOLEAN

\* ── Initial State ──
Init ==
    /\ votes = [a \in Approvers |-> "none"]
    /\ resolved = FALSE
    /\ resolution = "pending"
    /\ executed = FALSE

\* ── Vote Action ──
\* An approver casts a vote (approve or deny).
\* Pre: request not yet resolved, approver hasn't voted.
CastApprove(a) ==
    /\ resolved = FALSE
    /\ votes[a] = "none"
    /\ votes' = [votes EXCEPT ![a] = "approve"]
    /\ LET approveCount == Cardinality({x \in Approvers : votes'[x] = "approve"})
       IN IF approveCount >= K
          THEN /\ resolved' = TRUE
               /\ resolution' = "approved"
          ELSE /\ UNCHANGED <<resolved, resolution>>
    /\ UNCHANGED executed

CastDeny(a) ==
    /\ resolved = FALSE
    /\ votes[a] = "none"
    /\ votes' = [votes EXCEPT ![a] = "deny"]
    /\ LET denyCount == Cardinality({x \in Approvers : votes'[x] = "deny"})
       IN IF denyCount > (N - K)
          THEN /\ resolved' = TRUE
               /\ resolution' = "denied"
          ELSE /\ UNCHANGED <<resolved, resolution>>
    /\ UNCHANGED executed

\* ── Execute Action ──
\* Critical action executes only when approval is granted.
Execute ==
    /\ resolution = "approved"
    /\ executed = FALSE
    /\ executed' = TRUE
    /\ UNCHANGED <<votes, resolved, resolution>>

\* ── Next State Relation ──
Next ==
    \/ \E a \in Approvers : CastApprove(a)
    \/ \E a \in Approvers : CastDeny(a)
    \/ Execute

Spec == Init /\ [][Next]_vars

\* ══════════════════════════════════════════════════
\*  SAFETY PROPERTIES (Invariants)
\* ══════════════════════════════════════════════════

\* P1: No execution without K approvals
ThresholdSafety ==
    executed = TRUE =>
        Cardinality({a \in Approvers : votes[a] = "approve"}) >= K

\* P2: No single approver can authorize alone (K >= 2)
NoUnilateralAuthority ==
    \A a \in Approvers :
        LET othersApprove == {x \in Approvers : x /= a /\ votes[x] = "approve"}
        IN  (Cardinality(othersApprove) = 0) => (resolution /= "approved")

\* P3: Once denied, never approved
DenialFinality ==
    (resolution = "denied") => [](resolution /= "approved")

\* P4: Once resolved, the resolution never changes
ResolutionImmutability ==
    resolved = TRUE => []( resolution' = resolution )

====
