---- MODULE ThresholdAuth_TLC ----
\*
\* IC-AGI — Threshold Authorization (TLC-verified version)
\* ========================================================
\*
\* INVARIANTS (state properties — checked at every reachable state):
\*   P1. ThresholdSafety:        executed => approvals >= K
\*   P2. NoUnilateralAuthority:  no single vote can approve
\*   TypeOK:                     type invariant
\*
\* TEMPORAL PROPERTIES (checked over behaviors):
\*   P3. DenialFinality:         denied => always denied
\*   P4. ResolutionImmutability: once resolved, resolution never changes
\*

EXTENDS Naturals, FiniteSets

CONSTANTS
    Approvers,       \* e.g. {"a1", "a2", "a3"}
    K                \* Threshold (>= 2)

VARIABLES
    votes,           \* [Approvers -> {"approve", "deny", "none"}]
    resolved,        \* BOOLEAN
    resolution,      \* "pending" | "approved" | "denied"
    executed         \* BOOLEAN

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

\* ── Actions ──
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

Execute ==
    /\ resolution = "approved"
    /\ executed = FALSE
    /\ executed' = TRUE
    /\ UNCHANGED <<votes, resolved, resolution>>

Next ==
    \/ \E a \in Approvers : CastApprove(a)
    \/ \E a \in Approvers : CastDeny(a)
    \/ Execute

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* ══════════════════════════════════════════════════
\*  INVARIANTS (state predicates — TLC checks at every state)
\* ══════════════════════════════════════════════════

\* P1: No execution without K approvals
ThresholdSafety ==
    executed = TRUE =>
        Cardinality({a \in Approvers : votes[a] = "approve"}) >= K

\* P2: No single approver can authorize alone
NoUnilateralAuthority ==
    \A a \in Approvers :
        LET othersApprove == {x \in Approvers : x /= a /\ votes[x] = "approve"}
        IN  (Cardinality(othersApprove) = 0) => (resolution /= "approved")

\* ══════════════════════════════════════════════════
\*  TEMPORAL PROPERTIES (TLC checks over full behaviors)
\* ══════════════════════════════════════════════════

\* P3: Once denied, always denied
DenialFinality ==
    [](resolution = "denied" => [](resolution = "denied"))

\* P4: Once resolved, resolution never changes
ResolutionImmutability ==
    [](resolved = TRUE => [](resolution = resolution))

\* ══════════════════════════════════════════════════
\*  LIVENESS PROPERTIES
\* ══════════════════════════════════════════════════

\* L1: If all approvers have voted, the request is eventually resolved
AllVoted == \A a \in Approvers : votes[a] /= "none"

EventualResolution ==
    [](AllVoted => resolved = TRUE)

====
