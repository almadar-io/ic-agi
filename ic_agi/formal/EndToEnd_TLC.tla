---- MODULE EndToEnd_TLC ----
\*
\* IC-AGI — End-to-End Composition Spec (TLC-verified)
\* =====================================================
\*
\* Models the complete pipeline: request → threshold vote → token →
\* assign → execute. Verifies that the 3 subsystems compose correctly.
\*
\* INVARIANTS:
\*   C1. NoExecWithoutPipeline: execution requires ALL gates passed
\*   C2. PipelineOrder:         correct sequencing of phases
\*   C3. TokenRequiresApproval: critical tokens need threshold approval
\*   C4. ComposedThreshold:     P1 + P11 composed
\*   TypeOK
\*
\* LIVENESS:
\*   C5. EventualCompletion: under fairness, pipeline eventually completes
\*

EXTENDS Naturals, FiniteSets

CONSTANTS
    Approvers,       \* e.g. {a1, a2, a3}
    K,               \* Threshold ≥ 2
    Workers,         \* e.g. {w1, w2}
    Budget           \* Token budget (e.g. 1)

VARIABLES
    \* ── Threshold Auth Phase ──
    votes,           \* [Approvers -> {"approve","deny","none"}]
    resolved,        \* BOOLEAN
    resolution,      \* "pending"|"approved"|"denied"
    \* ── Token Phase ──
    tokenIssued,     \* BOOLEAN
    tokenUses,       \* Nat
    tokenRevoked,    \* BOOLEAN
    \* ── Execution Phase ──
    assigned,        \* Workers ∪ {"unassigned"}
    circuitOpen,     \* [Workers -> BOOLEAN]
    executed,        \* BOOLEAN
    \* ── Pipeline tracking ──
    phase            \* "voting"|"token"|"assigning"|"executing"|"done"|"denied"

vars == <<votes, resolved, resolution,
          tokenIssued, tokenUses, tokenRevoked,
          assigned, circuitOpen, executed, phase>>

N == Cardinality(Approvers)
ApproveCount == Cardinality({a \in Approvers : votes[a] = "approve"})
DenyCount == Cardinality({a \in Approvers : votes[a] = "deny"})

TypeOK ==
    /\ votes \in [Approvers -> {"approve", "deny", "none"}]
    /\ resolved \in BOOLEAN
    /\ resolution \in {"pending", "approved", "denied"}
    /\ tokenIssued \in BOOLEAN
    /\ tokenUses \in 0..Budget
    /\ tokenRevoked \in BOOLEAN
    /\ assigned \in Workers \cup {"unassigned"}
    /\ circuitOpen \in [Workers -> BOOLEAN]
    /\ executed \in BOOLEAN
    /\ phase \in {"voting", "token", "assigning", "executing", "done", "denied"}

Init ==
    /\ votes = [a \in Approvers |-> "none"]
    /\ resolved = FALSE
    /\ resolution = "pending"
    /\ tokenIssued = FALSE
    /\ tokenUses = 0
    /\ tokenRevoked = FALSE
    /\ assigned = "unassigned"
    /\ circuitOpen = [w \in Workers |-> FALSE]
    /\ executed = FALSE
    /\ phase = "voting"

\* ══════════════════════════════════════════════════
\*  ACTIONS — Pipeline Phases
\* ══════════════════════════════════════════════════

\* Phase 1: Threshold voting
CastApprove(a) ==
    /\ phase = "voting"
    /\ votes[a] = "none"
    /\ votes' = [votes EXCEPT ![a] = "approve"]
    /\ LET newCount == Cardinality({x \in Approvers : votes'[x] = "approve"})
       IN IF newCount >= K
          THEN /\ resolved' = TRUE
               /\ resolution' = "approved"
               /\ phase' = "token"
          ELSE /\ UNCHANGED <<resolved, resolution, phase>>
    /\ UNCHANGED <<tokenIssued, tokenUses, tokenRevoked,
                    assigned, circuitOpen, executed>>

CastDeny(a) ==
    /\ phase = "voting"
    /\ votes[a] = "none"
    /\ votes' = [votes EXCEPT ![a] = "deny"]
    /\ LET newCount == Cardinality({x \in Approvers : votes'[x] = "deny"})
       IN IF newCount > (N - K)
          THEN /\ resolved' = TRUE
               /\ resolution' = "denied"
               /\ phase' = "denied"
          ELSE /\ UNCHANGED <<resolved, resolution, phase>>
    /\ UNCHANGED <<tokenIssued, tokenUses, tokenRevoked,
                    assigned, circuitOpen, executed>>

\* Phase 2: Issue token (only after approval)
IssueToken ==
    /\ phase = "token"
    /\ resolution = "approved"
    /\ tokenIssued = FALSE
    /\ tokenIssued' = TRUE
    /\ phase' = "assigning"
    /\ UNCHANGED <<votes, resolved, resolution,
                    tokenUses, tokenRevoked,
                    assigned, circuitOpen, executed>>

\* Phase 3: Assign to a healthy worker
AssignWorker(w) ==
    /\ phase = "assigning"
    /\ tokenIssued = TRUE
    /\ assigned = "unassigned"
    /\ circuitOpen[w] = FALSE
    /\ assigned' = w
    /\ phase' = "executing"
    /\ UNCHANGED <<votes, resolved, resolution,
                    tokenIssued, tokenUses, tokenRevoked,
                    circuitOpen, executed>>

\* Phase 4: Execute segment
ExecuteSegment ==
    /\ phase = "executing"
    /\ tokenIssued = TRUE
    /\ tokenUses < Budget
    /\ tokenRevoked = FALSE
    /\ assigned /= "unassigned"
    /\ circuitOpen[assigned] = FALSE
    /\ executed' = TRUE
    /\ tokenUses' = tokenUses + 1
    /\ phase' = "done"
    /\ UNCHANGED <<votes, resolved, resolution,
                    tokenIssued, tokenRevoked,
                    assigned, circuitOpen>>

\* ── Adversarial actions (can happen anytime) ──

RevokeToken ==
    /\ tokenIssued = TRUE
    /\ tokenRevoked = FALSE
    /\ tokenRevoked' = TRUE
    /\ UNCHANGED <<votes, resolved, resolution,
                    tokenIssued, tokenUses,
                    assigned, circuitOpen, executed, phase>>

TripCircuit(w) ==
    /\ circuitOpen[w] = FALSE
    /\ circuitOpen' = [circuitOpen EXCEPT ![w] = TRUE]
    /\ UNCHANGED <<votes, resolved, resolution,
                    tokenIssued, tokenUses, tokenRevoked,
                    assigned, executed, phase>>

ResetCircuit(w) ==
    /\ circuitOpen[w] = TRUE
    /\ circuitOpen' = [circuitOpen EXCEPT ![w] = FALSE]
    /\ UNCHANGED <<votes, resolved, resolution,
                    tokenIssued, tokenUses, tokenRevoked,
                    assigned, executed, phase>>

Next ==
    \/ \E a \in Approvers : CastApprove(a)
    \/ \E a \in Approvers : CastDeny(a)
    \/ IssueToken
    \/ \E w \in Workers : AssignWorker(w)
    \/ ExecuteSegment
    \/ RevokeToken
    \/ \E w \in Workers : TripCircuit(w)
    \/ \E w \in Workers : ResetCircuit(w)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)
       /\ \A w \in Workers : SF_vars(ResetCircuit(w))

\* ══════════════════════════════════════════════════
\*  INVARIANTS
\* ══════════════════════════════════════════════════

\* C1: Execution requires ALL gates passed
NoExecWithoutPipeline ==
    executed = TRUE =>
        /\ resolution = "approved"
        /\ tokenIssued = TRUE
        /\ assigned /= "unassigned"

\* C2: Pipeline phases are correctly ordered
PipelineOrder ==
    /\ (tokenIssued = TRUE => resolved = TRUE)
    /\ (assigned /= "unassigned" => tokenIssued = TRUE)
    /\ (executed = TRUE => assigned /= "unassigned")

\* C3: Token requires threshold approval
TokenRequiresApproval ==
    tokenIssued = TRUE => resolution = "approved"

\* C4: Composed threshold safety (P1 + P11)
ComposedThreshold ==
    executed = TRUE =>
        /\ ApproveCount >= K
        /\ tokenIssued = TRUE

\* C5: Token uses don't exceed budget
ComposedAntiReplay ==
    tokenUses <= Budget

\* C6: Revoked token blocks execution
ComposedRevocation ==
    (tokenRevoked = TRUE /\ phase = "executing") =>
        executed = FALSE

\* ══════════════════════════════════════════════════
\*  LIVENESS
\* ══════════════════════════════════════════════════

\* Under fairness, if all approvers vote approve, pipeline completes
AllApproved == \A a \in Approvers : votes[a] = "approve"
EventualCompletion ==
    [](AllApproved => <>(phase \in {"done", "denied"}))

====
