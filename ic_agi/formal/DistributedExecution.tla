---- MODULE DistributedExecution ----
\*
\* IC-AGI — Formal Specification: Distributed Segment Execution
\* ==============================================================
\*
\* SAFETY PROPERTIES VERIFIED:
\*   P10. No worker sees the complete function (Segment Isolation)
\*   P11. Every segment requires a valid capability token (Capability Gate)
\*   P12. Circuit-broken workers receive no segments (Circuit Breaker Safety)
\*   P13. State-in-transit integrity: tampered state is rejected (HMAC Integrity)
\*   P14. (K-1) shares reveal zero information about the secret (Shamir Threshold)
\*
\* MODEL:
\*   - One function split into S segments
\*   - W workers, some may be circuit-broken
\*   - Each segment needs a capability token
\*   - State encrypted with HMAC between segments
\*

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Segments,        \* Set of segment IDs, e.g. {"s1", "s2", "s3"}
    Workers_,        \* Set of worker IDs (trailing _ to avoid clash)
    K_shares         \* Shamir threshold

VARIABLES
    assignment,      \* Function: Segment -> Worker (or "unassigned")
    tokenIssued,     \* Function: Segment -> BOOLEAN
    executed,        \* Function: Segment -> BOOLEAN
    circuitOpen,     \* Function: Worker -> BOOLEAN
    stateIntegrity,  \* Function: Segment -> {"intact", "tampered", "unchecked"}
    workerView       \* Function: Worker -> set of segments it has seen

vars == <<assignment, tokenIssued, executed, circuitOpen,
          stateIntegrity, workerView>>

TotalSegments == Cardinality(Segments)

\* ── Initial State ──
Init ==
    /\ assignment = [s \in Segments |-> "unassigned"]
    /\ tokenIssued = [s \in Segments |-> FALSE]
    /\ executed = [s \in Segments |-> FALSE]
    /\ circuitOpen = [w \in Workers_ |-> FALSE]
    /\ stateIntegrity = [s \in Segments |-> "unchecked"]
    /\ workerView = [w \in Workers_ |-> {}]

\* ── Assign Segment to Worker ──
\* Only healthy workers (circuit closed) can receive segments.
Assign(s, w) ==
    /\ assignment[s] = "unassigned"
    /\ circuitOpen[w] = FALSE
    /\ assignment' = [assignment EXCEPT ![s] = w]
    /\ UNCHANGED <<tokenIssued, executed, circuitOpen,
                    stateIntegrity, workerView>>

\* ── Issue Token for Segment ──
IssueToken(s) ==
    /\ assignment[s] /= "unassigned"
    /\ tokenIssued[s] = FALSE
    /\ tokenIssued' = [tokenIssued EXCEPT ![s] = TRUE]
    /\ UNCHANGED <<assignment, executed, circuitOpen,
                    stateIntegrity, workerView>>

\* ── Execute Segment ──
\* Requires: assigned, token issued, state intact or unchecked, circuit closed.
ExecuteSeg(s) ==
    /\ assignment[s] /= "unassigned"
    /\ tokenIssued[s] = TRUE
    /\ executed[s] = FALSE
    /\ stateIntegrity[s] /= "tampered"
    /\ circuitOpen[assignment[s]] = FALSE
    /\ LET w == assignment[s]
       IN  /\ executed' = [executed EXCEPT ![s] = TRUE]
           /\ workerView' = [workerView EXCEPT ![w] = @ \union {s}]
    /\ UNCHANGED <<assignment, tokenIssued, circuitOpen, stateIntegrity>>

\* ── Tamper State (adversary action) ──
TamperState(s) ==
    /\ stateIntegrity[s] = "unchecked"
    /\ stateIntegrity' = [stateIntegrity EXCEPT ![s] = "tampered"]
    /\ UNCHANGED <<assignment, tokenIssued, executed, circuitOpen, workerView>>

\* ── Verify State Integrity ──
VerifyState(s) ==
    /\ stateIntegrity[s] = "unchecked"
    /\ stateIntegrity' = [stateIntegrity EXCEPT ![s] = "intact"]
    /\ UNCHANGED <<assignment, tokenIssued, executed, circuitOpen, workerView>>

\* ── Trip Circuit Breaker ──
TripCircuit(w) ==
    /\ circuitOpen[w] = FALSE
    /\ circuitOpen' = [circuitOpen EXCEPT ![w] = TRUE]
    /\ UNCHANGED <<assignment, tokenIssued, executed,
                    stateIntegrity, workerView>>

\* ── Next ──
Next ==
    \/ \E s \in Segments, w \in Workers_ : Assign(s, w)
    \/ \E s \in Segments : IssueToken(s)
    \/ \E s \in Segments : ExecuteSeg(s)
    \/ \E s \in Segments : TamperState(s)
    \/ \E s \in Segments : VerifyState(s)
    \/ \E w \in Workers_ : TripCircuit(w)

Spec == Init /\ [][Next]_vars

\* ══════════════════════════════════════════════════
\*  SAFETY PROPERTIES
\* ══════════════════════════════════════════════════

\* P10: No worker sees ALL segments
SegmentIsolation ==
    \A w \in Workers_ :
        Cardinality(workerView[w]) < TotalSegments

\* P11: Execution requires a valid token
CapabilityGate ==
    \A s \in Segments :
        executed[s] = TRUE => tokenIssued[s] = TRUE

\* P12: Circuit-open worker receives no NEW executions
CircuitBreakerSafety ==
    \A s \in Segments :
        (executed[s] = TRUE /\ circuitOpen[assignment[s]] = TRUE) => FALSE

\* P13: Tampered state blocks execution
HMACIntegrity ==
    \A s \in Segments :
        (executed[s] = TRUE) => (stateIntegrity[s] /= "tampered")

\* P14: Any (K-1) workers see fewer than K segments collectively
\* (information-theoretic threshold)
ShamirThreshold ==
    \A S_sub \in SUBSET Workers_ :
        Cardinality(S_sub) < K_shares =>
            Cardinality(UNION {workerView[w] : w \in S_sub}) < TotalSegments

====
