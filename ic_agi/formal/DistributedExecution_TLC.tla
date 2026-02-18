---- MODULE DistributedExecution_TLC ----
\*
\* IC-AGI — Distributed Segment Execution (TLC-verified version)
\* ==============================================================
\*
\* INVARIANTS:
\*   P10. SegmentIsolation:      no worker sees ALL segments
\*   P11. CapabilityGate:        executed => token was issued
\*   P12. CircuitBreakerSafety:  executed => circuit was closed at exec time
\*   P13. HMACIntegrity:         executed => state was not tampered
\*   P14. ShamirThreshold:       any (K-1) workers see < total segments
\*   TypeOK:                     type invariant
\*

EXTENDS Naturals, FiniteSets

CONSTANTS
    Segments,        \* e.g. {"s1", "s2", "s3"}
    Workers,         \* e.g. {"w1", "w2", "w3"}
    K_shares         \* Shamir threshold (e.g. 2)

VARIABLES
    assignment,      \* [Segments -> Workers \cup {"unassigned"}]
    tokenIssued,     \* [Segments -> BOOLEAN]
    executed,        \* [Segments -> BOOLEAN]
    circuitOpen,     \* [Workers -> BOOLEAN]
    stateIntegrity,  \* [Segments -> {"intact", "tampered", "unchecked"}]
    workerView,      \* [Workers -> SUBSET Segments]
    \* ── Snapshot variables (capture state at execution time) ──
    execCircuitSnapshot,   \* [Segments -> BOOLEAN] circuit state when executed
    execIntegritySnapshot  \* [Segments -> {"intact","tampered","unchecked","none"}]

vars == <<assignment, tokenIssued, executed, circuitOpen,
          stateIntegrity, workerView,
          execCircuitSnapshot, execIntegritySnapshot>>

TotalSegments == Cardinality(Segments)

AllWorkerValues == Workers \cup {"unassigned"}

TypeOK ==
    /\ assignment \in [Segments -> AllWorkerValues]
    /\ tokenIssued \in [Segments -> BOOLEAN]
    /\ executed \in [Segments -> BOOLEAN]
    /\ circuitOpen \in [Workers -> BOOLEAN]
    /\ stateIntegrity \in [Segments -> {"intact", "tampered", "unchecked"}]
    /\ workerView \in [Workers -> SUBSET Segments]
    /\ execCircuitSnapshot \in [Segments -> BOOLEAN]
    /\ execIntegritySnapshot \in [Segments -> {"intact", "tampered", "unchecked", "none"}]

\* ── Initial State ──
Init ==
    /\ assignment = [s \in Segments |-> "unassigned"]
    /\ tokenIssued = [s \in Segments |-> FALSE]
    /\ executed = [s \in Segments |-> FALSE]
    /\ circuitOpen = [w \in Workers |-> FALSE]
    /\ stateIntegrity = [s \in Segments |-> "unchecked"]
    /\ workerView = [w \in Workers |-> {}]
    /\ execCircuitSnapshot = [s \in Segments |-> FALSE]
    /\ execIntegritySnapshot = [s \in Segments |-> "none"]

\* ── Actions ──

\* Assign segment to worker (healthy only, isolation guard)
Assign(s, w) ==
    /\ assignment[s] = "unassigned"
    /\ circuitOpen[w] = FALSE
    \* Isolation guard: worker must not end up with ALL segments
    /\ LET currentCount == Cardinality({x \in Segments : assignment[x] = w})
       IN  currentCount + 1 < TotalSegments
    /\ assignment' = [assignment EXCEPT ![s] = w]
    /\ UNCHANGED <<tokenIssued, executed, circuitOpen,
                    stateIntegrity, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

\* Issue capability token for assigned segment
IssueToken(s) ==
    /\ assignment[s] /= "unassigned"
    /\ tokenIssued[s] = FALSE
    /\ tokenIssued' = [tokenIssued EXCEPT ![s] = TRUE]
    /\ UNCHANGED <<assignment, executed, circuitOpen,
                    stateIntegrity, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

\* Execute segment (all guards must pass)
ExecuteSeg(s) ==
    /\ assignment[s] /= "unassigned"
    /\ tokenIssued[s] = TRUE
    /\ executed[s] = FALSE
    /\ stateIntegrity[s] /= "tampered"
    /\ circuitOpen[assignment[s]] = FALSE
    /\ LET w == assignment[s]
       IN  /\ executed' = [executed EXCEPT ![s] = TRUE]
           /\ workerView' = [workerView EXCEPT ![w] = @ \union {s}]
           /\ execCircuitSnapshot' = [execCircuitSnapshot EXCEPT ![s] = circuitOpen[w]]
           /\ execIntegritySnapshot' = [execIntegritySnapshot EXCEPT ![s] = stateIntegrity[s]]
    /\ UNCHANGED <<assignment, tokenIssued, circuitOpen, stateIntegrity>>

\* Adversary tampers state
TamperState(s) ==
    /\ stateIntegrity[s] = "unchecked"
    /\ stateIntegrity' = [stateIntegrity EXCEPT ![s] = "tampered"]
    /\ UNCHANGED <<assignment, tokenIssued, executed, circuitOpen, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

\* Verify state integrity (HMAC check passes)
VerifyState(s) ==
    /\ stateIntegrity[s] = "unchecked"
    /\ stateIntegrity' = [stateIntegrity EXCEPT ![s] = "intact"]
    /\ UNCHANGED <<assignment, tokenIssued, executed, circuitOpen, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

\* Circuit breaker trips for a worker
TripCircuit(w) ==
    /\ circuitOpen[w] = FALSE
    /\ circuitOpen' = [circuitOpen EXCEPT ![w] = TRUE]
    /\ UNCHANGED <<assignment, tokenIssued, executed,
                    stateIntegrity, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

\* Circuit breaker recovers (half-open -> closed in real system)
ResetCircuit(w) ==
    /\ circuitOpen[w] = TRUE
    /\ circuitOpen' = [circuitOpen EXCEPT ![w] = FALSE]
    /\ UNCHANGED <<assignment, tokenIssued, executed,
                    stateIntegrity, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

Next ==
    \/ \E s \in Segments, w \in Workers : Assign(s, w)
    \/ \E s \in Segments : IssueToken(s)
    \/ \E s \in Segments : ExecuteSeg(s)
    \/ \E s \in Segments : TamperState(s)
    \/ \E s \in Segments : VerifyState(s)
    \/ \E w \in Workers : TripCircuit(w)
    \/ \E w \in Workers : ResetCircuit(w)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)
       /\ \A w \in Workers : SF_vars(ResetCircuit(w))

\* ══════════════════════════════════════════════════
\*  INVARIANTS
\* ══════════════════════════════════════════════════

\* P10: No worker sees ALL segments
SegmentIsolation ==
    \A w \in Workers :
        Cardinality(workerView[w]) < TotalSegments

\* P11: Execution requires a valid token
CapabilityGate ==
    \A s \in Segments :
        executed[s] = TRUE => tokenIssued[s] = TRUE

\* P12: If a segment was executed, the circuit was closed AT EXECUTION TIME
\* (Verified against snapshot captured during ExecuteSeg)
CircuitBreakerSafety ==
    \A s \in Segments :
        executed[s] = TRUE =>
            execCircuitSnapshot[s] = FALSE

\* P13: Executed segments were not tampered AT EXECUTION TIME
\* (Verified against snapshot captured during ExecuteSeg)
HMACIntegrity ==
    \A s \in Segments :
        executed[s] = TRUE =>
            execIntegritySnapshot[s] /= "tampered"

\* P14: Any (K-1) workers collectively see fewer than all segments
ShamirThreshold ==
    \A S_sub \in SUBSET Workers :
        Cardinality(S_sub) < K_shares =>
            Cardinality(UNION {workerView[w] : w \in S_sub}) < TotalSegments

\* ══════════════════════════════════════════════════
\*  LIVENESS PROPERTIES
\* ══════════════════════════════════════════════════

\* L4: An open circuit eventually recovers
CircuitRecovery ==
    \A w \in Workers :
        [](circuitOpen[w] = TRUE => <>( circuitOpen[w] = FALSE))

====
