---- MODULE DistributedExecution_TLAPS ----
\*
\* IC-AGI — Distributed Execution (TLAPS proof for P11 CapabilityGate)
\* ====================================================================
\*
\* Machine-checked proof that for ANY number of segments, workers, K:
\*   executed[s] = TRUE  ⇒  tokenIssued[s] = TRUE
\*
\* THEOREM:
\*   Thm_CapabilityGate — □(∀s: executed[s] ⇒ tokenIssued[s])
\*

EXTENDS Naturals, FiniteSets, TLAPS

CONSTANTS
    Segments,        \* Any finite set
    Workers,         \* Any finite set
    K_shares         \* Shamir threshold

ASSUME Assumption ==
    /\ IsFiniteSet(Segments)
    /\ IsFiniteSet(Workers)
    /\ K_shares \in Nat
    /\ K_shares >= 2
    /\ Cardinality(Segments) >= 1
    /\ Cardinality(Workers) >= 2

VARIABLES
    assignment,      \* [Segments -> Workers ∪ {"unassigned"}]
    tokenIssued,     \* [Segments -> BOOLEAN]
    executed,        \* [Segments -> BOOLEAN]
    circuitOpen,     \* [Workers -> BOOLEAN]
    stateIntegrity,  \* [Segments -> {"intact", "tampered", "unchecked"}]
    workerView,      \* [Workers -> SUBSET Segments]
    execCircuitSnapshot,
    execIntegritySnapshot

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

Init ==
    /\ assignment = [s \in Segments |-> "unassigned"]
    /\ tokenIssued = [s \in Segments |-> FALSE]
    /\ executed = [s \in Segments |-> FALSE]
    /\ circuitOpen = [w \in Workers |-> FALSE]
    /\ stateIntegrity = [s \in Segments |-> "unchecked"]
    /\ workerView = [w \in Workers |-> {}]
    /\ execCircuitSnapshot = [s \in Segments |-> FALSE]
    /\ execIntegritySnapshot = [s \in Segments |-> "none"]

Assign(s, w) ==
    /\ assignment[s] = "unassigned"
    /\ circuitOpen[w] = FALSE
    /\ LET currentCount == Cardinality({x \in Segments : assignment[x] = w})
       IN  currentCount + 1 < TotalSegments
    /\ assignment' = [assignment EXCEPT ![s] = w]
    /\ UNCHANGED <<tokenIssued, executed, circuitOpen,
                    stateIntegrity, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

IssueToken(s) ==
    /\ assignment[s] /= "unassigned"
    /\ tokenIssued[s] = FALSE
    /\ tokenIssued' = [tokenIssued EXCEPT ![s] = TRUE]
    /\ UNCHANGED <<assignment, executed, circuitOpen,
                    stateIntegrity, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

ExecuteSeg(s) ==
    /\ assignment[s] /= "unassigned"
    /\ tokenIssued[s] = TRUE          \* ← THE GUARD that makes P11 hold
    /\ executed[s] = FALSE
    /\ stateIntegrity[s] /= "tampered"
    /\ circuitOpen[assignment[s]] = FALSE
    /\ LET w == assignment[s]
       IN  /\ executed' = [executed EXCEPT ![s] = TRUE]
           /\ workerView' = [workerView EXCEPT ![w] = @ \union {s}]
           /\ execCircuitSnapshot' = [execCircuitSnapshot EXCEPT ![s] = circuitOpen[w]]
           /\ execIntegritySnapshot' = [execIntegritySnapshot EXCEPT ![s] = stateIntegrity[s]]
    /\ UNCHANGED <<assignment, tokenIssued, circuitOpen, stateIntegrity>>

TamperState(s) ==
    /\ stateIntegrity[s] = "unchecked"
    /\ stateIntegrity' = [stateIntegrity EXCEPT ![s] = "tampered"]
    /\ UNCHANGED <<assignment, tokenIssued, executed, circuitOpen, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

VerifyState(s) ==
    /\ stateIntegrity[s] = "unchecked"
    /\ stateIntegrity' = [stateIntegrity EXCEPT ![s] = "intact"]
    /\ UNCHANGED <<assignment, tokenIssued, executed, circuitOpen, workerView,
                    execCircuitSnapshot, execIntegritySnapshot>>

TripCircuit(w) ==
    /\ circuitOpen[w] = FALSE
    /\ circuitOpen' = [circuitOpen EXCEPT ![w] = TRUE]
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

Spec == Init /\ [][Next]_vars

\* ══════════════════════════════════════════════════
\*  P11: CapabilityGate
\* ══════════════════════════════════════════════════

CapabilityGate ==
    \A s \in Segments :
        executed[s] = TRUE => tokenIssued[s] = TRUE

\* Inductive invariant: CapabilityGate itself is inductive
\* because the only action that sets executed[s]=TRUE is
\* ExecuteSeg(s), which guards on tokenIssued[s]=TRUE,
\* and no action ever sets tokenIssued[s] back to FALSE.

InductiveInv ==
    /\ TypeOK
    /\ CapabilityGate
    \* Strengthening: tokenIssued is monotonic (once TRUE, always TRUE)
    \* This follows from the spec: no action sets tokenIssued[s]=FALSE

\* ══════════════════════════════════════════════════
\*  TLAPS PROOFS
\* ══════════════════════════════════════════════════

THEOREM Thm_Inv_Init == Init => InductiveInv
<1>1. SUFFICES ASSUME Init PROVE InductiveInv
    OBVIOUS
<1>2. executed = [s \in Segments |-> FALSE]
    BY <1>1 DEF Init
<1>3. \A s \in Segments : executed[s] = FALSE
    BY <1>2
<1>4. CapabilityGate
    BY <1>3 DEF CapabilityGate
<1>5. TypeOK
    BY <1>1 DEF Init, TypeOK, AllWorkerValues
<1>6. QED
    BY <1>4, <1>5 DEF InductiveInv

THEOREM Thm_Inv_Next == InductiveInv /\ [Next]_vars => InductiveInv'
<1>1. SUFFICES ASSUME InductiveInv, [Next]_vars PROVE InductiveInv'
    OBVIOUS
<1>2. CASE UNCHANGED vars
    BY <1>2, <1>1 DEF InductiveInv, vars, TypeOK, CapabilityGate
<1>3. CASE \E s \in Segments, w \in Workers : Assign(s, w)
    \* Assign does not change executed or tokenIssued
    BY <1>3, <1>1 DEF Assign, InductiveInv, TypeOK, CapabilityGate, AllWorkerValues
<1>4. CASE \E s \in Segments : IssueToken(s)
    \* IssueToken sets tokenIssued[s]=TRUE, does not change executed
    \* CapabilityGate preserved: if executed[s]=TRUE then it was already
    \* TRUE and tokenIssued[s] was TRUE (by InductiveInv), still TRUE
    BY <1>4, <1>1 DEF IssueToken, InductiveInv, TypeOK, CapabilityGate
<1>5. CASE \E s \in Segments : ExecuteSeg(s)
    \* ExecuteSeg sets executed[s]=TRUE and guards tokenIssued[s]=TRUE
    \* For this s: executed'[s]=TRUE and tokenIssued'[s]=tokenIssued[s]=TRUE ✓
    \* For other s': executed'[s']=executed[s'] and tokenIssued'[s']=tokenIssued[s'] ✓
    <2>1. PICK s0 \in Segments : ExecuteSeg(s0)
        BY <1>5
    <2>2. tokenIssued[s0] = TRUE
        BY <2>1 DEF ExecuteSeg
    <2>3. UNCHANGED tokenIssued
        BY <2>1 DEF ExecuteSeg
    <2>4. tokenIssued' = tokenIssued
        BY <2>3
    <2>5. \A s \in Segments : tokenIssued'[s] = tokenIssued[s]
        BY <2>4
    <2>6. executed' = [executed EXCEPT ![s0] = TRUE]
        BY <2>1 DEF ExecuteSeg
    <2>7. \A s \in Segments :
            executed'[s] = TRUE => tokenIssued'[s] = TRUE
        <3>1. TAKE s \in Segments
        <3>2. CASE s = s0
            BY <3>2, <2>2, <2>5
        <3>3. CASE s /= s0
            BY <3>3, <2>5, <2>6, <1>1 DEF InductiveInv, CapabilityGate
        <3>4. QED
            BY <3>2, <3>3
    <2>8. QED
        BY <2>7, <2>1, <1>1 DEF ExecuteSeg, InductiveInv, TypeOK, CapabilityGate
<1>6. CASE \E s \in Segments : TamperState(s)
    BY <1>6, <1>1 DEF TamperState, InductiveInv, TypeOK, CapabilityGate
<1>7. CASE \E s \in Segments : VerifyState(s)
    BY <1>7, <1>1 DEF VerifyState, InductiveInv, TypeOK, CapabilityGate
<1>8. CASE \E w \in Workers : TripCircuit(w)
    BY <1>8, <1>1 DEF TripCircuit, InductiveInv, TypeOK, CapabilityGate
<1>9. QED
    BY <1>2, <1>3, <1>4, <1>5, <1>6, <1>7, <1>8 DEF Next

\* ── Main Theorem: P11 CapabilityGate holds universally ──
THEOREM Thm_CapabilityGate == Spec => []CapabilityGate
<1>1. InductiveInv => CapabilityGate
    BY DEF InductiveInv
<1>2. Init => InductiveInv
    BY Thm_Inv_Init
<1>3. InductiveInv /\ [Next]_vars => InductiveInv'
    BY Thm_Inv_Next
<1>4. QED
    BY <1>1, <1>2, <1>3, PTL DEF Spec

====
