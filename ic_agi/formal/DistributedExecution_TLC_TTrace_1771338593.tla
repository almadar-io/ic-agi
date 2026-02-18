---- MODULE DistributedExecution_TLC_TTrace_1771338593 ----
EXTENDS Sequences, TLCExt, DistributedExecution_TLC_TEConstants, Toolbox, DistributedExecution_TLC, Naturals, TLC

_expression ==
    LET DistributedExecution_TLC_TEExpression == INSTANCE DistributedExecution_TLC_TEExpression
    IN DistributedExecution_TLC_TEExpression!expression
----

_trace ==
    LET DistributedExecution_TLC_TETrace == INSTANCE DistributedExecution_TLC_TETrace
    IN DistributedExecution_TLC_TETrace!trace
----

_prop ==
    ~(([]<>(
            stateIntegrity = ((s1 :> "tampered" @@ s2 :> "intact" @@ s3 :> "intact"))
            /\
            assignment = ((s1 :> w1 @@ s2 :> w1 @@ s3 :> w2))
            /\
            tokenIssued = ((s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE))
            /\
            execCircuitSnapshot = ((s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE))
            /\
            execIntegritySnapshot = ((s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"))
            /\
            executed = ((s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE))
            /\
            workerView = ((w1 :> {} @@ w2 :> {} @@ w3 :> {}))
            /\
            circuitOpen = ((w1 :> TRUE @@ w2 :> FALSE @@ w3 :> TRUE))
    ))/\([]<>(
            stateIntegrity = ((s1 :> "tampered" @@ s2 :> "intact" @@ s3 :> "intact"))
            /\
            assignment = ((s1 :> w1 @@ s2 :> w1 @@ s3 :> w2))
            /\
            tokenIssued = ((s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE))
            /\
            execCircuitSnapshot = ((s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE))
            /\
            execIntegritySnapshot = ((s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"))
            /\
            executed = ((s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE))
            /\
            workerView = ((w1 :> {} @@ w2 :> {} @@ w3 :> {}))
            /\
            circuitOpen = ((w1 :> FALSE @@ w2 :> FALSE @@ w3 :> TRUE))
    )))
----

_init ==
    /\ execCircuitSnapshot = _TETrace[1].execCircuitSnapshot
    /\ assignment = _TETrace[1].assignment
    /\ execIntegritySnapshot = _TETrace[1].execIntegritySnapshot
    /\ circuitOpen = _TETrace[1].circuitOpen
    /\ stateIntegrity = _TETrace[1].stateIntegrity
    /\ executed = _TETrace[1].executed
    /\ workerView = _TETrace[1].workerView
    /\ tokenIssued = _TETrace[1].tokenIssued
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
           \/ /\ i = _TTraceLassoEnd
              /\ j = _TTraceLassoStart
        /\ execCircuitSnapshot  = _TETrace[i].execCircuitSnapshot
        /\ execCircuitSnapshot' = _TETrace[j].execCircuitSnapshot
        /\ assignment  = _TETrace[i].assignment
        /\ assignment' = _TETrace[j].assignment
        /\ execIntegritySnapshot  = _TETrace[i].execIntegritySnapshot
        /\ execIntegritySnapshot' = _TETrace[j].execIntegritySnapshot
        /\ circuitOpen  = _TETrace[i].circuitOpen
        /\ circuitOpen' = _TETrace[j].circuitOpen
        /\ stateIntegrity  = _TETrace[i].stateIntegrity
        /\ stateIntegrity' = _TETrace[j].stateIntegrity
        /\ executed  = _TETrace[i].executed
        /\ executed' = _TETrace[j].executed
        /\ workerView  = _TETrace[i].workerView
        /\ workerView' = _TETrace[j].workerView
        /\ tokenIssued  = _TETrace[i].tokenIssued
        /\ tokenIssued' = _TETrace[j].tokenIssued

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("DistributedExecution_TLC_TTrace_1771338593.json", _TETrace)


_view ==
    <<execCircuitSnapshot, assignment, execIntegritySnapshot, circuitOpen, stateIntegrity, executed, workerView, tokenIssued, IF TLCGet("level") = _TTraceLassoEnd + 1 THEN _TTraceLassoStart ELSE TLCGet("level")>>
=============================================================================

 Note that you can extract this module `DistributedExecution_TLC_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `DistributedExecution_TLC_TEExpression.tla` file takes precedence 
  over the module `DistributedExecution_TLC_TEExpression` below).

---- MODULE DistributedExecution_TLC_TEExpression ----
EXTENDS Sequences, TLCExt, DistributedExecution_TLC_TEConstants, Toolbox, DistributedExecution_TLC, Naturals, TLC

expression == 
    [
        \* To hide variables of the `DistributedExecution_TLC` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        execCircuitSnapshot |-> execCircuitSnapshot
        ,assignment |-> assignment
        ,execIntegritySnapshot |-> execIntegritySnapshot
        ,circuitOpen |-> circuitOpen
        ,stateIntegrity |-> stateIntegrity
        ,executed |-> executed
        ,workerView |-> workerView
        ,tokenIssued |-> tokenIssued
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_execCircuitSnapshotUnchanged |-> execCircuitSnapshot = execCircuitSnapshot'
        
        \* Format the `execCircuitSnapshot` variable as Json value.
        \* ,_execCircuitSnapshotJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(execCircuitSnapshot)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_execCircuitSnapshotModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].execCircuitSnapshot # _TETrace[s-1].execCircuitSnapshot
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE DistributedExecution_TLC_TETrace ----
\*EXTENDS IOUtils, DistributedExecution_TLC_TEConstants, DistributedExecution_TLC, TLC
\*
\*trace == IODeserialize("DistributedExecution_TLC_TTrace_1771338593.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE DistributedExecution_TLC_TETrace ----
EXTENDS DistributedExecution_TLC_TEConstants, DistributedExecution_TLC, TLC

trace == 
    <<
    ([stateIntegrity |-> (s1 :> "unchecked" @@ s2 :> "unchecked" @@ s3 :> "unchecked"),assignment |-> (s1 :> "unassigned" @@ s2 :> "unassigned" @@ s3 :> "unassigned"),tokenIssued |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execCircuitSnapshot |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execIntegritySnapshot |-> (s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"),executed |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),workerView |-> (w1 :> {} @@ w2 :> {} @@ w3 :> {}),circuitOpen |-> (w1 :> FALSE @@ w2 :> FALSE @@ w3 :> FALSE)]),
    ([stateIntegrity |-> (s1 :> "unchecked" @@ s2 :> "intact" @@ s3 :> "unchecked"),assignment |-> (s1 :> "unassigned" @@ s2 :> "unassigned" @@ s3 :> "unassigned"),tokenIssued |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execCircuitSnapshot |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execIntegritySnapshot |-> (s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"),executed |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),workerView |-> (w1 :> {} @@ w2 :> {} @@ w3 :> {}),circuitOpen |-> (w1 :> FALSE @@ w2 :> FALSE @@ w3 :> FALSE)]),
    ([stateIntegrity |-> (s1 :> "unchecked" @@ s2 :> "intact" @@ s3 :> "unchecked"),assignment |-> (s1 :> "unassigned" @@ s2 :> "unassigned" @@ s3 :> w2),tokenIssued |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execCircuitSnapshot |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execIntegritySnapshot |-> (s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"),executed |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),workerView |-> (w1 :> {} @@ w2 :> {} @@ w3 :> {}),circuitOpen |-> (w1 :> FALSE @@ w2 :> FALSE @@ w3 :> FALSE)]),
    ([stateIntegrity |-> (s1 :> "unchecked" @@ s2 :> "intact" @@ s3 :> "unchecked"),assignment |-> (s1 :> w1 @@ s2 :> "unassigned" @@ s3 :> w2),tokenIssued |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execCircuitSnapshot |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execIntegritySnapshot |-> (s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"),executed |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),workerView |-> (w1 :> {} @@ w2 :> {} @@ w3 :> {}),circuitOpen |-> (w1 :> FALSE @@ w2 :> FALSE @@ w3 :> FALSE)]),
    ([stateIntegrity |-> (s1 :> "unchecked" @@ s2 :> "intact" @@ s3 :> "intact"),assignment |-> (s1 :> w1 @@ s2 :> "unassigned" @@ s3 :> w2),tokenIssued |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execCircuitSnapshot |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execIntegritySnapshot |-> (s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"),executed |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),workerView |-> (w1 :> {} @@ w2 :> {} @@ w3 :> {}),circuitOpen |-> (w1 :> FALSE @@ w2 :> FALSE @@ w3 :> FALSE)]),
    ([stateIntegrity |-> (s1 :> "tampered" @@ s2 :> "intact" @@ s3 :> "intact"),assignment |-> (s1 :> w1 @@ s2 :> "unassigned" @@ s3 :> w2),tokenIssued |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execCircuitSnapshot |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execIntegritySnapshot |-> (s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"),executed |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),workerView |-> (w1 :> {} @@ w2 :> {} @@ w3 :> {}),circuitOpen |-> (w1 :> FALSE @@ w2 :> FALSE @@ w3 :> FALSE)]),
    ([stateIntegrity |-> (s1 :> "tampered" @@ s2 :> "intact" @@ s3 :> "intact"),assignment |-> (s1 :> w1 @@ s2 :> "unassigned" @@ s3 :> w2),tokenIssued |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execCircuitSnapshot |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execIntegritySnapshot |-> (s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"),executed |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),workerView |-> (w1 :> {} @@ w2 :> {} @@ w3 :> {}),circuitOpen |-> (w1 :> FALSE @@ w2 :> FALSE @@ w3 :> TRUE)]),
    ([stateIntegrity |-> (s1 :> "tampered" @@ s2 :> "intact" @@ s3 :> "intact"),assignment |-> (s1 :> w1 @@ s2 :> w1 @@ s3 :> w2),tokenIssued |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execCircuitSnapshot |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execIntegritySnapshot |-> (s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"),executed |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),workerView |-> (w1 :> {} @@ w2 :> {} @@ w3 :> {}),circuitOpen |-> (w1 :> FALSE @@ w2 :> FALSE @@ w3 :> TRUE)]),
    ([stateIntegrity |-> (s1 :> "tampered" @@ s2 :> "intact" @@ s3 :> "intact"),assignment |-> (s1 :> w1 @@ s2 :> w1 @@ s3 :> w2),tokenIssued |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execCircuitSnapshot |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),execIntegritySnapshot |-> (s1 :> "none" @@ s2 :> "none" @@ s3 :> "none"),executed |-> (s1 :> FALSE @@ s2 :> FALSE @@ s3 :> FALSE),workerView |-> (w1 :> {} @@ w2 :> {} @@ w3 :> {}),circuitOpen |-> (w1 :> TRUE @@ w2 :> FALSE @@ w3 :> TRUE)])
    >>
----


=============================================================================

---- MODULE DistributedExecution_TLC_TEConstants ----
EXTENDS DistributedExecution_TLC

CONSTANTS s1, s2, s3, w1, w2, w3, _TTraceLassoStart, _TTraceLassoEnd

=============================================================================

---- CONFIG DistributedExecution_TLC_TTrace_1771338593 ----
CONSTANTS
    Segments = { s1 , s2 , s3 }
    Workers = { w1 , w2 , w3 }
    K_shares = 2
    s2 = s2
    w2 = w2
    s1 = s1
    w3 = w3
    s3 = s3
    w1 = w1
_TTraceLassoStart = 8
_TTraceLassoEnd = 9

PROPERTY
    _prop

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

VIEW
    _view

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Tue Feb 17 11:29:58 ART 2026