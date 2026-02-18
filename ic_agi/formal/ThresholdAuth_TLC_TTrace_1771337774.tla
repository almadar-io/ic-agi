---- MODULE ThresholdAuth_TLC_TTrace_1771337774 ----
EXTENDS Sequences, TLCExt, ThresholdAuth_TLC, ThresholdAuth_TLC_TEConstants, Toolbox, Naturals, TLC

_expression ==
    LET ThresholdAuth_TLC_TEExpression == INSTANCE ThresholdAuth_TLC_TEExpression
    IN ThresholdAuth_TLC_TEExpression!expression
----

_trace ==
    LET ThresholdAuth_TLC_TETrace == INSTANCE ThresholdAuth_TLC_TETrace
    IN ThresholdAuth_TLC_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        executed = (TRUE)
        /\
        votes = ((a1 :> "approve" @@ a2 :> "approve" @@ a3 :> "none"))
        /\
        resolution = ("approved")
        /\
        resolved = (TRUE)
    )
----

_init ==
    /\ resolved = _TETrace[1].resolved
    /\ resolution = _TETrace[1].resolution
    /\ executed = _TETrace[1].executed
    /\ votes = _TETrace[1].votes
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ resolved  = _TETrace[i].resolved
        /\ resolved' = _TETrace[j].resolved
        /\ resolution  = _TETrace[i].resolution
        /\ resolution' = _TETrace[j].resolution
        /\ executed  = _TETrace[i].executed
        /\ executed' = _TETrace[j].executed
        /\ votes  = _TETrace[i].votes
        /\ votes' = _TETrace[j].votes

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("ThresholdAuth_TLC_TTrace_1771337774.json", _TETrace)

=============================================================================

 Note that you can extract this module `ThresholdAuth_TLC_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `ThresholdAuth_TLC_TEExpression.tla` file takes precedence 
  over the module `ThresholdAuth_TLC_TEExpression` below).

---- MODULE ThresholdAuth_TLC_TEExpression ----
EXTENDS Sequences, TLCExt, ThresholdAuth_TLC, ThresholdAuth_TLC_TEConstants, Toolbox, Naturals, TLC

expression == 
    [
        \* To hide variables of the `ThresholdAuth_TLC` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        resolved |-> resolved
        ,resolution |-> resolution
        ,executed |-> executed
        ,votes |-> votes
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_resolvedUnchanged |-> resolved = resolved'
        
        \* Format the `resolved` variable as Json value.
        \* ,_resolvedJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(resolved)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_resolvedModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].resolved # _TETrace[s-1].resolved
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE ThresholdAuth_TLC_TETrace ----
\*EXTENDS IOUtils, ThresholdAuth_TLC, ThresholdAuth_TLC_TEConstants, TLC
\*
\*trace == IODeserialize("ThresholdAuth_TLC_TTrace_1771337774.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE ThresholdAuth_TLC_TETrace ----
EXTENDS ThresholdAuth_TLC, ThresholdAuth_TLC_TEConstants, TLC

trace == 
    <<
    ([executed |-> FALSE,votes |-> (a1 :> "none" @@ a2 :> "none" @@ a3 :> "none"),resolution |-> "pending",resolved |-> FALSE]),
    ([executed |-> FALSE,votes |-> (a1 :> "approve" @@ a2 :> "none" @@ a3 :> "none"),resolution |-> "pending",resolved |-> FALSE]),
    ([executed |-> FALSE,votes |-> (a1 :> "approve" @@ a2 :> "approve" @@ a3 :> "none"),resolution |-> "approved",resolved |-> TRUE]),
    ([executed |-> TRUE,votes |-> (a1 :> "approve" @@ a2 :> "approve" @@ a3 :> "none"),resolution |-> "approved",resolved |-> TRUE])
    >>
----


=============================================================================

---- MODULE ThresholdAuth_TLC_TEConstants ----
EXTENDS ThresholdAuth_TLC

CONSTANTS a1, a2, a3

=============================================================================

---- CONFIG ThresholdAuth_TLC_TTrace_1771337774 ----
CONSTANTS
    Approvers = { a1 , a2 , a3 }
    K = 2
    a1 = a1
    a2 = a2
    a3 = a3

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Tue Feb 17 11:16:16 ART 2026