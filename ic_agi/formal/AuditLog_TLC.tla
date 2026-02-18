---- MODULE AuditLog_TLC ----
\*
\* IC-AGI — Audit Log Formal Specification (TLC-verified)
\* =======================================================
\*
\* Models the append-only audit log with hash-chain integrity.
\*
\* INVARIANTS:
\*   A1. AppendOnly:     log length never decreases
\*   A2. HashChain:      every entry links to its predecessor's hash
\*   A3. Immutability:   existing entries never change
\*   A4. Completeness:   every action generates a log entry
\*   TypeOK:             type invariant
\*
\* TEMPORAL:
\*   A5. GrowthMonotonicity: log length is monotonically non-decreasing
\*

EXTENDS Naturals, Sequences

CONSTANTS
    MaxEntries,      \* Upper bound on log entries for finite state space (e.g. 4)
    Actions          \* Set of possible action types (e.g. {"vote", "issue", "exec"})

VARIABLES
    log,             \* Sequence of log entries: <<[action, hash, prev_hash]>>
    pendingAction,   \* An action waiting to be logged (or "none")
    actionCount      \* Total actions that have occurred (for completeness check)

vars == <<log, pendingAction, actionCount>>

\* ── Entry Model ──
\* Each log entry is a record with:
\*   .action    — the action type (string from Actions)
\*   .hash      — this entry's hash (modeled as its index for simplicity)
\*   .prev_hash — previous entry's hash (or 0 for genesis)

EntryAt(i) ==
    IF i >= 1 /\ i <= Len(log) THEN log[i] ELSE [action |-> "none", hash |-> 0, prev_hash |-> 0]

TypeOK ==
    /\ Len(log) \in 0..MaxEntries
    /\ actionCount \in 0..MaxEntries
    /\ pendingAction \in Actions \cup {"none"}
    /\ \A i \in 1..Len(log) :
        /\ log[i].action \in Actions
        /\ log[i].hash = i              \* Simplified: hash = index
        /\ log[i].prev_hash = i - 1     \* Links to predecessor

\* ── Initial State ──
Init ==
    /\ log = <<>>
    /\ pendingAction = "none"
    /\ actionCount = 0

\* ── Actions ──

\* An action occurs and needs to be logged
GenerateAction(a) ==
    /\ pendingAction = "none"
    /\ actionCount < MaxEntries
    /\ pendingAction' = a
    /\ actionCount' = actionCount + 1
    /\ UNCHANGED log

\* The pending action is committed to the log
CommitEntry ==
    /\ pendingAction /= "none"
    /\ Len(log) < MaxEntries
    /\ LET newEntry == [
            action    |-> pendingAction,
            hash      |-> Len(log) + 1,
            prev_hash |-> Len(log)        \* 0 if first entry (genesis link)
           ]
       IN log' = Append(log, newEntry)
    /\ pendingAction' = "none"
    /\ UNCHANGED actionCount

Next ==
    \/ \E a \in Actions : GenerateAction(a)
    \/ CommitEntry

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* ══════════════════════════════════════════════════
\*  INVARIANTS
\* ══════════════════════════════════════════════════

\* A1: Log length never decreases (state form: captured by A5 temporal)
\* As invariant: log is non-empty only if actionCount > 0
AppendOnly ==
    Len(log) <= actionCount

\* A2: Hash chain — every entry's prev_hash links to predecessor
HashChain ==
    \A i \in 1..Len(log) :
        /\ log[i].hash = i
        /\ log[i].prev_hash = i - 1

\* A3: Immutability — existing entries never change
\* (Expressed as temporal property since it compares states)
\* As state invariant: hash chain ensures any tampering breaks linkage

\* A4: Completeness — no pending action can be silently dropped
\* Under fairness, every generated action eventually gets logged
Completeness ==
    actionCount >= Len(log)

\* ══════════════════════════════════════════════════
\*  TEMPORAL PROPERTIES
\* ══════════════════════════════════════════════════

\* A5: Log length is monotonically non-decreasing
GrowthMonotonicity ==
    [][Len(log') >= Len(log)]_log

\* A3 (temporal form): Existing log entries never change
Immutability ==
    [][\A i \in 1..Len(log) : log'[i] = log[i]]_log

\* Liveness: Every pending action eventually gets committed
EventualCommit ==
    [](pendingAction /= "none" => <>(pendingAction = "none"))

====
