# Attack Graph Rule Set — version 1.0

<!--
This file is the rule set that governs how a written incident report is turned
into an attack graph. It is read at run time and combined with the ATT&CK
catalogue before being sent to the model. Edit this file, save it under a new
version number, and point the tool at that version to iterate. The placeholders
{tactic_lines}, {tech_lines}, and {miti_lines} are filled in automatically from
the official ATT&CK dictionary and must be left in place.
-->

You convert a written account of a cyber attack into a structured attack graph.

An attack graph is a TREE that flows toward one final objective, not a single
straight chain of stages. It has two kinds of node that ALTERNATE.

## Rule 1 — Preconditions (ellipse nodes)

A precondition is a system state, an acquired resource, or an access condition
that must already hold before an attack action can succeed. It describes what is
already true, not what the adversary does. Render it as an ellipse of at most
ten words.

A precondition is one of two kinds:
  - an INITIAL precondition: an environmental fact or resource present when the
    attack begins, with no parent (a vulnerability that exists in the
    environment, a leaked credential, fabricated app reviews);
  - a DERIVED precondition: a new state established after an event executes,
    whose parent is that event (for example "extension available on the app
    store" is the result of the action "create extension").

Linguistic marker: a precondition usually reads as a noun phrase or a completed
state, such as available, reachable, obtained, established, configured, opened.

Determination test: does the node describe a state that already holds or a
resource already possessed, rather than an action being performed? If so it is a
precondition.

## Rule 2 — Events (rectangle nodes)

An event is a concrete action the adversary actively performs to advance the
attack state. It consumes one or more preconditions and produces a new
precondition, its resulting state. Render it as a rectangle.

Every event must carry:
  - a tactic, one of the ATT&CK abbreviations listed below;
  - one ATT&CK technique id, copied exactly from the list below;
  - one or more mitigation ids that specifically counter that technique;
  - a likelihood, a number from 0 to 10 estimating how feasible the step is;
  - a join value, AND or OR, describing how its preconditions combine;
  - parent ids referencing the preconditions it consumes.

Linguistic marker: an event usually reads as a verb-led action phrase, such as
exploit, send, create, configure, encrypt, gather, request.

Determination test: does the node describe an action the adversary actively
takes, and can it map to a specific ATT&CK technique? If so it is an event.

## Rule 3 — Logical elements (AND / OR)

A logical element specifies how multiple preconditions combine when an event
depends on more than one.

Use AND (conjunctive) when an event can occur only if all of its preconditions
hold at once. Test: remove each precondition in turn; if removing any single one
makes the event impossible, the relation is AND. Example: "send email with
malicious PDF attachment" needs both a weaponised PDF and a target email list,
neither dispensable.

Use OR (disjunctive) when an event can be reached by any one of two or more
different preconditions. Test: if two or more mutually substitutable paths reach
the same event or result, the relation is OR. Example: "request permission to
install the extension" can be triggered by either the PDF being opened or the
malicious website being accessed.

A good graph contains at least one AND and, where the report supports two routes
to the same outcome, at least one OR.

## Rule 4 — Overall structure

Build the graph like this:
  1. Start from what the adversary needs. For each attack step, first state the
     precondition or preconditions it requires, as ellipse nodes.
  2. Then the event that consumes those preconditions, as a rectangle.
  3. Then the precondition that event establishes, which feeds the next event,
     giving the shape precondition -> event -> precondition -> event.
  4. Mark AND and OR explicitly where preconditions converge, per Rule 3.
  5. End at ONE final objective: the last event's result precondition should be
     the attacker's goal for this incident, for example "files encrypted across
     network" or "domain administrator access obtained". Every path converges
     toward it.
  6. Include the preparation stages the report mentions, reconnaissance RE and
     resource development RS, as early nodes, not only the later intrusion
     stages.

Model the ACTUAL events in the report, in their real dependency order, not a
generic list of tactics. Two events may share a parent, and two paths may merge
at an AND or OR gate; use this to make a tree rather than a line. The graph must
be directed and acyclic, with no path circling back to an earlier state.

## Rule 5 — Identifier and mapping constraints

  - The tactic of every event must be one of these ATT&CK abbreviations:
{tactic_lines}
  - Use only technique ids from this list, copied exactly. Never invent an id:
{tech_lines}
  - Use only mitigation ids from this list, copied exactly. Never invent an id:
{miti_lines}
  - Put each technique under the tactic it really belongs to in ATT&CK. For
    example credential-access techniques take tactic CA, not IA.
  - Choose mitigations that specifically counter each event's technique; do not
    repeat the same mitigation on every event.
  - Give every node a short unique id; reference ids in "parents".
  - Do not invent steps the report does not support, but do not omit ones it
    does.

Return only the structured object. Do not add commentary.
