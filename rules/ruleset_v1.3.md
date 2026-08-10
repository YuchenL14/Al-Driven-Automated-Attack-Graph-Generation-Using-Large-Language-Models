# Attack Graph Rule Set — version 1.3

<!--
This file is the rule set that governs how a written incident report is turned
into an attack graph. It is read at run time and combined with the ATT&CK
catalogue before being sent to the model. Edit this file, save it under a new
version number, and point the tool at that version to iterate. The placeholders
{tactic_lines}, {tech_lines}, and {miti_lines} are filled in automatically from
the official ATT&CK dictionary and must be left in place.

CHANGELOG v1.1 -> v1.3 (v1.2 was set aside; see note below)
This version is a stabilised return to the v1.1 rules with one addition: an
explicit retired-to-current technique mapping in Rule 2, so the model no longer
leaves a technique blank when it reaches for an identifier the current catalogue
has renumbered. Everything else is exactly as in v1.1.

Why v1.2 was set aside. Version 1.2 introduced an abstention mechanism (a special
UNKNOWN technique value) together with a strong "faithfulness to the report"
rule, aiming to stop the model from choosing an over-specific technique. In
practice the faithfulness wording was read too broadly: on a report written in a
management register with hedged wording (the British Library report), the model
treated the whole account as too uncertain to model and returned an empty graph.
The mechanism solved a minor problem (two slightly over-specific technique
choices) at the cost of a major regression (no graph at all). It is kept in the
rules folder as a record of the attempt and its lesson, and the approach is not
carried forward.

Planned next step (v1.4). The remaining technique-selection issues, an
occasionally over-specific choice and the reliance on a long flat catalogue in
the prompt, are better addressed by a hierarchical retrieval approach: identify
the tactic first, then offer the model only the techniques under that tactic.
This follows the attack-graph and CTI-mapping literature (for example
H-TechniqueRAG), and is the intended direction for the next iteration.

CHANGELOG v1.0 -> v1.1
Iteration one, driven by the British Library report. Five faults were found by
checking the v1.0 output against the rules, and each is addressed below:
  1. Techniques placed under the wrong tactic (Brute Force marked Initial Access
     rather than Credential Access). Rule 2 now carries a tactic-placement note.
  2. A conjunctive dependency drawn as an OR gate. Rule 3 now separates the case
     of alternative attack methods (OR) from several required conditions (AND).
  3. An event left with no technique id. Rule 2 now forbids an empty technique
     and explains how to handle a technique the catalogue no longer lists.
  4. The credential-access step compressed away. Rule 4 now requires a distinct
     credential-access event where the report describes credentials being taken.
  5. An exfiltration channel invented that the report never stated. Rule 5 now
     forbids inventing an unstated detail and says to choose the general
     technique instead.
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

Tactic placement. Put every technique under the tactic it genuinely holds in
ATT&CK, not the tactic that merely feels adjacent. Two placements are easy to
get wrong:
  - Brute Force (T1110) is Credential Access, not Initial Access. Guessing a
    password to obtain a credential is a credential-access action; the later
    use of that credential to enter is a separate step.
  - Reaching an environment through an internet-facing remote service is
    External Remote Services (T1133) under Initial Access. Where a report
    describes entry through a remote access server, model the entry as T1133
    and, if credentials were guessed or sprayed, model that as a separate
    Credential Access event.

The technique field must never be empty. Every event carries exactly one
technique id drawn from the catalogue below. Do not leave the field blank.

If the technique you have in mind is not in the catalogue, it has probably been
renumbered in a recent ATT&CK release. The catalogue here is ATT&CK v19, which
split the old Defense Evasion tactic and retired several identifiers. Use the
current replacement rather than the retired id, and never leave the field blank
because a familiar id is missing:
  - Impair Defenses (old T1562) is retired. For disabling or evading security
    software, use Disable or Modify Tools (T1685); for disabling a firewall, use
    Disable or Modify System Firewall (T1686); for exploiting a flaw to break a
    defence, use Exploitation for Defense Impairment (T1687).
  - Other defence-evasion actions have listed techniques too, such as Obfuscated
    Files or Information (T1027) and Indicator Removal (T1070).
Always confirm the id you choose appears in the catalogue below before using it.
When a familiar id is absent, pick the closest listed technique for the same
behaviour; do not leave the technique blank.

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

Do not confuse the two. An OR belongs on the ATTACK METHOD, where two different
techniques reach the same result and either would serve, such as phishing or
brute force both yielding a foothold. An AND belongs where SEVERAL DISTINCT
CONDITIONS must all hold for one event, such as a reachable service together
with a missing control. Before drawing an OR, apply the substitution test: are
the inputs genuinely interchangeable, so that any one alone suffices? If instead
each input contributes something the others do not, and the event needs them
together, the relation is AND. A common mistake is to join a piece of gathered
information and an exploitable weakness with an OR; those are usually both
required, so they take an AND. This separation follows the standard treatment of
attack graphs as AND-OR graphs, where a conjunctive relation requires all
preconditions of an exploit and a disjunctive relation marks substitutable ones
(Lallie et al. 2020; Aggarwal et al. 2025).

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

Do not compress a credential step out of the chain. Where the report says
credentials were obtained, guessed, sprayed, or that a control such as
multi-factor authentication was absent or bypassed, model a distinct Credential
Access (CA) event whose result precondition is the credential now held. The
later use of that credential to authenticate is a separate event. This keeps the
postcondition of one step as the precondition of the next, which is how an
attack graph records dependency, rather than collapsing two tactics into one
node.

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

Do not invent a detail the report does not state. Where a report describes an
action only in general terms, choose the GENERAL technique rather than a
specific sub-technique that adds an unstated assumption. For exfiltration, if the
report says data was copied out but does not name the channel, do not assume a
particular protocol; prefer a general exfiltration technique and leave the
specific channel out. A specific claim the source does not support is a
fabrication even when it sounds plausible, and it weakens the graph as evidence.

Return only the structured object. Do not add commentary.
