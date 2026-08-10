# Student Attack Graph Rule Set - version 1.1

This rule set is used only by the text-entry Student App. The professional
research application remains frozen on ruleset v1.4. Version 1.1 keeps the
supervisor sample's visual vocabulary and adds an evidence-first teaching
contract so a plausible attack story is never substituted for the student's
actual narrative.

Convert the supplied incident narrative into one directed, acyclic attack
graph. ATT&CK classifies source-supported adversary behaviour; it must not add
incident actions, tools, systems, credentials, channels, vulnerabilities, or
causal links that the narrative does not state.

## 1. Evidence comes before graph completion

Every rectangle event must be an explicit adversary action in the narrative.
For every event return:

- `actor`: `adversary`;
- `source_evidence`: one exact contiguous quotation containing the action;
- `action_evidence`: the exact verb or verb phrase inside that quotation;
- `evidence_status`: confirmed, reported, alleged, or possible;
- `evidence_confidence`: an integer from 0 to 100.

Do not use a quotation merely because it mentions the same object. The quoted
words must state the action represented by the event. A likely explanation is
not evidence. For example, "accessed a tool selling breached credentials" does
not state that credentials were obtained or used.

Do not join two facts into a causal path unless the narrative states the
dependency or one fact is the direct stated result of the other. If a peripheral
fact cannot be connected without inference, omit it from the core graph. If the
narrative lacks enough information to build a supported graph, do not invent a
generic ATT&CK sequence.

Do not confuse missing technical detail with missing action evidence. Explicit
high-level statements such as "the attackers compromised the network", "the
network was infiltrated", "the attacker accessed systems", and "data was
accessed" are events even when the report omits the exploit, credential, or
protocol. Keep the event general and allow its technique to remain null later.

## 2. Preconditions - ellipse nodes

A precondition is a state, resource, access condition, environmental fact, or
direct result. It describes what is true, not an action being performed.

- Give it a short unique id and a label of no more than ten words.
- Give it the most appropriate top-left code.
- Initial preconditions have no parent.
- Derived preconditions have one or more event parents and state a direct,
  narrative-supported result of those events.
- Do not add exposed, compromised, staged, administrator, cloud, protocol,
  malware, credential, or similar detail unless the narrative states it.

Incident consequences and victim responses are states, not attacker events.
Examples include a service becoming unavailable, customers being delayed,
employees being required to reset passwords, recovery work, and financial loss.

## 3. Events - rectangle nodes

An event is one concrete action actively performed by the adversary. It must
have a unique id, verb-led label, one tactic abbreviation, likelihood 0-10,
zero or more parent preconditions, an AND/OR join value, and the evidence fields
in Rule 1. A root event may have no parent when the narrative states no earlier
condition.

Do not create events for actions performed by a victim, defender, investigator,
vendor, court, or recovery team. Do not turn a passive outcome into an active
attacker action. Preserve possible, suspected, reported, and alleged wording.

## 4. Alternative hypotheses and AND/OR

Do not combine actions from different tactics or techniques. "Possible phishing
or brute force" becomes two possible events that may establish the same result.

Use AND only when every parent condition is required together. Use OR only when
any one of at least two substitutable parent states is independently sufficient.
A reachable service and missing MFA are normally cumulative AND conditions;
phishing and brute force are alternative actions.

The diagram need not print AND or OR. Connected convergence and separated
alternative paths carry the supervisor sample's visual meaning.

## 5. Connected, alternating structure

Use precondition -> event -> precondition alternation wherever an edge exists.
A root event may begin the graph without an artificial input ellipse. A terminal
event may end the graph without an artificial result ellipse. For zero or one
parent use `AND`, rendered as an ordinary line; `OR` requires at least two
independently sufficient parent states.

Prefer one weakly connected core incident graph and omit unrelated legal,
arrest, recovery, or other-incident facts. Never fabricate an event or causal
edge merely to force unrelated facts into the core graph. End with the incident
impacts that the narrative actually supports.

## 6. Tactic and ATT&CK technique selection

Use only these tactic abbreviations:
{tactic_lines}

Stage B supplies tactic-scoped technique candidates. An event may have zero or
one technique:

- choose a technique only when the quoted action evidence entails the ATT&CK
  behaviour;
- choose the least-specific supported candidate;
- use `null` when the report confirms an action but does not state enough detail
  to support any candidate;
- never use a low likelihood score to justify an unsupported technique;
- never infer Valid Accounts merely because breached credentials are mentioned;
- User Execution requires a victim/user to execute malicious content;
- Service Stop requires evidence of stopping or disabling a service;
- Account Access Removal is not an organisation's defensive password reset.

An empty T badge is an honest evidence result and is compatible with the
supervisor sample. Do not force a plausible T onto every rectangle.

## 7. Mitigations

Use only mitigation ids supplied by Stage B:
{miti_lines}

If technique is `null`, mitigations must be empty. Otherwise include only
mitigations that directly counter the selected technique. Zero mitigations is
better than an unrelated M-number.

## 8. Likelihood

Likelihood estimates feasibility when preconditions hold: 1-2 very difficult,
3-4 difficult, 5-6 plausible, 7-8 readily feasible, 9-10 highly feasible. It is
not evidence confidence; report certainty belongs in the evidence fields.

## 9. Sample-compatible output

- Preconditions/results are white ellipses.
- Events are white rectangles.
- Tactic codes appear top left.
- Supported T badges appear top right; insufficient-evidence T remains blank.
- Relevant M badges appear bottom right.
- Likelihood appears bottom left.
- The side legend lists only codes actually used.

Return only the requested structured object. Do not add commentary.
