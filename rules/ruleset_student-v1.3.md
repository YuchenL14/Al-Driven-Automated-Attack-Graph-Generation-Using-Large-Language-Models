# Student Attack Graph Rule Set - version 1.3

This iteration moves the ATT&CK mapping back to the student. Version 1.2 read
the narrative and chose the technique itself, and its evidence gate could clear
a technique it judged insufficiently supported. That inverted the exercise: the
narrative a student pastes in is already their own curated evidence, and the
mapping is the work they came to do.

## Identifiers you supply

Write the T-numbers and M-numbers into your description, next to the step they
belong to. The tool copies them out and draws them as you wrote them.

- An identifier you supply is kept. Whether it is the right one for that step
  is your judgement, and the tool does not overrule it. A wrong number gives a
  wrong graph, which is the point of checking your own work.
- An identifier that is not in the ATT&CK catalogue is reported against the
  step it came from and not used, because it is a typo rather than a judgement
  and the legend cannot render it. A retired identifier is reported with its
  replacements, and nothing is substituted for you.
- A mitigation MITRE does not connect to the technique you chose is still
  drawn, with a note saying so. Disagreeing with MITRE is allowed; not knowing
  that you are is not.
- A step you leave without a technique is answered by the tool, and every such
  step is named back to you so you can decide whether you agree.

Nothing is silently corrected. Everything the tool did differently from what
you wrote appears beside the graph.

This is otherwise the final general-mechanism iteration for the text-entry
Student App.
It preserves the supervisor sample's visual syntax and the evidence-first
contract of Student v1.1. It does not modify the frozen professional v1.4
research baseline.

Convert the supplied incident narrative into one directed, acyclic attack
graph. ATT&CK classifies source-supported adversary behaviour; it must not add
incident actions, tools, systems, credentials, channels, vulnerabilities, or
causal links that the narrative does not state.

## 1. Evidence threshold for an event

Every rectangle is one explicit adversary action. For every event return the
adversary actor, one exact contiguous `source_evidence` quotation, the exact
`action_evidence` verb or verb phrase inside it, evidence status, and evidence
confidence.

An explicitly possible, suspected, alleged, or reported action is still an
event, but preserve that qualification and do not imply it succeeded. A
high-level statement such as "the network was infiltrated" supports a
high-level action even when the method is unknown. Missing technical detail is
not missing action evidence.

Do not promote a nearby fact into an action. Accessing a marketplace that sells
credentials does not prove credentials were bought or used. A victim response,
investigation, recovery step, service outage, customer delay, or financial loss
is not an attacker event unless the quotation explicitly says the adversary
performed that action.

## 2. Preconditions and explicit condition coverage

An ellipse is a state, resource, access condition, environmental fact, or
direct result. Give it a short state label and the most appropriate code.

Include every explicitly stated condition that materially enables a core
action, including absent MFA, excessive privileges, an exposed/reachable
service, an available account or tool, and an unpatched vulnerability. Do not
invent a condition to complete a familiar attack chain.

Initial conditions have no parent. Derived conditions have event parents and
must describe a direct, narrative-supported result.

## 3. Events

Give each rectangle a unique id, verb-led label, one tactic abbreviation,
likelihood 0-10, parent precondition ids, AND/OR join, and all evidence fields.
A root event may have no artificial input ellipse when the narrative states no
prerequisite.

Use the same lexical action as `action_evidence`; inflection changes are
allowed, synonyms that change the behaviour are not. Do not combine actions
from different tactics or techniques.

## 4. Explicit impact coverage

Include every explicitly stated security outcome of the core incident as a
result ellipse, including unavailable services, corrupted or encrypted
systems, stolen or published data, account lockout, and inhibited recovery.
A terminal result ellipse is valid even when no later event consumes it.

Financial, legal, arrest, sentencing, and general threat commentary may be
omitted unless it is itself required by the graph's teaching objective.

## 5. AND/OR and connected structure

Use precondition -> event -> precondition alternation wherever an edge exists.
Use AND only when all parent conditions are jointly necessary. Use OR only
when at least two parent states are independently sufficient alternatives.
Alternative actions such as possible phishing or possible brute force remain
separate branches and must not be shown as confirmed success.

Prefer one weakly connected core incident graph. Omit unrelated facts rather
than inventing an event or causal edge to force connectivity.

## 6. Tactic and ATT&CK v19 technique selection

Use only these tactic abbreviations:
{tactic_lines}

Stage B supplies tactic-scoped candidates from the local ATT&CK v19 catalogue.
Choose the least-specific technique whose behaviour-defining details are
directly stated by the quotation. Use `null` when no candidate is supported.

The following high-risk mappings have explicit minimum evidence:

- Remote Services T1021 (including its sub-techniques) requires an explicitly
  stated remote service/access method or protocol such as RDP, SSH, SMB,
  WinRM, VNC, DCOM, or administrative shares. "Moved laterally" alone is
  insufficient.
- Masquerading T1036 requires evidence of disguising, mimicking, renaming,
  spoofing, impersonating, or otherwise making an artifact appear legitimate.
  Running cleanup or antivirus software alone is insufficient.
- Disable or Modify Tools T1685 requires both an action that disables/modifies
  a tool and evidence that the target is a security tool such as Defender,
  antivirus, or EDR.

Do not return retired T1562. A blank T badge is an honest evidence result.

## 7. Technique-scoped mitigations

Use the mitigation ids the student supplied for that step. Where the student
supplied none, use only mitigation ids supplied by Stage B:
{miti_lines}

For a non-null technique, retain only mitigations linked to that exact
technique by the official MITRE Enterprise ATT&CK STIX
course-of-action--mitigates relationship. A globally valid but unrelated
M-number is invalid. If technique is `null`, mitigations must be empty. Zero
mitigations is preferable to an unrelated recommendation.

## 8. Likelihood and evidence confidence

Likelihood estimates attack-step feasibility when its preconditions hold:
1-2 very difficult, 3-4 difficult, 5-6 plausible, 7-8 readily feasible, and
9-10 highly feasible. Evidence confidence describes how strongly the quotation
supports the extracted claim. They are separate dimensions.

## 9. Sample-compatible output

- Preconditions and results are white ellipses.
- Events are white rectangles.
- Tactic codes appear top left.
- Supported T badges appear top right; unsupported T remains blank.
- Officially related M badges appear bottom right.
- Likelihood appears bottom left.
- The side legend lists only codes actually used.

Return only the requested structured object. Do not add commentary.
