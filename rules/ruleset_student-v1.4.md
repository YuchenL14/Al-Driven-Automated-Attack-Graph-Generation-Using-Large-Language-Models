# Student Attack Graph Rule Set - version 1.4

This post-evaluation teaching revision preserves Student v1.3's evidence and
identifier contract and adds explicit instruction for the three visual
constructs already used by the professional v1.6 notation: external resources,
annotations, and dotted uncertain or alternative branches. These constructs
are evidence-triggered, not quotas. If the student's text does not support one,
the correct count is zero.

## Identifiers you supply

Write the T-numbers and M-numbers into your description, next to the step they
belong to. The tool copies them out and draws them as you wrote them.

- An identifier you supply is kept. Whether it is the right one for that step
  is your judgement, and the tool does not overrule it.
- An identifier that is not in the ATT&CK catalogue is reported against the
  step it came from and not used. A retired identifier is reported with its
  replacements, and nothing is substituted for you.
- A mitigation MITRE does not connect to the technique you chose is still
  drawn, with a note saying so.
- A step you leave without a technique is answered by the tool, and every such
  step is named back to you so you can decide whether you agree.

Nothing is silently corrected. Everything the tool did differently from what
you wrote appears beside the graph.

Identifier preservation happens before catalogue judgement. Therefore, every
explicit action clause carrying a student-supplied T- or M-number must remain
an event even when an identifier appears unsuitable, unknown, or unrelated.
The later feedback step may question the mapping, but Stage A must not omit the
action, move its identifiers to another action, or replace it with a state or
visual annotation.

Convert the supplied incident narrative into one directed, acyclic attack
graph. ATT&CK classifies source-supported adversary behaviour; it must not add
incident actions, tools, systems, credentials, channels, vulnerabilities,
recommendations, uncertainty, or causal links that the narrative does not
state.

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

## 2. Preconditions, results, and external resources

An ordinary ellipse is a state, access condition, environmental fact, or direct
result. Give it role `precondition`, a short state label, and the most
appropriate code.

Include every explicitly stated condition that materially enables a core
action, including absent MFA, excessive privileges, an exposed/reachable
service, or an available account. Initial conditions have no parent. Derived
conditions have event parents and must describe a direct, narrative-supported
result. Do not invent a condition to complete a familiar attack chain.

When the narrative explicitly names something the adversary already possesses
or can obtain independently of the causal path, give it role
`external_resource`. Examples include attacker-controlled infrastructure,
malware or a toolkit, purchased or stolen credentials, a certificate, exploit,
prepared lure, or delivery resource. It is an ellipse, has no producing event
parents, and may be consumed by the relevant event. An ordinary system state,
access state, or result is not an external resource.

## 3. Events

Give each rectangle a unique id, verb-led label, one tactic abbreviation,
likelihood 0-10, parent precondition ids, AND/OR join, outline style, and all
evidence fields. A root event may have no artificial input ellipse when the
narrative states no prerequisite.

Use the same lexical action as `action_evidence`; inflection changes are
allowed, synonyms that change the behaviour are not. Do not combine actions
from different tactics or techniques.

## 4. Explicit impact coverage

Include every explicitly stated security outcome of the core incident as a
result ellipse, including unavailable services, corrupted or encrypted
systems, stolen or published data, account lockout, and inhibited recovery. A
terminal result ellipse is valid even when no later event consumes it.

Financial, legal, arrest, sentencing, and general threat commentary may be
omitted unless it is itself required by the graph's teaching objective.

## 5. Annotations

When the narrative explicitly states a defensive recommendation,
detection/control observation, or contextual note that explains an event but
is not required for the event to occur, include it as role `annotation`, style
`dashed`, with the event it comments on as its parent. It is a dashed rectangle
beside the attack and never part of the causal path. An event must never consume
an annotation.

Do not invent a recommendation from an ATT&CK mitigation and do not turn a
victim response or impact into an annotation when it is actually a result
state. If the narrative contains no qualifying commentary, return no
annotations.

An explicitly stated defensive or recovery fact is also contextual annotation
when it does not enable an adversary action and is not an impact produced by
the adversary. For example, backup snapshots that remained untouched on a
separate network and were later used to restore service belong in one dashed
annotation beside the closest relevant adversary event. By contrast, backups
destroyed, deleted, encrypted, disabled, corrupted, made unavailable, or used
by the adversary remain causal conditions or results. Never infer a recovery
fact or recommendation that the narrative does not state.

## 6. Uncertain and alternative branches; AND/OR

Use precondition -> event -> precondition alternation wherever a causal edge
exists. Use AND only when all parent conditions are jointly necessary. Use OR
only when at least two parent states are independently sufficient alternatives.

Possible, suspected, alleged, and explicitly alternative attacker behaviour
remains in the graph with style `dotted`; it must not be shown as confirmed.
A state produced only by dotted events is dotted as well. Dotted texture records
the source's uncertainty or alternative path; uncertainty by itself does not
make a join OR. Confirmed causal paths use style `solid`. Dashed style is
reserved for annotations.

Prefer one weakly connected core incident graph. Omit unrelated facts rather
than inventing an event or causal edge to force connectivity.

## 7. Tactic and ATT&CK v19 technique selection

Use only these tactic abbreviations:
{tactic_lines}

Stage B supplies tactic-scoped candidates from the local ATT&CK v19 catalogue.
Choose the least-specific technique whose behaviour-defining details are
directly stated by the quotation. Use `null` when no candidate is supported.

- Remote Services T1021 requires an explicitly stated remote service/access
  method or protocol. "Moved laterally" alone is insufficient.
- Masquerading T1036 requires evidence of disguising, mimicking, renaming,
  spoofing, impersonating, or making an artefact appear legitimate.
- Disable or Modify Tools T1685 requires both an action that disables/modifies
  a tool and evidence that the target is a security tool.

Do not return retired T1562. A blank T badge is an honest evidence result.

## 8. Technique-scoped mitigations

Use the mitigation ids the student supplied for that step. Where the student
supplied none, use only mitigation ids supplied by Stage B:
{miti_lines}

For a technique suggested by the tool, retain only mitigations linked to that
exact technique by the official MITRE Enterprise ATT&CK STIX relationship. If
the suggested technique is `null`, suggested mitigations must be empty. These
restrictions do not erase identifiers supplied by the student: those remain as
written and an unrelated mapping is identified in the teaching feedback. Zero
tool-suggested mitigations is preferable to an unrelated recommendation.

## 9. Likelihood and evidence confidence

Likelihood estimates attack-step feasibility when its preconditions hold:
1-2 very difficult, 3-4 difficult, 5-6 plausible, 7-8 readily feasible, and
9-10 highly feasible. Evidence confidence describes how strongly the quotation
supports the extracted claim. They are separate dimensions.

## 10. Visual-construct coverage check

Before returning the structured object, scan the narrative once for:

1. explicitly named adversary-held external resources;
2. explicitly stated recommendations, controls, or contextual observations;
3. possible, suspected, alleged, or alternative attacker branches.

Represent every source-supported instance using the roles and styles above.
Never add one to increase a construct count. Zero annotations, external
resources, or dotted branches is valid when the narrative contains none.

## 11. Sample-compatible output

- Preconditions and results are white ellipses.
- External resources are white ellipses outside the causal chain.
- Events are white rectangles.
- Annotations are dashed rectangles beside the event they explain.
- Uncertain or explicitly alternative branches are dotted.
- Tactic codes appear top left.
- Supported T badges appear top right; unsupported T remains blank.
- Officially related M badges appear bottom right.
- Likelihood appears bottom left.
- The side legend lists only codes actually used.

Return only the requested structured object. Do not add commentary.
