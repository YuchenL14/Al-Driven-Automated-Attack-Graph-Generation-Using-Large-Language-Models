# Attack Graph Rule Set v1.5 - Evidence Handling Specification

**Status: DRAFT - NOT LOADED BY THE APPLICATION**

This file defines the proposed v1.5 behaviour before coordinated changes are
made to the runtime rule set, schema, extraction stages, ATT&CK relationship
data, and tests. It is deliberately stored under `rules/drafts/` so the current
application cannot offer or execute an incomplete v1.5 implementation.

Version 1.4 remains the frozen baseline. Version 1.5 must preserve the sample
diagram's node shapes and badge locations while making the evidence threshold
for nodes, techniques, mitigations, and logical relations explicit and
testable.

## 1. Design objective

Convert the actions that a report actually states, reports, alleges, or
explicitly proposes into an attack graph without completing missing attack
stages from general threat knowledge.

The following decisions are independent:

1. Does the report support an event?
2. Does the report support an ATT&CK tactic for that event?
3. Does the report support a specific ATT&CK technique?
4. Does ATT&CK define one or more mitigations for that technique?

Failure at a later decision MUST NOT erase an event that passed an earlier
decision. In particular, a supported event may have a tactic but no technique
or mitigation badge. This matches the reference sample, which contains action
rectangles with different combinations of metadata.

## 2. Normative terms

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are requirements for the
extractor and its output.

### 2.1 Source evidence

`source_evidence` is an exact, contiguous quotation from the supplied report
that supports one event. It MUST:

- contain the adversary action or the report's explicit attribution of it;
- preserve qualifying language such as `possibly`, `reportedly`, `alleged`,
  `suspected`, `likely`, or `confirmed`;
- normally contain one sentence, or at most two adjacent sentences when the
  actor and action are split across them;
- come only from the supplied report, not from model knowledge, ATT&CK text, a
  different incident, or an actor's general profile;
- be stored for audit even when it is not rendered inside the graph.

A later implementation SHOULD also store a `source_locator`, such as the PDF
page number or extracted paragraph/sentence index. The exact quotation is the
primary evidence; a locator alone is insufficient.

### 2.2 Evidence status

Each event MUST preserve the source's epistemic status in an
`evidence_status` field:

- `confirmed`: the report presents the action as directly observed, admitted,
  forensically established, or otherwise confirmed;
- `reported`: the report presents the action as a factual report but does not
  claim direct confirmation in the quoted passage;
- `alleged`: the report explicitly attributes an allegation or disputed claim;
- `possible`: the report explicitly presents the action as possible,
  suspected, likely, probable, or one of several hypotheses.

The model MUST preserve the source's qualifier. It MUST NOT upgrade `possible`
or `alleged` to `confirmed` merely because the action is common for that actor
or attack type.

`inferred` is not an admissible event status in the evidence-backed graph. A
model-only inference MAY be retained in a diagnostic log for analyst review,
but MUST NOT become a main-graph event.

### 2.3 Evidence confidence and likelihood are different

`evidence_confidence` describes confidence in the correctness of the extracted
claim. It uses the STIX-compatible 0-100 scale. Initial implementation SHOULD
use the coarse representative values 15 (low), 50 (medium), and 85 (high)
rather than manufacture false numeric precision.

`likelihood` remains the sample diagram's 0-10 estimate of how feasible or
probable the attack step/path is under its preconditions. It MUST NOT be used as
a substitute for evidence confidence.

The source's wording primarily determines `evidence_status`. Evidence
confidence additionally considers whether the quotation clearly contains the
actor, action, and object. The extractor MUST NOT automatically treat a common
or plausible attack behaviour as high-confidence evidence.

## 3. Rule E1 - Creating an event

Create an event when the supplied report explicitly states, reports, alleges,
or proposes an adversary action. The quoted passage must contain a verb or
action attribution that advances, attempts, prepares, executes, or causes the
attack.

An explicitly hedged action is still an event. For example, a report that says
the initial access was `possibly phishing or brute force` supports possible
phishing and brute-force events. The uncertainty is preserved in
`evidence_status`; it is not a reason to delete the events or return an empty
graph.

Do not create an event when:

- the report describes only a state, asset, vulnerability, condition, or
  outcome; represent that information as a precondition or result instead;
- the action is supplied only by general knowledge about the actor or attack
  family;
- the action belongs only to a separate incident or victim;
- the text describes a defender, investigator, vendor, or victim response and
  the model would have to reattribute it to the adversary;
- the action is required only to make a generic ATT&CK sequence look complete;
- no exact source quotation can be supplied.

Test: if the `source_evidence` quotation were removed, could a reviewer still
find the claimed adversary action elsewhere in the supplied report? If not, the
event MUST be rejected.

## 4. Rule E2 - Preconditions

A precondition remains an ellipse of at most ten words. It may be:

- an initial state or resource explicitly supported by the report; or
- a derived state that follows mechanically from a supported event.

A derived precondition MAY paraphrase the direct result of its parent event,
but MUST NOT introduce a new tool, credential, channel, vulnerability, access
level, system, or capability absent from the event evidence.

Reports often describe impact without the preceding technical mechanism. Such
an impact may be retained as a result state. The extractor MUST NOT invent an
intermediate event solely to connect it to a conventional attack chain.

## 5. Rule E3 - Assigning a tactic

Every rendered event retains one ATT&CK tactic abbreviation because the tactic
badge is part of the current graph contract and sample-style layout.

Assign the tactic whose objective is directly described by the supported
action. Do not infer a tactic from an actor profile or from a downstream impact.
Where the report states only a broad incident outcome and does not support an
adversary action or objective, represent it as a result/precondition rather than
forcing it into an event tactic.

## 6. Rule E4 - Assigning a technique

Technique assignment follows an evidence-specificity ladder.

### Level 1 - Specific technique or sub-technique

Assign a specific technique or sub-technique only when the source evidence
states all behaviour-defining details required by that ATT&CK definition. A
shared keyword is insufficient.

### Level 2 - Parent technique

When the source supports the behaviour of a valid ATT&CK parent technique but
does not support a narrower sub-technique, assign the parent technique. Use a
parent only if:

- it exists as a current technique in the supplied catalogue;
- its own ATT&CK definition matches the quoted behaviour; and
- using it adds no unstated channel, protocol, data source, access method,
  platform, tool, or target.

### Level 3 - No supported technique

Set `technique` to `null` when the report supports an event but neither a
specific technique nor a valid parent technique is entailed by the evidence.

The extractor MUST NOT choose:

- the nearest semantic match merely to fill the top-right badge;
- a tactic's most common or most general-looking technique;
- a child technique whose distinguishing detail is absent;
- an actor-associated technique that the incident passage does not describe;
- an obsolete identifier when no evidence-supported current replacement fits.

There is no universal generic ATT&CK technique for every tactic. For example,
`data was exfiltrated` does not by itself establish C2, a web service, an
alternative protocol, physical media, or automated exfiltration. If the channel
or qualifying behaviour is absent and no current parent definition fits, retain
the exfiltration event with tactic `EF` and `technique: null`.

Technique absence MUST NOT remove the event, its tactic badge, its likelihood,
its evidence record, or its graph connections.

## 7. Rule E5 - Assigning mitigations

Mitigation badges are recommendations associated with a supported ATT&CK
technique; they are not attack evidence detected in the report.

- If `technique` is `null`, `mitigations` MUST be an empty list.
- If a technique is present, every mitigation MUST be connected to that
  technique by an official ATT&CK `course-of-action --mitigates-->
  attack-pattern` relationship in the frozen catalogue version.
- A mitigation MUST NOT be selected merely because its M-number exists or its
  name sounds relevant.
- Zero mitigations is valid when the frozen ATT&CK data defines no applicable
  relationship.
- Different events MAY therefore show different numbers of T and M badges,
  exactly as the source evidence and ATT&CK relationship data permit.

The legend and dissertation MUST describe M values as `Recommended
mitigations`, not as mitigations observed in the incident.

## 8. Rule E6 - Logical relations

Keep the v1.4 substitution test:

- AND means every parent condition is required;
- OR means any one of several genuinely substitutable paths is sufficient.

Remove the v1.4 preference that a good graph should contain at least one AND or
OR. The report determines whether either relation exists. The extractor MUST NOT
manufacture branches to demonstrate visual or logical variety.

Explicit alternative hypotheses in the report, such as `phishing or brute
force`, may be represented as OR paths when either could independently produce
the same state. Mere uncertainty about what happened is not permission to add
other unmentioned alternatives.

## 9. Rule E7 - Sample-compatible rendering

The v1.5 evidence rules do not change the accepted visual syntax:

- preconditions/results remain white ellipses;
- events remain white rectangles;
- tactic badges remain at the top left;
- technique badges remain pink at the top right when a technique exists;
- mitigation badges remain orange at the bottom right when relationships exist;
- likelihood remains the cyan 0-10 badge at the bottom left;
- an event with `technique: null` has an empty top-right corner;
- an event with no mitigations has an empty bottom-right corner;
- the legend lists only identifiers that actually appear.

Do not introduce Kill Chain letters W/D/E/I into the ATT&CK tactic field. The
reference sample mixes schemes without defining those letters in its legend;
v1.5 retains the project's single ATT&CK tactic vocabulary.

Evidence quotations, evidence status, and evidence confidence are initially
audit metadata and SHOULD NOT be placed inside the graph nodes. A separate
evidence table or review view may expose them later without making the sample-
style image unreadable.

## 10. Rule E8 - No-empty-graph safeguard

Evidence restraint applies independently to each candidate event. It MUST NOT
be interpreted as permission to reject the entire report because some actions
are tentative or lack technique mappings.

The extraction sequence is:

1. extract every report-supported adversary action and its evidence;
2. preserve explicit uncertainty;
3. build event/precondition dependencies;
4. assign tactics;
5. assign a technique only when supported;
6. derive mitigations only from official technique relationships.

A report that describes an attack but gives no technique-level detail should
produce a smaller evidence-backed graph with empty T/M corners, not an empty
graph and not a fabricated full ATT&CK chain.

## 11. British Library development examples

These examples clarify the generic rules; they MUST NOT become hard-coded
keywords or case-specific branches.

### Explicit alternative initial-access hypotheses

If the development report explicitly says `possibly phishing or brute force`,
retain both actions as `possible` events and connect them as alternative OR
paths when either could yield the same credential/access state. `Brute Force`
may receive T1110 because the behaviour is explicitly named. A phishing mapping
may use the valid parent technique only when the quoted behaviour satisfies its
definition; do not invent email, attachment, link, voice, or SMS sub-techniques.

### Exfiltration without a channel

If the report states that approximately 600 GB was copied or exfiltrated but
does not identify a channel or protocol, retain the EF event and amount. Do not
choose T1048, T1567, T1041, or another channel-bearing technique without the
required evidence. Use `technique: null` when no valid parent definition fits.

### Weak defensive coverage

If the report states that security software was incomplete or ineffective,
represent that as an environmental precondition. Do not create a Disable or
Modify Tools event unless the report states that the adversary actively
disabled, degraded, or modified the tool.

## 12. Acceptance criteria for the v1.5 evidence iteration

The first implementation is accepted only if all of the following pass:

1. Every event has a non-empty exact `source_evidence` quotation.
2. Every event has one allowed `evidence_status`.
3. Evidence confidence and likelihood are stored separately.
4. Explicitly possible actions remain in the graph rather than causing an empty
   result.
5. No technique asserts a behaviour-defining detail absent from its evidence.
6. A supported event can validate and render with `technique: null`.
7. An event with `technique: null` has no mitigations.
8. Every non-empty mitigation is connected to its technique in frozen ATT&CK
   relationship data.
9. No event is added solely from actor profile knowledge or generic attack-
   chain expectations.
10. AND/OR relations are evidence-supported; neither is required by quota.
11. The reference-style PNG layout remains readable and unchanged apart from
    legitimately absent T/M badges.
12. The British Library development graph does not become empty and retains its
    report-supported attack actions and outcomes.

## 13. Required implementation work after approval

This specification is not executable yet. A coordinated implementation will
later require:

1. schema fields for `source_evidence`, `evidence_status`, and a separate
   `evidence_confidence`;
2. Stage A prompt and structured-output changes to extract evidence with each
   event;
3. an optional Stage B technique field and an explicit abstention path using
   JSON `null`, not a fictional `UNKNOWN` ATT&CK id;
4. removal of every retry instruction that forces a technique for all events;
5. an official technique-to-mitigation relationship index from the frozen
   ATT&CK data release;
6. validators for null-technique/empty-mitigation and valid T-M relationships;
7. evidence, uncertainty, regression, and rendering tests;
8. a real runtime `ruleset_v1.5.md` created only when all coordinated pieces are
   ready.

## 14. References informing the design

- Lallie, Debattista, and Bal: attack-graph preconditions, exploits/events, and
  AND/OR relations.
- OASIS STIX 2.1: confidence and external-reference concepts.
- MITRE ATT&CK Data Model: `course-of-action --mitigates--> attack-pattern`
  relationship.
- TRAM and NIST ALERT: analyst validation and active-learning treatment of
  uncertain ATT&CK mappings.
- TechniqueRAG and sentence-level ATT&CK mapping research: constrained
  candidates, re-ranking, and evidence-local technique classification.
- The Art of Abstention: selective prediction when evidence is insufficient.

