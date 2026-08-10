"""
extract.py -- Stage 3 of the pipeline: read report text and produce a
validated AttackGraph, with a language model finding the preconditions,
events, ATT&CK technique (T) numbers, and mitigation (M) numbers.

The provider is pluggable, because the choice of model is still open:
  * "ollama"    -- a local model, nothing leaves the machine (BSREC low risk)
  * "anthropic" -- the Claude API, stronger extraction, needs an API key

Both are made to emit JSON that conforms to the schema contract. The contract
is the safety net: whatever the model produces has to pass validation before a
graph is drawn, so a hallucinated or malformed element is rejected rather than
rendered. When validation fails, the error is fed back and the model is asked
to correct itself, up to a small number of attempts.
"""

from __future__ import annotations

import json
import os
import re
from contextvars import ContextVar
from pathlib import Path
from typing import Literal

import networkx as nx
from pydantic import (BaseModel, Field, ValidationError, field_validator,
                      model_validator)

from student_feedback import restate_graph, technique_shortlist
from student_identifiers import (classify_identifiers,
                                 identifier_coverage_problems,
                                 identifier_source_clauses,
                                 read_identifiers_from_text,
                                 summarise)
from schema import (AttackGraph, ATTACK_TACTICS, KNOWN_TECHNIQUES,
                    KNOWN_MITIGATIONS, MITIGATION_RE, TECHNIQUE_RE,
                    Event, Precondition)
from attack_graph import build_digraph
from attack_lookup import AttackResolver
from semantic_draft import (
    IncidentSemanticDraft,
    IncidentSemanticDraftWire,
    build_semantic_draft_prompt,
    project_draft_to_skeleton,
    semantic_presentation_sidecar,
    validate_evidence_against_report,
)

# --- cleaning the model's output before validation -------------------------
# A model trained on an older ATT&CK release will sometimes use a tactic id
# (TA0001) or a full tactic name instead of the abbreviation this tool expects,
# or a technique id that has since been revoked. Rather than fail on these, we
# clean them up: map the tactic to its abbreviation, and drop any technique or
# mitigation id the current ATT&CK data no longer contains. The graph is still
# produced, just without the identifiers that no longer exist.
_TACTIC_ID_MAP = {
    "TA0043": "RE", "TA0042": "RS", "TA0001": "IA", "TA0002": "EX",
    "TA0003": "PS", "TA0004": "PE", "TA0005": "DE", "TA0006": "CA",
    "TA0007": "DS", "TA0008": "LM", "TA0009": "CL", "TA0011": "C2",
    "TA0010": "EF", "TA0040": "IM",
}
_TACTIC_NAME_MAP = {name.lower(): abbr for abbr, name in ATTACK_TACTICS.items()}


def _fix_tactic(t: str) -> str:
    if t in ATTACK_TACTICS:                 # already an abbreviation
        return t
    if t in _TACTIC_ID_MAP:                 # ATT&CK tactic id, e.g. TA0001
        return _TACTIC_ID_MAP[t]
    if t.lower() in _TACTIC_NAME_MAP:       # full name, e.g. "Initial Access"
        return _TACTIC_NAME_MAP[t.lower()]
    return t                                # leave it; validation will flag it


def _sanitize(raw_json: str) -> str:
    """Clean an LLM response so recoverable mistakes do not fail the whole graph."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return raw_json                     # let validation report the parse error

    # If the model did not return the expected object shape, do not try to clean
    # it. Hand it to validation unchanged so the schema reports the real problem
    # and the retry loop can ask the model to correct itself.
    if not isinstance(data, dict):
        return raw_json

    # Recover from double wrapping. A model sometimes returns the value of
    # "preconditions" or "events" as a JSON STRING that itself contains the whole
    # object, for example {"preconditions": "{\"preconditions\": [ ... ]}"}. Parse
    # such a string and lift out the array it holds, so a recoverable formatting
    # slip does not fail the graph.
    for key in ("preconditions", "events"):
        val = data.get(key)
        if isinstance(val, str):
            try:
                inner = json.loads(val)
            except json.JSONDecodeError:
                continue
            if isinstance(inner, list):
                data[key] = inner                     # the string held the array directly
            elif isinstance(inner, dict) and isinstance(inner.get(key), list):
                data[key] = inner[key]                # the string held {key: [...]}

    events = data.get("events", [])
    preconditions = data.get("preconditions", [])
    if not isinstance(events, list):
        events = []
    if not isinstance(preconditions, list):
        preconditions = []
    data["events"] = events
    data["preconditions"] = preconditions

    for e in events:
        if not isinstance(e, dict):
            continue                        # skip a malformed event, let validation catch it
        if isinstance(e.get("tactic"), str):
            e["tactic"] = _fix_tactic(e["tactic"])
        tech = e.get("technique")
        if tech and KNOWN_TECHNIQUES and tech not in KNOWN_TECHNIQUES:
            e["technique"] = None           # drop a revoked or unknown technique
            e["mitigations"] = []           # M values require a supported T value
        if isinstance(e.get("mitigations"), list) and KNOWN_MITIGATIONS:
            e["mitigations"] = [m for m in e["mitigations"] if m in KNOWN_MITIGATIONS]

    return json.dumps(data)


# --- grounding: what the model must obey -----------------------------------
_TACTIC_LINES = "\n".join(f"  {abbr} = {name}" for abbr, name in ATTACK_TACTICS.items())

# The tool supports a fixed catalogue of ATT&CK ids. Giving the model that
# catalogue keeps it from inventing ids and lets the legend always resolve.
_resolver = AttackResolver()
_TECH_LINES = "\n".join(f"  {tid} = {name}" for tid, name in sorted(_resolver._techniques.items()))
_MITI_LINES = "\n".join(f"  {mid} = {name}" for mid, name in sorted(_resolver._mitigations.items()))

# --- tactic-scoped technique index (for hierarchical retrieval, v1.4) --------
# Load the technique -> tactic mapping added to the dictionary, and invert it to
# tactic -> techniques. This lets stage B offer the model only the techniques
# under a given tactic, rather than the whole catalogue.
_lookup_raw = json.loads(
    (Path(__file__).resolve().parent.parent / "data" / "attack_lookup.json")
    .read_text(encoding="utf-8"))
_TECHNIQUE_TACTICS = _lookup_raw.get("technique_tactics", {})
_TECHNIQUE_MITIGATIONS = _lookup_raw.get("technique_mitigations", {})
_TACTIC_TECHNIQUES: dict[str, list[str]] = {}
for _tid, _tacs in _TECHNIQUE_TACTICS.items():
    for _tac in _tacs:
        _TACTIC_TECHNIQUES.setdefault(_tac, []).append(_tid)


def _tech_lines_for_tactic(tactic: str) -> str:
    """The 'Tid = name' lines for techniques under one tactic, for stage B."""
    ids = sorted(_TACTIC_TECHNIQUES.get(tactic, []))
    return "\n".join(f"  {tid} = {_resolver._techniques.get(tid, '')}" for tid in ids)

# --- rule set: loaded from a versioned file so it can be iterated -----------
# The judgement rules that decide what a precondition, an event, and a logical
# element are, live in rules/ruleset_v<version>.md rather than in this file. This
# keeps the rule set explicit and version controlled: each iteration is a new
# file, and the tool can be pointed at a specific version for comparison. The
# ATT&CK catalogue is injected into the placeholders at load time.
_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
DEFAULT_RULESET = "v1"


_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def load_ruleset(version: str = DEFAULT_RULESET, *,
                 include_full_catalogue: bool = True) -> str:
    """Read rules/ruleset_<version>.md and fill in the ATT&CK catalogue.

    Raises FileNotFoundError with a clear message if the version is missing, so
    a mistyped version fails loudly rather than silently using stale rules.
    """
    if not re.fullmatch(r"(?:v\d+(?:\.\d+)*|student-v\d+(?:\.\d+)*)", version):
        raise ValueError(
            f"invalid rule set version {version!r}; expected v1, v1.5, "
            "student-v1, etc.")
    path = _RULES_DIR / f"ruleset_{version}.md"
    if not path.is_file():
        available = sorted(p.stem.replace("ruleset_", "")
                           for p in _RULES_DIR.glob("ruleset_*.md"))
        raise FileNotFoundError(
            f"rule set {version!r} not found at {path}. "
            f"available versions: {available or 'none'}"
        )
    text = path.read_text(encoding="utf-8")
    # Strip the maintainer commentary before the file becomes a system prompt.
    # Every rule file opens with an HTML comment holding the changelog, notes
    # to whoever edits the file next, and the history of abandoned versions.
    # None of it is addressed to the model, and it was 34% of what v1.4 sent:
    # the model read "Why v1.2 was set aside... it returned an empty graph"
    # and this project's dissertation notes before it read Rule 1. The file on
    # disk keeps the commentary, which is where it belongs.
    text = _COMMENT_RE.sub("", text).lstrip()
    # The old single-stage pipeline needs the complete catalogue in its system
    # prompt. The hierarchical v1.4/student pipelines do not: Stage A chooses
    # only a tactic and Stage B receives the short candidate lists for the
    # tactics actually used. Omitting the duplicate full catalogue here cuts
    # tens of thousands of input tokens without changing the rule text on disk
    # or the set of techniques the model may select.
    tech_lines = (_TECH_LINES if include_full_catalogue else
                  "[Supplied by the application as tactic-scoped Stage B candidates]")
    miti_lines = (_MITI_LINES if include_full_catalogue else
                  "[Supplied by the application in the Stage B assignment prompt]")
    return text.format(
        tactic_lines=_TACTIC_LINES,
        tech_lines=tech_lines,
        miti_lines=miti_lines,
    )


USER_TEMPLATE = """Here is the report. Extract the attack graph from it.

REPORT:
{report}"""


# --- hierarchical (two-stage) prompts, used by rule set v1.4 ----------------
# Stage A asks only for the graph skeleton with a tactic per event, choosing from
# the 14 tactics. Stage B then offers, per event, only the techniques under that
# event's tactic, and asks the model to pick the technique and mitigations. This
# keeps the model from searching the whole 700-technique catalogue at once.

STAGE_A_USER = """Here is a cyber incident report. Identify the attack as a graph
of alternating preconditions (ellipse states) and events (adversary actions).

For each EVENT give: a short id, a short label, the ATT&CK TACTIC it belongs to
(one of the 14 abbreviations), a likelihood 0-10, its join (AND or OR), and its
parent ids. Do NOT choose technique or mitigation ids yet; those come next.
For each PRECONDITION give: a short id, a short label, and its parent ids.

The two node types alternate and must be chained into one connected path.
Every event lists at least one precondition id in its parents, and the state
that event establishes is a precondition whose parent is that event and which
the next event then consumes. Never leave an event's parents empty, and never
return a set of isolated event/result pairs.

Model the whole attack the report describes, from reconnaissance to the final
objective, even where the report is brief or tentative. Return only the JSON.

REPORT:
{report}"""

# v1.6 keeps v1.4's two-stage mechanism and adds the three constructs the
# reference diagram uses. The wide-top instruction is the operative difference
# in shape: v1.4's prompt forbade a parentless event, which made the reference
# sample's four opening actions inexpressible and serialised the preparation
# phase into a chain.
STAGE_A_V16_USER = """Here is a cyber incident report. Identify the attack as a
graph of alternating preconditions (ellipse states) and events (adversary
actions).

For each EVENT give: a short id, a short label, the ATT&CK TACTIC it belongs to
(one of the 14 abbreviations), a likelihood 0-10, its join (AND or OR), its
parent ids, and its outline style. Do NOT choose technique or mitigation ids
yet; those come next.
For each PRECONDITION give: a short id, a label of AT MOST 10 WORDS, a short
badge code, its role, its outline style, and its parent ids. The label is drawn
inside an ellipse, so a longer one cannot be rendered. Name the state, not its
contents: "Attack toolkit staged" rather than "Off-the-shelf attack toolkit
staged (Mimikatz, Procdump, PsExec, EternalBlue, Nirsoft tools, KPortScan)".

ROLE, for state nodes only. Choose one:
  "precondition"      a state of the VICTIM environment, or a state the attack
                      itself established. The default; use it unless one of the
                      two below clearly applies.
  "external_resource" an asset the ADVERSARY brought from outside: a stolen
                      signing certificate, a pre-registered domain, a purchased
                      credential, malware they wrote. It has no parents, because
                      nothing in this graph produced it.
  "annotation"        a REMARK beside the step rather than a condition of it:
                      advice, a detection opportunity, an observation about the
                      response. "Staff awareness training would have helped",
                      "detected by SOC on day 4", "no evidence of data theft
                      was found". Its parent is the step it comments on. No
                      event may list it as a parent, because it is commentary
                      beside the attack, not part of it.

Test, in this order. Would removing this node make some attack event
impossible, or visibly change how feasible it was? Then it is a PRECONDITION --
including when what it describes is a missing or absent security control,
because a control the attack needed to be absent is part of why the attack
worked. "MFA not enabled" and "no egress filtering" are preconditions, not
annotations. Otherwise: did the adversary already hold it before touching the
target? That is an EXTERNAL RESOURCE. Otherwise, if removing it changes no
event's dependencies at all, it is an ANNOTATION. The subject being defensive
does not settle it.

STYLE, the outline. An annotation is always "dashed"; nothing else ever is.
For the other two node types, use "dotted" for a node on an
ALTERNATIVE or UNCONFIRMED branch: one of two or more routes to the same result
where the report does not establish which was taken. Use "solid" otherwise. A
dotted event is still a full event and still needs its tactic and likelihood.
Where two routes are dotted, join them at their shared result with OR.

EACH EVENT CONSUMES WHAT IT ACTUALLY NEEDS. This is the rule that decides the
graph's shape, so apply it to every event separately.

For each event, ask what state had to exist before it could happen, and list
exactly those states as its parents. Do not ask what the report mentioned just
before it. The order of the writing is not the order of dependency.

THE TEST, applied to each pair of steps: if the earlier step had NOT happened,
could this one still have occurred? If it could, they are NOT linked. Give this
event the state it genuinely required instead, which is usually an earlier,
shared one.

Worked example. An adversary with a foothold dumps process memory, reads saved
browser passwords, and sniffs network traffic. Reading browser passwords does
not require having dumped memory first: remove the memory dump and it still
works. All three require only the foothold. So all three take the FOOTHOLD as
their parent and sit side by side. Chaining them into memory dump -> browser
passwords -> sniffing invents a dependency the report does not state.

Steps that genuinely enable one another DO chain: you cannot install through a
prompt that was never shown, and you cannot use an account that was never
created. Link those.

The result is neither a single line nor a set of loose pieces. Independent work
sits side by side and shares its input; dependent work follows in sequence; the
paths converge as the attack narrows toward its objective.

STARTING POINTS. A few events at the very top may have no parents at all,
because the adversary did them before touching the target and nothing in the
report precedes them. Whatever they produce must still be consumed by a later
event, or they are not part of the graph.

Model the whole attack the report describes, from reconnaissance to the final
objective, even where the report is brief or tentative. Return only the JSON.

REPORT:
{report}"""

STAGE_B_V16_USER = """You previously produced this attack-graph skeleton, with
a tactic on each event but no technique or mitigation ids yet:

{events}

Your task is ONLY to assign technique ids to each listed event. Do not return a
graph, preconditions, labels, parents, tactics, or join values: the application
preserves those from Stage A itself.

Return exactly one JSON object in this form:
{{"assignments": [
  {{"id": "event id from the list", "techniques": ["T####", "T####.###"]}}
]}}

HOW MANY TECHNIQUES PER EVENT. Give an event every technique the report
attributes to that one action, and no others. Most actions have exactly one.
Some have several, because ATT&CK classifies behaviours and a single action can
exhibit more than one.

Decision test, applied to the report's own wording:
  - Does the report describe these behaviours as things this one action does?
    Then they are techniques OF this event. "The malware logs keystrokes,
    reads saved browser passwords and sends them to the attacker's server"
    describes ONE execution with three classified behaviours.
  - Does the report describe them as separate steps, at different times, or
    with a state in between that the next step needed? Then they belong to
    different events, and you should give this event only its own.

Do not add a technique to make an event look richer, and do not merge
behaviours the report separates. The count comes from the report, not from a
preferred graph size.

Return exactly {n_events} assignments, one per id, with no duplicate ids. The
required ids are: {event_ids}.

ORDER MATTERS. List the PRIMARY technique first: the one that classifies what
the action was for, matching the tactic Stage A assigned. Choose it from that
event's list below.

Any FURTHER technique classifies a secondary behaviour of the same action, and
belongs to whichever tactic ATT&CK puts it under. It does not have to come from
this event's list, and it usually will not: an execution that also logs
keystrokes is Execution first and Collection second. Use an exact identifier
from the catalogue in either case.

{candidates}

Never return an empty techniques array. Return only the assignments object."""


STAGE_B_USER = """You previously produced this attack-graph skeleton, with a
tactic on each event but no technique or mitigation ids yet:

{events}

Your task is ONLY to assign a technique id and mitigation ids to each listed
event. Do not return a graph, preconditions, labels, parents, tactics, or join
values: the application preserves those from Stage A itself.

Return exactly one JSON object in this form:
{{"assignments": [
  {{"id": "event id from the list", "technique": "T#### or T####.###",
   "mitigations": ["M####"]}}
]}}

Return exactly {n_events} assignments, one per id, with no duplicate ids. The
required ids are: {event_ids}.

For each event choose the technique from ONLY the list under that event's tactic:

{candidates}

Mitigations to choose from (pick those that counter each event's technique):
{miti_lines}

Never leave a technique blank. Return only the assignments object."""


# v1.5 preserves v1.4's reliable two-stage pipeline but makes evidence and
# abstention explicit.  Separate prompts keep the frozen v1.4 behaviour intact.
STAGE_A_V15_USER = """Here is a cyber incident report. Identify ONLY the
adversary actions that this supplied report states, reports, alleges, or
explicitly proposes. Build an alternating graph of preconditions (ellipse
states) and events (adversary actions).

For each EVENT give: a short id, a short label, the ATT&CK TACTIC it belongs to
(one of the 14 abbreviations), a likelihood 0-10, its join (AND or OR), its
parent ids, and all three evidence fields below:
  - source_evidence: an exact contiguous quotation from this report that states
    or explicitly attributes the adversary action; normally one sentence and
    at most two adjacent sentences. Preserve words such as possibly, alleged,
    suspected, likely, or reportedly.
  - evidence_status: exactly confirmed, reported, alleged, or possible.
  - evidence_confidence: 0-100 confidence that the quotation supports the
    extracted claim. Prefer the coarse values 15, 50, or 85.

Likelihood is attack-step/path feasibility. Evidence confidence is confidence
in the extracted textual claim. They are different and must not substitute for
each other.

For each PRECONDITION give: a short id, a label of no more than 10 words, and
its parent ids. A precondition may be an explicit state or the direct state
mechanically produced by a supported event. It must not add an unstated tool,
credential, channel, vulnerability, system, or capability.

Nodes must strictly alternate. An event's parents must all be preconditions,
never another event, and a precondition's parents must all be events. When one
event follows another, place a precondition between them that represents the
state the first event produces, and let the second event consume that
precondition.

Do NOT choose technique or mitigation ids yet; those come next. Do not complete
a generic attack chain. Do not turn defender, victim, investigator, or vendor
actions into adversary events. Do not import actions from another incident or
from a threat actor's general profile. Tentative actions explicitly mentioned
in the report are still events with evidence_status possible. Return only JSON.

REPORT:
{report}"""


STAGE_B_V15_USER = """You previously produced these evidence-backed Stage A
events. Their labels, tactics, evidence, likelihoods, parents, and joins are
preserved by the application:

{events}

Your task is ONLY to assign an ATT&CK technique and zero or more recommended
mitigations to each listed event. Do not return a graph or rewrite Stage A.

Return exactly one JSON object in this form:
{{"assignments": [
  {{"id": "event id from the list", "technique": "T#### or T####.### or null",
   "mitigations": ["M####"]}}
]}}

Return exactly {n_events} assignments, one per id, with no duplicate ids. The
required ids are: {event_ids}.

For each event choose a technique only from the list under that event's tactic:

{candidates}

Mitigation identifiers available to the tool:
{miti_lines}

Apply this evidence-specificity ladder independently to every event:
1. Choose a specific technique/sub-technique only when source_evidence states
   every behaviour-defining detail required by it.
2. Otherwise choose a valid parent technique only when its own definition is
   directly entailed and adds no unstated channel, protocol, platform, tool,
   target, data source, or access method.
3. Otherwise set technique to null. Never select the nearest plausible or most
   common technique merely to fill the badge.

If technique is null, mitigations MUST be []. If a technique is present, include
only mitigations that specifically counter it; zero mitigations is valid. M
badges are recommendations, not evidence observed in the incident. Return only
the assignments object."""


# The teaching path keeps the sample-compatible v1.4 T/M contract but gives
# Stage A stricter graph-construction instructions. It is isolated from the
# professional v1.4 prompt so teaching fixes cannot change the research baseline.
STAGE_A_STUDENT_USER = """Here is a student's cyber-incident narrative. Build
ONE connected, directed, acyclic attack graph containing only the adversary
actions, conditions, and impacts supported by this narrative.

Return an alternating skeleton of preconditions (states/resources) and events
(adversary actions). For each event give a short id, verb-led label, one ATT&CK
tactic abbreviation, likelihood 0-10, parent precondition ids, and join AND or
OR. For each precondition give a short id, a state label of at most ten words,
its top-left code, and parent event ids.

Every event MUST consume at least one precondition and produce at least one
derived precondition. All nodes must belong to one connected graph. Do not
create an isolated reconnaissance or impact fragment.

Do not combine different actions into one event. In particular, if the narrative
says "phishing or brute force", create two possible events under their different
tactics that may establish the same result state. Do not put OR between a remote
service and missing MFA: those are cumulative conditions and therefore AND. Use
OR only for independently sufficient parent states.

Do not turn states such as "credentials obtained" into rectangle events. Do not
add unstated words such as exposed, staged, administrator, protocol, cloud, or
malware. Preserve words such as possible, suspected, or alleged in labels. Do
not add defender, investigator, victim-response, or generic ATT&CK actions.

Do NOT choose technique or mitigation ids yet; Stage B assigns them. Return only
the graph skeleton as JSON.

NARRATIVE:
{report}"""


STAGE_B_STUDENT_USER = """Assign ATT&CK techniques and mitigations to the
student graph events below without rewriting their labels, tactics, parents,
joins, or likelihoods:

{events}

Return exactly one JSON object:
{{"assignments": [
  {{"id": "event id", "technique": "T#### or T####.###",
   "mitigations": ["M####"]}}
]}}

Return exactly {n_events} assignments, one for every id and no duplicates. The
required ids are: {event_ids}.

Choose a technique only from the candidate list under that event's tactic:

{candidates}

Available mitigation ids:
{miti_lines}

Choose the least-specific candidate that accurately describes the student's
narrative. Do not add an unstated protocol, service, platform, tool, target, or
sub-technique detail. Brute Force T1110 is Credential Access; Phishing T1566 is
Initial Access; publishing stolen data is not Defacement. Include only
mitigations that directly counter the selected technique; an empty mitigation
list is valid. Return only the assignments object."""


STAGE_A_STUDENT_EVIDENCE_USER = """Here is a student's cyber-incident
narrative. Build ONE evidence-grounded, directed, acyclic attack graph. Include
only actions explicitly performed by the adversary and outcomes explicitly
stated in the narrative.

Return an alternating skeleton of preconditions (states/resources) and events
(adversary actions). For each event give: short id, verb-led label, one ATT&CK
tactic abbreviation, likelihood 0-10, parent precondition ids, join AND/OR,
actor exactly "adversary", source_evidence as one exact contiguous quotation
from the narrative that states the action, action_evidence as the exact verb or
verb phrase inside that quotation, evidence_status (confirmed, reported,
alleged, or possible), and evidence_confidence 0-100.

COPY OUT, DO NOT CHOOSE, the ATT&CK identifiers. The student did this mapping
themselves before writing, so where the narrative already gives a T-number or
an M-number for a step, put it in stated_technique and stated_mitigations for
that step, exactly as written, including any sub-technique suffix. Where the
narrative gives none for a step, leave stated_technique null and
stated_mitigations empty. Do NOT choose technique or mitigation ids yet for
those steps; Stage B assigns them, and the student is told which steps that
happened to. Never move an identifier to a step the
narrative did not attach it to, and never supply one of your own here.

The action_evidence must be the action represented by the event, not a nearby
word about the same object. Its grammatical actor must be the adversary. A
victim response, investigation, recovery step, password reset, service impact,
customer delay, or financial loss is a state/outcome, not an attacker event,
unless the quotation explicitly states that the adversary performed that
action. A consequential phrase such as "forcing employees to reset passwords"
does not prove that password reset was a separate adversary technique.

Start the label with the same lexical action used in action_evidence; do not
replace it with a synonym or a merely related ATT&CK action. Inflection changes
are allowed: "was exfiltrated" may be labelled "Exfiltrate data", but it must
not be relabelled "Steal data"; "ransomware was deployed" may be labelled
"Deploy ransomware", but it must not be relabelled "Encrypt systems". Keep all
objects and targets supported by the quotation.

Do not bridge separate facts with a plausible story. In particular, accessing a
tool that sells breached credentials does not prove credentials were obtained
or used. Connect a parent state to an event only when the narrative states the
dependency or the state is the direct stated result of an earlier event. Omit a
peripheral fact that cannot join the core incident without inference.

The absence of a technical method is NOT a reason to omit a stated action. A
sentence such as "the pair compromised the network", "the network was
infiltrated", "the attacker accessed systems", or "data was accessed" supports
a high-level event. Preserve that high-level wording and let Stage B return a
null technique if no ATT&CK behaviour is sufficiently evidenced. Do not demand
an exploit, credential, vulnerability, or tool before modelling an explicitly
reported compromise or access action.

A root event may have no parent when the narrative does not state a prerequisite.
A terminal event may have no derived precondition when the narrative states no
further result. This matches the supervisor sample: never create an artificial
ellipse merely to surround every rectangle. For zero or one parent use join AND,
which renders as an ordinary line. Use OR only for two or more independently
sufficient parent states.

Prefer one connected core incident graph and omit unrelated arrest, legal,
recovery, or other-incident facts. Never invent an event or causal edge to force
connectivity. Preserve possible, suspected, reported, and alleged wording.
Return only the graph skeleton as JSON.

NARRATIVE:
{report}"""


STAGE_B_STUDENT_EVIDENCE_USER = """Assign ATT&CK techniques and mitigations to
the evidence-grounded student events below without rewriting their labels,
tactics, evidence, parents, joins, or likelihoods:

{events}

Return exactly one JSON object:
{{"assignments": [
  {{"id": "event id", "technique": "T#### or T####.### or null",
   "mitigations": ["M####"]}}
]}}

Return exactly {n_events} assignments, one for every id and no duplicates. The
required ids are: {event_ids}.

Choose a technique only from the candidate list under that event's tactic:

{candidates}

The candidate list is the application's authoritative MITRE Enterprise ATT&CK
v19 catalogue. Do not use an identifier remembered from an earlier ATT&CK
release and do not return any T-number absent from the supplied candidates.
In particular, retired T1562 must not be returned. Disabling or modifying a
security tool may use current T1685 only when that candidate is listed under the
event's tactic and the quoted evidence supports it. If no listed v19 candidate
is directly supported, return null with an empty mitigation list.

Available mitigation ids:
{miti_lines}

Map the quoted behaviour, not a plausible explanation of the incident. Choose
the least-specific candidate entailed by source_evidence and action_evidence.
Use null with an empty mitigation list when the quote does not support any
candidate. Do not infer Valid Accounts because breached credentials are merely
mentioned. User Execution requires a victim/user to execute malicious content.
Service Stop requires an adversary action that stops or disables a service.
Account Access Removal is not a victim organisation's password-reset response.
Only include mitigations that directly counter a non-null technique. Return only
the assignments object."""


# Student v1.2 keeps the stable v1.1 evidence contract and adds a final,
# report-agnostic coverage check. It is a separate prompt so historical v1.1
# remains available for dissertation comparisons.
STAGE_A_STUDENT_V12_USER = STAGE_A_STUDENT_EVIDENCE_USER.replace(
    "\nNARRATIVE:\n{report}",
    """

Before returning the skeleton, perform this coverage check against the supplied
narrative:
1. Include each explicit adversary action in the core incident, including an
   explicitly tentative action. Keep alternatives such as phishing or brute
   force separate and preserve their uncertainty; do not imply that a possible
   action succeeded.
2. Include every explicitly stated condition that materially enables a core
   action, such as absent MFA, excessive privileges, an exposed service, or an
   available account/tool. Represent a condition as an ellipse, never as an
   invented adversary event.
3. Include every explicitly stated security outcome of the core incident as a
   result ellipse, including unavailable services, corrupted or encrypted
   systems, stolen/published data, lockout, and inhibited recovery. A terminal
   result ellipse is valid even when no later event consumes it.
4. Omit legal proceedings, arrests, quotations about general threat, and facts
   from another incident unless they are part of this incident's causal graph.

NARRATIVE:
{report}""")


class SkeletonEvent(BaseModel):
    """Stage A event before a tactic-scoped T/M assignment is made."""

    id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    tactic: Literal[tuple(ATTACK_TACTICS)]
    # The reference sample carries a cyan likelihood badge on every action, and
    # Rule 2 asks for one. Left optional it was simply omitted: the Stolen
    # Pencil run returned no likelihood at all, so every action lost its badge.
    likelihood: float = Field(ge=0, le=10)
    # Not constrained to be non-empty. The reference sample opens with four
    # attacker actions that consume nothing at all - creating the extension,
    # building the lure PDF, gathering addresses, configuring the website -
    # and those root events are what give it its wide top. Requiring a parent
    # here made them impossible to express and flattened the fan. The graph as
    # a whole is still held together, by the connectivity and chaining checks
    # in _skeleton_graph_problems, which reject a set of isolated pairs
    # without dictating that every single event consume something.
    parents: list[str] = Field(default_factory=list)
    join: Literal["AND", "OR"] = "AND"


class ProjectedSkeletonEvent(SkeletonEvent):
    """A skeleton event that may legitimately open the graph.

    The evidence-first pathway keeps a root event when the source supplies no
    surrounding state to invent, so its projected skeleton is checked against
    the permissive shape rather than the professional wire contract.
    """

    parents: list[str] = Field(default_factory=list)


class AttackGraphSkeleton(BaseModel):
    """Non-empty Stage A graph whose events intentionally have no T/M fields."""

    title: str = "Attack graph"
    # Every event must name at least one precondition parent, so a graph with
    # no preconditions cannot be satisfiable. Stating the minimum here puts it
    # in the schema the provider enforces instead of leaving it to be detected
    # afterwards as a set of dangling references.
    preconditions: list[Precondition] = Field(min_length=1)
    events: list[SkeletonEvent] = Field(min_length=1)


class ProjectedAttackGraphSkeleton(AttackGraphSkeleton):
    """The permissive counterpart used for locally projected skeletons."""

    events: list[ProjectedSkeletonEvent] = Field(min_length=1)


# --- v1.6: the constructs the reference diagram uses -------------------------
# The canonical Precondition already carries role and style, so those fields
# would technically reach the provider through AttackGraphSkeleton. They are
# restated here as a plain wire model for the reason the rest of this module
# was rewritten: the canonical model raises its cross-field rules *inside* the
# SDK call, where a merely cosmetic disagreement (an annotation the model drew
# solid) would cost a paid retry. The wire model states what the schema can
# enforce as a hard constraint and leaves what it cannot to the normaliser
# below, which repairs locally instead of asking again.


class ConstructTechniqueAssignment(BaseModel):
    """Locally validated v1.6 assignment."""

    id: str
    techniques: list[str] = Field(min_length=1)

    @field_validator("techniques")
    @classmethod
    def _known_and_unique(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("technique ids must not contain duplicates")
        for value in values:
            if KNOWN_TECHNIQUES and value not in KNOWN_TECHNIQUES:
                raise ValueError(
                    f"technique {value!r} is not in this tool's ATT&CK set")
        return values


class ConstructTechniqueAssignments(BaseModel):
    assignments: list[ConstructTechniqueAssignment] = Field(min_length=1)


class ConstructPreconditionWire(BaseModel):
    """API-visible Stage A state node carrying role and outline style."""

    id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    code: str = Field(min_length=1)
    role: Literal["precondition", "external_resource", "annotation"] = (
        "precondition")
    style: Literal["solid", "dotted", "dashed"] = "solid"
    parents: list[str] = Field(default_factory=list)


class ConstructSkeletonEvent(SkeletonEvent):
    """A Stage A event that may sit on a dotted alternative branch.

    Dashed is absent from the enum rather than rejected by a validator: an
    event is never commentary, and a value the schema does not offer cannot be
    returned at all.
    """

    style: Literal["solid", "dotted"] = "solid"


class ConstructAttackGraphSkeleton(BaseModel):
    """Stage A contract for v1.6, with external resources and annotations."""

    title: str = "Attack graph"
    preconditions: list[ConstructPreconditionWire] = Field(min_length=1)
    events: list[ConstructSkeletonEvent] = Field(min_length=1)


def _normalise_constructs(data: dict) -> dict:
    """Reconcile role with outline style, returning a repaired copy.

    Role is the decision that carries meaning; style is how that decision is
    drawn. When the two disagree the role is authoritative, so the disagreement
    is a drawing error and is corrected here rather than sent back to the model.
    Spending a paid call to be told again what the role already says would be
    the expensive way to learn nothing.
    """

    def repaired(node: dict) -> dict:
        role = node.get("role", "precondition")
        style = node.get("style", "solid")
        if role == "annotation":
            # Commentary is dashed by definition, and it comments on a step
            # rather than depending on one, so it never feeds the attack path.
            return {**node, "style": "dashed"}
        if role == "external_resource":
            # Something the adversary brought with them is not produced by any
            # event in this graph, so a parent here is a category error.
            return {**node, "style": "solid" if style == "dashed" else style,
                    "parents": []}
        if style == "dashed":
            return {**node, "style": "solid"}
        return node

    def deduplicated(node: dict) -> dict:
        """Drop repeated and blank parent ids.

        A precondition listed twice is the same dependency twice: the set is
        unchanged, so there is nothing to ask the model about. schema.py
        rejects the duplicate, but only after Stage B has been paid for, so
        without this a meaningless repetition discarded a complete graph.
        """
        seen, ordered = set(), []
        for parent in node.get("parents", []):
            cleaned = str(parent).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                ordered.append(cleaned)
        return {**node, "parents": ordered}

    preconditions = [deduplicated(repaired(node))
                     for node in data.get("preconditions", [])]
    annotations = {
        node["id"] for node in preconditions if node.get("role") == "annotation"
    }
    events = [
        deduplicated({
            **event,
            "parents": [p for p in event.get("parents", [])
                        if p not in annotations],
        })
        for event in data.get("events", [])
    ]
    return {**data, "preconditions": preconditions, "events": events}


class StudentEvidenceEvent(Event):
    """A student Stage A event, carrying the identifiers they already chose.

    The teaching workflow puts the ATT&CK mapping with the student: they
    research the incident, decide the technique and mitigation numbers, and
    write them into the narrative. Stage A copies those out rather than
    choosing its own, so the fields are deliberately unconstrained strings: a
    mistyped identifier has to reach the checker, which reports it against the
    step it came from, instead of the provider rejecting the whole payload
    with a message that names neither the step nor the number.
    """

    stated_technique: str | None = None
    stated_mitigations: list[str] = Field(default_factory=list)


class StudentEvidenceGraph(AttackGraph):
    """Student v1.1+ Stage A contract: evidence metadata plus >=1 action."""

    events: list[StudentEvidenceEvent] = Field(min_length=1)


class StudentEvidenceEventWire(BaseModel):
    """API-visible Stage A event for the student rule sets.

    The student path sent a strict model straight to the provider, which is
    what the wire/strict split in this file exists to avoid. Six of its fields
    carried defaults, so each reached the API as an optional property inside an
    ``anyOf`` with null: the evidence contract the rules insist on was, to the
    provider, entirely skippable, and the grammar carried six branches nobody
    wanted. Requiring them here is the same correction ``EvidenceEventWire``
    already made for the professional evidence rule set.

    ``stated_technique`` is an ordinary string rather than a nullable one, for
    the same reason: a step the student left unnumbered is an empty string,
    which needs no branch in the grammar and no null in the payload. It carries
    no default, so it is required, and this is the whole point. Giving it a
    default made it optional to the provider, the model omitted it on every
    event, and a student's own T1213 was silently discarded on the first real
    run -- exactly the failure the paragraph above describes, walked into while
    writing the paragraph above.
    """

    id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    tactic: Literal[tuple(ATTACK_TACTICS)]
    likelihood: float = Field(ge=0, le=10)
    parents: list[str] = Field(default_factory=list)
    join: Literal["AND", "OR"] = "AND"
    source_evidence: str = Field(min_length=1)
    action_evidence: str = Field(min_length=1)
    actor: Literal["adversary", "victim", "defender", "investigator",
                   "unknown"]
    evidence_status: Literal["confirmed", "reported", "alleged", "possible"]
    evidence_confidence: int = Field(ge=0, le=100)
    # Copied out of the narrative, never chosen here. Left unconstrained so a
    # mistyped identifier reaches the checker, which names it against this
    # step, rather than the provider rejecting the payload.
    stated_technique: str
    stated_mitigations: list[str]


class StudentEvidenceGraphWire(BaseModel):
    """API-visible Stage A shape for the student rule sets."""

    title: str = "Attack graph"
    preconditions: list[Precondition] = Field(min_length=1)
    events: list[StudentEvidenceEventWire] = Field(min_length=1)


class EvidenceEventWire(BaseModel):
    """API-visible Stage A event for the evidence rule set.

    The evidence fields are required here, not optional. Rule 1 asks for all
    three in prose, and the Stage A prompt lists them again, but a field with a
    default reaches the provider as an optional property, and the model
    returned events with none of them. A rule the schema does not carry is a
    request, not a constraint.

    Technique and mitigation are deliberately absent: Stage A must not choose
    them, and omitting them also removes a whole class of provider-side
    rejection, since the tactic/technique consistency check is a model
    validator that no JSON Schema can express.
    """

    id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    tactic: Literal[tuple(ATTACK_TACTICS)]
    likelihood: float = Field(ge=0, le=10)
    # The evidence rule set declines to invent a precondition the report does
    # not state, so a root event stays legitimate and this is not constrained.
    parents: list[str] = Field(default_factory=list)
    join: Literal["AND", "OR"] = "AND"
    source_evidence: str = Field(min_length=1)
    evidence_status: Literal["confirmed", "reported", "alleged", "possible"]
    evidence_confidence: int = Field(ge=0, le=100)


class EvidenceGraphWire(BaseModel):
    """API-visible Stage A shape for the evidence rule set.

    ``AttackGraph`` carries referential integrity as a Pydantic model
    validator. A JSON Schema cannot express that, so sending ``AttackGraph`` as
    the output format meant the SDK rejected a dangling reference from inside
    the provider call, with a message that names neither the missing node nor
    what to do about it, before the local gate could produce one that does.

    This model keeps the constraints a schema can carry, so the payload comes
    back and the gate reports it. ``AttackGraph`` still validates the result
    afterwards, so nothing is accepted that the contract would reject.
    """

    title: str = "Attack graph"
    preconditions: list[Precondition] = Field(min_length=1)
    events: list[EvidenceEventWire] = Field(min_length=1)


class TechniqueAssignment(BaseModel):
    """Stage B's small, immutable add-on for one Stage A event."""

    id: str
    technique: str = Field(..., description="ATT&CK T-number")
    mitigations: list[str] = Field(default_factory=list,
                                   description="ATT&CK mitigation M-numbers")

    @field_validator("technique")
    @classmethod
    def _known_technique(cls, value: str) -> str:
        if not TECHNIQUE_RE.match(value):
            raise ValueError("technique must be T#### or T####.###")
        if KNOWN_TECHNIQUES and value not in KNOWN_TECHNIQUES:
            raise ValueError(f"technique {value!r} is not in this ATT&CK catalogue")
        return value

    @field_validator("mitigations")
    @classmethod
    def _known_mitigations(cls, values: list[str]) -> list[str]:
        for value in values:
            if not MITIGATION_RE.match(value):
                raise ValueError("mitigation must be M####")
            if KNOWN_MITIGATIONS and value not in KNOWN_MITIGATIONS:
                raise ValueError(f"mitigation {value!r} is not in this ATT&CK catalogue")
        return values


def _decode_assignment_list(value):
    """Recover a Stage B array that a model double-encoded as JSON text."""
    if not isinstance(value, str):
        return value
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "assignments was returned as a string, but it was not valid JSON") from exc
    if isinstance(decoded, dict) and "assignments" in decoded:
        decoded = decoded["assignments"]
    if not isinstance(decoded, list):
        raise ValueError("decoded assignments must be a JSON array")
    return decoded


class TechniqueAssignments(BaseModel):
    """The complete set of technique assignments for an existing skeleton."""

    assignments: list[TechniqueAssignment]

    @field_validator("assignments", mode="before")
    @classmethod
    def _accept_double_encoded_array(cls, value):
        return _decode_assignment_list(value)


# Anthropic's structured-output transformer intentionally downgrades regex
# ``pattern`` constraints to descriptions. Literal enums remain hard API
# constraints, so the wire vocabulary is generated from the installed ATT&CK
# v19 catalogue instead of relying on a local-only pattern validator.
TechniqueIdWire = Literal.__getitem__(
    tuple(sorted(KNOWN_TECHNIQUES))
)
MitigationIdWire = Literal.__getitem__(
    tuple(sorted(KNOWN_MITIGATIONS))
)


class TechniqueAssignmentWire(BaseModel):
    """API-visible T/M syntax before catalogue and tactic validation."""

    id: str = Field(min_length=1)
    technique: TechniqueIdWire
    mitigations: list[MitigationIdWire] = Field(default_factory=list)


class TechniqueAssignmentsWire(BaseModel):
    """Strict structured-output payload for the professional T/M call."""

    assignments: list[TechniqueAssignmentWire] = Field(min_length=1)


class ConstructTechniqueAssignmentWire(BaseModel):
    """v1.6 assignment: an action may be classified more than once.

    ATT&CK classifies behaviours, and one action a report describes can exhibit
    several. The reference diagram uses this: its "GREASE malware executed"
    node carries seven techniques, because the report describes one execution
    that logs keystrokes, reads stored credentials and exfiltrates them.
    Forcing one technique per event forces one event per behaviour, which
    lengthens the graph for a reason that comes from the schema rather than
    from the incident.

    The list is offered as a capability, not a target. How many techniques an
    action carries is decided by the report, and the prompt supplies a
    determination test rather than a number: tuning that number to reproduce
    one reference diagram, then evaluating against that same diagram, would
    measure nothing.
    """

    id: str = Field(min_length=1)
    techniques: list[TechniqueIdWire] = Field(min_length=1)


class ConstructTechniqueAssignmentsWire(BaseModel):
    assignments: list[ConstructTechniqueAssignmentWire] = Field(min_length=1)


class EvidenceTechniqueAssignment(BaseModel):
    """v1.5 Stage B assignment with an explicit abstention path."""

    id: str
    technique: str | None = Field(
        None, description="ATT&CK T-number, or null when evidence is insufficient")
    mitigations: list[str] = Field(default_factory=list)

    @field_validator("technique")
    @classmethod
    def _known_optional_technique(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not TECHNIQUE_RE.match(value):
            raise ValueError("technique must be T####, T####.###, or null")
        if KNOWN_TECHNIQUES and value not in KNOWN_TECHNIQUES:
            raise ValueError(f"technique {value!r} is not in this ATT&CK catalogue")
        return value

    @field_validator("mitigations")
    @classmethod
    def _known_optional_mitigations(cls, values: list[str]) -> list[str]:
        for value in values:
            if not MITIGATION_RE.match(value):
                raise ValueError("mitigation must be M####")
            if KNOWN_MITIGATIONS and value not in KNOWN_MITIGATIONS:
                raise ValueError(f"mitigation {value!r} is not in this ATT&CK catalogue")
        return values

    @model_validator(mode="after")
    def _null_technique_has_no_mitigations(self):
        if self.technique is None and self.mitigations:
            raise ValueError("a null technique must have an empty mitigation list")
        return self


class EvidenceTechniqueAssignments(BaseModel):
    assignments: list[EvidenceTechniqueAssignment]

    @field_validator("assignments", mode="before")
    @classmethod
    def _accept_double_encoded_array(cls, value):
        return _decode_assignment_list(value)


class EvidenceTechniqueAssignmentWire(BaseModel):
    """API-visible Stage B assignment for the evidence rule set.

    Catalogue membership is a field validator on the strict model, which no
    JSON Schema can express, so the provider was free to return a renumbered
    identifier and the SDK rejected it inside the paid call. A Literal
    vocabulary is a hard API constraint, so the identifier cannot be returned
    at all. ``None`` remains valid: abstention is the point of this rule set.
    """

    id: str = Field(min_length=1)
    technique: TechniqueIdWire | None = None
    mitigations: list[MitigationIdWire] = Field(default_factory=list)


class EvidenceTechniqueAssignmentsWire(BaseModel):
    assignments: list[EvidenceTechniqueAssignmentWire] = Field(min_length=1)


# Output size is chosen by what the response *is*, and the test names the small
# case rather than the large one. It was written the other way round -- an
# allowlist of graph-shaped models each granted 8192 tokens -- and
# ConstructAttackGraphSkeleton, added for v1.6, was not on it. A v1.6 skeleton
# is the largest graph this tool asks for, since role and style are carried on
# every node, and it would have been given the smallest budget. Stated this way
# a model omitted from the table gets the generous default and is merely
# wasteful; under the old form it was silently truncated mid-graph.
_ASSIGNMENT_MODELS = frozenset({
    TechniqueAssignments, TechniqueAssignmentsWire,
    EvidenceTechniqueAssignments, EvidenceTechniqueAssignmentsWire,
})
_SMALL_RESPONSE_TOKENS = 4096

# Raised from 8192 after a v1.6 run on STOLEN PENCIL returned 24 preconditions
# referring to 23 events but only one event: the answer was cut off, not wrong.
# A v1.6 skeleton is the largest response this tool asks for, since role and
# style ride on every node, and the reference incident alone needs about fifty.
_GRAPH_TOKENS_ENV = "ATTACK_GRAPH_MAX_OUTPUT_TOKENS"
_GRAPH_RESPONSE_TOKENS_DEFAULT = 16384


class _TruncatedResponse(RuntimeError):
    """The model ran out of output space. Retrying unchanged cannot help.

    Deliberately a RuntimeError, which is NOT in the tuple the Stage A and
    Stage B loops catch. It therefore propagates on the first occurrence
    instead of consuming the one permitted correction on a retry that would
    hit the same ceiling. The message reaches the user unchanged and names the
    variable to raise.
    """


def _graph_response_tokens() -> int:
    """Output ceiling for a graph-shaped response, overridable for a big report."""

    raw = os.environ.get(_GRAPH_TOKENS_ENV, "").strip()
    if not raw:
        return _GRAPH_RESPONSE_TOKENS_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        return _GRAPH_RESPONSE_TOKENS_DEFAULT
    return value if value > 0 else _GRAPH_RESPONSE_TOKENS_DEFAULT

# A Stage A call that fills its 8192-token budget legitimately takes longer than
# three minutes on a long report. The previous 180s ceiling turned a slow but
# succeeding request into an APITimeoutError, which is indistinguishable to the
# caller from a dropped connection and discards work already paid for.
_REQUEST_TIMEOUT_S = 600.0


def _sanitize_student_v19_assignments(raw_json: str) -> str:
    """Apply the Student app's closed ATT&CK v19 vocabulary without a retry.

    Claude can ignore the supplied candidates and return an id remembered from
    an older ATT&CK release, such as retired T1562. Student rules already allow
    an evidence-honest abstention, so an out-of-catalogue technique becomes
    ``null`` and its mitigations become empty. Unknown mitigation ids are
    dropped. Malformed payloads remain unchanged for Pydantic to diagnose.

    The professional v1.4 path does not call this function.
    """
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return raw_json
    if not isinstance(data, dict) or "assignments" not in data:
        return raw_json

    try:
        assignments = _decode_assignment_list(data["assignments"])
    except ValueError:
        return raw_json
    if not isinstance(assignments, list):
        return raw_json

    for assignment in assignments:
        if not isinstance(assignment, dict):
            continue
        technique = assignment.get("technique")
        if (isinstance(technique, str) and KNOWN_TECHNIQUES
                and technique not in KNOWN_TECHNIQUES):
            assignment["technique"] = None
            assignment["mitigations"] = []
            continue

        mitigations = assignment.get("mitigations")
        if isinstance(mitigations, list) and KNOWN_MITIGATIONS:
            assignment["mitigations"] = [
                mitigation for mitigation in mitigations
                if mitigation in KNOWN_MITIGATIONS
            ]
        if assignment.get("technique") is None:
            assignment["mitigations"] = []

    data["assignments"] = assignments
    return json.dumps(data)


# Minimum evidence profiles for recurrent over-mappings found during blind
# testing. Each tuple contains independent requirements; every expression must
# match the quoted source evidence. This mechanism is deliberately small and
# extensible: it prevents a few semantically specific techniques from being
# inferred from generic labels without hard-coding any particular incident.
_STUDENT_V12_TECHNIQUE_EVIDENCE = {
    "T1021": (
        re.compile(
            r"\b(remote service|remote access|remote desktop|rdp|ssh|smb|"
            r"admin(?:istrative)? share|dcom|winrm|vnc)\b",
            re.IGNORECASE),
    ),
    "T1036": (
        re.compile(
            r"\b(masquerad\w*|disguis\w*|mimic\w*|spoof\w*|renam\w*|"
            r"impersonat\w*|look[- ]?alike|pretend\w*)\b",
            re.IGNORECASE),
    ),
    "T1685": (
        re.compile(
            r"\b(disabl\w*|degrad\w*|tamper\w*|kill\w*|stop\w*|"
            r"uninstall\w*|modify\w*)\b",
            re.IGNORECASE),
        re.compile(
            r"\b(defender|anti[- ]?virus|antivirus|edr|security tool|"
            r"security software|security agent|logging tool|sensor)\b",
            re.IGNORECASE),
    ),
}


def _enforce_student_v12_attack_mappings(events: list[dict]) -> None:
    """Apply v19 evidence specificity and official T->M relationships in place.

    Stage B remains probabilistic, but the accepted graph is deterministic:
    techniques with a known minimum-evidence profile abstain when that profile
    is not present, and every mitigation must be an official STIX relationship
    for the selected technique. No extra API retry is required.
    """
    for event in events:
        technique = event.get("technique")
        if not technique:
            event["mitigations"] = []
            continue

        # Sub-techniques inherit the semantic gate of their parent technique.
        parent_technique = technique.split(".", 1)[0]
        evidence = " ".join(filter(None, (
            event.get("source_evidence"),
            event.get("action_evidence"),
        )))
        requirements = _STUDENT_V12_TECHNIQUE_EVIDENCE.get(
            parent_technique, ())
        if requirements and not all(pattern.search(evidence)
                                    for pattern in requirements):
            event["technique"] = None
            event["mitigations"] = []
            continue

        allowed = set(_TECHNIQUE_MITIGATIONS.get(technique, []))
        event["mitigations"] = [
            mitigation for mitigation in event.get("mitigations", [])
            if mitigation in allowed
        ]



# ---------------------------------------------------------------------------
# providers
# ---------------------------------------------------------------------------
def _call_ollama(system: str, user: str, model: str,
                 response_model: type[BaseModel] = AttackGraph) -> str:
    """Local model through Ollama, constrained to the requested schema.

    Thinking mode is requested so a reasoning model (such as qwen3) works the
    steps out before emitting the JSON, which gives a fuller graph. Not every
    model supports it, so we fall back to a plain call if it is rejected.
    """
    import ollama
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": user}]
    schema = response_model.model_json_schema()
    try:
        resp = ollama.chat(model=model, messages=messages, format=schema,
                           think=True, options={"temperature": 0})
    except Exception:
        resp = ollama.chat(model=model, messages=messages, format=schema,
                           options={"temperature": 0})
    return resp["message"]["content"]


# --- hosted API cost guard -------------------------------------------------
# The budget uses Sonnet's standard (post-introductory) $3/$15 MTok price, not
# the temporarily cheaper launch price, so the ceiling remains conservative.
# Raised from 0.45 after a real v1.6 run on the 12k-character STOLEN PENCIL
# report was stopped at a worst case of $0.496, before Stage B had been sent.
# The old figure was calibrated on report length, which is the wrong variable:
# the report is small, but the graph it yields has 47 nodes, and Stage B's
# prompt carries a tactic-scoped candidate list for every event. Cost tracks
# GRAPH SIZE far more than input length. 0.90 covers a graph of that size plus
# one Stage B retry, and remains a real ceiling rather than a removed one.
_MAX_GENERATION_COST_USD = 0.90
_MAX_GENERATION_CALLS = 5
# Shape observations from the last professional run. They are not errors: the
# graph is valid and is returned. They record that it came out thinner than the
# rules prefer, which the layout quality report and the write-up both want.
# What the student was told about their own identifiers: which were rejected,
# which MITRE does not connect to the technique they chose, and which steps
# they left for the tool to answer. Separate from the shape notes because the
# audience is different: these are feedback on the student's mapping, not on
# the pipeline's behaviour.
_LAST_STUDENT_NOTES: ContextVar[tuple[str, ...]] = ContextVar(
    "last_student_notes", default=())


def get_last_student_notes() -> tuple[str, ...]:
    """Feedback on the identifiers the student supplied, for the results page."""

    return _LAST_STUDENT_NOTES.get()


# What the drawn graph claims, in ordinary sentences. Separate from the notes
# because it is not a problem report: a student reads it to check the graph
# against what they meant, which is the evaluation route's own question asked
# of the person who wrote the input.
_LAST_GRAPH_RESTATEMENT: ContextVar[tuple[str, ...]] = ContextVar(
    "last_graph_restatement", default=())


def get_last_graph_restatement() -> tuple[str, ...]:
    """A plain-English reading of the graph, for the results page."""

    return _LAST_GRAPH_RESTATEMENT.get()


_LAST_SHAPE_NOTES: ContextVar[tuple[str, ...]] = ContextVar(
    "attack_graph_last_shape_notes", default=())

# Nodes removed to save an otherwise-complete skeleton. Never silent: the
# caller reports them, and the write-up needs them.
_LAST_SALVAGED_NODES: ContextVar[tuple[str, ...]] = ContextVar(
    "attack_graph_last_salvaged_nodes", default=())


_LAST_SHAPE_MEASURE: ContextVar[dict | None] = ContextVar(
    "attack_graph_last_shape_measure", default=None)


def get_last_shape_measure() -> dict | None:
    """Structural facts about the skeleton the last run accepted."""

    return _LAST_SHAPE_MEASURE.get()


def get_last_salvaged_nodes() -> tuple[str, ...]:
    """Ids dropped from the last run to keep the connected remainder."""

    return _LAST_SALVAGED_NODES.get()



def get_last_shape_notes() -> tuple[str, ...]:
    """Shape preferences the last returned graph did not meet."""

    return _LAST_SHAPE_NOTES.get()


_LAST_API_USAGE: ContextVar[dict | None] = ContextVar(
    "last_attack_graph_api_usage", default=None)


def _model_prices_per_million(model: str) -> tuple[float, float]:
    """Return conservative input/output USD prices per million tokens."""
    name = model.lower()
    if "haiku" in name:
        return 1.0, 5.0
    if "sonnet" in name:
        return 3.0, 15.0
    if "opus" in name:
        return 5.0, 25.0
    if "fable" in name or "mythos" in name:
        return 10.0, 50.0
    # Unknown future models are treated as premium rather than under-priced.
    return 10.0, 50.0


def _configured_max_cost_usd() -> float:
    """Return the per-generation ceiling, overridable for a larger report.

    The default covers a report yielding a graph of roughly fifty nodes,
    including one Stage B retry. A larger graph legitimately costs more, and
    the guard should then be raised on purpose and on the record rather than
    removed. An unreadable or non-positive value falls back to the default
    instead of disabling the guard.
    """

    raw = os.environ.get("ATTACK_GRAPH_MAX_COST_USD", "").strip()
    if not raw:
        return _MAX_GENERATION_COST_USD
    try:
        value = float(raw)
    except ValueError:
        return _MAX_GENERATION_COST_USD
    return value if value > 0 else _MAX_GENERATION_COST_USD


class _AnthropicCostBudget:
    """Per-generation budget shared by all Stage A/B calls and retries."""

    def __init__(self, max_usd: float | None = None,
                 max_calls: int = _MAX_GENERATION_CALLS):
        self.max_usd = _configured_max_cost_usd() if max_usd is None else max_usd
        self.max_calls = max_calls
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.estimated_cost_usd = 0.0
        _LAST_API_USAGE.set(self.summary())

    @staticmethod
    def _cost(model: str, input_tokens: int, output_tokens: int) -> float:
        input_price, output_price = _model_prices_per_million(model)
        return ((input_tokens * input_price) +
                (output_tokens * output_price)) / 1_000_000

    def preflight(self, model: str, input_tokens: int,
                  max_output_tokens: int) -> None:
        if self.calls >= self.max_calls:
            raise RuntimeError(
                f"API cost guard stopped the generation after {self.calls} calls; "
                f"the per-image limit is US${self.max_usd:.2f}.")
        worst_case = self.estimated_cost_usd + self._cost(
            model, input_tokens, max_output_tokens)
        if worst_case > self.max_usd:
            raise RuntimeError(
                "API cost guard stopped the next model call before it was sent: "
                f"its conservative worst-case total would be US${worst_case:.3f}, "
                f"above the US${self.max_usd:.2f} per-image limit.")

    def commit(self, model: str, input_tokens: int,
               output_tokens: int) -> None:
        self.calls += 1
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.estimated_cost_usd += self._cost(
            model, input_tokens, output_tokens)
        _LAST_API_USAGE.set(self.summary())

    def summary(self) -> dict:
        return {
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "limit_usd": self.max_usd,
        }


def get_last_api_usage() -> dict | None:
    """Return conservative usage for the current request/thread context."""
    return _LAST_API_USAGE.get()


def _call_anthropic(system: str, user: str, model: str,
                    response_model: type[BaseModel] = AttackGraph,
                    budget: _AnthropicCostBudget | None = None) -> str:
    """Claude API extraction with server-enforced structured output.

    The SDK's ``messages.parse`` path sends the Pydantic schema as a JSON output
    format and returns an already validated model. This is deliberately used
    instead of an ordinary forced tool call: non-strict tools may legally return
    an empty input object even when the local model has required fields.
    """
    import anthropic
    # Disable SDK-level retries: every submitted request must be visible to the
    # application cost guard. A failed request is reported rather than silently
    # resubmitted by the HTTP client.
    client = anthropic.Anthropic(max_retries=0, timeout=_REQUEST_TIMEOUT_S)
    max_output_tokens = (
        _SMALL_RESPONSE_TOKENS if response_model in _ASSIGNMENT_MODELS
        else _graph_response_tokens())
    system_text = (
        system
        + "\n\nReturn only the requested structured result. The response must "
          "satisfy the supplied JSON schema."
    )
    messages = [{"role": "user", "content": user}]
    request_kwargs = dict(
        model=model,
        max_tokens=max_output_tokens,
        system=system_text,
        messages=messages,
        output_format=response_model,
        thinking={"type": "disabled"},
    )
    if budget is not None:
        try:
            counted = client.messages.count_tokens(
                model=model,
                system=system_text,
                messages=messages,
                output_format=response_model,
                thinking={"type": "disabled"},
            )
            input_tokens = counted.input_tokens
        except Exception as exc:
            # Authentication/credit errors should remain explicit. For older SDKs
            # that lack token counting, use a deliberately conservative fallback.
            if "count_tokens" not in str(exc).lower() and not isinstance(
                    exc, AttributeError):
                raise
            payload_chars = (
                len(system_text)
                + len(user)
                + len(json.dumps(
                    response_model.model_json_schema(),
                    ensure_ascii=False,
                ))
            )
            input_tokens = payload_chars  # at most one token per character
        budget.preflight(model, input_tokens, max_output_tokens)
    # One submitted request means one deliberate cost decision. Do not catch an
    # arbitrary API/billing/rate error and silently submit a second request.
    try:
        msg = client.messages.parse(**request_kwargs)
    except Exception:
        if budget is not None:
            # A response that fails the structured-output schema was still
            # generated and billed, but the SDK raises before any usage is
            # returned. Charging the guard the worst case that preflight had
            # already approved keeps a correction attempt from spending an
            # uncounted call. Over-counting is the safe direction here.
            budget.commit(model, input_tokens, max_output_tokens)
        raise
    if budget is not None:
        usage = msg.usage
        billed_input = (
            getattr(usage, "input_tokens", 0) +
            getattr(usage, "cache_creation_input_tokens", 0) +
            getattr(usage, "cache_read_input_tokens", 0))
        budget.commit(model, billed_input,
                      getattr(usage, "output_tokens", 0))
    # stop_reason was consulted only when parsing FAILED. A response cut off
    # at the token limit can still parse: the wire schema asks for at least one
    # event, so a graph whose events array was truncated to one satisfies it.
    # That arrived as "the events array is missing 22 events", which asks the
    # model to send everything again -- and it truncates again. Truncation is
    # not a structural fault and must not be corrected as one.
    if getattr(msg, "stop_reason", None) == "max_tokens":
        raise _TruncatedResponse(
            f"the model ran out of output space after {max_output_tokens} "
            "tokens, so the answer is incomplete rather than wrong. Raise "
            f"{_GRAPH_TOKENS_ENV} above {max_output_tokens}, or use a report "
            "that yields a smaller graph. Asking again with the same limit "
            "will truncate again.")
    parsed = getattr(msg, "parsed_output", None)
    if isinstance(parsed, BaseModel):
        return parsed.model_dump_json()
    if parsed is not None:
        return json.dumps(parsed)

    # Do not fall back to unvalidated text or an empty object. A refusal,
    # truncation, or incompatible model must fail here, before a second paid
    # semantic/TM call can be made.
    raise RuntimeError(
        "model returned no validated structured result "
        f"(stop_reason={msg.stop_reason}); content block types were "
        f"{[getattr(b, 'type', '?') for b in msg.content]}"
    )


_PROVIDERS = {"ollama": _call_ollama, "anthropic": _call_anthropic}

_DEFAULT_MODELS = {"ollama": "qwen3:8b", "anthropic": "claude-sonnet-5"}


def resolve_model(provider: str, model: str | None = None) -> str:
    """Return the actual model id used for extraction and output provenance."""
    if provider not in _DEFAULT_MODELS:
        raise ValueError(
            f"unknown provider {provider!r}; choose from {list(_DEFAULT_MODELS)}")
    return model or _DEFAULT_MODELS[provider]


STAGE_A_PROMPT_MARKERS = (
    "Do NOT choose technique or mitigation ids yet",
    "Stage B assigns them",
)


def _is_stage_a_prompt(user: str) -> bool:
    """Does this prompt ask for a skeleton rather than a finished graph?

    Compared on normalised whitespace. The prompts are hard-wrapped, so a
    marker can fall across a line break: v1.6's Stage A prompt says the words
    but wraps between "ids" and "yet", and the mock therefore never recognised
    it and answered every v1.6 skeleton request with a complete graph. The same
    line-break trap has now caught two comparisons in this project, so no
    prose match here is done on the raw text.
    """

    flattened = " ".join(user.split())
    return any(" ".join(marker.split()) in flattened
               for marker in STAGE_A_PROMPT_MARKERS)


def _call_mock(system: str, user: str, model: str,
               response_model: type[BaseModel] = AttackGraph) -> str:
    """Offline stand-in for a model, so the pipeline can run with no setup.

    It returns a fixed, valid graph. Use it only to check that ingestion,
    validation, and rendering are wired together; it does not read the report.
    For the two-stage path it is stage-aware: Stage A returns a tactic-only
    skeleton and Stage B returns the short id-to-T/M assignment list.
    """
    from pathlib import Path
    canned = Path(__file__).resolve().parent.parent / "examples" / "mock_extraction.json"
    full = json.loads(canned.read_text(encoding="utf-8"))
    if response_model in {
        IncidentSemanticDraft, IncidentSemanticDraftWire
    }:
        report = user.split("REPORT:\n", 1)[-1].strip()
        quote = report or "Mock report text."
        return json.dumps({
            "title": "Mock semantic incident",
            "evidence": [{
                "id": "ev_reported_action",
                "quote": quote,
                "status": "reported",
            }],
            "nodes": [
                {
                    "id": "p_initial",
                    "label": "Initial target state",
                    "role": "state",
                    "shape": "ellipse",
                    "evidence_id": "ev_reported_action",
                    "evidence_status": "reported",
                    "page": 1,
                    "branch": "main",
                },
                {
                    "id": "e_reported_action",
                    "label": "Exploit the exposed target service",
                    "role": "event",
                    "shape": "rectangle",
                    "evidence_id": "ev_reported_action",
                    "evidence_status": "reported",
                    "page": 1,
                    "branch": "main",
                    "tactic": "IA",
                    "likelihood": 7.0,
                },
                {
                    "id": "p_result",
                    "label": "Initial access obtained",
                    "role": "state",
                    "shape": "ellipse",
                    "evidence_id": "ev_reported_action",
                    "evidence_status": "derived",
                    "page": 1,
                    "branch": "main",
                },
            ],
            "edges": [
                {
                    "source": "p_initial",
                    "target": "e_reported_action",
                    "relation": "causal",
                    "style": "solid",
                    "logic": None,
                },
                {
                    "source": "e_reported_action",
                    "target": "p_result",
                    "relation": "causal",
                    "style": "solid",
                    "logic": None,
                },
            ],
            "pages": [{
                "page": 1,
                "title": "Mock incident",
                "entry_nodes": ["p_initial"],
                "exit_nodes": ["p_result"],
                "rank_groups": [],
            }],
        })
    if response_model in {
        TechniqueAssignments, TechniqueAssignmentsWire
    }:
        if "e_reported_action" in user:
            return json.dumps({"assignments": [{
                "id": "e_reported_action",
                "technique": "T1190",
                "mitigations": ["M1051"],
            }]})
        return json.dumps({"assignments": [
            {"id": event["id"], "technique": event["technique"],
             "mitigations": event.get("mitigations", [])}
            for event in full.get("events", [])
        ]})
    if response_model in {
        EvidenceTechniqueAssignments, EvidenceTechniqueAssignmentsWire
    }:
        return json.dumps({"assignments": [
            {"id": event["id"], "technique": event.get("technique"),
             "mitigations": event.get("mitigations", [])}
            for event in full.get("events", [])
        ]})
    if response_model in {
        ConstructTechniqueAssignments, ConstructTechniqueAssignmentsWire
    }:
        # v1.6 asks for a list of techniques per action and derives the
        # mitigations itself from the ATT&CK data, so the mock supplies
        # techniques only.
        #
        # Without this branch the mock fell through to the finished graph
        # below, which is not an assignment list, so every offline v1.6 run
        # died in Stage B. The offline provider therefore could not exercise
        # the one rule set the project actually uses, and the failure was
        # invisible for as long as the interface offered v1.4 by default.
        return json.dumps({"assignments": [
            {"id": event["id"], "techniques": [event["technique"]]}
            for event in full.get("events", [])
            if event.get("technique")
        ]})
    # Stage A prompt asks not to choose technique ids yet; detect it and strip
    # techniques/mitigations so the mock mimics a tactic-only skeleton.
    #
    # This reads the prompt's prose to decide which stage it is looking at, so
    # every Stage A prompt's wording is load-bearing: rewording the student
    # prompt once silently turned this off, and the mock answered a Stage A
    # request with a finished graph. Naming the markers does not remove the
    # coupling, but it makes it visible and lets a test assert every Stage A
    # prompt still carries one.
    if _is_stage_a_prompt(user):
        skel = json.loads(json.dumps(full))
        if "student" in user.casefold():
            # The maintained mock predates the teaching rule that every event
            # produces an ellipse result. Add only the missing terminal result
            # to the mock skeleton; professional v1.4 mock output is unchanged.
            produced = {
                event_id
                for precondition in skel.get("preconditions", [])
                for event_id in precondition.get("parents", [])
            }
            for event in skel.get("events", []):
                if event["id"] not in produced:
                    skel.setdefault("preconditions", []).append({
                        "id": f"result_{event['id']}",
                        "label": "Incident impact achieved",
                        "code": event.get("tactic", "IM"),
                        "parents": [event["id"]],
                    })
        evidence = "Mock report text."
        for marker in ("REPORT:\n", "NARRATIVE:\n"):
            if marker in user:
                report_block = user.split(marker, 1)[1]
                report_block = report_block.split(
                    "\n\nYour previous answer", 1)[0].strip()
                if report_block:
                    evidence = report_block[:240]
                break
        mock_actions = {
            "e_exploit": "exploited",
            "e_propagate": "spread",
            "e_encrypt": "encrypted",
        }
        for e in skel.get("events", []):
            e.pop("technique", None)
            e.pop("mitigations", None)
            if "source_evidence" in user:
                e["source_evidence"] = evidence
                e["evidence_status"] = "reported"
                e["evidence_confidence"] = 85
                e["actor"] = "adversary"
                e["action_evidence"] = mock_actions.get(e["id"], "attacked")
                if e["id"] == "e_propagate":
                    e["label"] = "Spread to other unpatched hosts"
        return json.dumps(skel)
    return json.dumps(full)


_PROVIDERS["mock"] = _call_mock
_DEFAULT_MODELS["mock"] = "none"

# Stage A failures that describe the *shape* of the returned graph. The model
# can repair these, so they receive the structural correction rather than the
# generic one. Two sources produce them with different wording: this module's
# own gate, and schema.py's contract. Routing on a shared fragment, in one
# named place, is what stops a rewording on either side from silently
# disconnecting the correction, which has already happened twice.
# Mirrors Precondition._max_ten_words in schema.py. Named here so the Stage A
# gate and the canonical contract cannot drift apart.
_MAX_LABEL_WORDS = 10

# Above this many disconnected pieces the graph is fragmented rather than
# merely missing a few links, and the fragmentation message is the one the
# model can act on.
_MAX_NAMED_STRAYS = 5

_STRUCTURAL_FAULT_MARKERS = (
    "unique",                      # both sources; Pydantic says "globally unique"
    "array is missing",            # gate: truncated events/preconditions
    "references unknown parent",   # both sources
    "as a parent",                 # gate: wrong-direction link
    "must consume preconditions",  # schema.py contract
    "must be produced by events",  # schema.py contract
    "consume no precondition",     # gate: event consumes nothing
    "contains a cycle",            # gate
    "disconnected pieces",         # gate: uniformly fragmented
    "detached from the attack",    # gate: one graph plus a few orphans
    "will not fit inside an ellipse",  # gate: over-long precondition label
    "empty or only whitespace",    # gate: blank id/label/code
    "no step follows from another",  # gate: flat fan
)


def is_structural_stage_a_fault(message: str) -> bool:
    """Does this Stage A failure describe a repairable graph shape?"""

    return any(marker in message for marker in _STRUCTURAL_FAULT_MARKERS)


# The remaining Stage A corrections were selected by inline substring tests
# written at the call site, which is how "must be unique" once failed to match
# "must be globally unique" and silently disabled a targeted correction. Naming
# each one puts the markers next to the message that produces them and lets a
# test assert, for every real producer, that the intended correction fires.

_EMPTY_GRAPH_MARKERS = (
    "no events",     # extract.py stage A gate and the merged-graph check
    "too_short",     # Pydantic: minItems on the events array
)

_VERBATIM_FAULT_MARKERS = (
    "not a verbatim extract",   # _stage_a_evidence_problems
)

_GROUNDED_ACTION_MARKERS = (
    "label does not contain the grounded action",   # student v1.1+
)

_STUDENT_IDENTIFIER_COVERAGE_MARKERS = (
    "student identifier coverage missing from stage a events",
)


def is_empty_graph_fault(message: str) -> bool:
    """Did Stage A return no events at all?"""

    lowered = message.lower()
    return any(marker in lowered for marker in _EMPTY_GRAPH_MARKERS)


def is_verbatim_evidence_fault(message: str) -> bool:
    """Did an event quote the report inexactly?"""

    lowered = message.lower()
    return any(marker in lowered for marker in _VERBATIM_FAULT_MARKERS)


def is_grounded_action_fault(message: str) -> bool:
    """Did an event label drift from the action its evidence names?"""

    lowered = message.lower()
    return any(marker in lowered for marker in _GROUNDED_ACTION_MARKERS)


def is_student_identifier_coverage_fault(message: str) -> bool:
    """Did Student Stage A silently drop identifiers from the submission?"""

    lowered = message.lower()
    return any(marker in lowered
               for marker in _STUDENT_IDENTIFIER_COVERAGE_MARKERS)


# Routed separately from the structural faults on purpose. The structural
# correction forbids deleting a node, and the repair for a mixed join is to
# merge two states into one -- so sending this fault there would hand the model
# two instructions that contradict each other.
_MIXED_JOIN_MARKERS = ("is marked or but consumes",)


def is_mixed_join_fault(message: str) -> bool:
    """Did one event's join try to be conjunctive and disjunctive at once?"""

    lowered = message.lower()
    return any(marker in lowered for marker in _MIXED_JOIN_MARKERS)


# A skeleton is discarded only when what survives is not a graph. Anything else
# is a worse outcome than the model produced.
_SALVAGE_MIN_SHARE = 0.85


def salvage_largest_component(data: dict) -> tuple[dict, tuple[str, ...]]:
    """Drop nodes that hang off the graph, keeping the connected remainder.

    A real v1.6 run returned forty-eight nodes, forty-six of which formed one
    connected graph; the other two were an event and the state it produced,
    which nothing consumed. The whole answer was discarded, and with it two
    paid calls, because of that fringe.

    A detached node contributes nothing to the causal structure -- that is what
    "detached" means -- so removing it costs the graph nothing it was using,
    while discarding the answer costs everything. This runs only after the
    correction attempt has been spent, and only when the surviving component is
    at least ``_SALVAGE_MIN_SHARE`` of the nodes: below that the model did not
    produce a graph with a fringe, it produced fragments, and no honest repair
    exists. Whatever is dropped is returned so the caller can report it.
    """

    preconditions = list(data.get("preconditions") or [])
    events = list(data.get("events") or [])
    causal = [p for p in preconditions if p.get("role") != "annotation"]
    graph = nx.Graph()
    graph.add_nodes_from(item["id"] for item in causal if item.get("id"))
    graph.add_nodes_from(item["id"] for item in events if item.get("id"))
    for item in causal + events:
        for parent in item.get("parents") or []:
            if parent in graph and item.get("id") in graph:
                graph.add_edge(parent, item["id"])
    if graph.number_of_nodes() == 0:
        return data, ()

    components = sorted(nx.connected_components(graph), key=len, reverse=True)
    keep = components[0]
    if len(keep) < _SALVAGE_MIN_SHARE * graph.number_of_nodes():
        return data, ()

    dropped = tuple(sorted(
        node for node in graph.nodes if node not in keep))
    if not dropped:
        return data, ()

    # An annotation survives with the step it comments on, and is cut with it.
    kept_events = [e for e in events if e.get("id") in keep]
    kept_event_ids = {e["id"] for e in kept_events}
    kept_preconditions = [
        p for p in preconditions
        if (p.get("id") in keep)
        or (p.get("role") == "annotation"
            and all(parent in kept_event_ids for parent in p.get("parents") or []))
    ]
    pruned = {
        **data,
        "preconditions": [
            {**p, "parents": [q for q in (p.get("parents") or [])
                              if q in kept_event_ids]}
            for p in kept_preconditions
        ],
        "events": [
            {**e, "parents": [q for q in (e.get("parents") or [])
                              if any(p.get("id") == q for p in kept_preconditions)]}
            for e in kept_events
        ],
    }
    return pruned, dropped


# A skeleton can satisfy every structural rule and still be an implausible
# reading of the report. Validity is "no cycles, no dangling ids, one connected
# graph"; plausibility is "does this dependency structure match what the report
# says". Only the first was ever checked, and the gap between them is where two
# opposite failures lived: 23 of 23 events strung on one path, and every event
# starting from nothing.
#
# The threshold is on the share of events lying on the single longest
# dependency path. Measured on three real runs: the chain that prompted this
# was 100%, a healthy v1.6 run was 41%, the v1.4 baseline was 92%.
_MAX_CRITICAL_PATH_SHARE = 0.70

# Below this many events the measure means little: a four-step attack that is
# genuinely sequential is 100% and entirely correct.
_MIN_EVENTS_FOR_SHAPE_REVIEW = 8

# States an event established that nothing ever consumes. The supervisor's
# reference graph has none at all; this schema ends on a state rather than an
# action, so at least the final objective is always one, and a report may
# genuinely record two or three separate outcomes. Measured: the supervisor
# fixture 0, a healthy Stolen Pencil run 1, the WannaCry blind run 3 (business
# impact, ransom C2, recovery denied -- all genuine endings), and the run that
# prompted this 9, of which six were recovered credentials the report says were
# used. The threshold sits above the largest correct reading observed and below
# the incorrect one. The request it triggers lets the model answer that they are
# endings and change nothing, so firing on a correct graph costs little.
_MAX_UNUSED_STATES = 3


def measure_skeleton_shape(data: dict) -> dict:
    """Structural facts about a Stage A skeleton, before any technique exists."""

    events = [e for e in data.get("events") or [] if e.get("id")]
    causal = [p for p in data.get("preconditions") or []
              if p.get("id") and p.get("role") != "annotation"]
    graph = nx.DiGraph()
    graph.add_nodes_from(item["id"] for item in causal + events)
    for item in causal + events:
        for parent in item.get("parents") or []:
            if parent in graph:
                graph.add_edge(parent, item["id"])
    event_ids = {e["id"] for e in events}
    if not event_ids or not nx.is_directed_acyclic_graph(graph):
        return {"events": len(event_ids), "on_critical_path": 0,
                "critical_path_share": 0.0, "ranks": 0, "widest": 0,
                "path_event_ids": (), "unused_states": 0,
                "unused_state_ids": ()}

    # A state an event established that no event ever consumes. The final
    # objective is legitimately one of these; a pile of them means branches
    # were produced and then abandoned.
    consumed = {parent for e in events for parent in (e.get("parents") or [])}
    unused = tuple(
        p["id"] for p in causal
        if (p.get("parents") or []) and p["id"] not in consumed
    )
    longest = nx.dag_longest_path(graph)
    on_path = [n for n in longest if n in event_ids]
    levels: dict[str, int] = {}
    for node in nx.topological_sort(graph):
        levels[node] = max(
            [levels[p] + 1 for p in graph.predecessors(node)], default=0)
    widths: dict[int, int] = {}
    for level in levels.values():
        widths[level] = widths.get(level, 0) + 1
    return {
        "events": len(event_ids),
        "on_critical_path": len(on_path),
        "critical_path_share": len(on_path) / len(event_ids),
        "ranks": max(levels.values()) + 1 if levels else 0,
        "widest": max(widths.values()) if widths else 0,
        "path_event_ids": tuple(on_path),
        "unused_states": len(unused),
        "unused_state_ids": unused,
    }


def _critical_path_observation(shape: dict) -> str:
    """Too much of the graph claims to depend on the step before it."""

    if shape["critical_path_share"] <= _MAX_CRITICAL_PATH_SHARE:
        return ""
    ids = ", ".join(shape["path_event_ids"][:8])
    more = ", ..." if len(shape["path_event_ids"]) > 8 else ""
    return (
        f"Of your {shape['events']} events, {shape['on_critical_path']} lie on "
        "a single dependency path, so nearly every step is claimed to require "
        f"the one before it. That path begins: {ids}{more}.\n\n"
        "For each consecutive pair on it, apply the test: if the earlier step "
        "had NOT happened, could the later one still have occurred? Where it "
        "could, the two are not linked; give the later event the earlier "
        "SHARED state it did require instead. Where the earlier step genuinely "
        "enabled the later one, leave the link alone.")


def _unused_state_observation(shape: dict, ids_shown: int = 8) -> str:
    """Branches were produced and then abandoned."""

    if shape["unused_states"] <= _MAX_UNUSED_STATES:
        return ""
    ids = ", ".join(shape["unused_state_ids"][:ids_shown])
    more = ", ..." if len(shape["unused_state_ids"]) > ids_shown else ""
    return (
        f"{shape['unused_states']} of your states are established by an event "
        f"and then consumed by nothing: {ids}{more}.\n\n"
        "For each one, ask the report: does it say what the adversary did with "
        "this next? Where it does, give that later event this state as a "
        "parent. Where the report treats it as an outcome the attack was for, "
        "or simply never returns to it, leave it as it is -- an attack has "
        "endings, and inventing a consumer for one is worse than leaving it "
        "unconsumed.")


def _same_nodes_apart_from_parents(before: dict, after: dict) -> bool:
    """Did the revision change anything the request told it to leave alone?

    The request permits exactly one edit: a parents list. Everything else --
    which nodes exist, their ids, labels, tactics, likelihoods, roles and
    styles -- must survive untouched. Comparing each node with its parents
    removed states that requirement rather than restating it in prose, which
    is the difference between a rule and a constraint.
    """

    def fingerprint(graph: dict) -> dict[str, tuple]:
        nodes = {}
        for key in ("events", "preconditions"):
            for node in graph.get(key) or []:
                nodes[node.get("id")] = tuple(sorted(
                    (field, json.dumps(value, sort_keys=True))
                    for field, value in node.items()
                    if field != "parents"
                ))
        return nodes

    return fingerprint(before) == fingerprint(after)


def shape_revision_request(shape: dict) -> str:
    """Ask about the report, never about a target shape.

    The measurement is the evidence; the instruction is the same dependency
    test the rules give. Saying "make it wider" would be describing a shape,
    which is what produced both of the failures this exists to catch.

    Width is deliberately not measured here. A rank is wide when several steps
    depended on nothing but a shared earlier state, which is what the
    counterfactual test is supposed to produce; asking the model to narrow it
    would contradict the test in the paragraph above and re-create the chain.
    Width is a page-size problem and is solved by pagination.
    """

    if shape["events"] < _MIN_EVENTS_FOR_SHAPE_REVIEW:
        return ""
    observations = [
        text for text in (
            _critical_path_observation(shape),
            _unused_state_observation(shape),
        ) if text
    ]
    if not observations:
        return ""
    return "\n\n".join(observations) + (
        "\n\nChange only parents lists. Keep every event, precondition, id, "
        "label, tactic, likelihood, role and style exactly as they are.")


def _mixed_join_problems(data: dict) -> list[str]:
    """An OR that is really an AND with alternatives hidden inside it.

    A join sits on the event, so one event has one logic for all its inputs.
    That is enough only while every input plays the same part. A British
    Library run produced a remote login needing a credential obtained EITHER by
    phishing OR by brute force, AND a reachable server, AND a missing MFA
    control, and marked the whole thing OR. Read literally, the graph then
    claims the missing control alone was enough to log in. Marking it AND would
    have claimed the adversary had to phish and brute-force both. Neither value
    is right, so this is not a wrong choice by the model -- it is a shape that
    cannot be written this way at all.

    It can be written the other way. Logical attack graphs (MulVAL; Ou et al.
    2005) put conjunction on the action and disjunction on the state: an action
    needs all of its inputs, a state is established by any of its producers. So
    alternatives belong in a SHARED STATE that each alternative produces, and
    the consuming event is AND. Rule 3 now says this; this gate is what makes
    it a constraint rather than a sentence.

    The test is mechanical. A state with no producer is an initial condition of
    the incident: it is not an alternative to anything, because nothing in the
    graph could have produced it instead. An OR event that consumes one is
    therefore mixing "either of these routes" with "and this had to be true",
    which is exactly the case above. Measured over five real runs, this
    separates the one wrong graph from six correct ORs.
    """

    events = data.get("events") or []
    preconditions = data.get("preconditions") or []
    roots = {
        node.get("id") for node in preconditions
        if not (node.get("parents") or [])
    }
    labels = {node.get("id"): node.get("label") for node in preconditions}
    problems: list[str] = []
    for event in events:
        if event.get("join") != "OR":
            continue
        required = [
            parent for parent in (event.get("parents") or [])
            if parent in roots
        ]
        if not required or len(event.get("parents") or []) < 2:
            continue
        named = ", ".join(f"{labels.get(p) or p!r}" for p in required[:3])
        problems.append(
            f"event {event.get('id')!r} is marked OR but consumes "
            f"{len(required)} initial condition(s) that nothing in the graph "
            f"produces: {named}. OR says any one input alone would do, so this "
            "claims the attack needed none of the others. An initial condition "
            "is not an alternative to anything. Set this event's join to AND, "
            "and where two of its inputs really were substitutable routes, "
            "merge them into ONE state that both of those events produce and "
            "let this event consume that single state."
        )
    return problems[:4]


def _annotation_problems(data: dict) -> list[str]:
    """Check the one rule annotations are still bound by: what they attach to.

    Annotations are stripped before the causal checks, and correctly so: an
    annotation is consumed by nothing, which connectivity would read as a
    dangling state, and it must never create a rank or lengthen a path.

    Stripping them removed them from the node-kind check as well, which is not
    a causal rule but a shape-of-the-graph rule that binds every node. Rule 6.2
    says an annotation's parent is "the step it comments on" -- a step, so an
    event. A run of the STOLEN PENCIL report attached "No evidence of data
    theft" to a state instead, passed Stage A, and failed inside Stage B, where
    only technique and mitigation identifiers come back and nothing can be
    relinked. The graph was lost after both calls had been paid for.
    """

    event_ids = {item.get("id") for item in data.get("events") or []}
    precondition_ids = {
        item.get("id") for item in data.get("preconditions") or []
    }
    annotations = [
        node for node in data.get("preconditions") or []
        if node.get("role") == "annotation"
    ]
    annotation_ids = {node.get("id") for node in annotations}
    problems: list[str] = []

    # Uniqueness is checked on the causal graph, which annotations are absent
    # from, so an annotation sharing an id with an event was invisible until
    # Stage B. Found by writing one violation per schema rule and asking which
    # stage caught it, rather than by waiting for the next failed run.
    seen: dict[str, int] = {}
    for node in (data.get("events") or []) + (data.get("preconditions") or []):
        seen[node.get("id")] = seen.get(node.get("id"), 0) + 1
    for node in annotations:
        if seen.get(node.get("id"), 0) > 1:
            problems.append(
                f"annotation {node.get('id')!r} reuses the id of another "
                "node. Every id in the graph must be unique, annotations "
                "included; give it its own id")

    # The gate reported this as a missing state, which invited the model to
    # invent one. The rule is that an annotation is never consumed at all.
    for event in data.get("events") or []:
        for parent in event.get("parents") or []:
            if parent in annotation_ids:
                problems.append(
                    f"event {event.get('id')!r} consumes annotation "
                    f"{parent!r}; an annotation is commentary beside a step, "
                    "never part of the attack path. Give this event the state "
                    "it actually needed, and leave the annotation hanging off "
                    "the step it remarks on")

    for node in annotations:
        for parent in node.get("parents") or []:
            if parent in event_ids:
                continue
            if parent in precondition_ids:
                problems.append(
                    f"annotation {node.get('id')!r} lists state {parent!r} "
                    "as a parent; an annotation comments on a step, so its "
                    "parent must be the event it remarks on, not a state. "
                    "Point it at that event, or drop the annotation if the "
                    "report does not tie the remark to a step")
            else:
                problems.append(
                    f"annotation {node.get('id')!r} lists {parent!r} as a "
                    "parent, and no node has that id. Point it at the event "
                    "it comments on")
    return problems[:6]


def _skeleton_graph_problems(
    data: dict,
    *,
    require_event_parents: bool = True,
) -> list[str]:
    """Report Stage A id, parent-reference, acyclicity and shape faults.

    ``AttackGraphSkeleton`` mirrors the API's JSON schema, and a JSON schema
    can express neither referential integrity nor acyclicity. Checking them
    here rather than letting the merged graph fail during Stage B keeps the
    correction with the stage that is able to make it: Stage B returns only
    technique and mitigation identifiers, so it can never add, rename, relink,
    or reorder a node.

    ``require_event_parents`` is disabled for the evidence-first rule set,
    whose Rule 8 declines to invent a precondition the report does not state,
    so a root event is legitimate there. The connectivity and chaining checks
    still apply, and between them they reject a graph of isolated pairs.
    """

    preconditions = [
        item for item in (data.get("preconditions") or [])
        if isinstance(item, dict)
    ]
    events = [
        item for item in (data.get("events") or []) if isinstance(item, dict)
    ]
    precondition_ids = {item.get("id") for item in preconditions}
    event_ids = {item.get("id") for item in events}
    problems: list[str] = []

    all_ids = [item.get("id") for item in (*preconditions, *events)]
    duplicates = sorted({
        value for value in all_ids if all_ids.count(value) > 1
    })
    if duplicates:
        problems.append(
            "every precondition and event id must be unique, but these are "
            f"used more than once: {', '.join(duplicates)}")

    # Dangling references are grouped by the id that is missing rather than
    # reported once per reference. A truncated events array otherwise produces
    # one near-identical complaint per precondition, which reads as "the
    # preconditions are wrong" and invites the model to delete their parents
    # instead of returning the events it left out.
    missing_events: set[str] = set()
    missing_preconditions: set[str] = set()
    wrong_direction: list[str] = []

    for event in events:
        for parent in event.get("parents") or []:
            if parent in precondition_ids:
                continue
            if parent in event_ids:
                wrong_direction.append(
                    f"event {event.get('id')!r} lists event {parent!r} as a "
                    "parent; an event consumes preconditions, so add the state "
                    "that event establishes and reference that state instead")
            else:
                missing_preconditions.add(str(parent))

    for precondition in preconditions:
        for parent in precondition.get("parents") or []:
            if parent in event_ids:
                continue
            if parent in precondition_ids:
                wrong_direction.append(
                    f"precondition {precondition.get('id')!r} lists "
                    f"precondition {parent!r} as a parent; a precondition is "
                    "established by an event, so reference that event instead")
            else:
                missing_events.add(str(parent))

    if missing_events:
        listed = ", ".join(sorted(missing_events))
        problems.append(
            f"the events array is missing {len(missing_events)} event(s) that "
            f"the preconditions already refer to: {listed}. You returned "
            f"{len(events)} event(s). Return every attack step you identified, "
            "under exactly those ids, instead of leaving them out of the "
            "events array")
    if missing_preconditions:
        listed = ", ".join(sorted(missing_preconditions))
        problems.append(
            f"the preconditions array is missing {len(missing_preconditions)} "
            f"state(s) that the events already refer to: {listed}. Return "
            "every state you identified, under exactly those ids")
    problems.extend(wrong_direction[:6])

    # Rule 2 of the professional rule set defines an event as consuming one or
    # more preconditions and producing a new one. An event with an empty
    # parents list is therefore not a step, and a whole graph of them collapses
    # into isolated event/result pairs with no attack path between them. This
    # is also the cheapest way for a model to satisfy a "no invalid reference"
    # correction, so it has to be rejected explicitly.
    parentless = [
        str(event.get("id")) for event in events
        if not (event.get("parents") or [])
    ]
    if parentless and require_event_parents:
        problems.append(
            f"these events consume no precondition: {', '.join(parentless)}. "
            "Every event must list at least one precondition id in its "
            "parents: the state it needed before it could happen. Give each "
            "of these the state it actually consumed")

    if problems:
        # The parent links are already inconsistent, so an acyclicity result
        # computed from them would not be meaningful.
        return problems

    digraph = nx.DiGraph()
    digraph.add_nodes_from(precondition_ids | event_ids)
    for item in (*preconditions, *events):
        for parent in item.get("parents") or []:
            digraph.add_edge(parent, item.get("id"))
    if not nx.is_directed_acyclic_graph(digraph):
        loop = " -> ".join(
            str(source) for source, _ in nx.find_cycle(digraph)
        )
        problems.append(
            f"the graph contains a cycle ({loop}); an attack graph must flow "
            "forward only, so break the loop by removing the link that points "
            "back to an earlier step")
        return problems

    # Rule 4 of the professional rule set requires every path to converge on
    # one final objective, so a report about a single incident yields a single
    # connected graph. Giving each event its own private root satisfies every
    # check above yet still produces one isolated pair per event, which the
    # deterministic paginator can only lay out as one page each.
    components = sorted(
        (sorted(component) for component in
         nx.weakly_connected_components(digraph)),
        key=lambda component: component[0],
    )
    if len(components) > 1:
        # Diagnose by shape. Two very different faults both arrive here, and a
        # correction written for one cannot repair the other. Naming the wrong
        # one wastes the single permitted Stage A retry, which is the whole
        # budget for repairing a paid answer.
        main = max(components, key=len)
        strays = sorted(
            (node for component in components if component is not main
             for node in component))
        stray_components = [c for c in components if c is not main]
        largest_stray = max((len(c) for c in stray_components), default=0)
        # Size ratio alone picks the wrong branch. A graph of twenty-four
        # isolated event/result pairs plus one real component satisfies
        # "the main component is much larger than any single stray", yet it is
        # not a few strays hanging off a good graph -- it is a flat fan, and
        # naming forty-nine ids tells the model nothing it can act on. The
        # COUNT of pieces is what separates the two faults.
        if len(stray_components) <= _MAX_NAMED_STRAYS and (
                len(main) >= 3 * largest_stray):
            # One real graph plus a few nodes hanging off nothing. Listing the
            # main component here would bury the answer in dozens of ids the
            # model got right; only the strays need to move.
            problems.append(
                f"{len(strays)} node(s) are detached from the attack graph: "
                f"{', '.join(strays)}. Every other node forms one connected "
                f"graph of {len(main)}. Do not restructure that graph. For "
                "each detached node either give it a result state that a "
                "later event consumes, or make it consume a state an earlier "
                "event establishes, so it joins the attack path. Drop it only "
                "if the report does not support it. A root event with no "
                "parents is fine, but what it produces must be used")
        else:
            # A generic "join them into a single path" did not work: the
            # model returned the same fan on the retry. The correction now
            # names the model's own ids and states the exact edit, because an
            # instruction that has to be interpreted before it can be applied
            # is one more thing that can go wrong on the only retry available.
            rootless = [
                event.get("id") for event in events
                if not (event.get("parents") or [])
            ]
            produced = [
                item.get("id") for item in preconditions if item.get("parents")
            ]
            example = ""
            unlinked = rootless or [
                event.get("id") for event in events
                if not any(parent in produced
                           for parent in (event.get("parents") or []))
            ]
            if len(unlinked) >= 2 and produced:
                example = (
                    f" Concretely: {unlinked[1]!r} is not reached from any "
                    "earlier step. Add to its parents the id of the state the "
                    f"step before it produced, for example {produced[0]!r}, "
                    "and do the same for every other event in attack order.")
            # Two shapes reach here and they need different first sentences.
            # Either the events have no parents at all, or each has its own
            # private initial state that no earlier event produced. The edit
            # is the same, but naming the wrong one loses the model's trust in
            # the rest of the instruction.
            if rootless:
                opening = (
                    f"{len(rootless)} of your {len(events)} events start from "
                    "nothing, so each stands alone with its result")
            else:
                opening = (
                    f"each of your {len(events)} events consumes only its own "
                    "private starting state, which no earlier event produced")
            problems.append(
                f"the graph falls into {len(components)} disconnected pieces: "
                f"{opening} and no attack path runs through the graph. Keep "
                "every event and every state; change only the parents lists. "
                "Put your events in the order the attack happened, then give "
                "each one the RESULT STATE of the previous event as a parent. "
                "At most two to four preparation events at the very top may "
                f"begin from an initial condition of their own.{example}")

    # Whitespace-only text passes the wire model, whose min_length=1 counts
    # characters rather than content, and is then rejected by schema.py after
    # Stage B has been paid for. Only the model can supply the missing words,
    # so this is asked rather than repaired.
    blank = [
        f"{item.get('id') or '<no id>'}.{field}"
        for group in (preconditions, events)
        for item in group
        for field in ("id", "label", "code")
        if field in item and not str(item.get(field) or "").strip()
    ]
    if blank:
        problems.append(
            f"{len(blank)} field(s) are empty or only whitespace: "
            f"{', '.join(blank[:6])}. Every id, label and code must carry "
            "real text. Fill each one in; change nothing else")

    # The ten-word limit lives in schema.py, which runs only after Stage B has
    # merged its identifiers in. By then the fault is unfixable: Stage B
    # returns technique and mitigation ids and cannot rename a node, so a
    # twelve-word label discarded two paid calls and an otherwise complete
    # graph. Checking it here puts the correction with the stage that wrote
    # the label. A JSON schema cannot express a word count, so this is the
    # earliest point it can be caught at all.
    overlong = [
        (item.get("id"), item.get("label", ""))
        for item in preconditions
        if len((item.get("label") or "").split()) > _MAX_LABEL_WORDS
    ]
    if overlong:
        listed = "; ".join(
            f"{node_id} ({len(label.split())} words): {label!r}"
            for node_id, label in overlong[:4])
        problems.append(
            f"{len(overlong)} precondition label(s) exceed "
            f"{_MAX_LABEL_WORDS} words and will not fit inside an ellipse: "
            f"{listed}. Shorten each to a state of at most "
            f"{_MAX_LABEL_WORDS} words, keeping the state itself and dropping "
            "parenthetical lists and examples. Change nothing else")

    # Rule 4 requires the shape precondition -> event -> precondition -> event.
    # If every event consumes only an initial condition, the graph is a flat
    # fan with no attack path through it. It can be connected and have every
    # reference resolve, yet the deterministic paginator still has to give
    # each event its own page because nothing follows from anything else.
    # Skipped when the graph is already reported as fragmented: both faults
    # describe the same shape, and two corrections in one message dilute each
    # other. The single Stage A retry gets one clear instruction.
    derived_state_ids = {
        item.get("id") for item in preconditions if item.get("parents")
    }
    if not problems and len(events) >= 3 and not any(
        parent in derived_state_ids
        for event in events
        for parent in (event.get("parents") or [])
    ):
        problems.append(
            "no step follows from another: every event consumes an initial "
            "condition, so nothing in the graph builds on anything else. "
            "Where the report says one step made a later one possible, let "
            "that later event consume the state the earlier one establishes. "
            "Steps the report describes as independent stay independent")
    return problems


def _structure_problems(graph: AttackGraph,
                        require_logic_gate: bool = True) -> list[str]:
    """Flag graphs that collapsed into a bare chain, so we can ask for a retry."""
    problems = []
    n_pre = len(graph.preconditions)
    n_ev = len(graph.events)
    if n_ev == 0:
        problems.append(
            "the graph has no events: the report narrates an attack (entry, "
            "movement, impact), so extract those steps as events. Model the "
            "attack the report describes; do not return an empty graph just "
            "because the report is brief or written in general terms")
        return problems                     # nothing else matters if it is empty
    if n_pre < max(2, n_ev // 2):
        problems.append(
            "too few preconditions: every attack step needs the state or "
            "resource it requires as an ellipse; add precondition nodes")
    has_multi_parent = any(len(e.parents) >= 2 for e in graph.events)
    if require_logic_gate and not has_multi_parent and n_ev >= 3:
        problems.append(
            "no AND/OR logic gate: at least one event should depend on several "
            "preconditions (AND) or offer an alternative path (OR)")
    events_producing_pre = {p.parents[0] for p in graph.preconditions if p.parents}
    if n_ev >= 3 and len(events_producing_pre) < 1:
        problems.append(
            "events do not establish preconditions: after an event, add the "
            "precondition it produces so nodes alternate")
    return problems


def _student_structure_problems(graph: AttackGraph) -> list[str]:
    """Check the sample-compatible Student graph after local normalisation."""
    problems = []
    if not graph.events:
        problems.append(
            "the student graph has no evidence-supported adversary events")
        return problems

    invalid_or = [
        event.id for event in graph.events
        if event.join == "OR" and len(event.parents) < 2
    ]
    if invalid_or:
        problems.append(
            "OR requires at least two independently sufficient parent states; "
            f"invalid OR events: {', '.join(invalid_or)}")

    digraph = build_digraph(graph)
    if digraph.number_of_nodes() and not nx.is_weakly_connected(digraph):
        components = nx.number_weakly_connected_components(digraph)
        problems.append(
            f"the student graph has {components} disconnected components; "
            "connect every supported preparation and impact branch to the main "
            "attack graph without inventing actions")
    return problems


def _normalise_student_structure(
    graph: AttackGraph,
    model: type[AttackGraph] = AttackGraph,
) -> AttackGraph:
    """Apply supervisor-sample syntax without inventing evidence or edges.

    Root and terminal rectangles are valid in the sample, so Student graphs do
    not need artificial ellipses around every event. AND/OR has no meaning for
    fewer than two inputs; that case becomes an ordinary single-line join. If a
    news report produces unrelated fragments, retain the largest event-bearing
    component instead of fabricating causal links between them.
    """
    data = graph.model_dump()
    for event in data["events"]:
        if len(event.get("parents", [])) < 2:
            event["join"] = "AND"

    # Re-validate through the caller's model. Rebuilding a student graph
    # as a plain AttackGraph silently dropped the identifiers the
    # student had written, because a plain Event does not carry them.
    normalised = model.model_validate(data)
    digraph = build_digraph(normalised)
    components = list(nx.weakly_connected_components(digraph))
    if len(components) <= 1:
        return normalised

    event_order = {
        event.id: index for index, event in enumerate(normalised.events)
    }

    def component_rank(nodes: set[str]) -> tuple[int, int, int]:
        event_ids = [node for node in nodes if node in event_order]
        first_event = min(
            (event_order[event_id] for event_id in event_ids),
            default=len(event_order),
        )
        return len(event_ids), len(nodes), -first_event

    core = max(components, key=component_rank)
    data["events"] = [
        event for event in data["events"] if event["id"] in core
    ]
    data["preconditions"] = [
        precondition for precondition in data["preconditions"]
        if precondition["id"] in core
    ]
    return AttackGraph.model_validate(data)


# ---------------------------------------------------------------------------
# extraction with validation and retry
# ---------------------------------------------------------------------------
# The single-stage path is a closed, historical set: v1 through v1.3, kept only
# so those versions still reproduce exactly. Everything else is hierarchical.
#
# The test is stated this way round on purpose. It used to be an allowlist of
# hierarchical versions, and v1.6 -- which exists only as a hierarchical rule
# set -- was not on it, so it fell through into the single-stage path. That path
# puts the entire ~700-technique catalogue into one prompt and asks for a
# complete graph in one response. The run did not fail with a clear message; it
# ran until the HTTP read timed out, which reads to the user as a network fault
# rather than a routing mistake. A rule set that nobody remembered to register
# must not be able to reach the legacy path.
#
# Exact equality, not a prefix: "v1.4".startswith("v1") is true, so a prefix
# test here would send every later version down the legacy path instead.
_SINGLE_STAGE_RULESETS = frozenset({"v1", "v1.1", "v1.2", "v1.3"})


def is_single_stage_ruleset(ruleset: str) -> bool:
    """True only for the frozen pre-v1.4 rule sets."""

    return ruleset in _SINGLE_STAGE_RULESETS


def is_construct_ruleset(ruleset: str) -> bool:
    """True for rule sets whose point is the v1.6 visual constructs.

    Defined here, beside the routing it drives, so the semantic pipeline and
    the extraction pipeline cannot disagree about which versions need external
    resources, annotations and dotted branches.
    """

    return ruleset.startswith("v1.6")


def extract_attack_graph(report_text: str, provider: str = "ollama",
                         model: str | None = None, max_attempts: int = 3,
                         ruleset: str = DEFAULT_RULESET) -> AttackGraph:
    """Extract a validated AttackGraph from report text using the chosen provider.

    The ruleset argument selects which version of the rule set governs the
    extraction, so different versions can be compared on the same report.
    """
    if provider not in _PROVIDERS:
        raise ValueError(f"unknown provider {provider!r}; choose from {list(_PROVIDERS)}")
    _LAST_API_USAGE.set(None)
    provider_call = _PROVIDERS[provider]
    model = resolve_model(provider, model)
    if provider == "anthropic":
        cost_budget = _AnthropicCostBudget()

        def call(system, user, selected_model,
                 response_model: type[BaseModel] = AttackGraph):
            return provider_call(
                system, user, selected_model, response_model,
                budget=cost_budget)
    else:
        call = provider_call

    if not is_single_stage_ruleset(ruleset):
        return _extract_hierarchical(report_text, call, model, ruleset)

    system = load_ruleset(ruleset)
    user = USER_TEMPLATE.format(report=report_text)
    last_error = None

    for attempt in range(1, max_attempts + 1):
        raw = call(system, user, model)
        raw = _sanitize(raw)
        try:
            graph = AttackGraph.model_validate_json(raw)
            build_digraph(graph)  # also enforces acyclicity
            missing_techniques = [e.id for e in graph.events if not e.technique]
            if missing_techniques:
                raise ValueError(
                    "this rule version requires one technique per event; missing "
                    f"for: {', '.join(missing_techniques)}")
            problems = _structure_problems(graph)
            if problems and attempt < max_attempts:
                raise ValueError("; ".join(problems))
            return graph
        except (ValidationError, ValueError) as e:
            last_error = e
            msg = str(e)
            if is_empty_graph_fault(msg):
                # An empty result needs a strong, front-loaded correction: the
                # directive goes BEFORE the report, where the model attends most.
                user = (
                    "IMPORTANT: your previous answer contained no attack steps. "
                    "This report DOES describe an attack. Read it for the sequence "
                    "of actions (reconnaissance, entry through a server, credential "
                    "theft, data taken, files encrypted, ransom) and extract each as "
                    "an event, even where the report is tentative or brief. Every "
                    "event needs a real technique id from the catalogue; never "
                    "return an empty graph.\n\n"
                    + USER_TEMPLATE.format(report=report_text))
            else:
                # feed the specific error back so the model can repair its output
                user = (USER_TEMPLATE.format(report=report_text) +
                        f"\n\nYour previous answer was rejected with this error:\n{e}\n"
                        f"Return a corrected object that fixes it.")

    raise RuntimeError(f"extraction failed after {max_attempts} attempts: {last_error}")


# ---------------------------------------------------------------------------
# hierarchical (two-stage) extraction, used by rule set v1.4
# ---------------------------------------------------------------------------
# Call budget per graph is fixed and small: stage A up to 2 calls (1 try + 1
# retry), one further call for the v1.6 shape review, and stage B up to 2 calls
# (1 try + 1 retry). Worst case 5 model calls, normal case 2. The budget does
# not grow with the number of steps, because each stage handles all steps in a
# single call.
_STAGE_RETRIES = 1  # v1.4 keeps one retry per stage; v1.5 is two-call-only

# The shape review used to share Stage A's retry, and so ran only when nothing
# structural had gone wrong. Measured across three real runs, that meant it
# never ran at all: every one tripped the review's own gate, every one had used
# its retry on a structural fault, and every one was saved unreviewed with 8,
# 9 and 14 states that nothing consumed. A mechanism that cannot run in the
# cases it exists for is not a budget saving.
#
# It gets its own call. It still runs at most once, still never rejects, and a
# revision that comes back worse is still discarded, so the extra call is the
# whole of the risk. The cost guard remains the ceiling: a five-call run of the
# STOLEN PENCIL report is about US$0.42 against a US$0.90 limit.
_SHAPE_REVIEW_CALLS = 1

_EVIDENCE_STATUSES = {"confirmed", "reported", "alleged", "possible"}


def _normalise_evidence_text(value: str) -> str:
    """Normalise layout and typographic variants without weakening the check.

    A quotation lifted from a PDF often differs from the report only in
    presentation: curly quotation marks against straight ones, an en or em dash
    against a hyphen, a non-breaking space against a plain one, or a change of
    case. These are the same text as far as the evidence contract is concerned,
    so they are folded to a canonical form. Content differences, a changed or
    inserted word, still fail the check, so the guard against a fabricated or
    reworded quotation is preserved.
    """
    # Fold typographic variants to a canonical ASCII form.
    replacements = {
        "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'",   # single quotes
        "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u201f": '"',   # double quotes
        "\u2013": "-", "\u2014": "-", "\u2015": "-", "\u2212": "-",   # dashes and minus
        "\u00a0": " ", "\u2007": " ", "\u202f": " ", "\u2009": " ",   # special spaces
        "\u2026": "...",                                              # ellipsis
        "\ufeff": "",                                                  # zero-width no-break space
    }
    for src, dst in replacements.items():
        value = value.replace(src, dst)
    # Collapse whitespace and compare without regard to case.
    return " ".join(value.split()).casefold()


def _stage_a_evidence_problems(events: list[dict], report_text: str) -> list[str]:
    """Return v1.5 evidence-contract violations for Stage A events."""
    problems = []
    normalised_report = _normalise_evidence_text(report_text)
    for event in events:
        event_id = event.get("id", "<missing id>")
        quote = event.get("source_evidence")
        if not isinstance(quote, str) or not quote.strip():
            problems.append(f"{event_id}: source_evidence is missing")
        elif _normalise_evidence_text(quote) not in normalised_report:
            # Echo the rejected text back. Without it the model has to guess
            # which of its quotations was wrong and how it differed, and the
            # correction becomes a second attempt at the whole extraction.
            excerpt = " ".join(quote.split())
            if len(excerpt) > 160:
                excerpt = excerpt[:157] + "..."
            problems.append(
                f"{event_id}: source_evidence is not a verbatim extract of the "
                f"supplied report. You wrote: \"{excerpt}\"")

        status = event.get("evidence_status")
        if status not in _EVIDENCE_STATUSES:
            problems.append(
                f"{event_id}: evidence_status must be one of "
                f"{sorted(_EVIDENCE_STATUSES)}")

        confidence = event.get("evidence_confidence")
        if (isinstance(confidence, bool) or not isinstance(confidence, int)
                or not 0 <= confidence <= 100):
            problems.append(
                f"{event_id}: evidence_confidence must be an integer from 0 to 100")
    return problems


_ACTION_AUXILIARIES = {
    "am", "are", "be", "been", "being", "can", "could", "did", "do",
    "does", "had", "has", "have", "is", "may", "might", "must", "shall",
    "should", "was", "were", "will", "would",
}
_ACTION_QUALIFIERS = {
    "a", "an", "alleged", "possibly", "possible", "reported",
    "suspected", "the", "to",
}
_ACTION_IRREGULAR = {
    "built": "build", "done": "do", "made": "make", "ran": "run",
    "shut": "shut", "stole": "steal", "stolen": "steal",
    "taken": "take", "took": "take",
}


def _lexical_action_words(value: str) -> list[str]:
    """Return original lexical words without destructively stemming them."""
    return [
        word
        for word in re.findall(r"[a-z]+", value.casefold())
        if word not in _ACTION_AUXILIARIES
        and word not in _ACTION_QUALIFIERS
    ]


def _regular_action_forms(base: str) -> set[str]:
    """Generate conservative English inflections for a proposed base verb."""
    forms = {base}
    if not base:
        return forms

    if base.endswith(("s", "x", "z", "ch", "sh", "o")):
        forms.add(base + "es")
    elif base.endswith("y") and len(base) > 1 and base[-2] not in "aeiou":
        forms.add(base[:-1] + "ies")
    else:
        forms.add(base + "s")

    if base.endswith("e"):
        forms.update({base + "d", base[:-1] + "ing"})
    elif base.endswith("y") and len(base) > 1 and base[-2] not in "aeiou":
        forms.update({base[:-1] + "ied", base + "ing"})
    else:
        forms.update({base + "ed", base + "ing"})
        if (len(base) >= 3 and base[-1] not in "aeiouwxy"
                and base[-2] in "aeiou" and base[-3] not in "aeiou"):
            forms.update({
                base + base[-1] + "ed",
                base + base[-1] + "ing",
            })

    forms.update(
        word for word, canonical in _ACTION_IRREGULAR.items()
        if canonical == base
    )
    return forms


def _action_words_match(left: str, right: str) -> bool:
    """Match two action words by valid inflection, never by truncated stems."""
    left = left.casefold()
    right = right.casefold()
    if left == right:
        return True
    candidate_bases = {
        left, right,
        _ACTION_IRREGULAR.get(left, left),
        _ACTION_IRREGULAR.get(right, right),
    }
    return any(
        left in _regular_action_forms(base)
        and right in _regular_action_forms(base)
        for base in candidate_bases
    )


def _label_action_words(label: str, quote: str) -> list[str]:
    """Return only words that can be the predicate of ``label``.

    Student labels should normally start with the action (for example,
    ``Access Oyster data``).  A later token is accepted only for the
    actor-leading form that Claude occasionally emits when the same
    actor-action pair occurs in the source quotation (for example,
    ``Jubair accessing ...``).  This prevents a noun modifier such as
    ``breached`` in ``Obtain breached credentials`` from being mistaken for
    the event's action.
    """
    label_words = _lexical_action_words(label)
    if not label_words:
        return []

    actions = [label_words[0]]
    quote_words = re.findall(r"[a-z]+", quote.casefold())
    for word in label_words[1:]:
        actor_action_is_quoted = any(
            quote_words[q_index] == label_words[0]
            and _action_words_match(quote_words[q_index + 1], word)
            for q_index in range(len(quote_words) - 1)
        )
        if actor_action_is_quoted:
            actions.append(word)
    return actions


def _repair_auxiliary_only_action(event: dict, quote: str) -> str:
    """Replace a bare ``was/is`` with a matching verb from the same quote.

    Claude occasionally selects only the passive auxiliary for
    ``action_evidence``. Repair is deliberately narrow: the replacement token
    must occur in the already-validated source quotation, be morphologically
    verb-like, and be a valid inflection of the event label's action.
    """
    label_actions = _label_action_words(
        str(event.get("label", "")), quote)
    words = re.findall(r"[a-z]+", quote.casefold())
    for index, word in enumerate(words):
        previous = words[index - 1] if index else ""
        verb_like = (
            previous in _ACTION_AUXILIARIES
            or previous == "to"
            or word in _ACTION_IRREGULAR
            or word.endswith(("ed", "ing"))
        )
        if (verb_like and any(
                _action_words_match(label_action, word)
                for label_action in label_actions)):
            event["action_evidence"] = word
            return word
    return ""


def _repair_label_from_grounded_action(
        event: dict, quote: str, action: str) -> bool:
    """Replace an ungrounded display label with sufficiently specific evidence.

    The label is presentation text, but it must not change the action evidenced
    by the quotation. Claude sometimes returns a related ATT&CK paraphrase
    (for example, ``Steal data`` for ``was exfiltrated``). When the exact
    ``action_evidence`` is already a descriptive phrase, use that phrase as the
    label instead of rejecting the entire graph. A passive verb without its
    subject uses the complete source quotation so the displayed event does not
    lose its object.

    A single active verb is deliberately not repaired. In that case there is
    not enough local information to distinguish a harmless synonym from an
    unsupported action such as ``Obtain credentials`` grounded only by
    ``accessed``.
    """
    action = action.strip().strip(" .;:")
    if not action:
        return False

    raw_words = re.findall(r"[a-z]+", action.casefold())
    lexical_words = _lexical_action_words(action)
    passive_without_subject = (
        raw_words
        and raw_words[0] in {"be", "been", "being", "is", "was", "were"}
        and len(lexical_words) == 1
    )
    if passive_without_subject:
        replacement = quote.strip().strip(" .;:")
    elif len(lexical_words) >= 2:
        replacement = action
    else:
        return False

    if not replacement:
        return False
    event["label"] = replacement[0].upper() + replacement[1:]
    return True


def _student_evidence_problems(events: list[dict], report_text: str) -> list[str]:
    """Return Student v1.1 source, actor, and action-grounding violations."""
    problems = _stage_a_evidence_problems(events, report_text)
    for event in events:
        event_id = event.get("id", "<missing id>")
        if event.get("actor") != "adversary":
            problems.append(
                f"{event_id}: actor must be adversary; victim, defender, "
                "investigator, and recovery actions are not attack events")

        quote = event.get("source_evidence")
        action = event.get("action_evidence")
        if not isinstance(action, str) or not action.strip():
            problems.append(f"{event_id}: action_evidence is missing")
            continue
        if (not isinstance(quote, str)
                or _normalise_evidence_text(action)
                not in _normalise_evidence_text(quote)):
            problems.append(
                f"{event_id}: action_evidence must be an exact phrase inside "
                "source_evidence")
            continue

        label_actions = _label_action_words(
            str(event.get("label", "")),
            quote if isinstance(quote, str) else "",
        )
        evidence_actions = _lexical_action_words(action)
        if not evidence_actions and isinstance(quote, str):
            repaired_action = _repair_auxiliary_only_action(event, quote)
            evidence_actions = [repaired_action] if repaired_action else []
        if not evidence_actions:
            problems.append(
                f"{event_id}: action_evidence contains no grounded action verb")
            continue
        if not any(
                _action_words_match(label_action, evidence_action)
                for label_action in label_actions
                for evidence_action in evidence_actions):
            if not _repair_label_from_grounded_action(event, quote, action):
                problems.append(
                    f"{event_id}: label does not contain the grounded action "
                    f"action_evidence {action!r}")
    return problems


def _suppressed_state_code_note(merged: dict) -> tuple[str, ...]:
    """Say when a student's state codes were dropped from the drawing.

    An ATT&CK tactic classifies adversary behaviour, so the visual syntax
    forbids one on a state and the renderer drops it. That suppression is
    correct and stays. What was missing is that nobody told the student: one
    submission labelled all nine of its states with tactic abbreviations, every
    ellipse came out with no badge at all, and the figure gave no hint that
    anything the student wrote had been left out.

    Silent correction is the failure this project keeps finding in itself. The
    code is still in the saved JSON either way; this only makes the omission
    visible where the student can act on it.
    """

    from visual_syntax import active_profile

    prohibited = active_profile().prohibited_state_badges
    affected = [
        state for state in merged.get("preconditions") or []
        if state.get("role") != "annotation"
        and state.get("code") in prohibited
    ]
    if not affected:
        return ()
    codes = sorted({state["code"] for state in affected})
    subject = ("One of your states carries a code that is an ATT&CK tactic "
               "abbreviation"
               if len(affected) == 1
               else f"{len(affected)} of your states carry codes that are "
                    "ATT&CK tactic abbreviations")
    return (
        f"{subject} ({', '.join(codes)}). A "
        "tactic describes something the attacker did, so the visual syntax "
        "does not allow one on a state, and it is not drawn on the ellipse. "
        "It is still in the saved graph. To show a code there, use a short "
        "label of your own such as P1 or R1.",
    )


def _technique_tactic_mismatches(
        events: list[dict]) -> dict[str, tuple[str, str, tuple[str, ...]]]:
    """Return event -> (chosen tactic, technique, ATT&CK tactics) conflicts."""
    mismatches = {}
    for event in events:
        tactic = event.get("tactic")
        # v1.6 events carry a list; earlier versions carry the singular key.
        # Reading both keeps one consistency check for every rule set.
        assigned = event.get("techniques") or (
            [event["technique"]] if event.get("technique") else [])
        # Only the PRIMARY technique is held to the event's tactic. Where an
        # event carries several, the extra ones classify secondary behaviours
        # of the same action and belong wherever ATT&CK puts them: the
        # reference diagram's "GREASE malware executed" spans five tactics on
        # one node. Checking every technique against one tactic would make a
        # multi-technique event impossible to express, which is the constraint
        # this version exists to remove.
        for technique in assigned[:1]:
            allowed = tuple(_TECHNIQUE_TACTICS.get(technique, []))
            if allowed and tactic not in allowed:
                mismatches[event["id"]] = (tactic, technique, allowed)
    return mismatches


def _extract_hierarchical(report_text: str, call, model: str,
                          ruleset: str) -> AttackGraph:
    """Two-stage extraction: choose tactics first, then techniques per tactic."""
    # These report on the run about to start. Stage A and Stage B both append
    # to the notes, so without a reset a second extraction in the same context
    # would inherit the first one's explanations.
    _LAST_SHAPE_NOTES.set(())
    _LAST_SALVAGED_NODES.set(())
    _LAST_STUDENT_NOTES.set(())
    _LAST_GRAPH_RESTATEMENT.set(())
    system = load_ruleset(ruleset, include_full_catalogue=False)
    evidence_mode = ruleset.startswith("v1.5")
    # v1.6 is v1.4 plus the external-resource, annotation and dotted-branch
    # constructs. It keeps v1.4's retry budget and Stage B unchanged, so the
    # two remain comparable and any difference in the output is attributable
    # to the constructs rather than to a change of mechanism.
    construct_mode = is_construct_ruleset(ruleset)
    student_mode = ruleset.startswith("student-")
    # v1.3 keeps v1.2's evidence machinery and adds the rule that the
    # student's own identifiers are kept, so it runs the same gates.
    student_v12_mode = ruleset.startswith(("student-v1.2", "student-v1.3"))
    student_evidence_mode = ruleset.startswith(
        ("student-v1.1", "student-v1.2", "student-v1.3"))
    # v1.5 is deliberately two-call-only. v1.4 and the student path may repair
    # Stage A once, leaving the third and final API call available for Stage B.
    # Allowing two Stage A retries could consume the whole three-call budget and
    # make a successful graph impossible even after Stage A recovered.
    # The evidence rule set is otherwise two-call-only. Stage A still gets one
    # correction, because a structural fault there is not recoverable later:
    # Stage B returns identifiers and cannot relink a node, so refusing the
    # retry discards the whole paid run rather than saving a call.
    stage_a_retries = _STAGE_RETRIES
    stage_b_retries = 0 if (evidence_mode or student_mode) else _STAGE_RETRIES
    if student_evidence_mode:
        stage_a_template = (STAGE_A_STUDENT_V12_USER if student_v12_mode
                            else STAGE_A_STUDENT_EVIDENCE_USER)
        stage_b_template = STAGE_B_STUDENT_EVIDENCE_USER
    elif student_mode:
        stage_a_template = STAGE_A_STUDENT_USER
        stage_b_template = STAGE_B_STUDENT_USER
    else:
        if evidence_mode:
            stage_a_template = STAGE_A_V15_USER
        elif construct_mode:
            stage_a_template = STAGE_A_V16_USER
        else:
            stage_a_template = STAGE_A_USER
        if evidence_mode:
            stage_b_template = STAGE_B_V15_USER
        elif construct_mode:
            stage_b_template = STAGE_B_V16_USER
        else:
            stage_b_template = STAGE_B_USER
    assignments_model: type[BaseModel] = EvidenceTechniqueAssignments

    # The v1.4 rule document describes the final graph, where every event has a
    # T/M mapping. Stage A deliberately precedes that mapping. State the phase
    # boundary explicitly so the model does not resolve the apparent conflict by
    # returning an empty event list.
    stage_a_system = system + """

STAGE A EXECUTION OVERRIDE
You are producing only the graph skeleton in this call. The final-rule
requirement that every event carry a technique and mitigations is deferred to
Stage B. Do not omit an adversary action merely because its T/M assignment has
not happened yet. The skeleton must contain at least one event whenever the
report describes, reports, suspects, or proposes an attacker action.

Choose the tactic from the action's primary objective. In particular, DE
(Defense Evasion) means impairing or bypassing security controls. Stopping
services, destroying or encrypting data, and inhibiting recovery are IM
(Impact), even when those actions also make investigation more difficult.
"""

    # --- stage A: skeleton with a tactic on each event, no technique ids yet ---
    student_identifier_checklist = ""
    if ruleset.startswith("student-v1.3"):
        clauses = identifier_source_clauses(report_text)
        if clauses:
            numbered = "\n".join(
                f"{index}. {clause}"
                for index, clause in enumerate(clauses, start=1)
            )
            student_identifier_checklist = (
                "\n\nMANDATORY STUDENT IDENTIFIER CHECKLIST\n"
                "The following exact source clauses contain ATT&CK identifiers "
                "the student supplied. Before returning JSON, verify that every "
                "clause which states an adversary action has its own event, that "
                "the event copies the clause into source_evidence, and that all "
                "T/M identifiers from that clause are copied into stated_technique "
                "and stated_mitigations. Do not omit a listed action and do not "
                "move its identifiers to another event.\n"
                + numbered
            )
    user_a = (stage_a_template.format(report=report_text)
              + student_identifier_checklist)
    skeleton = None
    last_error = None
    last_answer = None
    last_data = None
    attempts_used = 0
    stage_a_model: type[BaseModel]
    if student_evidence_mode:
        # The wire model goes to the provider; StudentEvidenceGraph still
        # validates the answer locally, so nothing the contract rejects is
        # accepted.
        stage_a_model = StudentEvidenceGraphWire
    elif evidence_mode:
        stage_a_model = EvidenceGraphWire
    elif construct_mode:
        stage_a_model = ConstructAttackGraphSkeleton
    else:
        stage_a_model = AttackGraphSkeleton
    for attempt in range(stage_a_retries + 1):
        try:
            # The call sits inside the retry guard. With a structured output
            # schema the SDK validates the response before returning it, so a
            # schema violation such as an empty events array is raised here
            # and can be corrected, rather than escaping as a hard failure.
            raw = _sanitize(call(stage_a_system, user_a, model, stage_a_model))
            last_answer = raw
            data = json.loads(raw)
            last_data = data
            attempts_used = attempt + 1
            events = data.get("events", [])
            if not events:
                raise ValueError("stage A returned no events; extract the attack "
                                 "steps the report describes, each with a tactic")
            for e in events:
                if e.get("tactic") not in ATTACK_TACTICS:
                    raise ValueError(
                        f"event {e.get('id')} has tactic {e.get('tactic')!r}; "
                        f"use one of the 14 tactic abbreviations")
            if evidence_mode:
                evidence_problems = _stage_a_evidence_problems(events, report_text)
                if evidence_problems:
                    raise ValueError("; ".join(evidence_problems))
                # Run the structural gate before the Pydantic contract. Both
                # detect a duplicate or dangling id, but the model can only act
                # on a message that names the offending ids, and the gate also
                # sees the faults the contract cannot: a graph of isolated
                # event/result pairs resolves every reference yet lays out as
                # one page per event.
                skeleton_problems = _skeleton_graph_problems(
                    data,
                    require_event_parents=False,
                )
                if skeleton_problems:
                    raise ValueError("; ".join(skeleton_problems))
                # Validate the complete skeleton here so malformed evidence-era
                # graphs are repaired before any ATT&CK identifiers are added.
                AttackGraph.model_validate(data)
            elif student_evidence_mode:
                student_graph = _normalise_student_structure(
                    StudentEvidenceGraph.model_validate(data),
                    StudentEvidenceGraph)
                data = student_graph.model_dump(exclude_none=True)
                events = data["events"]
                # Student v1.3 promises to preserve the mapping the student
                # wrote.  A graph can be structurally perfect yet omit a whole
                # source paragraph and its identifiers (real run 17 did this
                # with T1486/M1040/M1053).  Check this before Stage B, while the
                # one structural correction can still restore the missing
                # event.  This is deliberately Student-only: professional
                # rule sets ask the model to derive identifiers instead.
                identifier_problems = identifier_coverage_problems(
                    events, report_text)
                if identifier_problems:
                    raise ValueError("; ".join(identifier_problems))
                evidence_problems = _student_evidence_problems(
                    events, report_text)
                if evidence_problems:
                    raise ValueError("; ".join(evidence_problems))
                # The two checks that bind every rule set, not just v1.6.
                # Neither changes the visual language a student is taught; both
                # catch a fault that would otherwise surface inside Stage B,
                # where only technique identifiers come back and nothing can be
                # relinked. See _annotation_problems and _mixed_join_problems.
                contract_problems = (_annotation_problems(data)
                                     + _mixed_join_problems(data))
                if contract_problems:
                    raise ValueError("; ".join(contract_problems))
                structure_problems = _student_structure_problems(student_graph)
                if structure_problems:
                    raise ValueError("; ".join(structure_problems))
            elif student_mode:
                student_graph = _normalise_student_structure(
                    AttackGraph.model_validate(data))
                data = student_graph.model_dump(exclude_none=True)
                contract_problems = (_annotation_problems(data)
                                     + _mixed_join_problems(data))
                if contract_problems:
                    raise ValueError("; ".join(contract_problems))
                structure_problems = _student_structure_problems(student_graph)
                if structure_problems:
                    raise ValueError("; ".join(structure_problems))
            elif construct_mode:
                # Repair a role/style disagreement locally, then hold the
                # result to the canonical contract, which is what the renderer
                # and every downstream check actually rely on.
                data = _normalise_constructs(data)
                data = ConstructAttackGraphSkeleton.model_validate(
                    data).model_dump(exclude_none=True)
                # Annotations sit beside the attack rather than in it, so the
                # structural gate must not see them: an annotation is consumed
                # by nothing, which the causal checks would read as a dangling
                # state. Strip them for the gate only, then keep the full graph.
                causal = {
                    **data,
                    "preconditions": [
                        node for node in data["preconditions"]
                        if node.get("role") != "annotation"
                    ],
                }
                # Annotation problems lead. The causal gate cannot see an
                # annotation, so when an event consumes one it reports a
                # missing state and invites the model to invent it; the
                # precise instruction has to be the one read first.
                skeleton_problems = (
                    _annotation_problems(data)
                    + _mixed_join_problems(data)
                    + _skeleton_graph_problems(
                        causal,
                        require_event_parents=False,
                    )
                )
                if skeleton_problems:
                    raise ValueError("; ".join(skeleton_problems))
                skeleton = data
                break
            else:
                # This is more than a post-hoc empty-list check: the same
                # minItems=1 requirement is present in Claude's tool schema.
                data = AttackGraphSkeleton.model_validate(data).model_dump(
                    exclude_none=True)
                # A root event is legitimate: the reference sample opens with
                # four of them. Connectivity and chaining still reject a graph
                # of isolated event/result pairs.
                skeleton_problems = _skeleton_graph_problems(
                    data,
                    require_event_parents=False,
                )
                if skeleton_problems:
                    raise ValueError("; ".join(skeleton_problems))
            skeleton = data
            break
        except (json.JSONDecodeError, ValidationError, ValueError,
                TypeError, AttributeError) as ex:
            last_error = ex
            correction = ""
            if is_empty_graph_fault(str(ex)):
                if student_evidence_mode:
                    correction = (
                        "IMPORTANT: your previous answer contained no events. "
                        "Evidence-first does not mean empty. Extract the explicit "
                        "high-level adversary actions even when the technical "
                        "method is not reported. Phrases such as 'the pair "
                        "compromised the network', 'the network was infiltrated', "
                        "'Jubair accessing TfL systems', and 'data was accessed' "
                        "are action evidence. Use their exact quotations, keep "
                        "labels equally general, and do not invent credentials, "
                        "exploits, or service-stop actions. Victim password resets, "
                        "customer delays, system unavailability, and financial "
                        "loss are result states. Create a neutral source-supported "
                        "initial state for the first event. Return at least one "
                        "event; uncertainty about its ATT&CK technique will be "
                        "handled by a null technique in Stage B.\n\n")
                else:
                    correction = (
                        "IMPORTANT: your previous answer contained no events, but "
                        "this report describes a cyber attack and you must extract "
                        "its steps. Read the report for adversary actions and return "
                        "one event for each. An uncertain, suspected, probable, or "
                        "reported action is still an event: hedged wording such as "
                        "'possibly phishing' or 'suspected reconnaissance' names an "
                        "action and must become an event. Typical steps to look for "
                        "are reconnaissance, initial access, credential attack, "
                        "discovery, lateral movement, defence evasion, collection, "
                        "exfiltration, encryption or destruction, and extortion. "
                        "Never return an empty events array for a report that "
                        "describes an attack.\n\n")
            elif (student_evidence_mode
                  and is_student_identifier_coverage_fault(str(ex))):
                correction = (
                    "IMPORTANT: the previous Student skeleton silently omitted "
                    "one or more source-supported steps carrying identifiers "
                    "that the student explicitly wrote. Preserve every existing "
                    "node. For each missing T-number named below, find the exact "
                    "sentence that contains it and add or repair the corresponding "
                    "adversary event. Copy that sentence exactly into "
                    "source_evidence, copy its action phrase into action_evidence, "
                    "put the T-number in stated_technique, and put the M-numbers "
                    "from the same sentence in stated_mitigations. Include the "
                    "direct result states explicitly described by the submission. "
                    "Do not move an identifier onto an unrelated existing event, "
                    "and do not invent an action merely to consume a number. Return "
                    "the complete corrected graph.\n\n")
            elif is_verbatim_evidence_fault(str(ex)):
                correction = (
                    "IMPORTANT: each source_evidence must be copied out of the "
                    "report character for character. Locate the sentence in "
                    "the report and copy it exactly: do not tidy punctuation, "
                    "do not shorten it, do not join two sentences that are not "
                    "adjacent, and do not restate it in your own words. Keep "
                    "the quotation to one sentence, or at most two adjacent "
                    "sentences. If no single contiguous passage supports an "
                    "action, remove that event rather than supplying an "
                    "approximate quotation: an action the report does not "
                    "state in one place is not evidence-backed. Leave every "
                    "other event unchanged.\n\n")
            elif is_mixed_join_fault(str(ex)):
                correction = (
                    "IMPORTANT: your previous answer identified the attack "
                    "correctly, but one event's join says something you did "
                    "not mean. A join covers every input of that event at "
                    "once, so OR claims each input alone would have been "
                    "enough. Fix only the events named below. Set the join to "
                    "AND, because an initial condition is required whichever "
                    "route the adversary took. Where two of that event's "
                    "inputs really were substitutable routes to the same "
                    "thing, merge those two states into ONE state that lists "
                    "both producing events as its parents, and let this event "
                    "consume that single state: an action needs all of its "
                    "inputs, a state is established by any of its producers. "
                    "That merge is the only node you may remove. Leave every "
                    "other event, state, id, label, tactic, likelihood, role "
                    "and style exactly as they are.\n\n")
            elif is_structural_stage_a_fault(str(ex)):
                correction = (
                    "IMPORTANT: your previous answer identified the attack "
                    "correctly but returned an inconsistent graph. Return the "
                    "COMPLETE graph this time. Emit one entry in the events "
                    "array for every attack step you name anywhere in the "
                    "answer, and one entry in the preconditions array for "
                    "every state you name; an id referenced in a parents list "
                    "must also exist as a node. Do not delete a node, and do "
                    "not empty a parents list, to make the error go away: an "
                    "attack step that vanishes is not a repair, and an event "
                    "that consumes nothing is not a valid step. You may merge "
                    "two events into one where the report describes them as a "
                    "single action, such as one tool run or one command; the "
                    "merged event then consumes what both consumed, produces "
                    "one state, and carries both sets of techniques. Every "
                    "other node you already found stays. List only "
                    "precondition ids in an event's parents, and only "
                    "event ids in a "
                    "precondition's parents. The graph must hold together as "
                    "one connected structure, with no fragment standing on "
                    "its own. Branches are expected: several events may "
                    "consume the same state, and one event may require "
                    "several states. Join a stray node by giving it the "
                    "precondition it actually consumes, not by putting it in "
                    "a line behind an unrelated step.\n\n")
            elif (student_evidence_mode
                  and is_grounded_action_fault(str(ex))):
                correction = (
                    "IMPORTANT: preserve every source-supported event from your "
                    "previous answer. Do not return an empty events array and do "
                    "not remove an event merely to fix its label. For each listed "
                    "event, rewrite only the label so that its first action verb "
                    "is the same lexical action as action_evidence; do not use a "
                    "synonym or a related ATT&CK action. Keep the exact quotation, "
                    "action_evidence, actor, parents, outcomes, and uncertainty "
                    "unless they independently violate the rules.\n\n")
            # Send the previous answer back with the correction. Every
            # call is stateless, so without it the model cannot see what
            # it returned, and a correction phrased as "keep every event,
            # change only the parents lists" asks for something it has no
            # way to do. It regenerated from the report instead, which is
            # a re-roll rather than a repair, and the same fault came back
            # run after run.
            if last_answer:
                user_a = (
                    correction
                    + "Here is the JSON you returned last time:\n\n"
                    + last_answer
                    + f"\n\nIt has this problem:\n{ex}\n\n"
                    "Edit that JSON to fix exactly this problem and return "
                    "the whole corrected object. Keep every id, label, "
                    "tactic, likelihood, role and style you already chose, "
                    "unless the problem above is about that field. Do not "
                    "start again from the report, and do not drop nodes to "
                    "make the problem go away.\n\nThe report is repeated "
                    "below for reference only.\n\n"
                    + stage_a_template.format(report=report_text)
                    + student_identifier_checklist)
            else:
                user_a = (
                    correction
                    + stage_a_template.format(report=report_text)
                    + student_identifier_checklist
                    + f"\n\nYour previous answer had this problem:\n{ex}\n"
                    "Return corrected JSON with one or more events.")
    if skeleton is None and last_data is not None and not (
            evidence_mode or student_mode):
        # The correction has been spent. Before discarding a paid answer,
        # see whether what came back is a graph with a fringe rather than
        # fragments. Only the professional paths salvage: the evidence and
        # student rule sets make claims about completeness that quietly
        # removing a node would falsify.
        candidate, dropped = salvage_largest_component(
            _normalise_constructs(last_data) if construct_mode
            else last_data)
        if dropped and not _skeleton_graph_problems(
                candidate, require_event_parents=False):
            try:
                model_cls = (ConstructAttackGraphSkeleton if construct_mode
                             else AttackGraphSkeleton)
                skeleton = model_cls.model_validate(candidate).model_dump(
                    exclude_none=True)
                _LAST_SALVAGED_NODES.set(dropped)
            except ValidationError:
                skeleton = None
    if skeleton is None:
        raise RuntimeError(f"stage A failed: {last_error}")

    # --- shape review -----------------------------------------------
    # The skeleton is valid. Validity is not plausibility: a graph can
    # satisfy every structural rule and still string every step of the
    # attack onto one dependency path, which asserts that each one
    # required the last. Measuring that and asking about it is the one
    # thing a human reviewer does that this pipeline never did.
    #
    # It runs at most once, it never rejects, and a revision that comes
    # back worse is discarded. Losing a paid, valid graph to a
    # presentational preference would be the wrong trade in every case.
    #
    # It has its own call rather than sharing Stage A's retry. Sharing meant a
    # graph that had needed structural repair got no review, and structural
    # repair turned out to be the common case, not the exception: see
    # _SHAPE_REVIEW_CALLS for the measurements that settled it.
    if construct_mode and _SHAPE_REVIEW_CALLS:
        shape = measure_skeleton_shape(skeleton)
        request = shape_revision_request(shape)
        if request:
            try:
                revised_raw = _sanitize(call(
                    stage_a_system,
                    request
                    + "\n\nHere is the JSON you returned:\n\n"
                    + json.dumps(skeleton, indent=2)
                    + "\n\nReturn the whole corrected object.",
                    model, stage_a_model))
                revised = _normalise_constructs(json.loads(revised_raw))
                revised = ConstructAttackGraphSkeleton.model_validate(
                    revised).model_dump(exclude_none=True)
                causal = {
                    **revised,
                    "preconditions": [
                        node for node in revised["preconditions"]
                        if node.get("role") != "annotation"
                    ],
                }
                revised_shape = measure_skeleton_shape(revised)
                # The request says "change only parents lists". Only events
                # were ever checked, so a revision could invent a state -- and
                # one did: asked to connect five abandoned credential results,
                # a run added a new "Wide array of credentials scavenged" node
                # with no parents of its own, leaving the five abandoned and
                # the new node floating.
                kept_every_node = _same_nodes_apart_from_parents(
                    skeleton, revised)
                # Accepting only on critical-path share made the unused-state
                # observation unable to take effect: a revision that connected
                # loose ends without shortening the longest path was discarded
                # silently, so the gate could fire forever and change nothing.
                improved = (
                    revised_shape["critical_path_share"]
                    < shape["critical_path_share"]
                    or revised_shape["unused_states"] < shape["unused_states"])
                not_worse = (
                    revised_shape["critical_path_share"]
                    <= shape["critical_path_share"]
                    and revised_shape["unused_states"]
                    <= shape["unused_states"])
                if (not _skeleton_graph_problems(
                        causal, require_event_parents=False)
                        and not _annotation_problems(revised)
                        and not _mixed_join_problems(revised)
                        and kept_every_node
                        and improved and not_worse):
                    skeleton = revised
                    shape = revised_shape
                elif not kept_every_node:
                    _LAST_SHAPE_NOTES.set(get_last_shape_notes() + (
                        "the shape review was answered with a different set "
                        "of nodes than it was given, so the answer was "
                        "discarded and the original graph kept",))
            except (json.JSONDecodeError, ValidationError, ValueError,
                    TypeError, AttributeError, _TruncatedResponse,
                    RuntimeError):
                # The graph in hand is valid. A failed improvement is not
                # a reason to lose it.
                pass
        _LAST_SHAPE_MEASURE.set(shape)

    # ``wire_model`` is the schema the API sees; ``assignments_model`` is the
    # schema the application trusts. They differ wherever the strict model
    # carries a rule a JSON Schema cannot express.
    wire_model: type[BaseModel] = assignments_model
    if evidence_mode:
        wire_model = EvidenceTechniqueAssignmentsWire
    if not (evidence_mode or student_evidence_mode):
        # A flat assignment list is used rather than a per-tactic Union schema.
        # The Union form, with one Literal-constrained branch per tactic, is hard
        # for the model to fill on a graph that spans many tactics: it tends to
        # repeat one assignment across every branch, which fails validation in
        # bulk. The tactic each technique must belong to is instead enforced by
        # the consistency check after the assignments are merged, so correctness
        # is kept while the schema the model sees stays simple.
        assignments_model = TechniqueAssignments
        # Anthropic downgrades a regex ``pattern`` to a description but enforces
        # a Literal enum as a hard constraint. Sending the vocabulary built from
        # the installed catalogue means an identifier the current ATT&CK release
        # has renumbered, such as the retired T1070.001, cannot be returned at
        # all, rather than being rejected only after the call has been paid for.
        wire_model = TechniqueAssignmentsWire
        if construct_mode:
            assignments_model = ConstructTechniqueAssignments
            wire_model = ConstructTechniqueAssignmentsWire

    # --- build per-tactic candidate lists for the tactics actually used --------
    used_tactics = sorted({e["tactic"] for e in skeleton["events"]})
    candidate_blocks = []
    for tac in used_tactics:
        lines = _tech_lines_for_tactic(tac)
        candidate_blocks.append(
            f"Techniques allowed for tactic {tac} "
            f"({ATTACK_TACTICS[tac]}):\n{lines}")
    candidates = "\n\n".join(candidate_blocks)

    # --- stage B: assign T/M values without re-emitting the graph --------------
    # Stage A's graph is deliberately kept in Python. Earlier versions asked the
    # model to reproduce the whole graph after choosing T/M values, which let a
    # long graph collapse to zero events during Stage B. Stage B now returns a
    # short id -> T/M mapping only; the preserved skeleton is then merged and
    # validated locally.
    skeleton_events_json = json.dumps(skeleton["events"], indent=2)
    n_events = len(skeleton["events"])
    event_ids = ", ".join(e["id"] for e in skeleton["events"])
    user_b = stage_b_template.format(
        events=skeleton_events_json, n_events=n_events,
        event_ids=event_ids, candidates=candidates, miti_lines=_MITI_LINES)
    last_error = None
    for attempt in range(stage_b_retries + 1):
        try:
            # The model call sits inside the retry guard. When a structured
            # output schema is supplied the SDK validates the response before
            # returning it, so a schema violation is raised here rather than at
            # the local validation below. Leaving the call outside the guard
            # turned a recoverable, correctable answer into a hard failure.
            raw = call(system, user_b, model, wire_model)
            if student_evidence_mode:
                raw = _sanitize_student_v19_assignments(raw)
            assignments = assignments_model.model_validate_json(raw).assignments
            assignment_ids = [assignment.id for assignment in assignments]
            expected_ids = [event["id"] for event in skeleton["events"]]
            if len(assignments) != n_events:
                raise ValueError(
                    f"stage B returned {len(assignments)} assignments but the skeleton "
                    f"has {n_events} events. Return one assignment for each id: "
                    f"{event_ids}.")
            if len(set(assignment_ids)) != n_events or set(assignment_ids) != set(expected_ids):
                raise ValueError(
                    "stage B assignments must contain every Stage A event id exactly "
                    f"once. Expected: {event_ids}. Returned: {', '.join(assignment_ids)}")

            by_id = {assignment.id: assignment for assignment in assignments}
            # Keep Stage B's answer separately for Student feedback. The
            # evidence gate below may correctly abstain and blank the badge;
            # that must not also erase the candidate the student was meant to
            # review. This side channel is Student-only and never changes the
            # accepted graph or the professional pipeline.
            student_stage_b_suggestions = {
                assignment.id: assignment.technique
                for assignment in assignments
            } if student_mode else {}
            merged = json.loads(json.dumps(skeleton))
            # The student did the ATT&CK mapping before writing. Where they
            # gave an identifier for a step, it is theirs; Stage B's answer for
            # that step is discarded rather than allowed to overrule it. Where
            # they gave none, Stage B answers and the student is told which
            # steps that was.
            student_identifiers, identifier_notes = ({}, [])
            if student_mode:
                read_identifiers_from_text(merged["events"], report_text)
                student_identifiers, identifier_notes = classify_identifiers(
                    merged["events"], _TECHNIQUE_MITIGATIONS)
            for event in merged["events"]:
                assignment = by_id[event["id"]]
                stated = student_identifiers.get(event["id"])
                if stated is not None and stated.technique:
                    event["technique"] = stated.technique
                    event["mitigations"] = list(stated.mitigations)
                    event.pop("stated_technique", None)
                    event.pop("stated_mitigations", None)
                    continue
                if construct_mode:
                    event["techniques"] = list(assignment.techniques)
                else:
                    event["technique"] = assignment.technique
                if construct_mode:
                    # Union, order preserved: a mitigation that counters two of
                    # the action's techniques is still one mitigation.
                    seen, ordered = set(), []
                    for technique in assignment.techniques:
                        for mitigation in _TECHNIQUE_MITIGATIONS.get(
                                technique, ()):
                            if mitigation not in seen:
                                seen.add(mitigation)
                                ordered.append(mitigation)
                    event["mitigations"] = ordered
                elif evidence_mode or student_mode:
                    event["mitigations"] = assignment.mitigations
                else:
                    # Rule 2 asks for "mitigation ids that specifically counter
                    # that technique" and Rule 5 repeats the requirement. MITRE
                    # already states which mitigations counter which technique
                    # as a STIX "mitigates" relationship, and the local
                    # catalogue carries it. Deriving the list is therefore both
                    # a faithful reading of the frozen rules and free: asking
                    # the model instead produced identifiers that were valid in
                    # isolation but had no relationship to the chosen
                    # technique. A technique MITRE lists no mitigation for
                    # correctly yields an empty list rather than an invented
                    # one.
                    event["mitigations"] = list(
                        _TECHNIQUE_MITIGATIONS.get(assignment.technique, ()))

            for event in merged["events"]:
                event.pop("stated_technique", None)
                event.pop("stated_mitigations", None)
            if student_v12_mode:
                # Only the steps the student left open. Their own choices have
                # already been kept above, and an evidence gate that blanked
                # one would be judging the student's curation with the
                # student's own text.
                _enforce_student_v12_attack_mappings([
                    event for event in merged["events"]
                    if not (student_identifiers.get(event["id"])
                            and student_identifiers[event["id"]].technique)
                ])
            # Student path only: these notes are written for someone who typed
            # the narrative, and nothing on the professional path reads them.
            suppressed_state_codes = (
                _suppressed_state_code_note(merged) if student_mode else ())
            if identifier_notes or suppressed_state_codes:
                lines = list(summarise(identifier_notes))
                lines.extend(suppressed_state_codes)
                # For every step the student left open, name a few candidates
                # and say why those. The list Stage B chose from is the list
                # they are shown; a second one assembled for display would be
                # a different answer wearing the same clothes.
                for event in merged["events"]:
                    accepted = student_identifiers.get(event["id"])
                    if accepted is not None and accepted.technique:
                        continue
                    shortlist = technique_shortlist(
                        event.get("label", ""),
                        " ".join(filter(None, (event.get("source_evidence"),
                                               event.get("action_evidence")))),
                        event.get("tactic", ""),
                        _tech_lines_for_tactic(event.get("tactic", "")),
                        suggested=student_stage_b_suggestions.get(
                            event.get("id", "")),
                    )
                    if shortlist:
                        lines.append(f"{event.get('label')}:")
                        lines.extend(f"  {line}" for line in shortlist)
                _LAST_STUDENT_NOTES.set(tuple(lines))

            mismatches = _technique_tactic_mismatches(merged["events"])
            # Reconciliation is a last resort, so it is reached only on the
            # final attempt and only after a correction attempt has been spent.
            # The two-call student path allows no retry and never reconciles.
            #
            # Settling an unambiguous mismatch immediately looks like a free
            # saving -- the catalogue names one tactic, so no call is needed to
            # learn it -- and it was tried. It costs more than it saves. A
            # tactic mismatch is often the symptom of a WRONG TECHNIQUE, not of
            # a wrong tactic: told that T1589.001 does not fit Credential
            # Access, the model returned T1110 Brute Force, which is what
            # "repeatedly guessed the password" actually describes. Rewriting
            # the tactic to Reconnaissance instead would have kept the wrong
            # technique and made the graph agree with itself about it. The
            # model gets its chance first; the catalogue settles only what is
            # left. v1.5 declines the retry, so it never reaches this at all.
            can_reconcile = (
                mismatches and attempt == stage_b_retries and attempt > 0
            )
            if can_reconcile:
                # Stage A commits to a tactic before any technique is known, so
                # its choice is a fourteen-way guess, whereas the catalogue's
                # technique-to-tactic mapping is a fact. Each mismatch is now
                # settled on its own: an earlier version required every one of
                # them to be unambiguous, so a single technique belonging to
                # several tactics discarded a whole graph whose other conflicts
                # the catalogue could have resolved outright.
                for event in merged["events"]:
                    if event["id"] not in mismatches:
                        continue
                    _, technique, allowed = mismatches[event["id"]]
                    if len(allowed) == 1:
                        # The catalogue names exactly one tactic, so it is a
                        # fact rather than a guess. Adopt it.
                        event["tactic"] = allowed[0]
                    else:
                        # The technique spans several tactics and none of them
                        # is the one Stage A chose, so nothing here can settle
                        # it without guessing. Withhold the badge rather than
                        # invent a tactic or discard the whole extraction; the
                        # action, its evidence and its place in the graph all
                        # survive with an empty technique corner.
                        #
                        # Clear whichever key this rule set uses. Writing only
                        # the singular one left a v1.6 event's `techniques`
                        # list untouched, so the mismatch survived the repair,
                        # the loop reported it unfixed, and a graph v1.4 would
                        # have recovered was discarded after both paid calls.
                        if "techniques" in event:
                            event["techniques"] = []
                        else:
                            event["technique"] = None
                        event["mitigations"] = []
                mismatches = _technique_tactic_mismatches(merged["events"])
            if mismatches:
                details = "; ".join(
                    f"{event_id}: technique {technique} belongs to "
                    f"{list(allowed)}, not tactic {tactic}"
                    for event_id, (tactic, technique, allowed)
                    in mismatches.items())
                raise ValueError(
                    "some techniques do not match their event's tactic; either "
                    "choose a technique from that tactic's candidate list or, "
                    "if Stage A classified the action incorrectly, repeat the "
                    "same unambiguous technique so its canonical ATT&CK tactic "
                    f"can be used. {details}")

            # Event validation enforces that every technique belongs to the
            # event's tactic. A mismatch raises here and is passed to the Stage
            # B correction attempt below.
            graph = AttackGraph.model_validate(merged)
            build_digraph(graph)
            problems = (_student_structure_problems(graph) if student_mode else
                        _structure_problems(
                            graph, require_logic_gate=not evidence_mode))
            # Every problem this reports is a property of the SKELETON: too few
            # preconditions, no AND/OR gate, events that establish nothing.
            # Stage B returns {id, techniques}. It cannot add a parent, add a
            # precondition, or open an alternative path, so retrying it here
            # bought a second paid call that could not change the answer and
            # then accepted the graph anyway. The finding is kept -- it is a
            # real quality signal and belongs in the layout report -- but it no
            # longer triggers a retry that has nothing to act on.
            #
            # The student and evidence paths keep the raise: their Stage B
            # returns evidence fields as well, so the answer can genuinely
            # differ on a second attempt.
            if problems and (evidence_mode or student_mode):
                raise ValueError("; ".join(problems))
            if problems:
                # Append. Stage A may already have recorded why a shape
                # revision was discarded, and replacing that would hide the
                # one note that explains why the graph looks as it does.
                _LAST_SHAPE_NOTES.set(get_last_shape_notes() + tuple(problems))
            if student_mode:
                # Said of the accepted graph, so the sentences describe what
                # was actually drawn rather than an intermediate skeleton.
                _LAST_GRAPH_RESTATEMENT.set(restate_graph(graph))
            return graph
        except (ValidationError, ValueError) as ex:
            last_error = ex
            user_b = (stage_b_template.format(
                          events=skeleton_events_json, n_events=n_events,
                          event_ids=event_ids, candidates=candidates,
                          miti_lines=_MITI_LINES) +
                      f"\n\nYour previous answer was rejected with this error:\n{ex}\n"
                      f"Return a corrected object that fixes it.")

    raise RuntimeError(f"stage B failed: {last_error}")


class SemanticExtractionResult(BaseModel):
    """Opt-in two-call result; not used by the frozen v1.4 web route yet."""

    graph: AttackGraph
    draft: IncidentSemanticDraft
    presentation: dict


def extract_attack_graph_semantic(
        report_text: str, provider: str = "ollama",
        model: str | None = None) -> SemanticExtractionResult:
    """Draft evidence/causality, then apply v1.4 T/M retrieval.

    This is intentionally a separate opt-in entry point. ``app.py`` continues
    to call :func:`extract_attack_graph` with the frozen v1.4 rules until this
    pathway passes known-case and blind-case acceptance tests. A valid result
    takes two model calls. If the first response satisfies the API JSON schema
    but violates a graph-wide rule that JSON Schema cannot express, exactly one
    bounded semantic correction is allowed before the T/M call.
    """

    if provider not in _PROVIDERS:
        raise ValueError(
            f"unknown provider {provider!r}; choose from {list(_PROVIDERS)}")
    if not report_text.strip():
        raise ValueError("report text must not be empty")

    _LAST_API_USAGE.set(None)
    provider_call = _PROVIDERS[provider]
    selected_model = resolve_model(provider, model)
    if provider == "anthropic":
        cost_budget = _AnthropicCostBudget()

        def call(system, user, chosen_model,
                 response_model: type[BaseModel] = AttackGraph):
            return provider_call(
                system, user, chosen_model, response_model,
                budget=cost_budget)
    else:
        call = provider_call

    # Call 1: evidence inventory, causal draft, branch groups, and state cuts.
    # The frozen v1.4 rule file remains unchanged; this execution override only
    # requests an intermediate object before the normal T/M assignment.
    system = load_ruleset("v1.4", include_full_catalogue=False)
    system += """

SEMANTIC DRAFT EXECUTION OVERRIDE
This call precedes ATT&CK Technique and Mitigation assignment. Return the
coordinate-free IncidentSemanticDraft requested by the user prompt. Do not
emit Technique or Mitigation IDs in this call.
"""
    semantic_user = build_semantic_draft_prompt(report_text)
    draft: IncidentSemanticDraft | None = None
    last_semantic_error: Exception | None = None
    previous_payload = ""
    for semantic_attempt in range(2):
        if semantic_attempt:
            semantic_user = (
                build_semantic_draft_prompt(report_text)
                + "\n\nPREVIOUS STRUCTURED DRAFT:\n"
                + previous_payload
                + "\n\nLOCAL GRAPH-WIDE VALIDATION ERROR:\n"
                + str(last_semantic_error)
                + "\n\nReturn one corrected complete draft. Preserve supported "
                  "evidence and semantics, but repair the cited references, "
                  "event/state alternation, annotation relation, page "
                  "boundary, rank group, continuation, or cycle error. Do not "
                  "invent an attacker action merely to satisfy validation."
            )
        raw_draft = call(
            system,
            semantic_user,
            selected_model,
            IncidentSemanticDraftWire,
        )
        previous_payload = raw_draft
        try:
            # The wire model has already enforced every role-specific JSON
            # Schema rule. The canonical model now verifies cross-references,
            # causal alternation, pages, continuation states, and acyclicity.
            wire = IncidentSemanticDraftWire.model_validate_json(raw_draft)
            candidate = IncidentSemanticDraft.model_validate(
                wire.model_dump())
            evidence_problems = validate_evidence_against_report(
                candidate, report_text)
            if evidence_problems:
                raise ValueError(
                    "unsupported evidence quotations: "
                    + "; ".join(evidence_problems))
            draft = candidate
            break
        except (ValidationError, ValueError) as exc:
            last_semantic_error = exc

    if draft is None:
        raise RuntimeError(
            "semantic draft failed graph-wide validation after one bounded "
            f"correction: {last_semantic_error}")

    skeleton = project_draft_to_skeleton(draft)
    # Validate the old core shape but retain richer evidence fields for the
    # final AttackGraph merge. The permissive variant is used deliberately:
    # this skeleton is projected locally from an already validated draft, and
    # the evidence-first contract allows a root event.
    ProjectedAttackGraphSkeleton.model_validate(skeleton)

    # Call 2: the same tactic-scoped, mandatory v1.4 T/M assignment contract.
    used_tactics = sorted({event["tactic"] for event in skeleton["events"]})
    candidate_blocks = [
        (
            f"Techniques allowed for tactic {tactic} "
            f"({ATTACK_TACTICS[tactic]}):\n"
            f"{_tech_lines_for_tactic(tactic)}"
        )
        for tactic in used_tactics
    ]
    n_events = len(skeleton["events"])
    event_ids = ", ".join(event["id"] for event in skeleton["events"])
    user_b = STAGE_B_USER.format(
        events=json.dumps(skeleton["events"], indent=2),
        n_events=n_events,
        event_ids=event_ids,
        candidates="\n\n".join(candidate_blocks),
        miti_lines=_MITI_LINES,
    )
    expected_ids = [event["id"] for event in skeleton["events"]]
    assignment_user = user_b
    previous_assignments = ""
    last_assignment_error: Exception | None = None
    merged: dict | None = None
    for assignment_attempt in range(2):
        if assignment_attempt:
            assignment_user = (
                user_b
                + "\n\nPREVIOUS STRUCTURED ASSIGNMENTS:\n"
                + previous_assignments
                + "\n\nLOCAL ASSIGNMENT VALIDATION ERROR:\n"
                + str(last_assignment_error)
                + "\n\nReturn one corrected complete assignments object. "
                  "Use every required event id exactly once, choose only a "
                  "listed technique for that event's tactic, and use only "
                  "catalogue mitigation ids."
            )
        raw_assignments = call(
            system,
            assignment_user,
            selected_model,
            TechniqueAssignmentsWire,
        )
        previous_assignments = raw_assignments
        try:
            assignment_wire = (
                TechniqueAssignmentsWire.model_validate_json(
                    raw_assignments))
            assignments = TechniqueAssignments.model_validate(
                assignment_wire.model_dump()).assignments
            returned_ids = [assignment.id for assignment in assignments]
            if (
                len(returned_ids) != len(expected_ids)
                or len(set(returned_ids)) != len(returned_ids)
                or set(returned_ids) != set(expected_ids)
            ):
                raise ValueError(
                    "must return every draft event exactly once; "
                    f"expected {expected_ids}, returned {returned_ids}")

            by_id = {
                assignment.id: assignment for assignment in assignments
            }
            candidate_merged = json.loads(json.dumps(skeleton))
            for event in candidate_merged["events"]:
                assignment = by_id[event["id"]]
                event["technique"] = assignment.technique
                event["mitigations"] = assignment.mitigations

            mismatches = _technique_tactic_mismatches(
                candidate_merged["events"])
            if mismatches:
                details = "; ".join(
                    f"{event_id}: {technique} is not in {tactic}"
                    for event_id, (
                        tactic, technique, _allowed
                    ) in mismatches.items()
                )
                raise ValueError(
                    "out-of-tactic technique assignments: " + details)
            merged = candidate_merged
            break
        except (ValidationError, ValueError) as exc:
            last_assignment_error = exc

    if merged is None:
        raise RuntimeError(
            "semantic Stage B failed after one bounded correction: "
            f"{last_assignment_error}")

    graph = AttackGraph.model_validate(merged)
    build_digraph(graph)
    return SemanticExtractionResult(
        graph=graph,
        draft=draft,
        presentation=semantic_presentation_sidecar(draft),
    )


if __name__ == "__main__":
    import sys
    from ingest import ingest
    if len(sys.argv) < 2:
        print("usage: python extract.py <report.pdf|report.txt> [ollama|anthropic]")
        raise SystemExit(1)
    provider = sys.argv[2] if len(sys.argv) > 2 else "ollama"
    text = ingest(sys.argv[1])
    g = extract_attack_graph(text, provider=provider)
    print(f"[ok] extracted {len(g.preconditions)} preconditions, {len(g.events)} events")
    print(g.model_dump_json(indent=2))
