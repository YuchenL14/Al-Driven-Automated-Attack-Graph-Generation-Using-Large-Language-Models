"""
schema.py -- the canonical data contract for the attack-graph tool.

DESIGN NOTE (Approach C: dual-input, single contract)
-----------------------------------------------------
Every input route -- an analyst filling in JSON by hand today, or an LLM
extracting elements from a narrative report tomorrow -- must converge on ONE
validated object model. The rendering engine only ever sees this model, so it
never needs to know where the data came from. This file *is* that contract.

The constructs mirror the primary constructs identified in
Lallie, Debattista & Bal (2020): a *precondition*, an *event* (exploit), and
*precondition logic* (AND / OR). Grounding the schema in that visual-syntax
theory is what makes the graph a faithful implementation rather than an
arbitrary drawing.

The two known fidelity issues are fixed *here*, at the contract, so bad data
can never reach the renderer:
  1. Sub-technique notation must be T####.### (three digits), so "T1566.02"
     is rejected in favour of "T1566.002".
  2. The tactic marker must be a real ATT&CK tactic abbreviation, so the old
     Kill-Chain letters (D / E / I) can no longer be mixed in.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# --- The 14 MITRE ATT&CK Enterprise tactics (abbreviation -> canonical) ------
# Used to REJECT non-ATT&CK tactic markers (fixes the mixed-scheme issue).
ATTACK_TACTICS = {
    "RE": "Reconnaissance",
    "RS": "Resource Development",
    "IA": "Initial Access",
    "EX": "Execution",
    "PS": "Persistence",
    "PE": "Privilege Escalation",
    "DE": "Defense Evasion",
    "CA": "Credential Access",
    "DS": "Discovery",
    "LM": "Lateral Movement",
    "CL": "Collection",
    "C2": "Command and Control",
    "EF": "Exfiltration",
    "IM": "Impact",
}

# The supervisor's reference diagram badges the Lockheed Martin Cyber Kill
# Chain phase, not the ATT&CK tactic: its own `code_namespaces` block records
# `supervisor_visual_phase: R W D E I C A` on 26 of its 32 nodes and an ATT&CK
# tactic on only 2. The two notations are not interchangeable, so the tool has
# to be able to speak both rather than assume one.
#
# The mapping is many-to-one and lossy in that direction, which is the point:
# the kill chain has seven phases and ATT&CK has fourteen tactics, so several
# tactics share a phase. It is derived, never stored, so a graph cannot carry a
# phase that contradicts its tactic.
KILL_CHAIN_PHASES = {
    "R": "Reconnaissance",
    "W": "Weaponization",
    "D": "Delivery",
    "E": "Exploitation",
    "I": "Installation",
    "C": "Command and Control",
    "A": "Actions on Objectives",
}

TACTIC_TO_KILL_CHAIN = {
    "RE": "R",   # Reconnaissance
    "RS": "W",   # Resource Development is where the adversary weaponises
    "IA": "D",   # Initial Access is the delivery of the attack to the target
    "EX": "E",   # Execution is the exploitation step
    "PS": "I",   # Persistence installs the foothold
    "PE": "E",   # Privilege Escalation exploits a further weakness
    "DE": "E",   # Defence Evasion exploits or subverts a control
    "CA": "E",   # Credential Access exploits to obtain credentials
    "DS": "A",   # Discovery is already action on the objective
    "LM": "A",
    "CL": "A",
    "C2": "C",   # Command and Control
    "EF": "A",   # Exfiltration is the objective itself
    "IM": "A",
}


def kill_chain_phase(tactic: str) -> str | None:
    """Return the kill-chain letter for an ATT&CK tactic, or None."""

    return TACTIC_TO_KILL_CHAIN.get(tactic)


# Technique id: T#### optionally .### (three-digit sub-technique).  Fixes .02 -> .002
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
MITIGATION_RE = re.compile(r"^M\d{4}$")

# --- known ATT&CK ids (the closed vocabulary the tool supports) -------------
# Loaded from the same offline lookup used for the legend. A technique or
# mitigation id must exist here, which stops a model inventing a plausible but
# non-existent id such as M1052. Extend data/attack_lookup.json to widen it.
_LOOKUP = Path(__file__).resolve().parent.parent / "data" / "attack_lookup.json"
try:
    _raw = json.loads(_LOOKUP.read_text(encoding="utf-8"))
    KNOWN_TECHNIQUES = set(_raw.get("techniques", {}))
    KNOWN_MITIGATIONS = set(_raw.get("mitigations", {}))
    KNOWN_TECHNIQUE_TACTICS = {
        tid: set(tactics)
        for tid, tactics in _raw.get("technique_tactics", {}).items()
    }
except Exception:                       # fall back to format-only if file missing
    KNOWN_TECHNIQUES = set()
    KNOWN_MITIGATIONS = set()
    KNOWN_TECHNIQUE_TACTICS = {}


NodeRole = Literal["precondition", "external_resource", "annotation"]

# Outline texture. This is independent of the construct: the reference diagram
# draws both an ordinary precondition and an ordinary event with a dotted
# outline on the alternative delivery branch, and those dotted events still
# carry their technique, mitigations and likelihood. Only an annotation is
# dashed. Lallie, Debattista and Bal (2020) record that 11.9% of surveyed
# attack graphs use edge texture but that no shared meaning exists for it, and
# that texture is a weak visual variable compared with shape or fill, so this
# is a documented project convention rather than a standard.
NodeStyle = Literal["solid", "dotted", "dashed"]


class Precondition(BaseModel):
    """An ellipse.  A state that must hold before an event can happen.

    A precondition may be a root (an initial resource, no parents) or it may be
    *produced* by an event -- e.g. the event 'Create extension' establishes the
    precondition 'extension available on store'. This precondition/exploit
    alternation is the classic attack-graph structure (Lallie 2020, MulVAL).

    ``role`` distinguishes the two further constructs the reference diagram
    uses, both of which sit outside the causal chain:

    * ``external_resource`` -- something the adversary already holds rather
      than something the attack produced, such as stolen certificates or
      fabricated app reviews. It is drawn as an ellipse and feeds an event
      through a dotted context line.
    * ``annotation`` -- a defensive control or commentary attached to a step,
      such as "Training / AV tools / IDS". It is drawn as a dashed box, is
      never part of the attack path, and carries no ATT&CK metadata.
    """
    id: str
    label: str = Field(..., description="<= 10 words, shown inside the ellipse")
    code: str = Field(..., description="short badge shown top-left, e.g. 'RS', 'R'")
    role: NodeRole = "precondition"
    style: NodeStyle = Field(
        "solid",
        description="dotted marks an alternative or uncertain branch")
    parents: List[str] = Field(default_factory=list,
                               description="event ids that establish this precondition")

    @model_validator(mode="after")
    def _style_matches_role(self) -> "Precondition":
        if self.role == "annotation" and self.style != "dashed":
            raise ValueError(
                f"annotation {self.id!r} must be dashed; dashed is reserved "
                "for commentary and every other construct uses solid or dotted")
        if self.role != "annotation" and self.style == "dashed":
            raise ValueError(
                f"{self.id!r} is a {self.role} but is dashed; dashed marks an "
                "annotation, an alternative branch is dotted")
        return self

    @field_validator("label")
    @classmethod
    def _max_ten_words(cls, v: str) -> str:
        if len(v.split()) > 10:
            raise ValueError(f"precondition label must be <= 10 words, got: {v!r}")
        return v

    @field_validator("id", "label", "code")
    @classmethod
    def _non_empty_text(cls, v: str) -> str:
        value = v.strip()
        if not value:
            raise ValueError("id, label, and code must not be empty")
        return value

    @field_validator("parents")
    @classmethod
    def _unique_parents(cls, values: List[str]) -> List[str]:
        if any(not value.strip() for value in values):
            raise ValueError("parent ids must not be empty")
        if len(values) != len(set(values)):
            raise ValueError("parent ids must not contain duplicates")
        return values


class Event(BaseModel):
    """A rectangle.  An action the adversary performs (an exploit)."""
    id: str
    label: str
    tactic: str = Field(..., description="ATT&CK tactic abbreviation, top-left")
    # A list, because the reference diagram stacks several T-numbers on one
    # action: two of its nodes carry seven. Stored as the canonical form so a
    # score computed against that diagram is comparing like with like.
    # ``technique`` remains readable as a property and remains accepted as an
    # input key, so v1.4 data and every existing reader are unaffected.
    techniques: List[str] = Field(default_factory=list,
                                  description="T-numbers, top-right stack")
    mitigations: List[str] = Field(default_factory=list, description="M-numbers, bottom-right")
    likelihood: Optional[float] = Field(None, ge=0, le=10, description="bottom-left, 0-10")
    # v1.5 evidence metadata.  These remain optional in the shared contract so
    # frozen v1.4 data and hand-written example JSON continue to validate.  The
    # v1.5 extraction path requires and checks all three fields explicitly.
    source_evidence: Optional[str] = Field(
        None, description="exact quotation from the supplied report")
    evidence_status: Optional[Literal[
        "confirmed", "reported", "alleged", "possible"
    ]] = None
    evidence_confidence: Optional[int] = Field(
        None, ge=0, le=100,
        description="confidence in the extracted claim, separate from likelihood")
    # Student v1.1 grounding metadata. Optional here so the frozen professional
    # v1.4 contract and existing examples remain byte-for-byte compatible.
    actor: Optional[Literal[
        "adversary", "victim", "defender", "investigator", "unknown"
    ]] = None
    action_evidence: Optional[str] = Field(
        None, description="exact action verb or verb phrase inside source_evidence")
    # An event on an alternative or uncertain branch is drawn dotted. It keeps
    # its technique, mitigations and likelihood: outline texture says how
    # certain the branch is, not whether the step is classified.
    style: NodeStyle = "solid"
    # precondition logic: which nodes feed this event, and how they combine
    parents: List[str] = Field(default_factory=list)
    join: Literal["AND", "OR"] = "AND"

    @field_validator("style")
    @classmethod
    def _events_are_never_dashed(cls, value: NodeStyle) -> NodeStyle:
        if value == "dashed":
            raise ValueError(
                "dashed is reserved for annotations; an alternative or "
                "uncertain event is dotted")
        return value

    @field_validator("tactic")
    @classmethod
    def _known_tactic(cls, v: str) -> str:
        if v not in ATTACK_TACTICS:
            raise ValueError(
                f"tactic {v!r} is not an ATT&CK abbreviation. "
                f"Use one of: {', '.join(ATTACK_TACTICS)}"
            )
        return v

    @field_validator("id", "label")
    @classmethod
    def _non_empty_text(cls, v: str) -> str:
        value = v.strip()
        if not value:
            raise ValueError("event id and label must not be empty")
        return value

    @model_validator(mode="before")
    @classmethod
    def _accept_singular_technique(cls, data):
        """Fold a legacy ``technique`` key into the canonical list.

        Every saved v1.4 run, every fixture and every Stage B assignment writes
        the singular key. Accepting it here means the storage change is not a
        data migration.
        """
        if not isinstance(data, dict):
            return data
        if "technique" not in data:
            return data
        # The singular key wins over any list already present. Stage B writes
        # it onto a skeleton that the student and evidence paths dumped from an
        # already-validated graph, so both keys arrive together and the
        # singular one is the later, explicit assignment. Letting the list win
        # discarded Stage B's answer silently, and silently overrode an
        # abstention -- the failure mode this schema exists to prevent.
        folded = dict(data)
        single = folded.pop("technique")
        folded["techniques"] = [single] if single else []
        return folded

    @property
    def technique(self) -> Optional[str]:
        """The first technique, for the many readers that expect one."""
        return self.techniques[0] if self.techniques else None

    @field_validator("techniques")
    @classmethod
    def _valid_technique(cls, values: List[str]) -> List[str]:
        if len(values) != len(set(values)):
            raise ValueError("technique ids must not contain duplicates")
        for v in values:
            if not TECHNIQUE_RE.match(v):
                raise ValueError(
                    f"technique {v!r} is malformed. Expected T#### or T####.### "
                    f"(three-digit sub-technique, e.g. T1566.002)."
                )
            if KNOWN_TECHNIQUES and v not in KNOWN_TECHNIQUES:
                raise ValueError(
                    f"technique {v!r} is not a real ATT&CK technique in this "
                    f"tool's set. Choose an existing technique id, do not "
                    f"invent one."
                )
        return values

    @field_validator("mitigations")
    @classmethod
    def _valid_mitigations(cls, v: List[str]) -> List[str]:
        if len(v) != len(set(v)):
            raise ValueError("mitigation ids must not contain duplicates")
        for m in v:
            if not MITIGATION_RE.match(m):
                raise ValueError(f"mitigation {m!r} is malformed. Expected M#### (e.g. M1051).")
            if KNOWN_MITIGATIONS and m not in KNOWN_MITIGATIONS:
                raise ValueError(
                    f"mitigation {m!r} is not a real ATT&CK mitigation in this tool's set. "
                    f"Choose an existing mitigation id, do not invent one."
                )
        return v

    @field_validator("parents")
    @classmethod
    def _unique_parents(cls, values: List[str]) -> List[str]:
        if any(not value.strip() for value in values):
            raise ValueError("parent ids must not be empty")
        if len(values) != len(set(values)):
            raise ValueError("parent ids must not contain duplicates")
        return values

    @model_validator(mode="after")
    def _metadata_is_consistent(self) -> "Event":
        if self.technique is None and self.mitigations:
            raise ValueError("an event without a technique cannot have mitigations")
        if self.technique:
            tactics = KNOWN_TECHNIQUE_TACTICS.get(self.technique, set())
            if tactics and self.tactic not in tactics:
                raise ValueError(
                    f"technique {self.technique} belongs to {sorted(tactics)}, "
                    f"not tactic {self.tactic}")
        return self


class AttackGraph(BaseModel):
    """The whole graph: the single object the renderer consumes."""
    title: str = "Attack Graph"
    preconditions: List[Precondition] = Field(default_factory=list)
    events: List[Event] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_references(self) -> "AttackGraph":
        """Require unique ids, valid references, and alternating node types."""
        pre_ids = {p.id for p in self.preconditions}
        event_ids = {e.id for e in self.events}
        all_ids = [p.id for p in self.preconditions] + [e.id for e in self.events]
        if len(all_ids) != len(set(all_ids)):
            raise ValueError("all precondition and event ids must be globally unique")
        for e in self.events:
            for parent in e.parents:
                if parent not in pre_ids:
                    if parent in event_ids:
                        raise ValueError(
                            f"event {e.id!r} must consume preconditions, but parent "
                            f"{parent!r} is an event")
                    raise ValueError(f"event {e.id!r} references unknown parent {parent!r}")
        for p in self.preconditions:
            if p.role == "external_resource" and p.parents:
                raise ValueError(
                    f"external resource {p.id!r} is something the adversary "
                    "already holds, so it cannot be produced by an event")
            for parent in p.parents:
                if parent not in event_ids:
                    if parent in pre_ids:
                        raise ValueError(
                            f"precondition {p.id!r} must be produced by events, but "
                            f"parent {parent!r} is a precondition")
                    raise ValueError(f"precondition {p.id!r} references unknown parent {parent!r}")
        annotation_ids = {
            p.id for p in self.preconditions if p.role == "annotation"
        }
        for e in self.events:
            for parent in e.parents:
                if parent in annotation_ids:
                    raise ValueError(
                        f"event {e.id!r} consumes annotation {parent!r}; an "
                        "annotation is commentary beside a step, never part "
                        "of the attack path")
        return self

    @property
    def causal_preconditions(self) -> List[Precondition]:
        """Preconditions that belong to the attack path, excluding commentary."""
        return [p for p in self.preconditions if p.role != "annotation"]

    @property
    def annotations(self) -> List[Precondition]:
        """Defensive controls and commentary attached beside a step."""
        return [p for p in self.preconditions if p.role == "annotation"]

    # ---- input adapters (Approach C) --------------------------------------
    @classmethod
    def from_json_file(cls, path: str | Path) -> "AttackGraph":
        """Route 1 (works today): load a canonical JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)
