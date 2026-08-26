from __future__ import annotations

import os
from dataclasses import dataclass, replace
from typing import Literal

from schema import (ATTACK_TACTICS, AttackGraph, KILL_CHAIN_PHASES,
                    kill_chain_phase)


NodeKind = Literal["event", "state", "annotation"]
Shape = Literal["rectangle", "ellipse", "annotation"]
BadgeNamespace = Literal["attack_tactic", "kill_chain_phase",
                         "state_phase", "none"]
BadgeSource = Literal["attack_tactic", "kill_chain_phase"]
EdgeStyle = Literal["solid", "dotted", "dashed"]

# Edges carry meaning too. Node constructs were made enumerable so that symbol
# overload could be checked; leaving edges as one undifferentiated line kept
# half the notation unexaminable, and it is the half the reference diagram uses
# to separate what caused a step from what merely accompanies it.
#
# The relation is derived from the endpoints rather than stored. Nothing else
# could make it disagree with the roles it describes, and no rule set has to
# remember to set it.
EdgeRelation = Literal["causal", "context", "annotation"]

EDGE_RELATION_STYLES: dict[EdgeRelation, EdgeStyle] = {
    "causal": "solid",
    "context": "dotted",
    "annotation": "dashed",
}


def edge_style(relation: EdgeRelation, source_style: EdgeStyle) -> EdgeStyle:
    """Texture for one edge, from its relation and the step it leaves.

    Relation alone is not enough. In the reference diagram six edges are dotted
    but only two are context edges: the other four are ordinary causal edges
    leaving a step on the uncertain branch. Uncertainty propagates forward, so
    what follows from an uncertain step is drawn uncertain too. Checked against
    all 32 of the fixture's edges, this rule reproduces every one.
    """

    if relation == "annotation":
        return "dashed"
    if relation == "context" or source_style == "dotted":
        return "dotted"
    return "solid"


def edge_relation(source_role: str, target_role: str) -> EdgeRelation:
    """Classify one edge from the constructs at its two ends.

    An external resource is not produced by the attack, so what it supplies is
    context rather than causation. An annotation is commentary, so the line
    reaching it carries no causal claim at all. Everything else is causal.
    """

    if target_role == "annotation":
        return "annotation"
    if source_role == "external_resource":
        return "context"
    return "causal"


@dataclass(frozen=True)
class VisualSyntaxProfile:
    """The immutable choices shared by every AGVS-SP renderer."""

    profile_id: str
    flow_direction: Literal["top_down"]
    event_shape: Literal["rectangle"]
    state_shape: Literal["ellipse"]
    and_notation: Literal["shared_bus"]
    or_notation: Literal["separate_edges"]
    event_tactic_badges_only: bool
    prohibited_state_badges: frozenset[str]
    # Which vocabulary the event badge speaks. The reference diagram badges the
    # kill-chain phase; this tool has always badged the ATT&CK tactic. Making
    # it a profile field means the difference is a stated, switchable choice
    # rather than an assumption buried in the renderer -- which is the whole
    # reason the profile exists.
    badge_source: BadgeSource = "attack_tactic"


AGVS_SP_V1 = VisualSyntaxProfile(
    profile_id="AGVS-SP-1.0",
    flow_direction="top_down",
    event_shape="rectangle",
    state_shape="ellipse",
    and_notation="shared_bus",
    or_notation="separate_edges",
    event_tactic_badges_only=True,
    # An ATT&CK tactic classifies adversary behaviour, so a precondition cannot
    # hold one: the supervisor identified IA on a prerequisite as invalid, and
    # the same argument applies to all fourteen. Drawing them on ellipses also
    # loaded one symbol with two concepts, since the purple circle already
    # means "this action's tactic" on rectangles. Lallie, Debattista and Bal
    # (2020) treat that overload as a failure of semiotic clarity. The original
    # value remains in the canonical graph for auditability; only its invalid
    # visual placement is suppressed by the presentation layer.
    prohibited_state_badges=frozenset(ATTACK_TACTICS),
)

# The same syntax reading its event badges in the supervisor's vocabulary. The
# tactic stays in the canonical graph either way; only the badge changes, so a
# graph rendered under both profiles is the same graph.
AGVS_SP_V1_KILL_CHAIN = replace(
    AGVS_SP_V1,
    profile_id="AGVS-SP-1.0-KC",
    badge_source="kill_chain_phase",
    prohibited_state_badges=frozenset(ATTACK_TACTICS) | frozenset(
        KILL_CHAIN_PHASES),
)

BADGE_SOURCE_ENV = "AGVS_BADGE_SOURCE"


# The badge vocabulary the dissertation's figures use.
#
# The supervisor's reference diagram badges the Lockheed Martin Cyber Kill
# Chain phase on 26 of its 32 nodes and an ATT&CK tactic on only 2, so kill
# chain is what conformance to that figure means. The tool badged the ATT&CK
# tactic for most of its life, which is why the mapping is many-to-one and
# lossy in that direction: fourteen tactics share seven phases. The tactic is
# never discarded, only unshown. It stays in the canonical JSON, drives the
# tactic-first technique selection, and still governs Stage B validation.
#
# Set AGVS_BADGE_SOURCE=attack_tactic to render the ATT&CK vocabulary instead,
# which is how the two are compared under otherwise identical conditions.
DEFAULT_BADGE_SOURCE: BadgeSource = "kill_chain_phase"


def active_profile() -> VisualSyntaxProfile:
    """The profile every renderer uses unless one is passed explicitly."""

    selected = os.environ.get(
        BADGE_SOURCE_ENV, DEFAULT_BADGE_SOURCE).strip().lower()
    if selected == "kill_chain_phase":
        return AGVS_SP_V1_KILL_CHAIN
    if selected != "attack_tactic":
        raise ValueError(
            f"invalid {BADGE_SOURCE_ENV}={selected!r}; expected "
            "attack_tactic or kill_chain_phase")
    return AGVS_SP_V1


@dataclass(frozen=True)
class VisualNodeSemantics:
    """Presentation-only view of one canonical graph node."""

    id: str
    kind: NodeKind
    shape: Shape
    label: str
    badge_code: str | None
    badge_namespace: BadgeNamespace
    techniques: tuple[str, ...]
    mitigations: tuple[str, ...]
    likelihood: float | None
    parents: tuple[str, ...]
    join: Literal["AND", "OR"]
    source_index: int
    # Outline texture, independent of the construct. A dotted precondition and
    # a dotted event both sit on an alternative branch, and the dotted event
    # still carries its technique, mitigations and likelihood.
    style: EdgeStyle = "solid"
    # The canonical construct. ``kind`` collapses external resources into
    # "state" because they are drawn as ellipses, so it cannot classify the
    # edges leaving them; this keeps the distinction the edge rule needs.
    role: str = "precondition"

    @property
    def technique(self) -> str | None:
        """The first technique, for readers that expect a single value."""
        return self.techniques[0] if self.techniques else None


# The whole vocabulary an ellipse can badge. Three values, and an annotation
# badges nothing at all because its dashed outline already says what it is.
#
# The codes used to come from the model, one per node, and the model invented a
# fresh set for every report: PRE1, RESULT2, EXT-RES, VULN, NET, COND, SVCSTOP,
# ENC-EXEC, XFER. Lallie, Debattista and Bal (2020) name exactly that as the
# defect in published attack graphs, and their 2018 conjoint study (n=212)
# found the precondition attribute carries the largest share of practitioner
# preference at 38.5%, so the least consistent notation sat on the construct
# readers weight most.
#
# Deriving it removes the possibility rather than discouraging it. Role and
# parentage are already validated by the schema, so no rule set has to remember
# a vocabulary and no two graphs can disagree about one.
STATE_BADGES: dict[str, str] = {
    "PRE": "a condition that held before the attack",
    "RES": "a state an action produced",
    "EXT": "a resource the adversary already held",
}


def state_badge_code(
    role: str,
    has_parents: bool,
    profile: VisualSyntaxProfile = AGVS_SP_V1,
) -> str | None:
    """Which of the three state codes an ellipse shows, or none.

    Derived from the graph rather than read from ``Precondition.code``. The
    canonical code stays in the JSON for auditability, in the same way the
    suppressed ATT&CK tactic does, so nothing is lost from the record; only the
    badge is decided here.
    """

    if role == "annotation":
        return None
    if role == "external_resource":
        return "EXT"
    return "RES" if has_parents else "PRE"


def project_visual_nodes(
    model: AttackGraph,
    profile: VisualSyntaxProfile = AGVS_SP_V1,
) -> tuple[VisualNodeSemantics, ...]:
    """Project a validated graph into deterministic visual node semantics.

    The function is deliberately pure: it neither mutates ``model`` nor tries
    to infer missing attack content.  In particular, event T/M/likelihood data
    is copied exactly, while prerequisite codes occupy the separate
    ``state_phase`` namespace and can never become event tactics.
    """

    projected: list[VisualNodeSemantics] = []
    source_index = 0

    for precondition in model.preconditions:
        is_annotation = precondition.role == "annotation"
        badge = state_badge_code(
            precondition.role, bool(precondition.parents), profile)
        projected.append(VisualNodeSemantics(
            id=precondition.id,
            kind="annotation" if is_annotation else "state",
            shape="annotation" if is_annotation else profile.state_shape,
            label=precondition.label,
            badge_code=badge,
            badge_namespace="state_phase" if badge else "none",
            techniques=(),
            mitigations=(),
            likelihood=None,
            parents=tuple(precondition.parents),
            # Several exploits producing the same state are independently
            # sufficient alternatives in the canonical schema.
            join="OR",
            source_index=source_index,
            style=precondition.style,
            role=precondition.role,
        ))
        source_index += 1

    for event in model.events:
        if profile.badge_source == "kill_chain_phase":
            badge_code = kill_chain_phase(event.tactic)
        else:
            badge_code = event.tactic
        projected.append(VisualNodeSemantics(
            id=event.id,
            kind="event",
            shape=profile.event_shape,
            label=event.label,
            badge_code=badge_code,
            badge_namespace=profile.badge_source,
            techniques=tuple(event.techniques),
            mitigations=tuple(event.mitigations),
            likelihood=event.likelihood,
            parents=tuple(event.parents),
            join=event.join,
            source_index=source_index,
            style=event.style,
            role="event",
        ))
        source_index += 1

    return tuple(projected)
