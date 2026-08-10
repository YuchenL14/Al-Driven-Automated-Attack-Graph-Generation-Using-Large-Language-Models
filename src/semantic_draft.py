"""Evidence-first, coordinate-free incident graph planning.

This module defines the semantic object that should sit between report
understanding and ATT&CK T/M assignment.  It intentionally contains no pixel
coordinates, Graphviz ranks, or renderer-specific geometry.  The language
model may describe evidence, causal nodes, alternatives, parallel branches,
annotations, and safe page boundaries; deterministic code remains responsible
for drawing those semantics.

The contract is deliberately separate from :mod:`schema`.  ``AttackGraph`` is
the frozen renderer input used by the professional v1.4 baseline.  Introducing
this draft as an intermediate representation lets the project evaluate the new
reasoning stage without silently changing that frozen contract.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, model_validator


EvidenceStatus = Literal[
    "confirmed",
    "reported",
    "suspected",
    "probable",
    "possible",
    "possible_alternatives",
    "reported_sequence",
    "reported_at_high_level",
    "reported_channel_unknown",
    "recommendation",
    "context",
    "derived",
]
EventEvidenceStatus = Literal[
    "confirmed",
    "reported",
    "suspected",
    "probable",
    "possible",
    "possible_alternatives",
    "reported_sequence",
    "reported_at_high_level",
    "reported_channel_unknown",
]
TacticCode = Literal[
    "RE", "RS", "IA", "EX", "PS", "PE", "DE",
    "CA", "DS", "LM", "CL", "C2", "EF", "IM",
]
JoinLogic = Literal["AND", "OR"]


SEMANTIC_DRAFT_USER = """Analyse the supplied cyber-incident report and return
one coordinate-free semantic attack-graph draft.

This is the evidence and causal-planning stage. Do NOT assign ATT&CK Technique
IDs or Mitigation IDs, and do NOT choose pixel coordinates, columns, lanes, or
line routes.

Work in this order:
1. Copy a short, contiguous source quotation for every reported, suspected,
   probable, or possible attacker action, every material enabling condition,
   every material outcome, and every defence/business-continuity observation.
   Preserve uncertainty words. A paraphrase is not a source quotation.
2. Create rectangle EVENT nodes only for attacker actions. Give each event one
   ATT&CK tactic describing its primary objective, but no Technique ID.
3. Create ellipse STATE nodes for prerequisites and results. States never carry
   tactic badges. Defender actions, recommendations, recovery activity, and
   business-continuity observations are not attacker events.
4. Create dashed ANNOTATION nodes for relevant defensive recommendations and
   business-continuity context. An annotation may point to the related attack
   branch but must never become part of the solid causal path.
5. Keep explicit alternative mechanisms as separate branches joined by OR.
   Do not combine text such as "phishing or brute force" into one event and do
   not imply that a possible mechanism succeeded.
6. Preserve event -> state -> event alternation. Use AND only when every parent
   state is jointly required. Parallel outcomes from one state remain sibling
   branches; do not serialize them merely to make one long chain.
7. Group macro-level parallel prerequisites or consequences in rank_groups.
   A rank group is semantic alignment only: it does not add, remove, or reverse
   a causal edge, and it may contain rectangles, ellipses, and annotations.
8. If the graph is too deep for one readable landscape page, split only at a
   meaningful STATE boundary. Repeat that state as a continuation_state on the
   next page, preserve its canonical id and label, and never cut an event from
   its direct result. The pages must losslessly recompose into the original
   causal graph.
9. Never complete a generic ATT&CK chain. If the report confirms an action but
   omits its tool, protocol, channel, or exploit, keep the action general.

Return only the structured semantic draft.

REPORT:
{report}"""


class EvidenceClaim(BaseModel):
    """One auditable statement copied from the supplied incident source."""

    id: str = Field(min_length=1)
    quote: str = Field(min_length=1)
    status: EvidenceStatus
    page: int | None = Field(None, ge=1)


class SemanticNodeBase(BaseModel):
    """Fields shared by every coordinate-free semantic element."""

    id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    evidence_status: EvidenceStatus
    page: int = Field(ge=1)
    branch: str = Field(min_length=1)
    likelihood: float | None = Field(None, ge=0, le=10)


class SemanticEventNode(SemanticNodeBase):
    """An attacker action; all role-dependent rules are visible in JSON Schema."""

    role: Literal["event"] = Field(
        json_schema_extra={"enum": ["event"]})
    shape: Literal["rectangle"] = Field(
        json_schema_extra={"enum": ["rectangle"]})
    evidence_status: EventEvidenceStatus
    tactic: TacticCode


class SemanticStateNode(SemanticNodeBase):
    """A prerequisite or result state."""

    role: Literal["state"] = Field(
        json_schema_extra={"enum": ["state"]})
    shape: Literal["ellipse"] = Field(
        json_schema_extra={"enum": ["ellipse"]})
    tactic: None = None
    continues_on_page: int | None = Field(None, ge=1)


class SemanticContinuationNode(SemanticNodeBase):
    """A page-boundary copy of one canonical state."""

    role: Literal["continuation_state"] = Field(
        json_schema_extra={"enum": ["continuation_state"]})
    shape: Literal["ellipse"] = Field(
        json_schema_extra={"enum": ["ellipse"]})
    tactic: None = None
    canonical_id: str = Field(min_length=1)
    continued_from_page: int = Field(ge=1)


class SemanticAnnotationNode(SemanticNodeBase):
    """Non-causal defence or business-continuity context."""

    role: Literal["annotation"] = Field(
        json_schema_extra={"enum": ["annotation"]})
    shape: Literal["annotation"] = Field(
        json_schema_extra={"enum": ["annotation"]})
    evidence_status: Literal["recommendation", "context"]
    tactic: None = None


# A discriminated union makes role/shape/tactic/evidence constraints part of
# the JSON Schema sent to Claude. Unlike a model-level validator, these rules
# are therefore enforced before the API response reaches local validation.
SemanticNode = Annotated[
    Union[
        SemanticEventNode,
        SemanticStateNode,
        SemanticContinuationNode,
        SemanticAnnotationNode,
    ],
    Field(discriminator="role"),
]


class SemanticEdgeBase(BaseModel):
    """Fields shared by semantic relations; never drawing coordinates."""

    source: str = Field(min_length=1)
    target: str = Field(min_length=1)


class SemanticCausalEdge(SemanticEdgeBase):
    """A solid event/state dependency."""

    relation: Literal["causal"] = Field(
        json_schema_extra={"enum": ["causal"]})
    style: Literal["solid"] = Field(
        json_schema_extra={"enum": ["solid"]})
    logic: JoinLogic | None = None


class SemanticAnnotationEdge(SemanticEdgeBase):
    """A dashed, non-causal recommendation or context relation."""

    relation: Literal["annotation"] = Field(
        json_schema_extra={"enum": ["annotation"]})
    style: Literal["dashed"] = Field(
        json_schema_extra={"enum": ["dashed"]})
    logic: None = None


# Relation and style are one discriminated choice in the API schema. This
# prevents the hosted model from returning combinations that only fail in a
# local model validator (for example, a dashed causal edge).
SemanticEdge = Annotated[
    Union[SemanticCausalEdge, SemanticAnnotationEdge],
    Field(discriminator="relation"),
]


class SemanticRankGroup(BaseModel):
    """Nodes that are parallel at a macro level, not causally equivalent."""

    id: str = Field(min_length=1)
    node_ids: list[str] = Field(min_length=2)
    rationale: Literal[
        "parallel_prerequisite_band",
        "parallel_consequence_band",
        "parallel_attack_methods",
        "context_beside_related_branch",
    ]

    @model_validator(mode="after")
    def _node_ids_are_unique(self) -> "SemanticRankGroup":
        if len(self.node_ids) != len(set(self.node_ids)):
            raise ValueError("a rank group must not repeat a node")
        return self


class SemanticPage(BaseModel):
    """One causal subgraph bounded by reusable state nodes."""

    page: int = Field(ge=1)
    title: str = Field(min_length=1)
    entry_nodes: list[str] = Field(min_length=1)
    exit_nodes: list[str] = Field(min_length=1)
    rank_groups: list[SemanticRankGroup] = Field(default_factory=list)


class IncidentSemanticDraftWire(BaseModel):
    """Strict API payload before graph-wide referential validation.

    JSON Schema can enforce required fields, node variants, edge variants,
    enums, and scalar ranges, but it cannot express that an edge id must name a
    node in the same response or that a page-local causal graph is acyclic.
    Keeping this wire contract separate lets the API enforce everything JSON
    Schema can prove, then lets deterministic local code report the remaining
    graph-wide errors and request one bounded correction.
    """

    title: str = Field(min_length=1)
    evidence: list[EvidenceClaim] = Field(min_length=1)
    nodes: list[SemanticNode] = Field(min_length=1)
    edges: list[SemanticEdge] = Field(default_factory=list)
    pages: list[SemanticPage] = Field(min_length=1)


class IncidentSemanticDraft(BaseModel):
    """Validated semantic plan produced before T/M assignment and rendering."""

    title: str = Field(min_length=1)
    evidence: list[EvidenceClaim] = Field(min_length=1)
    nodes: list[SemanticNode] = Field(min_length=1)
    edges: list[SemanticEdge] = Field(default_factory=list)
    pages: list[SemanticPage] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_graph_contract(self) -> "IncidentSemanticDraft":
        node_by_id = _unique_by_id(self.nodes, "node")
        evidence_by_id = _unique_by_id(self.evidence, "evidence")
        page_by_number = _unique_pages(self.pages)

        for node in self.nodes:
            if node.evidence_id not in evidence_by_id:
                raise ValueError(
                    f"node {node.id!r} references unknown evidence "
                    f"{node.evidence_id!r}")
            if node.page not in page_by_number:
                raise ValueError(
                    f"node {node.id!r} references unknown page {node.page}")

        edge_keys: set[tuple[str, str, str]] = set()
        for edge in self.edges:
            if edge.source not in node_by_id or edge.target not in node_by_id:
                raise ValueError(
                    f"edge {edge.source!r}->{edge.target!r} references an "
                    "unknown node")
            key = (edge.source, edge.target, edge.relation)
            if key in edge_keys:
                raise ValueError(f"duplicate edge {key!r}")
            edge_keys.add(key)

            source = node_by_id[edge.source]
            target = node_by_id[edge.target]
            if edge.relation == "annotation":
                if source.role != "annotation":
                    raise ValueError(
                        "an annotation edge must originate at an annotation")
                continue
            if source.role == "annotation" or target.role == "annotation":
                raise ValueError(
                    "annotation nodes cannot participate in causal edges")
            if source.page != target.page:
                raise ValueError(
                    "cross-page causality must use a repeated continuation "
                    "state, not a direct edge")
            source_is_event = source.role == "event"
            target_is_event = target.role == "event"
            if source_is_event == target_is_event:
                raise ValueError(
                    f"causal edge {source.id!r}->{target.id!r} violates "
                    "event/state alternation")

        for page in self.pages:
            grouped_node_ids: set[str] = set()
            for node_id in page.entry_nodes + page.exit_nodes:
                _require_node_on_page(node_by_id, node_id, page.page)
            for group in page.rank_groups:
                for node_id in group.node_ids:
                    _require_node_on_page(node_by_id, node_id, page.page)
                    if node_id in grouped_node_ids:
                        raise ValueError(
                            f"node {node_id!r} occurs in more than one rank "
                            f"group on page {page.page}")
                    grouped_node_ids.add(node_id)
                _validate_rank_group_causality(
                    page.page, group, node_by_id, self.edges)

        for node in self.nodes:
            if node.role != "continuation_state":
                continue
            canonical = node_by_id.get(node.canonical_id or "")
            if canonical is None:
                raise ValueError(
                    f"continuation {node.id!r} has unknown canonical node")
            if canonical.role != "state":
                raise ValueError(
                    f"continuation {node.id!r} must repeat a state")
            if canonical.label != node.label:
                raise ValueError(
                    f"continuation {node.id!r} must preserve the state label")
            if canonical.page != node.continued_from_page:
                raise ValueError(
                    f"continuation {node.id!r} cites the wrong source page")
            if canonical.continues_on_page != node.page:
                raise ValueError(
                    f"canonical state {canonical.id!r} does not point to "
                    f"page {node.page}")

        _require_acyclic_pages(self.nodes, self.edges)
        return self


def validate_evidence_against_report(
        draft: IncidentSemanticDraft, report_text: str) -> list[str]:
    """Return evidence quotations that are not contiguous report substrings.

    Whitespace and Unicode dash variants are normalised, but the wording itself
    is not stemmed or paraphrased.  This keeps the audit deterministic and
    prevents a model-authored summary from masquerading as a source quotation.
    """

    normalised_report = _normalise_quote(report_text)
    problems = []
    for claim in draft.evidence:
        if claim.status == "derived":
            # Derived state wording is allowed only when another source-backed
            # event mechanically establishes it.  It is not presented as a
            # direct quotation.
            continue
        quote = _normalise_quote(claim.quote)
        if quote not in normalised_report:
            problems.append(
                f"{claim.id}: evidence quote is not a contiguous report excerpt")
    return problems


def build_semantic_draft_prompt(report_text: str) -> str:
    """Return the report-agnostic Stage-A instruction with no case template."""

    if not report_text.strip():
        raise ValueError("a semantic draft requires non-empty report text")
    return SEMANTIC_DRAFT_USER.format(report=report_text)


def project_draft_to_skeleton(draft: IncidentSemanticDraft) -> dict:
    """Project semantic meaning into the existing Stage-A skeleton shape.

    Continuation states are presentation copies, so their outgoing edges are
    rewired to the canonical state. Annotation nodes/edges remain in the
    presentation sidecar and are not inserted into the causal AttackGraph.
    No Technique or Mitigation value is introduced here.
    """

    node_by_id = {node.id: node for node in draft.nodes}
    evidence_by_id = {claim.id: claim for claim in draft.evidence}
    canonical_id = {
        node.id: (node.canonical_id if node.role == "continuation_state"
                  else node.id)
        for node in draft.nodes
    }

    causal_edges = [
        edge for edge in draft.edges if edge.relation == "causal"
    ]
    incoming: dict[str, list[SemanticEdge]] = defaultdict(list)
    outgoing: dict[str, list[SemanticEdge]] = defaultdict(list)
    for edge in causal_edges:
        source_id = canonical_id[edge.source]
        target_id = canonical_id[edge.target]
        rewritten = SemanticCausalEdge(
            source=source_id,
            target=target_id,
            relation="causal",
            style="solid",
            logic=edge.logic,
        )
        incoming[target_id].append(rewritten)
        outgoing[source_id].append(rewritten)

    preconditions = []
    for node in draft.nodes:
        if node.role not in {"state"}:
            continue
        producer_edges = incoming[node.id]
        consumer_edges = outgoing[node.id]
        producer_tactics = [
            node_by_id[edge.source].tactic
            for edge in producer_edges
            if node_by_id[edge.source].role == "event"
        ]
        consumer_tactics = [
            node_by_id[edge.target].tactic
            for edge in consumer_edges
            if node_by_id[edge.target].role == "event"
        ]
        # ``code`` remains required by the frozen AttackGraph schema. It is an
        # internal state namespace here; the AGVS-SP projection suppresses
        # tactic badges on ellipses.
        code = next(
            (value for value in producer_tactics + consumer_tactics if value),
            "R",
        )
        preconditions.append({
            "id": node.id,
            "label": node.label,
            "code": code,
            "parents": [edge.source for edge in producer_edges],
        })

    events = []
    for node in draft.nodes:
        if node.role != "event":
            continue
        claim = evidence_by_id[node.evidence_id]
        parent_edges = incoming[node.id]
        parent_logics = {
            edge.logic for edge in parent_edges if edge.logic is not None
        }
        join = (
            next(iter(parent_logics))
            if len(parent_logics) == 1
            else "AND"
        )
        events.append({
            "id": node.id,
            "label": node.label,
            "tactic": node.tactic,
            "likelihood": (
                node.likelihood
                if node.likelihood is not None
                else _default_likelihood(node.evidence_status)
            ),
            "parents": [edge.source for edge in parent_edges],
            "join": join,
            "source_evidence": claim.quote,
            "evidence_status": _attack_graph_evidence_status(
                node.evidence_status),
            "evidence_confidence": _default_evidence_confidence(
                node.evidence_status),
        })

    return {
        "title": draft.title,
        "preconditions": preconditions,
        "events": events,
    }


def semantic_presentation_sidecar(draft: IncidentSemanticDraft) -> dict:
    """Return only presentation semantics that the frozen graph cannot store."""

    draft = normalise_parallel_rank_groups(draft)
    annotations = [
        node.model_dump(exclude_none=True)
        for node in draft.nodes if node.role == "annotation"
    ]
    annotation_ids = {node["id"] for node in annotations}
    annotation_edges = [
        edge.model_dump(exclude_none=True)
        for edge in draft.edges
        if edge.source in annotation_ids or edge.target in annotation_ids
    ]
    return {
        "semantic_contract": "incident-semantic-draft-v1",
        "annotations": annotations,
        "annotation_edges": annotation_edges,
        "pages": [
            page.model_dump(exclude_none=True) for page in draft.pages
        ],
    }


def normalise_parallel_rank_groups(
        draft: IncidentSemanticDraft) -> IncidentSemanticDraft:
    """Add only mechanically provable macro-level parallel bands.

    Model-authored rank groups are preserved after validation.  Missing groups
    are inferred from causal topology only when nodes are unambiguously
    parallel: alternative events establishing one state or sibling events
    consuming one state. Multiple prerequisites of one event are deliberately
    not auto-aligned because they may occur at very different causal depths;
    they share a row only when the authored semantic draft explicitly says
    they form one macro band. The function never changes nodes, causal edges,
    page boundaries, labels, or ATT&CK metadata.
    """

    node_by_id = {node.id: node for node in draft.nodes}
    causal_edges = [
        edge for edge in draft.edges if edge.relation == "causal"
    ]
    annotation_edges = [
        edge for edge in draft.edges if edge.relation == "annotation"
    ]
    incoming: dict[str, list[SemanticEdge]] = defaultdict(list)
    outgoing: dict[str, list[SemanticEdge]] = defaultdict(list)
    for edge in causal_edges:
        incoming[edge.target].append(edge)
        outgoing[edge.source].append(edge)

    normalised_pages: list[SemanticPage] = []
    for page in draft.pages:
        groups = list(page.rank_groups)
        grouped_ids = {
            node_id for group in groups for node_id in group.node_ids
        }
        candidates: list[tuple[str, list[str]]] = []

        # Independently sufficient attack methods that establish one state.
        for node in draft.nodes:
            if node.page != page.page or node.role not in {
                    "state", "continuation_state"}:
                continue
            producers = [
                edge.source for edge in incoming[node.id]
                if node_by_id[edge.source].role == "event"
            ]
            if (
                len(producers) >= 2
                and all(edge.logic == "OR" for edge in incoming[node.id])
            ):
                candidates.append(("parallel_attack_methods", producers))

        # Parallel consequences of the same established state.
        for node in draft.nodes:
            if node.page != page.page or node.role not in {
                    "state", "continuation_state"}:
                continue
            consumers = [
                edge.target for edge in outgoing[node.id]
                if node_by_id[edge.target].role == "event"
            ]
            if len(consumers) >= 2:
                candidates.append(("parallel_consequence_band", consumers))

        for rationale, candidate_ids in candidates:
            candidate_ids = list(dict.fromkeys(candidate_ids))
            if len(candidate_ids) < 2:
                continue
            if set(candidate_ids).issubset(grouped_ids):
                continue

            # Place a related context note beside the band when it annotates a
            # member or the immediate result of a member.  It remains dashed
            # and never enters the causal topology.
            attached_annotations = []
            for edge in annotation_edges:
                annotation = node_by_id[edge.source]
                if annotation.page != page.page:
                    continue
                if edge.target in candidate_ids or any(
                    causal.source == member_id
                    and causal.target == edge.target
                    for member_id in candidate_ids
                    for causal in causal_edges
                ):
                    attached_annotations.append(annotation.id)

            node_ids = [
                node_id for node_id in
                candidate_ids + attached_annotations
                if node_id not in grouped_ids
            ]
            if len(node_ids) < 2:
                continue
            group = SemanticRankGroup(
                id=f"p{page.page}_inferred_parallel_{len(groups) + 1}",
                node_ids=node_ids,
                rationale=rationale,
            )
            _validate_rank_group_causality(
                page.page, group, node_by_id, draft.edges)
            groups.append(group)
            grouped_ids.update(node_ids)

        normalised_pages.append(page.model_copy(
            update={"rank_groups": groups}))

    return draft.model_copy(update={"pages": normalised_pages})


def _normalise_quote(value: str) -> str:
    value = value.casefold().replace("\u2013", "-").replace("\u2014", "-")
    return re.sub(r"\s+", " ", value).strip()


def _attack_graph_evidence_status(
        status: EvidenceStatus) -> Literal[
            "confirmed", "reported", "alleged", "possible"]:
    if status == "confirmed":
        return "confirmed"
    if status in {
        "reported", "reported_sequence", "reported_at_high_level",
        "reported_channel_unknown",
    }:
        return "reported"
    if status in {"suspected", "probable"}:
        return "alleged"
    return "possible"


def _default_likelihood(status: EvidenceStatus) -> float:
    return {
        "confirmed": 9.0,
        "reported": 8.0,
        "reported_sequence": 8.0,
        "reported_at_high_level": 7.0,
        "reported_channel_unknown": 7.0,
        "probable": 6.0,
        "suspected": 5.0,
        "possible": 4.0,
        "possible_alternatives": 4.0,
    }.get(status, 5.0)


def _default_evidence_confidence(status: EvidenceStatus) -> int:
    return {
        "confirmed": 95,
        "reported": 85,
        "reported_sequence": 85,
        "reported_at_high_level": 75,
        "reported_channel_unknown": 75,
        "probable": 65,
        "suspected": 50,
        "possible": 35,
        "possible_alternatives": 35,
    }.get(status, 50)


def _validate_rank_group_causality(
        page_number: int,
        group: SemanticRankGroup,
        node_by_id: dict[str, SemanticNode],
        edges: list[SemanticEdge]) -> None:
    """Reject visual alignment that would conceal a causal sequence."""

    page_node_ids = {
        node.id for node in node_by_id.values()
        if node.page == page_number and node.role != "annotation"
    }
    adjacency: dict[str, list[str]] = defaultdict(list)
    causal_edge_keys: set[tuple[str, str]] = set()
    for edge in edges:
        if (
            edge.relation == "causal"
            and edge.source in page_node_ids
            and edge.target in page_node_ids
        ):
            adjacency[edge.source].append(edge.target)
            causal_edge_keys.add((edge.source, edge.target))

    def has_path(source: str, target: str) -> bool:
        pending = [source]
        visited = {source}
        while pending:
            current = pending.pop()
            for child in adjacency[current]:
                if child == target:
                    return True
                if child not in visited:
                    visited.add(child)
                    pending.append(child)
        return False

    causal_group_ids = [
        node_id for node_id in group.node_ids
        if node_by_id[node_id].role != "annotation"
    ]
    for index, left in enumerate(causal_group_ids):
        for right in causal_group_ids[index + 1:]:
            if has_path(left, right) or has_path(right, left):
                raise ValueError(
                    f"rank group {group.id!r} cannot align causally ordered "
                    f"nodes {left!r} and {right!r}")

    annotation_targets = {
        edge.source: edge.target
        for edge in edges if edge.relation == "annotation"
    }
    for annotation_id in (
        node_id for node_id in group.node_ids
        if node_by_id[node_id].role == "annotation"
    ):
        target = annotation_targets.get(annotation_id)
        if target is None:
            raise ValueError(
                f"ranked annotation {annotation_id!r} must point to its "
                "related branch")
        related = (
            target in causal_group_ids
            or any((node_id, target) in causal_edge_keys
                   for node_id in causal_group_ids)
            or any((target, node_id) in causal_edge_keys
                   for node_id in causal_group_ids)
        )
        if not related:
            raise ValueError(
                f"ranked annotation {annotation_id!r} is not adjacent to "
                f"rank group {group.id!r}")


def _unique_by_id(items, kind: str):
    by_id = {}
    for item in items:
        if item.id in by_id:
            raise ValueError(f"duplicate {kind} id {item.id!r}")
        by_id[item.id] = item
    return by_id


def _unique_pages(pages: list[SemanticPage]) -> dict[int, SemanticPage]:
    by_number = {}
    for page in pages:
        if page.page in by_number:
            raise ValueError(f"duplicate semantic page {page.page}")
        by_number[page.page] = page
    expected = list(range(1, len(pages) + 1))
    if sorted(by_number) != expected:
        raise ValueError(
            f"semantic pages must be contiguous from 1; expected {expected}")
    return by_number


def _require_node_on_page(
        node_by_id: dict[str, SemanticNode], node_id: str, page: int) -> None:
    node = node_by_id.get(node_id)
    if node is None:
        raise ValueError(f"page {page} references unknown node {node_id!r}")
    if node.page != page:
        raise ValueError(
            f"page {page} references node {node_id!r} from page {node.page}")


def _require_acyclic_pages(
        nodes: list[SemanticNode], edges: list[SemanticEdge]) -> None:
    nodes_by_page: dict[int, set[str]] = defaultdict(set)
    for node in nodes:
        if node.role != "annotation":
            nodes_by_page[node.page].add(node.id)

    for page, node_ids in nodes_by_page.items():
        adjacency: dict[str, list[str]] = defaultdict(list)
        indegree = {node_id: 0 for node_id in node_ids}
        for edge in edges:
            if edge.relation != "causal":
                continue
            if edge.source in node_ids and edge.target in node_ids:
                adjacency[edge.source].append(edge.target)
                indegree[edge.target] += 1
        queue = deque(
            node_id for node_id, degree in indegree.items() if degree == 0)
        visited = 0
        while queue:
            node_id = queue.popleft()
            visited += 1
            for target in adjacency[node_id]:
                indegree[target] -= 1
                if indegree[target] == 0:
                    queue.append(target)
        if visited != len(node_ids):
            raise ValueError(f"semantic page {page} contains a causal cycle")
