from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from textwrap import wrap

from semantic_draft import (
    IncidentSemanticDraft,
    SemanticNode,
    normalise_parallel_rank_groups,
)


NODE_WIDTH = 150
ANNOTATION_WIDTH = 190
MIN_NODE_HEIGHT = 64
ROW_GAP = 24
COLUMN_GAP = 30
SIDE_MARGIN = 28
TOP_MARGIN = 52
BOTTOM_MARGIN = 32
MIN_GRAPH_WIDTH = 820


class SemanticLayoutValidationError(ValueError):
    """Raised when deterministic geometry violates semantic constraints."""


@dataclass(frozen=True)
class SemanticPlannedNode:
    id: str
    canonical_id: str
    role: str
    shape: str
    branch: str
    rank: int
    x: int
    y: int
    width: int
    height: int

    @property
    def right(self) -> int:
        return self.x + self.width

    @property
    def bottom(self) -> int:
        return self.y + self.height

    @property
    def cx(self) -> int:
        return self.x + self.width // 2

    @property
    def cy(self) -> int:
        return self.y + self.height // 2


@dataclass(frozen=True)
class SemanticPlannedEdge:
    source: str
    target: str
    relation: str
    style: str
    logic: str | None


@dataclass(frozen=True)
class SemanticPageLayout:
    page: int
    title: str
    width: int
    height: int
    nodes: tuple[SemanticPlannedNode, ...]
    edges: tuple[SemanticPlannedEdge, ...]
    entry_nodes: tuple[str, ...]
    exit_nodes: tuple[str, ...]
    rank_groups: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class SemanticLayoutPlan:
    title: str
    pages: tuple[SemanticPageLayout, ...]


class _UnionFind:
    def __init__(self, node_ids: list[str]):
        self.parent = {node_id: node_id for node_id in node_ids}

    def find(self, node_id: str) -> str:
        parent = self.parent[node_id]
        if parent != node_id:
            self.parent[node_id] = self.find(parent)
        return self.parent[node_id]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def _node_width(node: SemanticNode) -> int:
    return ANNOTATION_WIDTH if node.role == "annotation" else NODE_WIDTH


def _node_height(node: SemanticNode) -> int:
    line_width = 27 if node.role == "annotation" else 22
    lines = wrap(
        node.label,
        width=line_width,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    return max(MIN_NODE_HEIGHT, 24 + len(lines) * 15)


def _component_ranks(
        page_node_ids: list[str],
        rank_groups: list[list[str]],
        causal_edges: list[tuple[str, str]],
        annotation_edges: list[tuple[str, str]]) -> dict[str, int]:
    """Collapse same-row constraints, then rank the resulting causal DAG."""

    union = _UnionFind(page_node_ids)
    ranked_ids = {node_id for group in rank_groups for node_id in group}
    for group in rank_groups:
        for node_id in group[1:]:
            union.union(group[0], node_id)

    # A context note without an explicit macro band sits beside its target.
    for source, target in annotation_edges:
        if source not in ranked_ids:
            union.union(source, target)

    components: dict[str, list[str]] = defaultdict(list)
    for node_id in page_node_ids:
        components[union.find(node_id)].append(node_id)

    adjacency: dict[str, set[str]] = defaultdict(set)
    indegree = {component: 0 for component in components}
    for source, target in causal_edges:
        source_component = union.find(source)
        target_component = union.find(target)
        if source_component == target_component:
            raise SemanticLayoutValidationError(
                f"same-row constraint hides causal edge {source!r} -> "
                f"{target!r}")
        if target_component not in adjacency[source_component]:
            adjacency[source_component].add(target_component)
            indegree[target_component] += 1

    queue = deque(sorted(
        component for component, degree in indegree.items() if degree == 0
    ))
    component_rank = {component: 0 for component in components}
    visited = 0
    while queue:
        component = queue.popleft()
        visited += 1
        for child in sorted(adjacency[component]):
            component_rank[child] = max(
                component_rank[child], component_rank[component] + 1)
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    if visited != len(components):
        raise SemanticLayoutValidationError(
            "same-row constraints created a component cycle")
    return {
        node_id: component_rank[union.find(node_id)]
        for node_id in page_node_ids
    }


def _branch_order(
        page_node_ids: list[str],
        node_by_id: dict[str, SemanticNode],
        rank_groups: list[list[str]]) -> dict[str, int]:
    """Use the widest authored band as the page's stable left-right order."""

    branches: list[str] = []
    if rank_groups:
        widest = max(rank_groups, key=len)
        branches.extend(
            node_by_id[node_id].branch for node_id in widest
        )
    branches.extend(node_by_id[node_id].branch for node_id in page_node_ids)
    return {
        branch: index
        for index, branch in enumerate(dict.fromkeys(branches))
    }


def _ordered_rank_nodes(
        node_ids: list[str],
        node_by_id: dict[str, SemanticNode],
        branch_order: dict[str, int],
        rank_groups: list[list[str]]) -> list[str]:
    authored_position = {
        node_id: (group_index, position)
        for group_index, group in enumerate(rank_groups)
        for position, node_id in enumerate(group)
    }
    source_position = {
        node_id: index for index, node_id in enumerate(node_by_id)
    }
    return sorted(
        node_ids,
        key=lambda node_id: (
            authored_position.get(node_id, (10_000, 10_000)),
            branch_order[node_by_id[node_id].branch],
            source_position[node_id],
        ),
    )


def _fit_rank_centres(
        ordered_ids: list[str],
        desired: list[float],
        node_by_id: dict[str, SemanticNode],
        graph_width: int) -> dict[str, int]:
    # Fit in stable order while guaranteeing non-overlap.
    centres: list[float] = []
    for index, node_id in enumerate(ordered_ids):
        half_width = _node_width(node_by_id[node_id]) / 2
        center = desired[index]
        if centres:
            previous_id = ordered_ids[index - 1]
            minimum = (
                centres[-1]
                + _node_width(node_by_id[previous_id]) / 2
                + COLUMN_GAP
                + half_width
            )
            center = max(center, minimum)
        centres.append(center)

    underflow = (
        SIDE_MARGIN
        + _node_width(node_by_id[ordered_ids[0]]) / 2
        - centres[0]
    )
    if underflow > 0:
        centres = [center + underflow for center in centres]
    overflow = (
        centres[-1]
        + _node_width(node_by_id[ordered_ids[-1]]) / 2
        + SIDE_MARGIN
        - graph_width
    )
    if overflow > 0:
        centres = [center - overflow for center in centres]
    return {
        node_id: round(center)
        for node_id, center in zip(ordered_ids, centres)
    }


def plan_semantic_layout(
        draft: IncidentSemanticDraft) -> SemanticLayoutPlan:
    """Produce page-local deterministic geometry from validated semantics."""

    draft = normalise_parallel_rank_groups(draft)
    node_by_id = {node.id: node for node in draft.nodes}
    pages: list[SemanticPageLayout] = []

    for semantic_page in draft.pages:
        page_nodes = [
            node for node in draft.nodes if node.page == semantic_page.page
        ]
        page_node_ids = [node.id for node in page_nodes]
        page_node_set = set(page_node_ids)
        page_edges = [
            edge for edge in draft.edges
            if edge.source in page_node_set and edge.target in page_node_set
        ]
        causal_edges = [
            (edge.source, edge.target)
            for edge in page_edges if edge.relation == "causal"
        ]
        causal_parents: dict[str, list[str]] = defaultdict(list)
        for source, target in causal_edges:
            causal_parents[target].append(source)
        annotation_edges = [
            (edge.source, edge.target)
            for edge in page_edges if edge.relation == "annotation"
        ]
        rank_groups = [
            list(group.node_ids) for group in semantic_page.rank_groups
        ]
        ranks = _component_ranks(
            page_node_ids,
            rank_groups,
            causal_edges,
            annotation_edges,
        )
        by_rank: dict[int, list[str]] = defaultdict(list)
        for node_id, rank in ranks.items():
            by_rank[rank].append(node_id)

        branch_order = _branch_order(
            page_node_ids, node_by_id, rank_groups)
        maximum_row_width = max(
            (
                sum(_node_width(node_by_id[node_id]) for node_id in ids)
                + COLUMN_GAP * max(0, len(ids) - 1)
                + SIDE_MARGIN * 2
                for ids in by_rank.values()
            ),
            default=MIN_GRAPH_WIDTH,
        )
        graph_width = max(MIN_GRAPH_WIDTH, maximum_row_width)

        row_y: dict[int, int] = {}
        y_cursor = TOP_MARGIN
        for rank in sorted(by_rank):
            row_y[rank] = y_cursor
            y_cursor += max(
                _node_height(node_by_id[node_id])
                for node_id in by_rank[rank]
            ) + ROW_GAP

        planned_nodes: list[SemanticPlannedNode] = []
        centres_by_id: dict[str, int] = {}
        macro_group_desired: dict[str, float] = {}
        for group in semantic_page.rank_groups:
            if group.rationale not in {
                "parallel_prerequisite_band",
                "parallel_consequence_band",
            }:
                continue
            total_width = (
                sum(_node_width(node_by_id[node_id])
                    for node_id in group.node_ids)
                + COLUMN_GAP * (len(group.node_ids) - 1)
            )
            cursor = (graph_width - total_width) / 2
            for node_id in group.node_ids:
                width = _node_width(node_by_id[node_id])
                macro_group_desired[node_id] = cursor + width / 2
                cursor += width + COLUMN_GAP
        for rank in sorted(by_rank):
            ordered_ids = _ordered_rank_nodes(
                by_rank[rank], node_by_id, branch_order, rank_groups)
            compact_group_desired: dict[str, float] = {}
            for group in semantic_page.rank_groups:
                if (
                    group.rationale in {
                        "parallel_prerequisite_band",
                        "parallel_consequence_band",
                    }
                    or not set(group.node_ids).issubset(by_rank[rank])
                ):
                    continue
                parent_centres = [
                    centres_by_id[parent_id]
                    for node_id in group.node_ids
                    for parent_id in causal_parents[node_id]
                    if parent_id in centres_by_id
                ]
                anchor = (
                    sum(parent_centres) / len(parent_centres)
                    if parent_centres else graph_width / 2
                )
                total_width = (
                    sum(_node_width(node_by_id[node_id])
                        for node_id in group.node_ids)
                    + COLUMN_GAP * (len(group.node_ids) - 1)
                )
                cursor = anchor - total_width / 2
                for node_id in group.node_ids:
                    width = _node_width(node_by_id[node_id])
                    compact_group_desired[node_id] = cursor + width / 2
                    cursor += width + COLUMN_GAP
            desired: list[float] = []
            for node_id in ordered_ids:
                if node_id in macro_group_desired:
                    desired.append(macro_group_desired[node_id])
                    continue
                if node_id in compact_group_desired:
                    desired.append(compact_group_desired[node_id])
                    continue
                parents = [
                    centres_by_id[parent_id]
                    for parent_id in causal_parents[node_id]
                    if parent_id in centres_by_id
                ]
                if parents:
                    desired.append(sum(parents) / len(parents))
                    continue
                semantic = node_by_id[node_id]
                if (
                    node_id in semantic_page.entry_nodes
                    or semantic.role == "continuation_state"
                ):
                    desired.append(graph_width / 2)
                    continue
                branch_count = max(1, len(branch_order))
                branch_index = branch_order[semantic.branch]
                desired.append(
                    graph_width
                    * (branch_index + 0.5)
                    / branch_count
                )

            centres = _fit_rank_centres(
                ordered_ids, desired, node_by_id, graph_width)
            centres_by_id.update(centres)
            for node_id in ordered_ids:
                semantic = node_by_id[node_id]
                width = _node_width(semantic)
                height = _node_height(semantic)
                planned_nodes.append(SemanticPlannedNode(
                    id=node_id,
                    canonical_id=(
                        getattr(semantic, "canonical_id", None)
                        or semantic.id
                    ),
                    role=semantic.role,
                    shape=semantic.shape,
                    branch=semantic.branch,
                    rank=rank,
                    x=round(centres[node_id] - width / 2),
                    y=row_y[rank],
                    width=width,
                    height=height,
                ))

        page_layout = SemanticPageLayout(
            page=semantic_page.page,
            title=semantic_page.title,
            width=graph_width,
            height=max(
                (node.bottom for node in planned_nodes),
                default=TOP_MARGIN,
            ) + BOTTOM_MARGIN,
            nodes=tuple(planned_nodes),
            edges=tuple(SemanticPlannedEdge(
                source=edge.source,
                target=edge.target,
                relation=edge.relation,
                style=edge.style,
                logic=edge.logic,
            ) for edge in page_edges),
            entry_nodes=tuple(semantic_page.entry_nodes),
            exit_nodes=tuple(semantic_page.exit_nodes),
            rank_groups=tuple(tuple(group) for group in rank_groups),
        )
        validate_semantic_page_layout(draft, page_layout)
        pages.append(page_layout)

    return SemanticLayoutPlan(title=draft.title, pages=tuple(pages))


def validate_semantic_page_layout(
        draft: IncidentSemanticDraft,
        page: SemanticPageLayout) -> None:
    """Prove node coverage, same-row alignment, and downward causality."""

    expected_ids = {
        node.id for node in draft.nodes if node.page == page.page
    }
    actual_ids = [node.id for node in page.nodes]
    if len(actual_ids) != len(set(actual_ids)) or set(actual_ids) != expected_ids:
        raise SemanticLayoutValidationError(
            f"page {page.page} must place every semantic node exactly once")

    planned = {node.id: node for node in page.nodes}
    for group in page.rank_groups:
        if len({planned[node_id].rank for node_id in group}) != 1:
            raise SemanticLayoutValidationError(
                f"page {page.page} rank group is not aligned: {group!r}")

    for edge in page.edges:
        if edge.relation != "causal":
            continue
        if planned[edge.target].rank <= planned[edge.source].rank:
            raise SemanticLayoutValidationError(
                f"non-downward causal edge {edge.source!r} -> "
                f"{edge.target!r}")

    by_rank: dict[int, list[SemanticPlannedNode]] = defaultdict(list)
    for node in page.nodes:
        by_rank[node.rank].append(node)
    for rank, nodes in by_rank.items():
        ordered = sorted(nodes, key=lambda node: node.x)
        for left, right in zip(ordered, ordered[1:]):
            if left.right + COLUMN_GAP > right.x:
                raise SemanticLayoutValidationError(
                    f"page {page.page} nodes overlap on rank {rank}: "
                    f"{left.id!r}, {right.id!r}")
