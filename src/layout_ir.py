from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import networkx as nx

from causal_split import _last_producer, event_dependency_dag
from schema import AttackGraph
from visual_syntax import (
    active_profile,
    VisualNodeSemantics,
    VisualSyntaxProfile,
    project_visual_nodes,
)


# ``state_proxy`` is retained in the type for compatibility with archived
# layout fixtures, but new Stage-A projections never create same-page proxies.
VisualRole = Literal["canonical", "state_proxy"]
Logic = Literal["AND", "OR"]


class LayoutIRValidationError(ValueError):
    """Raised when presentation data cannot reproduce its canonical graph."""


@dataclass(frozen=True)
class CanonicalTopology:
    """Ordered canonical topology used for audit and equivalence checks."""

    node_ids: tuple[str, ...]
    edges: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class LayoutNode:
    """One visual occurrence of a canonical attack-graph node."""

    visual_id: str
    canonical_id: str
    role: VisualRole
    semantics: VisualNodeSemantics
    suggested_rank: int
    # A root condition can be placed beside the event that consumes it.
    # This is a placement hint only and never becomes a causal edge.
    anchor_event_id: str | None = None


@dataclass(frozen=True)
class LayoutEdge:
    """A display edge carrying its original canonical endpoints."""

    source_visual_id: str
    target_visual_id: str
    source_canonical_id: str
    target_canonical_id: str


@dataclass(frozen=True)
class LogicGroup:
    """Explicit multi-input convergence for a future orthogonal router."""

    id: str
    target_visual_id: str
    target_canonical_id: str
    input_visual_ids: tuple[str, ...]
    canonical_parent_ids: tuple[str, ...]
    logic: Logic


@dataclass(frozen=True)
class AtomicBlock:
    """Events and directly established states that must stay together."""

    id: str
    event_ids: tuple[str, ...]
    result_state_ids: tuple[str, ...]
    input_state_ids: tuple[str, ...]
    parent_block_ids: tuple[str, ...]
    child_block_ids: tuple[str, ...]
    rank: int


@dataclass(frozen=True)
class LayoutIR:
    """Immutable, renderer-independent layout input."""

    title: str
    profile_id: str
    nodes: tuple[LayoutNode, ...]
    edges: tuple[LayoutEdge, ...]
    logic_groups: tuple[LogicGroup, ...]
    atomic_blocks: tuple[AtomicBlock, ...]
    canonical_topology: CanonicalTopology


class _DisjointEvents:
    """Small deterministic union-find for alternative event producers."""

    def __init__(self, event_ids: tuple[str, ...]):
        self.parent = {event_id: event_id for event_id in event_ids}

    def find(self, event_id: str) -> str:
        parent = self.parent[event_id]
        if parent != event_id:
            self.parent[event_id] = self.find(parent)
        return self.parent[event_id]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def _stable_unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def canonical_topology(model: AttackGraph) -> CanonicalTopology:
    """Return the input graph's ordered nodes and alternating causal edges."""

    node_ids = tuple(
        [state.id for state in model.preconditions]
        + [event.id for event in model.events]
    )
    edges: list[tuple[str, str]] = []
    for state in model.preconditions:
        edges.extend((event_id, state.id) for event_id in state.parents)
    for event in model.events:
        edges.extend((state_id, event.id) for state_id in event.parents)
    return CanonicalTopology(node_ids=node_ids, edges=tuple(edges))


def _canonical_graph(model: AttackGraph) -> nx.DiGraph:
    topology = canonical_topology(model)
    graph = nx.DiGraph()
    graph.add_nodes_from(topology.node_ids)
    graph.add_edges_from(topology.edges)
    if not nx.is_directed_acyclic_graph(graph):
        raise LayoutIRValidationError(
            "AGVS-SP layout requires an acyclic canonical attack graph"
        )
    return graph


def _longest_path_levels(graph: nx.DiGraph) -> dict[str, int]:
    levels: dict[str, int] = {}
    for node_id in nx.topological_sort(graph):
        parents = list(graph.predecessors(node_id))
        levels[node_id] = (
            0 if not parents else max(levels[parent] for parent in parents) + 1
        )
    return levels


def _build_atomic_blocks(
    model: AttackGraph,
) -> tuple[tuple[AtomicBlock, ...], dict[str, str]]:
    """Build deterministic event/result blocks without changing causality."""

    event_ids = tuple(event.id for event in model.events)
    event_order = {event_id: index for index, event_id in enumerate(event_ids)}
    union = _DisjointEvents(event_ids)

    # If several events establish the same state, they are alternative
    # producers of that result.  The state and all of its alternatives are
    # one indivisible visual unit.
    # Only events that cannot reach one another. Producers joined by a
    # dependency path are stages of one route, not substitutes for it, and
    # merging them puts that dependency inside a block, which closes a cycle
    # in the block graph that the node graph never had. The rule and its
    # reachability data are shared with causal_split, so the paginator and the
    # layout cannot disagree about which events may share a block.
    dependencies = event_dependency_dag(model)
    descendants = {
        event_id: nx.descendants(dependencies, event_id)
        for event_id in dependencies
    }
    group_members = {event_id: {event_id} for event_id in event_ids}

    def _independent(left: str, right: str) -> bool:
        first_group = group_members[union.find(left)]
        second_group = group_members[union.find(right)]
        if first_group is second_group:
            return True
        return not any(
            other in descendants.get(member, ())
            or member in descendants.get(other, ())
            for member in first_group
            for other in second_group
        )

    for state in model.preconditions:
        if len(state.parents) > 1:
            for other in state.parents[1:]:
                if not _independent(state.parents[0], other):
                    continue
                left_root = union.find(state.parents[0])
                right_root = union.find(other)
                if left_root == right_root:
                    continue
                union.union(state.parents[0], other)
                group_members[union.find(state.parents[0])] = (
                    group_members[left_root] | group_members[right_root])

    grouped: dict[str, list[str]] = {}
    for event_id in event_ids:
        grouped.setdefault(union.find(event_id), []).append(event_id)
    ordered_groups = sorted(
        grouped.values(),
        key=lambda group: min(event_order[event_id] for event_id in group),
    )

    event_to_block: dict[str, str] = {}
    block_events: dict[str, tuple[str, ...]] = {}
    for index, group in enumerate(ordered_groups):
        block_id = f"block_{index:03d}"
        ordered = tuple(sorted(group, key=event_order.get))
        block_events[block_id] = ordered
        for event_id in ordered:
            event_to_block[event_id] = block_id

    state_to_producer_block: dict[str, str] = {}
    result_states: dict[str, list[str]] = {
        block_id: [] for block_id in block_events
    }
    for state in model.preconditions:
        if not state.parents:
            continue
        # A state whose producers depend on one another has several producing
        # blocks by design. It exists once the last of them has run, so it is
        # attributed there and everything consuming it follows all producers.
        block_id = event_to_block[
            _last_producer(state.parents, event_order, descendants)]
        state_to_producer_block[state.id] = block_id
        result_states[block_id].append(state.id)

    block_graph = nx.DiGraph()
    block_graph.add_nodes_from(block_events)
    input_states: dict[str, list[str]] = {
        block_id: [] for block_id in block_events
    }
    for event in model.events:
        target_block = event_to_block[event.id]
        for state_id in event.parents:
            source_block = state_to_producer_block.get(state_id)
            if source_block != target_block:
                input_states[target_block].append(state_id)
            if source_block is not None and source_block != target_block:
                block_graph.add_edge(source_block, target_block)

    if not nx.is_directed_acyclic_graph(block_graph):
        raise LayoutIRValidationError(
            "event/result atomic blocks unexpectedly formed a cycle"
        )
    block_levels = _longest_path_levels(block_graph)
    block_order = {block_id: index for index, block_id in enumerate(block_events)}

    blocks: list[AtomicBlock] = []
    for block_id, events in block_events.items():
        parents = tuple(sorted(
            block_graph.predecessors(block_id),
            key=block_order.get,
        ))
        children = tuple(sorted(
            block_graph.successors(block_id),
            key=block_order.get,
        ))
        blocks.append(AtomicBlock(
            id=block_id,
            event_ids=events,
            result_state_ids=tuple(result_states[block_id]),
            input_state_ids=_stable_unique(input_states[block_id]),
            parent_block_ids=parents,
            child_block_ids=children,
            rank=block_levels[block_id],
        ))
    return tuple(blocks), event_to_block


def build_layout_ir(
    model: AttackGraph,
    profile: VisualSyntaxProfile | None = None,
) -> LayoutIR:
    """Project a validated graph into the reversible Stage-A visual IR."""

    graph = _canonical_graph(model)
    levels = _longest_path_levels(graph)
    profile = profile or active_profile()
    projected = project_visual_nodes(model, profile)
    source_order = {node.id: node.source_index for node in projected}
    root_state_ids = {
        state.id for state in model.preconditions if not state.parents
    }

    consumers: dict[str, list[str]] = {
        state_id: [] for state_id in root_state_ids
    }
    for event in model.events:
        for state_id in event.parents:
            if state_id in root_state_ids:
                consumers[state_id].append(event.id)
    for state_id in consumers:
        consumers[state_id].sort(
            key=lambda event_id: (levels[event_id], source_order[event_id])
        )

    nodes: list[LayoutNode] = []
    for semantics in projected:
        # A root used by exactly one event can stay local to that event's
        # atomic block. A shared prerequisite deliberately has no single
        # anchor: the macro planner places its one ellipse above all consumers.
        root_consumers = consumers.get(semantics.id, [])
        anchor = root_consumers[0] if len(root_consumers) == 1 else None
        nodes.append(LayoutNode(
            visual_id=semantics.id,
            canonical_id=semantics.id,
            role="canonical",
            semantics=semantics,
            suggested_rank=levels[semantics.id],
            anchor_event_id=anchor,
        ))

    topology = canonical_topology(model)
    edges: list[LayoutEdge] = []
    for source_id, target_id in topology.edges:
        edges.append(LayoutEdge(
            source_visual_id=source_id,
            target_visual_id=target_id,
            source_canonical_id=source_id,
            target_canonical_id=target_id,
        ))

    logic_groups: list[LogicGroup] = []
    for semantics in projected:
        if len(semantics.parents) < 2:
            continue
        logic_groups.append(LogicGroup(
            id=f"logic__{semantics.id}",
            target_visual_id=semantics.id,
            target_canonical_id=semantics.id,
            input_visual_ids=tuple(
                semantics.parents
            ),
            canonical_parent_ids=semantics.parents,
            logic=semantics.join,
        ))

    atomic_blocks, _ = _build_atomic_blocks(model)
    layout_ir = LayoutIR(
        title=model.title,
        profile_id=profile.profile_id,
        nodes=tuple(nodes),
        edges=tuple(edges),
        logic_groups=tuple(logic_groups),
        atomic_blocks=atomic_blocks,
        canonical_topology=topology,
    )
    validate_layout_ir(model, layout_ir, profile)
    return layout_ir


def reconstruct_canonical_topology(layout_ir: LayoutIR) -> CanonicalTopology:
    """Collapse display copies and recover the canonical node/edge topology."""

    node_ids = tuple(
        node.canonical_id
        for node in layout_ir.nodes
        if node.role == "canonical"
    )
    edges = tuple(
        (edge.source_canonical_id, edge.target_canonical_id)
        for edge in layout_ir.edges
    )
    return CanonicalTopology(node_ids=node_ids, edges=edges)


def validate_layout_ir(
    model: AttackGraph,
    layout_ir: LayoutIR,
    profile: VisualSyntaxProfile | None = None,
) -> None:
    """Reject any presentation projection that changes canonical meaning."""

    profile = profile or active_profile()
    expected = canonical_topology(model)
    rebuilt = reconstruct_canonical_topology(layout_ir)
    if rebuilt != expected or layout_ir.canonical_topology != expected:
        raise LayoutIRValidationError(
            "layout IR does not reconstruct the canonical graph exactly"
        )

    visual_ids = [node.visual_id for node in layout_ir.nodes]
    if len(visual_ids) != len(set(visual_ids)):
        raise LayoutIRValidationError("layout visual ids must be unique")

    expected_semantics = {
        node.id: node for node in project_visual_nodes(model, profile)
    }
    primary_nodes = {
        node.canonical_id: node
        for node in layout_ir.nodes
        if node.role == "canonical"
    }
    if set(primary_nodes) != set(expected.node_ids):
        raise LayoutIRValidationError(
            "every canonical node needs exactly one primary visual occurrence"
        )
    for canonical_id, node in primary_nodes.items():
        if node.semantics != expected_semantics[canonical_id]:
            raise LayoutIRValidationError(
                f"visual metadata changed for {canonical_id!r}"
            )

    root_state_ids = {
        state.id for state in model.preconditions if not state.parents
    }
    for node in layout_ir.nodes:
        if node.role != "state_proxy":
            continue
        if (
            node.canonical_id not in root_state_ids
            or node.semantics.kind != "state"
        ):
            raise LayoutIRValidationError(
                "only root conditions may have Stage-A display proxies"
            )
        if node.semantics != expected_semantics[node.canonical_id]:
            raise LayoutIRValidationError(
                f"proxy metadata changed for {node.canonical_id!r}"
            )

    if len(layout_ir.edges) != len(expected.edges):
        raise LayoutIRValidationError(
            "one and only one display edge must represent each canonical edge"
        )
    known_visual_ids = set(visual_ids)
    for edge in layout_ir.edges:
        if (
            edge.source_visual_id not in known_visual_ids
            or edge.target_visual_id not in known_visual_ids
        ):
            raise LayoutIRValidationError(
                "layout edge references an unknown visual occurrence"
            )

    node_by_id = {node.id: node for node in project_visual_nodes(model, profile)}
    expected_logic_targets = {
        node.id for node in node_by_id.values() if len(node.parents) > 1
    }
    actual_logic_targets = {
        group.target_canonical_id for group in layout_ir.logic_groups
    }
    if actual_logic_targets != expected_logic_targets:
        raise LayoutIRValidationError(
            "multi-input logic groups do not match canonical targets"
        )
    for group in layout_ir.logic_groups:
        semantics = node_by_id[group.target_canonical_id]
        if (
            group.canonical_parent_ids != semantics.parents
            or group.logic != semantics.join
        ):
            raise LayoutIRValidationError(
                f"logic changed for {group.target_canonical_id!r}"
            )
        input_canonical_ids = tuple(
            next(
                node.canonical_id
                for node in layout_ir.nodes
                if node.visual_id == visual_id
            )
            for visual_id in group.input_visual_ids
        )
        if input_canonical_ids != semantics.parents:
            raise LayoutIRValidationError(
                f"logic inputs changed for {group.target_canonical_id!r}"
            )

    block_event_ids = [
        event_id
        for block in layout_ir.atomic_blocks
        for event_id in block.event_ids
    ]
    expected_event_ids = [event.id for event in model.events]
    if (
        len(block_event_ids) != len(set(block_event_ids))
        or set(block_event_ids) != set(expected_event_ids)
    ):
        raise LayoutIRValidationError(
            "atomic blocks must cover every canonical event exactly once"
        )
    event_to_block = {
        event_id: block.id
        for block in layout_ir.atomic_blocks
        for event_id in block.event_ids
    }
    # Producers of one state share a block only when they are genuine
    # alternatives. Where one depends on another they are stages of a single
    # route, and blocks are built to keep them apart: merging them would put a
    # dependency inside a block and close a cycle in the block graph.
    #
    # What is checked here is the SAFETY property -- no block contains two
    # events where one depends on the other. The completeness property, "every
    # pair of independent producers shares a block", was checked instead, and
    # it is not satisfiable. Independence does not compose. A real run produced
    # a state with eight producers where seven were mutually independent but
    # e_dump_lsass enabled e_run_mimikatz: dumping the process memory is what
    # Mimikatz then reads. No partition puts all seven independent pairs
    # together while keeping that one dependent pair apart, so the check
    # rejected a graph the builder had assembled correctly.
    #
    # Keeping alternatives on one page is a layout preference, and the builder
    # pursues it as far as the dependencies allow. It is not an invariant, and
    # asserting it as one cost a valid graph and two paid calls.
    dependencies = event_dependency_dag(model)
    descendants = {
        event_id: nx.descendants(dependencies, event_id)
        for event_id in dependencies
    }
    block_of: dict[str, list[str]] = {}
    for event_id, block_id in event_to_block.items():
        block_of.setdefault(block_id, []).append(event_id)
    for block_id, members in block_of.items():
        for index, first in enumerate(sorted(members)):
            for second in sorted(members)[index + 1:]:
                if (second in descendants.get(first, ())
                        or first in descendants.get(second, ())):
                    raise LayoutIRValidationError(
                        f"atomic block {block_id!r} contains a dependency "
                        f"between {first!r} and {second!r}; one enables the "
                        "other, so they cannot share a block"
                    )
