"""Lossless causal-boundary pagination for validated attack graphs.

The extraction pipeline decides *what* the attack graph means.  This module
only decides which already-validated nodes appear on each rendered page.

The split contract is deliberately stricter than a tactic- or list-based
split:

* an event and every state it directly establishes are one atomic block;
* events that are alternative producers of the same state remain together;
* cuts occur through state boundaries, never through an event;
* a boundary state may be repeated as a bridge, but an event may not;
* the union of the page graphs must reconstruct every original node and edge.

This lets a long graph be rendered as two or more readable figures without
changing labels, ATT&CK metadata, scores, or causal semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import networkx as nx

from schema import AttackGraph


DEFAULT_MAX_EVENTS_PER_PART = 12
DEFAULT_MAX_RANKS = 9

# A page is bounded in shape, not in width alone. Events at the same causal
# depth are drawn side by side in one rank, so a wide fan-out produces an
# unreadable page even when the event and rank budgets are both satisfied.
# Same-depth events are mutually independent by construction, so the fan may be
# divided across pages without cutting any causal edge.
#
# Bounding width on its own is not enough: one page came back three ranks tall
# and six events wide, at an aspect ratio of 0.26, while its neighbour was nine
# ranks tall and two wide at 2.07. Width has to be bounded against height.
#
# Measured on the planner's own geometry, a rank is about 137 units tall and a
# node about 270 wide, and an event layer occupies two visual ranks plus the
# leading input rank. A page of L event layers and W parallel events therefore
# has an aspect ratio near (2L + 1) * 0.507 / W. Checked against three real
# pages: L=3,W=4 gave 0.94; L=2,W=4 gave 0.50; L=1,W=6 gave 0.26.
#
# The cap below is for the narrowest case, a page of one event layer, and the
# rule scales it with height from there. It is calibrated against the rendered
# `page_aspect_ratio`, not against the planner's own width and height: the
# legend column adds page width that the planner never sees, so a plan measuring
# 0.36 renders at 0.25. Calibrating against the plan was tried first and read
# about 30% high.
#
# Aiming at a 2:1 rendered page was measured and rejected. It divided one
# report's eight-way credential convergence across three pages -- the one
# structure on that page worth seeing whole -- for six pages where four had
# been enough. The target is roughly 3:1, which a landscape slide or a
# landscape A4 page carries.
#
# This is now where the search starts, not where it ends. `plan_causal_split`
# measures the pages this produces and tightens the count if they are too wide
# to print, because a count of actions and a width in pixels are not the same
# quantity: a rank of four actions can establish a dozen states beside them.
DEFAULT_MAX_PARALLEL_EVENTS = 4

# How many times its own page count a graph may grow to meet the width budget.
# A judgement, not a measurement: see the note in `plan_causal_split`. Two is
# the point at which a reader is following more bridges than graph.
PAGE_COUNT_CEILING = 2

# How far over the width budget a page may be before pages are spent narrowing
# it. One run's natural plan was three pages at 1260px against a 1240px budget
# -- labels at 7.9pt against an 8.0pt floor -- and the planner bought two extra
# pages to close a gap of twenty pixels. The floor is a convention, not a
# threshold in anyone's eye, so paying a certain cost for an imperceptible gain
# is the wrong trade. `layout_quality` still reports against the strict budget,
# so the tolerance changes what is bought, never what is claimed.
WIDTH_BUDGET_TOLERANCE = 0.05


def max_parallel_events_for(
    event_layers: int,
    absolute_cap: int = DEFAULT_MAX_PARALLEL_EVENTS,
) -> int:
    """How wide a page of this many event layers is allowed to be.

    Width is allowed to grow, and only grow, with height. An event layer
    occupies two visual ranks, plus the leading input rank, so a page of L
    layers may be (2L + 1)/3 times as wide as the one-layer case.

    ``absolute_cap`` is the caller's budget for a single-layer page. Scaling
    the whole rule from it keeps the two limits consistent: a caller that asks
    for narrower pages must not end up with a division the pagination then
    refuses to accept.
    """

    visual_ranks = 2 * max(1, event_layers) + 1
    return max(1, absolute_cap * visual_ranks // 3)


@dataclass(frozen=True)
class CausalSplitPart:
    """One page in a causal split plan.

    ``bridge_in_ids`` are states produced on an earlier page and repeated here
    as roots. ``bridge_out_ids`` are states established here and consumed on a
    later page.  Root conditions reused on several pages are not bridges
    because they have no producer in the attack graph.
    """

    index: int
    component_index: int
    event_ids: tuple[str, ...]
    precondition_ids: tuple[str, ...]
    bridge_in_ids: tuple[str, ...]
    bridge_out_ids: tuple[str, ...]


@dataclass(frozen=True)
class CausalSplitPlan:
    """Immutable, auditable pagination decision."""

    parts: tuple[CausalSplitPart, ...]
    original_node_count: int
    original_edge_count: int
    estimated_ranks: int

    @property
    def is_split(self) -> bool:
        return len(self.parts) > 1


class _DisjointEvents:
    """Small union-find used to form event/result-state atomic blocks."""

    def __init__(self, event_ids: Iterable[str]):
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


def _canonical_graph(model: AttackGraph) -> nx.DiGraph:
    graph = nx.DiGraph()
    for precondition in model.preconditions:
        graph.add_node(precondition.id, kind="precondition")
        for parent in precondition.parents:
            graph.add_edge(parent, precondition.id)
    for event in model.events:
        graph.add_node(event.id, kind="event")
        for parent in event.parents:
            graph.add_edge(parent, event.id)
    if not nx.is_directed_acyclic_graph(graph):
        raise ValueError("causal splitting requires an acyclic attack graph")
    return graph


def _longest_path_levels(graph: nx.DiGraph) -> dict[str, int]:
    levels: dict[str, int] = {}
    for node_id in nx.topological_sort(graph):
        parents = list(graph.predecessors(node_id))
        levels[node_id] = (
            0 if not parents else max(levels[parent] for parent in parents) + 1
        )
    return levels


def event_dependency_dag(model) -> nx.DiGraph:
    """Event -> event when a state one produces is consumed by the other.

    Shared with layout_ir so both stages group events the same way; two
    different answers to "may these share a block?" would let one stage build
    a page the other cannot lay out.
    """

    producers: dict[str, list[str]] = {}
    for precondition in model.preconditions:
        if precondition.parents:
            producers[precondition.id] = list(precondition.parents)
    dag = nx.DiGraph()
    dag.add_nodes_from(event.id for event in model.events)
    for event in model.events:
        for precondition_id in event.parents:
            for producer in producers.get(precondition_id, ()):
                if producer != event.id:
                    dag.add_edge(producer, event.id)
    return dag


def _last_producer(parents, event_order, descendants) -> str:
    """The producer no other producer depends on, ties broken by order."""

    candidates = [
        event_id for event_id in parents
        if not any(other in descendants.get(event_id, ())
                   for other in parents if other != event_id)
    ] or list(parents)
    return max(candidates, key=lambda event_id: event_order.get(event_id, 0))


def _event_blocks(
    model: AttackGraph,
    max_events_per_block: int | None = None,
) -> tuple[
    dict[str, str],
    dict[str, tuple[str, ...]],
    dict[str, str],
    nx.DiGraph,
]:
    """Return event->block, block->events, produced-state->block, block DAG."""

    event_order = {event.id: index for index, event in enumerate(model.events)}
    union = _DisjointEvents(event_order)

    # Several events producing the same state are usually OR alternatives, and
    # keeping them together stops the split from fragmenting the alternative
    # set. But "usually" is not "always": a state can also be the shared
    # outcome of steps that run in sequence. STOLEN PENCIL produced exactly
    # that -- "persistent foothold retained" listed three producers, one of
    # which consumed credentials the other two had to obtain first. Merging
    # them put a dependency inside a single block, and the block graph then
    # closed a cycle the node graph never had.
    #
    # So merge only events that cannot reach one another. Two events joined by
    # a path are stages of one route, not substitutes for it.
    dependencies = event_dependency_dag(model)
    descendants = {
        event_id: nx.descendants(dependencies, event_id)
        for event_id in dependencies
    }
    group_members = {event_id: {event_id} for event_id in event_order}

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

    for precondition in model.preconditions:
        if len(precondition.parents) > 1:
            first = precondition.parents[0]
            for other in precondition.parents[1:]:
                if not _independent(first, other):
                    continue
                left_root, right_root = union.find(first), union.find(other)
                if left_root == right_root:
                    continue
                union.union(first, other)
                group_members[union.find(first)] = (
                    group_members[left_root] | group_members[right_root])

    grouped: dict[str, list[str]] = {}
    for event_id in event_order:
        grouped.setdefault(union.find(event_id), []).append(event_id)

    ordered_groups = sorted(
        grouped.values(),
        key=lambda group: min(event_order[event_id] for event_id in group),
    )
    event_to_block: dict[str, str] = {}
    block_events: dict[str, tuple[str, ...]] = {}
    # A group is merged only from events that cannot reach one another, so its
    # members are mutually independent by construction and dividing one splits
    # no causal chain. Keeping an alternative set whole is a readability
    # preference; a group wider than a page defeats the purpose. STOLEN PENCIL
    # produced a group of eight credential-dumping events sharing one result
    # state, which is correct modelling and an unreadable single rank.
    number = 0
    for group in ordered_groups:
        ordered = tuple(sorted(group, key=event_order.get))
        limit = max_events_per_block or len(ordered)
        for start in range(0, len(ordered), limit):
            block_id = f"block_{number}"
            chunk = ordered[start:start + limit]
            block_events[block_id] = chunk
            for event_id in chunk:
                event_to_block[event_id] = block_id
            number += 1

    produced_by_block: dict[str, str] = {}
    for precondition in model.preconditions:
        if precondition.parents:
            # Producers that depend on one another were deliberately left in
            # separate blocks above, so a state can have several producing
            # blocks. It exists once all of them have run, so it belongs with
            # the last: anything consuming it then sits after every producer.
            produced_by_block[precondition.id] = event_to_block[
                _last_producer(precondition.parents, event_order, descendants)]

    block_graph = nx.DiGraph()
    block_graph.add_nodes_from(block_events)
    for event in model.events:
        target_block = event_to_block[event.id]
        for precondition_id in event.parents:
            source_block = produced_by_block.get(precondition_id)
            if source_block is not None and source_block != target_block:
                block_graph.add_edge(source_block, target_block)

    if not nx.is_directed_acyclic_graph(block_graph):
        raise ValueError("atomic event blocks unexpectedly formed a cycle")
    return event_to_block, block_events, produced_by_block, block_graph


def _crossing_state_count(
    left_blocks: set[str],
    all_blocks: set[str],
    model: AttackGraph,
    event_to_block: dict[str, str],
    produced_by_block: dict[str, str],
) -> int:
    """Count stable state boundaries crossed by a proposed page cut."""

    right_blocks = all_blocks - left_blocks
    crossing: set[str] = set()
    for event in model.events:
        consumer_block = event_to_block[event.id]
        if consumer_block not in right_blocks:
            continue
        for precondition_id in event.parents:
            producer_block = produced_by_block.get(precondition_id)
            if producer_block in left_blocks:
                crossing.add(precondition_id)
    return len(crossing)


def _partition_component(
    component_blocks: set[str],
    block_graph: nx.DiGraph,
    block_events: dict[str, tuple[str, ...]],
    model: AttackGraph,
    event_to_block: dict[str, str],
    produced_by_block: dict[str, str],
    max_events_per_part: int,
    max_ranks: int,
    max_parallel_events: int,
) -> list[set[str]]:
    """Partition one causal component into contiguous topological layers."""

    component_graph = block_graph.subgraph(component_blocks).copy()
    block_order = {
        block_id: index
        for index, block_id in enumerate(
            nx.lexicographical_topological_sort(
                component_graph,
                key=lambda item: item,
            )
        )
    }

    # Stable maximal non-branching modules mirror the macro layout planner.
    # A cut at a fork/merge boundary is preferred over cutting halfway through
    # a readable causal chain. An overlong chain may still be split to honour
    # the hard event/rank budgets.
    module_by_block: dict[str, int] = {}
    starts = [
        block_id
        for block_id in component_graph.nodes
        if (
            component_graph.in_degree(block_id) != 1
            or component_graph.out_degree(
                next(iter(component_graph.predecessors(block_id)))
            ) != 1
        )
    ]
    starts.sort(key=block_order.get)
    module_index = 0
    for start in starts:
        if start in module_by_block:
            continue
        current = start
        module_by_block[current] = module_index
        while component_graph.out_degree(current) == 1:
            child = next(iter(component_graph.successors(current)))
            if (
                component_graph.in_degree(child) != 1
                or child in module_by_block
            ):
                break
            module_by_block[child] = module_index
            current = child
        module_index += 1
    for block_id in sorted(component_graph.nodes, key=block_order.get):
        if block_id not in module_by_block:
            module_by_block[block_id] = module_index
            module_index += 1

    levels = _longest_path_levels(component_graph)
    buckets: dict[int, set[str]] = {}
    for block_id, level in levels.items():
        buckets.setdefault(level, set()).add(block_id)
    # Divide any level that is wider than the page allows. The pieces keep the
    # level they came from so the pagination below can refuse to put two of them
    # back on the same page, which is the only thing that makes the page narrow.
    ordered_buckets: list[set[str]] = []
    bucket_level: list[int] = []
    for level in sorted(buckets):
        blocks_at_level = sorted(buckets[level], key=block_order.get)
        piece: set[str] = set()
        piece_events = 0
        for block_id in blocks_at_level:
            count = len(block_events[block_id])
            if piece and piece_events + count > max_parallel_events:
                ordered_buckets.append(piece)
                bucket_level.append(level)
                piece, piece_events = set(), 0
            piece.add(block_id)
            piece_events += count
        ordered_buckets.append(piece)
        bucket_level.append(level)

    bucket_events = [
        sum(len(block_events[block_id]) for block_id in bucket)
        for bucket in ordered_buckets
    ]

    # One event layer normally occupies an event rank and a resulting state
    # rank. The leading input-state rank accounts for the "+1".
    max_event_layers = max(1, (max_ranks - 1) // 2)
    total_events = sum(bucket_events)
    if (
        total_events <= max_events_per_part
        and len(buckets) <= max_event_layers
        # A divided level must reach the pagination below; keeping the whole
        # component on one page would put it straight back together.
        and len(ordered_buckets) == len(buckets)
    ):
        return [set().union(*ordered_buckets)]

    prefix_events = [0]
    for count in bucket_events:
        prefix_events.append(prefix_events[-1] + count)

    # dp[end] = (score, segments). The score is lexicographic:
    #   1. minimum page count;
    #   2. minimum cuts inside a maximal causal module;
    #   3. minimum number of crossed bridge states;
    #   4. minimum unused capacity, favouring balanced readable pages.
    dp: list[
        tuple[tuple[int, int, int, int], list[tuple[int, int]]] | None
    ] = [
        None
    ] * (len(ordered_buckets) + 1)
    dp[0] = ((0, 0, 0, 0), [])
    all_blocks = set(component_blocks)

    for end in range(1, len(ordered_buckets) + 1):
        for start in range(end - 1, -1, -1):
            event_count = prefix_events[end] - prefix_events[start]
            segment_levels = bucket_level[start:end]
            # Two pieces of one level are redrawn as a single rank, so what
            # decides is how wide that rank comes out, not that it happened.
            #
            # Rejecting the combination outright was the same mistake as
            # counting actions instead of measuring the page. A six-way fan off
            # one state became six pages carrying one action each: every page
            # legible, and no page showing any structure at all. Lallie,
            # Debattista and Bal (2020) are writing about comprehension, and a
            # figure a reader cannot see the shape of fails that whether or not
            # its type is 9pt.
            #
            # Tried twice and reverted twice, the second time with the
            # routing-aware plan selector already in place to catch the damage.
            # It did not help enough: the British Library fan came back onto
            # two pages, but the second was 1994px -- labels at 5.9pt, still
            # unreadable -- and one saved run went back to failing "no
            # connector crosses a node". Fewer pages that cannot be read, plus
            # an arrow through a box, is not a trade worth making.
            #
            # The structure this loses -- "from broad lateral access the
            # adversary did six different things" -- is not pagination's to
            # keep. `visual_aggregation` is the tool for a wide fan, and it
            # declines this one correctly: those six actions carry four
            # different tactics and produce no state jointly, so folding them
            # into one box would assert they are the same kind of step.
            if len(set(segment_levels)) != len(segment_levels):
                continue
            layer_count = len(set(segment_levels))
            # Width is allowed to grow with height, and only with height.
            if max(bucket_events[start:end]) > max_parallel_events_for(
                    layer_count, max_parallel_events):
                continue
            single_unsplittable_layer = layer_count == 1
            if (
                not single_unsplittable_layer
                and (
                    event_count > max_events_per_part
                    or layer_count > max_event_layers
                )
            ):
                continue
            previous = dp[start]
            if previous is None:
                continue

            segment_blocks = set().union(*ordered_buckets[start:end])
            cut_cost = 0
            internal_module_cut = 0
            if end < len(ordered_buckets):
                left = set().union(*ordered_buckets[:end])
                right = all_blocks - left
                cut_cost = _crossing_state_count(
                    left,
                    all_blocks,
                    model,
                    event_to_block,
                    produced_by_block,
                )
                internal_module_cut = int(any(
                    module_by_block[source] == module_by_block[target]
                    for source, target in component_graph.edges
                    if source in left and target in right
                ))
            slack = max(0, max_events_per_part - event_count)
            old_score, old_segments = previous
            score = (
                old_score[0] + 1,
                old_score[1] + internal_module_cut,
                old_score[2] + cut_cost,
                old_score[3] + slack * slack,
            )
            candidate = (score, old_segments + [(start, end)])
            if dp[end] is None or candidate[0] < dp[end][0]:
                dp[end] = candidate

    if dp[-1] is None:
        raise ValueError("no valid causal-boundary pagination was found")
    return [
        set().union(*ordered_buckets[start:end])
        for start, end in dp[-1][1]
    ]


def _part_from_blocks(
    model: AttackGraph,
    blocks: set[str],
    event_to_block: dict[str, str],
    produced_by_block: dict[str, str],
    component_index: int,
) -> CausalSplitPart:
    event_order = {event.id: index for index, event in enumerate(model.events)}
    precondition_order = {
        precondition.id: index
        for index, precondition in enumerate(model.preconditions)
    }
    event_ids = {
        event.id for event in model.events
        if event_to_block[event.id] in blocks
    }
    precondition_ids: set[str] = set()

    # Include every input state so AND/OR input logic remains intact.
    for event in model.events:
        if event.id in event_ids:
            precondition_ids.update(event.parents)

    # Include every state established by this page's events. This is the
    # indivisible event -> result-state visual block.
    for precondition in model.preconditions:
        if any(parent in event_ids for parent in precondition.parents):
            precondition_ids.add(precondition.id)

    consumers: dict[str, set[str]] = {}
    for event in model.events:
        for precondition_id in event.parents:
            consumers.setdefault(precondition_id, set()).add(event.id)

    bridge_in: set[str] = set()
    bridge_out: set[str] = set()
    for precondition_id in precondition_ids:
        producer_block = produced_by_block.get(precondition_id)
        if producer_block is not None and producer_block not in blocks:
            bridge_in.add(precondition_id)
        if producer_block in blocks:
            outside_consumers = {
                event_id for event_id in consumers.get(precondition_id, set())
                if event_id not in event_ids
            }
            if outside_consumers:
                bridge_out.add(precondition_id)

    return CausalSplitPart(
        index=0,
        component_index=component_index,
        event_ids=tuple(sorted(event_ids, key=event_order.get)),
        precondition_ids=tuple(
            sorted(precondition_ids, key=precondition_order.get)
        ),
        bridge_in_ids=tuple(
            sorted(bridge_in, key=precondition_order.get)
        ),
        bridge_out_ids=tuple(
            sorted(bridge_out, key=precondition_order.get)
        ),
    )


def materialize_split_part(
    model: AttackGraph,
    part: CausalSplitPart,
    total_parts: int,
) -> AttackGraph:
    """Create the validated page graph without modifying canonical metadata."""

    event_ids = set(part.event_ids)
    precondition_ids = set(part.precondition_ids)
    events = [
        event.model_copy()
        for event in model.events
        if event.id in event_ids
    ]
    preconditions = []
    for precondition in model.preconditions:
        if precondition.id not in precondition_ids:
            continue
        local_parents = [
            event_id for event_id in precondition.parents
            if event_id in event_ids
        ]
        preconditions.append(
            precondition.model_copy(update={"parents": local_parents})
        )
    title = model.title
    if total_parts > 1:
        title = f"{title} (part {part.index} of {total_parts})"
    return AttackGraph(
        title=title,
        preconditions=preconditions,
        events=events,
    )


def validate_lossless_split(
    model: AttackGraph,
    plan: CausalSplitPlan,
) -> None:
    """Raise if page union cannot reconstruct the canonical graph exactly."""

    original_graph = _canonical_graph(model)
    original_nodes = set(original_graph.nodes)
    original_edges = set(original_graph.edges)
    union_nodes: set[str] = set()
    union_edges: set[tuple[str, str]] = set()
    seen_events: set[str] = set()
    event_by_id = {event.id: event for event in model.events}
    precondition_by_id = {
        precondition.id: precondition for precondition in model.preconditions
    }

    for part in plan.parts:
        page = materialize_split_part(model, part, len(plan.parts))
        page_graph = _canonical_graph(page)
        union_nodes.update(page_graph.nodes)
        union_edges.update(page_graph.edges)

        duplicate_events = seen_events.intersection(part.event_ids)
        if duplicate_events:
            raise ValueError(
                f"events may not be duplicated across pages: "
                f"{sorted(duplicate_events)}"
            )
        seen_events.update(part.event_ids)

        for event in page.events:
            if event.model_dump() != event_by_id[event.id].model_dump():
                raise ValueError(
                    f"event metadata changed while splitting: {event.id}"
                )
        for precondition in page.preconditions:
            original = precondition_by_id[precondition.id]
            if (
                precondition.label != original.label
                or precondition.code != original.code
            ):
                raise ValueError(
                    f"state metadata changed while splitting: "
                    f"{precondition.id}"
                )

    if union_nodes != original_nodes:
        raise ValueError(
            "split pages do not preserve the original node set: "
            f"missing={sorted(original_nodes - union_nodes)}, "
            f"extra={sorted(union_nodes - original_nodes)}"
        )
    if union_edges != original_edges:
        raise ValueError(
            "split pages do not preserve the original edge set: "
            f"missing={sorted(original_edges - union_edges)}, "
            f"extra={sorted(union_edges - original_edges)}"
        )


def terminal_outcomes(model: AttackGraph) -> tuple[str, ...]:
    """Labels of the causal states nothing further consumes.

    Annotations sit beside the attack rather than on it, so they are not
    endings and are not counted. A root precondition is not an ending either:
    it is where the attack started, which is why a produced state is required.
    """

    consumed = {parent for event in model.events for parent in event.parents}
    return tuple(
        node.label for node in model.preconditions
        if node.role != "annotation" and node.parents
        and node.id not in consumed
    )


def attack_objective(model: AttackGraph) -> str | None:
    """The state this attack converged on, or None if the graph names no one.

    Rule 5 asks the model to name the adversary's objective as a result
    precondition, and it does. Nothing then showed it. The British Library
    graph ends in nine terminal states and the objective is one of them, so a
    reader had to count arrows to find out which -- which is exactly what
    Lallie, Debattista and Bal (2020) report of published attack graphs, where
    a goal is represented in only 21.5% of the 180 they surveyed. Naming the
    objective in the data and not in the figure gets no credit for it.

    The test is mechanical and has to be, because the alternative is a
    judgement about which ending matters most: among the causal terminal
    states -- no consumer, annotations excluded, since an annotation is
    commentary and not an ending -- take the one the most actions can reach.

    A tie returns None. Two endings reached by equally much is a graph that
    does not converge on one objective, and drawing a winner would be asserting
    something the graph does not say.
    """

    annotations = {
        precondition.id for precondition in model.preconditions
        if precondition.role == "annotation"
    }
    edges = [
        (parent, node.id)
        for node in list(model.events) + list(model.preconditions)
        if node.id not in annotations
        for parent in node.parents
        if parent not in annotations
    ]
    return objective_from_edges(
        [event.id for event in model.events],
        [precondition.id for precondition in model.preconditions
         if precondition.id not in annotations],
        edges,
    )


def objective_from_edges(
    event_ids: Iterable[str],
    state_ids: Iterable[str],
    edges: Iterable[tuple[str, str]],
) -> str | None:
    """The rule itself, over ids and edges rather than over a model.

    The layout planner has a page of visual nodes, not an ``AttackGraph``, and
    needs the same answer for the page it is drawing. Two implementations of
    one rule is the drift this project keeps paying for, so there is one, and
    the callers adapt to it.
    """

    graph = nx.DiGraph()
    graph.add_nodes_from(event_ids)
    graph.add_nodes_from(state_ids)
    graph.add_edges_from(edges)

    events = [event_id for event_id in event_ids if event_id in graph]
    if not events:
        return None
    scored = [
        (sum(1 for event_id in events
             if nx.has_path(graph, event_id, state_id)), state_id)
        for state_id in state_ids
        if state_id in graph and graph.out_degree(state_id) == 0
    ]
    if not scored:
        return None
    best = max(count for count, _ in scored)
    winners = [state_id for count, state_id in scored if count == best]
    if best == 0 or len(winners) != 1:
        return None
    return winners[0]


def measure_plan_pages(
    model: AttackGraph,
    plan: CausalSplitPlan,
) -> tuple[int, bool]:
    """Draw this plan's pages far enough to judge them: (widest px, routes ok).

    Imported inside the function because ``layout_ir`` imports this module:
    the geometry depends on the pagination, not the other way round, and the
    module graph has to keep saying so.

    Routing is measured with the same call the conformance script uses, so
    "routes cleanly" cannot come to mean two different things.
    """

    from layout_ir import build_layout_ir
    from layout_planner import plan_layout
    from layout_quality import LEGEND_RESERVE_WIDTH
    from layout_router import route_layout, validate_routed_layout

    widest = 0
    routes_cleanly = True
    for part in plan.parts:
        page = materialize_split_part(model, part, len(plan.parts))
        layout_ir = build_layout_ir(page)
        planned = plan_layout(layout_ir)
        widest = max(widest, planned.width + LEGEND_RESERVE_WIDTH)
        routed = route_layout(layout_ir, planned)
        if validate_routed_layout(layout_ir, planned, routed):
            routes_cleanly = False
    return widest, routes_cleanly


def widest_page_width_px(model: AttackGraph, plan: CausalSplitPlan) -> int:
    """The drawn width of this plan's widest page, key column included."""

    return measure_plan_pages(model, plan)[0]


def plan_causal_split(
    model: AttackGraph,
    *,
    max_events_per_part: int = DEFAULT_MAX_EVENTS_PER_PART,
    max_ranks: int = DEFAULT_MAX_RANKS,
    max_parallel_events: int = DEFAULT_MAX_PARALLEL_EVENTS,
    max_page_width_px: int | None = None,
    page_count_ceiling: int = PAGE_COUNT_CEILING,
) -> CausalSplitPlan:
    """Paginate, then check the pages against the width they will be drawn at.

    ``max_parallel_events`` counts actions, and for a long time that was the
    only width control. It is not the same quantity as page width: a rank of
    four actions can establish a dozen result states drawn side by side, and
    the widest page this tool produced came out at 3731 px under a budget its
    own author believed was four nodes wide. Type printed from such a page is
    unreadable, which makes the figure unusable in the dissertation it exists
    for.

    So the count is a starting point rather than the answer. The plan is
    measured in the geometry that will actually be drawn, and while a page is
    over budget the count is tightened and the split re-planned. Some pages
    cannot be narrowed -- one action with a long label and several results is
    already indivisible -- so this gives up rather than looping, and the page
    is reported as over budget by ``layout_quality`` instead.

    Passing ``max_page_width_px=0`` restores the pure combinatorial behaviour,
    which is what the pagination unit tests measure.
    """

    from layout_planner import LayoutPlanValidationError

    if max_page_width_px is None:
        from layout_renderer import MAX_PAGE_WIDTH_PX
        max_page_width_px = MAX_PAGE_WIDTH_PX

    def attempt(budget: int) -> CausalSplitPlan:
        return _plan_causal_split(
            model,
            max_events_per_part=max_events_per_part,
            max_ranks=max_ranks,
            max_parallel_events=budget,
        )

    plan = attempt(max_parallel_events)
    if max_page_width_px <= 0:
        return plan

    # Three things are being traded, and they are not equal. A connector drawn
    # through a node is a wrong drawing; a page too wide to read is a correct
    # drawing that cannot be used; extra pages are a cost with no defect, but
    # not with no price either.
    #
    # The price became visible on a real run. One British Library graph fans
    # six actions off a single state, each with its own results, and the only
    # pagination meeting the width budget put ONE action on each of seven
    # pages: every page legible, no page showing any structure. The measured
    # ladder was 2 pages at 5.0pt, 2 at 6.0pt, 3 at 5.3pt and 7 at 9.4pt --
    # there is no middle, and buying readable type with a fivefold page count
    # is a judgement, not a measurement.
    #
    # The judgement is `PAGE_COUNT_CEILING`. Past it the reader is following
    # bridges between fragments rather than reading a graph, which is the
    # comprehension failure the width budget exists to prevent, reached from
    # the other side. Width is then reported by `layout_quality` instead.
    #
    # Tightening does not always help either -- width can come from a rank of
    # states, which no event budget touches -- and taking the narrowest attempt
    # regardless once gave a run sixteen pages still over budget in place of
    # four that were.
    base_pages = len(plan.parts)
    ceiling = max(base_pages * page_count_ceiling, base_pages + 1)
    good_enough = max_page_width_px * (1 + WIDTH_BUDGET_TOLERANCE)

    width, clean = measure_plan_pages(model, plan)
    if clean and width <= good_enough:
        return plan

    best = (plan, width) if clean else None
    for budget in range(max_parallel_events - 1, 0, -1):
        try:
            candidate = attempt(budget)
            candidate_width, clean = measure_plan_pages(model, candidate)
        except LayoutPlanValidationError:
            # A tighter budget can put a combination on the page that the
            # planner refuses. That is a reason to skip this budget, not a
            # reason to fail a run that already has a plan.
            continue
        if not clean or len(candidate.parts) > ceiling:
            continue
        if candidate_width <= good_enough:
            return candidate
        # Nothing fits yet. Keep the narrowest affordable plan rather than the
        # first one seen: two pages at 1650px beat two pages at 1994px for
        # free.
        if best is None or candidate_width < best[1]:
            best = (candidate, candidate_width)
    return best[0] if best is not None else plan


def _plan_causal_split(
    model: AttackGraph,
    *,
    max_events_per_part: int = DEFAULT_MAX_EVENTS_PER_PART,
    max_ranks: int = DEFAULT_MAX_RANKS,
    max_parallel_events: int = DEFAULT_MAX_PARALLEL_EVENTS,
) -> CausalSplitPlan:
    """Plan zero-loss pagination at stable state boundaries.

    Tactics are intentionally absent from this algorithm. They remain visible
    metadata but do not decide where the graph is cut.
    """

    if max_events_per_part < 1:
        raise ValueError("max_events_per_part must be at least 1")
    if max_ranks < 3:
        raise ValueError("max_ranks must be at least 3")
    if max_parallel_events < 1:
        raise ValueError("max_parallel_events must be at least 1")

    canonical = _canonical_graph(model)
    canonical_levels = _longest_path_levels(canonical)
    estimated_ranks = (
        max(canonical_levels.values(), default=-1) + 1
    )
    event_ids_all = {event.id for event in model.events}
    events_per_level: dict[int, int] = {}
    for node_id, level in canonical_levels.items():
        if node_id in event_ids_all:
            events_per_level[level] = events_per_level.get(level, 0) + 1
    widest_rank = max(events_per_level.values(), default=0)
    should_split = (
        len(model.events) > max_events_per_part
        or estimated_ranks > max_ranks
        or widest_rank > max_parallel_events
    )

    if not should_split:
        part = CausalSplitPart(
            index=1,
            component_index=1,
            event_ids=tuple(event.id for event in model.events),
            precondition_ids=tuple(
                precondition.id for precondition in model.preconditions
            ),
            bridge_in_ids=(),
            bridge_out_ids=(),
        )
        plan = CausalSplitPlan(
            parts=(part,),
            original_node_count=canonical.number_of_nodes(),
            original_edge_count=canonical.number_of_edges(),
            estimated_ranks=estimated_ranks,
        )
        validate_lossless_split(model, plan)
        return plan

    (
        event_to_block,
        block_events,
        produced_by_block,
        block_graph,
    ) = _event_blocks(model, max_events_per_block=max_parallel_events)

    block_order = {
        block_id: min(
            index
            for index, event in enumerate(model.events)
            if event.id in event_ids
        )
        for block_id, event_ids in block_events.items()
    }
    components = list(nx.weakly_connected_components(block_graph))
    components.sort(
        key=lambda component: min(block_order[block] for block in component)
    )

    raw_parts: list[CausalSplitPart] = []
    for component_index, component in enumerate(components, start=1):
        segments = _partition_component(
            set(component),
            block_graph,
            block_events,
            model,
            event_to_block,
            produced_by_block,
            max_events_per_part,
            max_ranks,
            max_parallel_events,
        )
        for segment in segments:
            raw_parts.append(
                _part_from_blocks(
                    model,
                    segment,
                    event_to_block,
                    produced_by_block,
                    component_index,
                )
            )

    # Preserve isolated state-only components as explicit pages rather than
    # dropping them. They are unusual but valid under the shared schema.
    attached_preconditions = {
        precondition_id
        for part in raw_parts
        for precondition_id in part.precondition_ids
    }
    for precondition in model.preconditions:
        if precondition.id not in attached_preconditions:
            raw_parts.append(
                CausalSplitPart(
                    index=0,
                    component_index=len(components) + 1,
                    event_ids=(),
                    precondition_ids=(precondition.id,),
                    bridge_in_ids=(),
                    bridge_out_ids=(),
                )
            )

    indexed_parts = tuple(
        CausalSplitPart(
            index=index,
            component_index=part.component_index,
            event_ids=part.event_ids,
            precondition_ids=part.precondition_ids,
            bridge_in_ids=part.bridge_in_ids,
            bridge_out_ids=part.bridge_out_ids,
        )
        for index, part in enumerate(raw_parts, start=1)
    )
    plan = CausalSplitPlan(
        parts=indexed_parts,
        original_node_count=canonical.number_of_nodes(),
        original_edge_count=canonical.number_of_edges(),
        estimated_ranks=estimated_ranks,
    )
    validate_lossless_split(model, plan)
    return plan


def continuation_labels(
    plan: CausalSplitPlan,
    part: CausalSplitPart,
) -> dict[str, str]:
    """Return display-only bridge notes for one page.

    The notes are deliberately absent from :class:`schema.AttackGraph`: a
    repeated bridge state keeps its canonical ID, wording and code, while the
    renderer tells the reader which adjacent page carries the other half of
    the causal edge.
    """
    labels: dict[str, str] = {}
    earlier = [candidate for candidate in plan.parts if candidate.index < part.index]
    later = [candidate for candidate in plan.parts if candidate.index > part.index]

    for state_id in part.bridge_in_ids:
        sources = [
            candidate.index
            for candidate in earlier
            if state_id in candidate.precondition_ids
        ]
        if sources:
            labels[state_id] = f"continued from part {max(sources)}"

    for state_id in part.bridge_out_ids:
        destinations = [
            candidate.index
            for candidate in later
            if state_id in candidate.precondition_ids
        ]
        if destinations:
            note = f"continues in part {min(destinations)}"
            if state_id in labels:
                labels[state_id] = f"{labels[state_id]}; {note}"
            else:
                labels[state_id] = note
    return labels
