from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from textwrap import wrap

import networkx as nx

from layout_ir import LayoutIR, LayoutNode
from macro_layout import analyze_macro_layout


NODE_WIDTH = 176
NODE_MIN_HEIGHT = 78
NODE_ROW_GAP = 36
NODE_COLUMN_GAP = 52
BLOCK_PADDING = 20
BLOCK_GAP = 82
SIDE_MARGIN = 24
# Leave room for the page title and the top-left badge overhang.
TOP_MARGIN = 56
BOTTOM_MARGIN = 36
# A report whose causal structure is a chain legitimately produces a narrow
# graph. Padding it out to a fixed landscape width only created dead space to
# the right of the drawing, so the planned width now follows the content.
MIN_GRAPH_WIDTH = 300


class LayoutPlanValidationError(ValueError):
    """Raised when a calculated plan violates the Stage-B contract."""


@dataclass(frozen=True)
class PlannedBlock:
    id: str
    module_id: str
    component_index: int
    causal_rank: int
    lane_index: int
    lane_count: int
    x: int
    y: int
    width: int
    height: int
    is_trunk: bool
    event_ids: tuple[str, ...]
    result_state_ids: tuple[str, ...]
    input_visual_ids: tuple[str, ...]

    @property
    def cx(self) -> int:
        return self.x + self.width // 2

    @property
    def right(self) -> int:
        return self.x + self.width


@dataclass(frozen=True)
class PlannedNode:
    visual_id: str
    canonical_id: str
    kind: str
    role: str
    block_id: str | None
    visual_rank: int
    lane_index: int
    x: int
    y: int
    width: int
    height: int

    @property
    def cx(self) -> int:
        return self.x + self.width // 2

    @property
    def cy(self) -> int:
        return self.y + self.height // 2

    @property
    def bottom(self) -> int:
        return self.y + self.height

    @property
    def right(self) -> int:
        return self.x + self.width


@dataclass(frozen=True)
class PlannedLogic:
    group_id: str
    logic: str
    target_visual_id: str
    input_visual_ids: tuple[str, ...]
    input_points: tuple[tuple[int, int], ...]
    target_ports: tuple[tuple[int, int], ...]
    shared_bus: tuple[tuple[int, int], tuple[int, int]] | None


@dataclass(frozen=True)
class LayoutPlan:
    profile_id: str
    width: int
    height: int
    blocks: tuple[PlannedBlock, ...]
    nodes: tuple[PlannedNode, ...]
    logic: tuple[PlannedLogic, ...]
    trunk_block_ids: tuple[str, ...]
    macro_module_ids: tuple[str, ...]


def _estimate_height(node: LayoutNode) -> int:
    """Estimate body height without coupling planning to a font backend.

    The character budget deliberately under-fills the shape. An ellipse only
    offers its full width across the middle, and the renderer breaks tokens
    that would otherwise overflow, so a pessimistic estimate here keeps the
    drawn text inside the planned box.
    """

    lines = wrap(
        node.semantics.label,
        width=19,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    return max(NODE_MIN_HEIGHT, 28 + len(lines) * 16)


def _pav(values: list[float]) -> list[float]:
    """Pool-adjacent-violators projection onto non-decreasing values."""

    blocks: list[list[float]] = []
    for value in values:
        blocks.append([value, 1.0])
        while len(blocks) > 1 and blocks[-2][0] > blocks[-1][0]:
            right_value, right_weight = blocks.pop()
            left_value, left_weight = blocks.pop()
            weight = left_weight + right_weight
            blocks.append([
                (
                    left_value * left_weight
                    + right_value * right_weight
                ) / weight,
                weight,
            ])
    projected: list[float] = []
    for value, weight in blocks:
        projected.extend([value] * int(weight))
    return projected


def _fit_centres(
    desired: list[float],
    widths: list[int],
    gap: int,
) -> list[float]:
    """Fit variable-width boxes while preserving their left-to-right order."""

    if not desired:
        return []
    offsets = [0.0]
    for index in range(1, len(desired)):
        offsets.append(
            offsets[-1]
            + widths[index - 1] / 2
            + gap
            + widths[index] / 2
        )
    transformed = [
        value - offset for value, offset in zip(desired, offsets)
    ]
    projected = _pav(transformed)
    return [
        value + offset for value, offset in zip(projected, offsets)
    ]


def _block_graph(layout_ir: LayoutIR) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_nodes_from(block.id for block in layout_ir.atomic_blocks)
    for block in layout_ir.atomic_blocks:
        graph.add_edges_from(
            (parent_id, block.id) for parent_id in block.parent_block_ids
        )
    if not nx.is_directed_acyclic_graph(graph):
        raise LayoutPlanValidationError("atomic block graph must be acyclic")
    return graph


def _component_indices(
    graph: nx.DiGraph,
    block_order: dict[str, int],
) -> dict[str, int]:
    components = sorted(
        nx.weakly_connected_components(graph),
        key=lambda component: min(block_order[node] for node in component),
    )
    return {
        block_id: component_index
        for component_index, component in enumerate(components)
        for block_id in component
    }


def _main_trunks(
    graph: nx.DiGraph,
    block_order: dict[str, int],
) -> tuple[str, ...]:
    """Return one deterministic longest causal spine per component."""

    trunks: list[str] = []
    components = sorted(
        nx.weakly_connected_components(graph),
        key=lambda component: min(block_order[node] for node in component),
    )
    for component in components:
        ordered = list(
            nx.lexicographical_topological_sort(
                graph.subgraph(component),
                key=block_order.get,
            )
        )
        best_length: dict[str, int] = {}
        predecessor: dict[str, str | None] = {}
        for block_id in ordered:
            parents = [
                parent for parent in graph.predecessors(block_id)
                if parent in component
            ]
            if not parents:
                best_length[block_id] = 1
                predecessor[block_id] = None
                continue
            best_parent = max(
                parents,
                key=lambda parent: (
                    best_length[parent],
                    -block_order[parent],
                ),
            )
            best_length[block_id] = best_length[best_parent] + 1
            predecessor[block_id] = best_parent

        end = max(
            component,
            key=lambda block_id: (
                best_length[block_id],
                -block_order[block_id],
            ),
        )
        path: list[str] = []
        current: str | None = end
        while current is not None:
            path.append(current)
            current = predecessor[current]
        trunks.extend(reversed(path))
    return tuple(trunks)


def _ordered_block_ranks(
    layout_ir: LayoutIR,
    graph: nx.DiGraph,
) -> dict[int, list[str]]:
    """Use deterministic barycentric sweeps to keep branch lanes coherent."""

    block_order = {
        block.id: index for index, block in enumerate(layout_ir.atomic_blocks)
    }
    ranks: dict[int, list[str]] = {}
    for block in layout_ir.atomic_blocks:
        ranks.setdefault(block.rank, []).append(block.id)
    for rank in ranks.values():
        rank.sort(key=block_order.get)

    def normalised_positions() -> dict[str, float]:
        positions: dict[str, float] = {}
        for rank in ranks.values():
            count = max(1, len(rank))
            for index, block_id in enumerate(rank):
                positions[block_id] = (index + 0.5) / count
        return positions

    levels = sorted(ranks)
    for _ in range(6):
        positions = normalised_positions()
        for level in levels[1:]:
            ranks[level].sort(key=lambda block_id: (
                median(
                    positions[parent]
                    for parent in graph.predecessors(block_id)
                ) if tuple(graph.predecessors(block_id))
                else positions[block_id],
                block_order[block_id],
            ))
        positions = normalised_positions()
        for level in reversed(levels[:-1]):
            ranks[level].sort(key=lambda block_id: (
                median(
                    positions[child]
                    for child in graph.successors(block_id)
                ) if tuple(graph.successors(block_id))
                else positions[block_id],
                block_order[block_id],
            ))
    return ranks


def _visual_block_membership(
    layout_ir: LayoutIR,
) -> tuple[dict[str, str], dict[str, list[str]]]:
    event_to_block = {
        event_id: block.id
        for block in layout_ir.atomic_blocks
        for event_id in block.event_ids
    }
    members: dict[str, list[str]] = {
        block.id: [] for block in layout_ir.atomic_blocks
    }
    # The IR has already decided which block owns each result state, and that
    # decision is not always "the first parent's block": where producers depend
    # on one another they sit in different blocks and the state belongs with
    # the last. Reading the IR's answer instead of recomputing one keeps the
    # two from disagreeing, which is what put a state in one block and its
    # own block's result list in another.
    state_owner = {
        state_id: block.id
        for block in layout_ir.atomic_blocks
        for state_id in block.result_state_ids
    }
    visual_to_block: dict[str, str] = {}
    for node in layout_ir.nodes:
        block_id: str | None = None
        if node.semantics.kind == "event":
            block_id = event_to_block[node.canonical_id]
        elif node.canonical_id in state_owner:
            block_id = state_owner[node.canonical_id]
        elif node.semantics.parents:
            block_id = event_to_block[node.semantics.parents[0]]
        elif node.anchor_event_id:
            block_id = event_to_block[node.anchor_event_id]
        if block_id is not None:
            visual_to_block[node.visual_id] = block_id
            members[block_id].append(node.visual_id)
    return visual_to_block, members


def _block_widths(
    layout_ir: LayoutIR,
    visual_to_block: dict[str, str],
) -> dict[str, int]:
    nodes = {node.visual_id: node for node in layout_ir.nodes}
    widths: dict[str, int] = {}
    for block in layout_ir.atomic_blocks:
        local_roots = [
            visual_id for visual_id, block_id in visual_to_block.items()
            if block_id == block.id
            and not nodes[visual_id].semantics.parents
            and nodes[visual_id].semantics.kind == "state"
        ]
        slots = max(
            1,
            len(block.event_ids),
            len(block.result_state_ids),
            len(local_roots),
        )
        widths[block.id] = (
            slots * NODE_WIDTH
            + max(0, slots - 1) * NODE_COLUMN_GAP
            + 2 * BLOCK_PADDING
        )
    return widths


def _block_centres(
    layout_ir: LayoutIR,
    graph: nx.DiGraph,
    ranks: dict[int, list[str]],
    widths: dict[str, int],
) -> dict[str, float]:
    centres: dict[str, float] = {}
    initial: dict[str, float] = {}
    for rank in ranks.values():
        rank_width = (
            sum(widths[block_id] for block_id in rank)
            + max(0, len(rank) - 1) * BLOCK_GAP
        )
        cursor = -rank_width / 2
        for block_id in rank:
            center = cursor + widths[block_id] / 2
            centres[block_id] = center
            initial[block_id] = center
            cursor += widths[block_id] + BLOCK_GAP

    def relax(levels, neighbours, strength: float) -> None:
        for level in levels:
            rank = ranks[level]
            desired: list[float] = []
            for block_id in rank:
                adjacent = [
                    centres[other] for other in neighbours(block_id)
                    if other in centres
                ]
                relational = (
                    median(adjacent) if adjacent else centres[block_id]
                )
                target = (
                    strength * relational
                    + (1.0 - strength) * initial[block_id]
                )
                desired.append(target)
            fitted = _fit_centres(
                desired,
                [widths[block_id] for block_id in rank],
                BLOCK_GAP,
            )
            for block_id, center in zip(rank, fitted):
                centres[block_id] = center

    levels = sorted(ranks)
    for _ in range(7):
        relax(levels[1:], graph.predecessors, 0.84)
        relax(reversed(levels[:-1]), graph.successors, 0.64)
    for _ in range(2):
        relax(levels[1:], graph.predecessors, 1.0)

    left = min(
        centres[block_id] - widths[block_id] / 2
        for block_id in centres
    )
    right = max(
        centres[block_id] + widths[block_id] / 2
        for block_id in centres
    )
    natural_width = right - left + 2 * SIDE_MARGIN
    target_width = max(MIN_GRAPH_WIDTH, natural_width)
    shift = SIDE_MARGIN - left + (target_width - natural_width) / 2
    return {
        block_id: center + shift
        for block_id, center in centres.items()
    }


def _even_centres(center: float, count: int) -> list[float]:
    if count <= 1:
        return [center] if count else []
    pitch = NODE_WIDTH + NODE_COLUMN_GAP
    start = center - pitch * (count - 1) / 2
    return [start + index * pitch for index in range(count)]


def _bounded_row_centres(
    desired: list[float],
    block_center: float,
    block_width: int,
) -> list[float]:
    fitted = _fit_centres(
        desired,
        [NODE_WIDTH] * len(desired),
        NODE_COLUMN_GAP,
    )
    if not fitted:
        return fitted
    left_bound = block_center - block_width / 2 + BLOCK_PADDING
    right_bound = block_center + block_width / 2 - BLOCK_PADDING
    if fitted[0] - NODE_WIDTH / 2 < left_bound:
        shift = left_bound - (fitted[0] - NODE_WIDTH / 2)
        fitted = [center + shift for center in fitted]
    if fitted[-1] + NODE_WIDTH / 2 > right_bound:
        shift = right_bound - (fitted[-1] + NODE_WIDTH / 2)
        fitted = [center + shift for center in fitted]
    return fitted


def page_objective(layout_ir: LayoutIR) -> str | None:
    """The visual id of the state this page converges on, if it has one.

    Same rule as `causal_split.attack_objective`, applied to the page being
    drawn, and computed by the same function so the two cannot drift.
    """

    from causal_split import objective_from_edges

    annotations = {
        node.visual_id for node in layout_ir.nodes
        if node.semantics.role == "annotation"
    }
    return objective_from_edges(
        [node.visual_id for node in layout_ir.nodes
         if node.semantics.kind == "event"],
        [node.visual_id for node in layout_ir.nodes
         if node.semantics.kind != "event"
         and node.visual_id not in annotations],
        [(edge.source_visual_id, edge.target_visual_id)
         for edge in layout_ir.edges
         if edge.source_visual_id not in annotations
         and edge.target_visual_id not in annotations],
    )


def _close_on_the_objective(
    layout_ir: LayoutIR,
    visual_rank: dict[str, int],
    objective_id: str | None = None,
) -> dict[str, int]:
    """Give the objective a row of its own, at the bottom.

    The rank projection puts a terminal state on the first row its own
    dependencies allow, which lands the objective beside every other ending the
    attack produced. The British Library page ended in nine terminal states,
    one of which was the objective, and the only way to tell was to count the
    arrows: three actions converge on it and one on each of the others. Lallie,
    Debattista and Bal (2020) found a goal represented in 21.5% of 180
    published attack graphs, and naming it in the data while burying it in a row
    of siblings does not count as representing it.

    Moving it down asserts nothing new. Rank carries dependency only through
    the arrows -- the key on every page says so -- and no arrow is added,
    removed or reversed here. What changes is that the shape now closes: the
    page reads as a funnel onto one ending instead of a fan onto several.

    Only a page whose objective shares its row with something else is touched,
    and only if it is the last row. A page that already ends on the objective
    alone is left exactly as planned.

    ``objective_id`` names the whole graph's objective. When that node is on
    this page it wins, because it is the node the key points at and the two
    must not disagree: three saved runs drew the objective in a row of other
    endings while the key said it stood at the foot, because placement asked
    the page and the caption asked the graph. Only a page that does not hold it
    falls back to its own convergence, which is the right answer for a page
    that is a stage of the attack rather than its end.
    """

    named = next(
        (node.visual_id for node in layout_ir.nodes
         if node.canonical_id == objective_id),
        None,
    ) if objective_id is not None else None
    objective = named if named is not None else page_objective(layout_ir)
    if objective is None or objective not in visual_rank:
        return visual_rank
    bottom = max(visual_rank.values())
    alone = sum(1 for rank in visual_rank.values()
                if rank == visual_rank[objective]) == 1
    if visual_rank[objective] == bottom and alone:
        return visual_rank
    if named is None:
        # Page-local convergence: only tidy a page that already ends on it.
        # Dragging a mid-page node to the foot would assert a shape the page
        # does not have, and nothing names it, so nothing is contradicted.
        if visual_rank[objective] != bottom:
            return visual_rank
    # The graph's objective goes below everything, annotations included. One
    # page put "No evidence of data exfiltration observed" -- commentary, off
    # the causal path -- lower than the objective, while the key said the
    # objective stood at the foot of the figure. An annotation's row carries no
    # causal meaning, so it is the one that gives way.
    return {**visual_rank, objective: bottom + 1}


def _separate_blocks_by_drawn_extent(
    ranks: dict[int, list[str]],
    members: dict[str, list[str]],
    node_centres: dict[str, float],
) -> None:
    """Pull same-rank blocks apart using the width they really occupy.

    Blocks are spaced by an estimate: slots times the node width, where slots
    is the largest of a block's event, result and local-root counts. A block
    can be drawn wider than that. Page-local roots are fitted across the whole
    visual rank rather than inside their block, because a prerequisite shared
    by several blocks belongs between them, and a root that drifts takes its
    block's boundary with it.

    The estimate was never checked against the drawing, so the drift only
    surfaced when narrower pagination put more bridge states on a page and the
    planner refused its own plan: "same-rank blocks overlap". The pages that
    triggered it were legitimate pages, and refusing them would have meant
    refusing the width budget that produced them.

    So the last word goes to the geometry rather than the estimate. Each block
    is measured where its nodes actually are, the row is fitted with the same
    order-preserving solver used everywhere else, and each block's nodes move
    together by one offset -- which leaves the arrangement inside a block, and
    the left-to-right order of the blocks, exactly as planned.
    """

    for rank_blocks in ranks.values():
        placed = [
            (block_id, [node_centres[visual_id]
                        for visual_id in members.get(block_id, ())
                        if visual_id in node_centres])
            for block_id in rank_blocks
        ]
        placed = [(block_id, cs) for block_id, cs in placed if cs]
        if len(placed) < 2:
            continue
        extents = [
            (min(cs) - NODE_WIDTH / 2 - BLOCK_PADDING,
             max(cs) + NODE_WIDTH / 2 + BLOCK_PADDING)
            for _, cs in placed
        ]
        fitted = _fit_centres(
            [(left + right) / 2 for left, right in extents],
            [round(right - left) for left, right in extents],
            BLOCK_GAP,
        )
        for (block_id, _), (left, right), centre in zip(
            placed, extents, fitted
        ):
            offset = centre - (left + right) / 2
            if not offset:
                continue
            for visual_id in members[block_id]:
                if visual_id in node_centres:
                    node_centres[visual_id] += offset


def _enforce_strict_downward_ranks(
    layout_ir: LayoutIR,
    preferred_ranks: dict[str, int],
) -> dict[str, int]:
    """Project preferred rows onto the canonical topological constraints.

    Atomic-block ranks are a macro-layout preference, not a sufficient proof
    that every visual edge has a lower target row. Shared bridge states and
    multi-consumer result states can expose combinations that are absent from
    small structural fixtures. A deterministic longest-path pass guarantees
    ``target_rank >= source_rank + 1`` without changing any graph edge.
    """

    graph = nx.DiGraph()
    graph.add_nodes_from(node.visual_id for node in layout_ir.nodes)
    graph.add_edges_from(
        (edge.source_visual_id, edge.target_visual_id)
        for edge in layout_ir.edges
    )
    if not nx.is_directed_acyclic_graph(graph):
        raise LayoutPlanValidationError(
            "visual rank projection requires an acyclic graph"
        )

    ranks = dict(preferred_ranks)
    for visual_id in nx.lexicographical_topological_sort(
        graph,
        key=lambda item: item,
    ):
        parents = tuple(graph.predecessors(visual_id))
        if parents:
            ranks[visual_id] = max(
                ranks[visual_id],
                max(ranks[parent] + 1 for parent in parents),
            )
    return ranks


def plan_layout(layout_ir: LayoutIR,
                objective_id: str | None = None) -> LayoutPlan:
    """Create a deterministic top-down branch layout from Stage-A IR.

    ``objective_id`` is the whole graph's objective, when the caller knows it.
    Only the foot of the page depends on it; everything else is unchanged.
    """

    graph = _block_graph(layout_ir)
    macro = analyze_macro_layout(layout_ir)
    block_to_module = dict(macro.block_to_module)
    block_order = {
        block.id: index for index, block in enumerate(layout_ir.atomic_blocks)
    }
    component_index = _component_indices(graph, block_order)
    # The trunk remains useful diagnostic metadata, but it no longer controls
    # module placement. The old centre bias made a valid causal chain dominate
    # the page and visually demoted its sibling branches.
    trunk_block_ids = _main_trunks(graph, block_order)
    trunk_ids = set(trunk_block_ids)
    ranks = _ordered_block_ranks(layout_ir, graph)
    visual_to_block, members = _visual_block_membership(layout_ir)
    widths = _block_widths(layout_ir, visual_to_block)
    centres = (
        _block_centres(
            layout_ir, graph, ranks, widths
        )
        if layout_ir.atomic_blocks
        else {}
    )

    node_by_visual = {node.visual_id: node for node in layout_ir.nodes}
    event_to_block = {
        event_id: block.id
        for block in layout_ir.atomic_blocks
        for event_id in block.event_ids
    }
    visual_rank: dict[str, int] = {}
    heights = {
        node.visual_id: _estimate_height(node) for node in layout_ir.nodes
    }
    consumer_events: dict[str, list[str]] = {}
    for edge in layout_ir.edges:
        if (
            node_by_visual[edge.source_visual_id].semantics.kind == "state"
            and node_by_visual[edge.target_visual_id].semantics.kind == "event"
        ):
            consumer_events.setdefault(
                edge.source_visual_id, []
            ).append(edge.target_visual_id)

    for node in layout_ir.nodes:
        block_id = visual_to_block.get(node.visual_id)
        if block_id is None:
            consumers = consumer_events.get(node.visual_id, [])
            if consumers:
                visual_rank[node.visual_id] = min(
                    next(
                        block.rank
                        for block in layout_ir.atomic_blocks
                        if event_to_block[event_id] == block.id
                    ) * 3
                    for event_id in consumers
                )
            else:
                visual_rank[node.visual_id] = 0
            continue
        block = next(
            item for item in layout_ir.atomic_blocks if item.id == block_id
        )
        if node.semantics.kind == "event":
            visual_rank[node.visual_id] = block.rank * 3 + 1
        elif node.semantics.parents:
            visual_rank[node.visual_id] = block.rank * 3 + 2
        else:
            visual_rank[node.visual_id] = block.rank * 3

    visual_rank = _enforce_strict_downward_ranks(
        layout_ir,
        visual_rank,
    )
    visual_rank = _close_on_the_objective(layout_ir, visual_rank,
                                          objective_id)

    occupied_ranks = sorted(set(visual_rank.values()))
    rank_y: dict[int, int] = {}
    y_cursor = TOP_MARGIN
    for rank in occupied_ranks:
        rank_y[rank] = y_cursor
        rank_height = max(
            heights[visual_id]
            for visual_id, item_rank in visual_rank.items()
            if item_rank == rank
        )
        y_cursor += rank_height + NODE_ROW_GAP

    node_centres: dict[str, float] = {}
    # Events establish the local columns used by roots and result states.
    for block in layout_ir.atomic_blocks:
        event_centres = _bounded_row_centres(
            _even_centres(centres[block.id], len(block.event_ids)),
            centres[block.id],
            widths[block.id],
        )
        for event_id, center in zip(block.event_ids, event_centres):
            node_centres[event_id] = center

    # Place every page-local root exactly once. Shared prerequisites sit above
    # the median of all consumer columns; single-consumer roots remain aligned
    # with their atomic event block. Fitting is performed per visual rank so
    # grouped prerequisite ellipses never overlap one another.
    roots_by_rank: dict[int, list[str]] = {}
    root_desired: dict[str, float] = {}
    for node in layout_ir.nodes:
        if node.semantics.kind != "state" or node.semantics.parents:
            continue
        consumers = consumer_events.get(node.visual_id, [])
        if consumers:
            desired = median(node_centres[event_id] for event_id in consumers)
        else:
            desired = max(node_centres.values(), default=MIN_GRAPH_WIDTH / 2)
        root_desired[node.visual_id] = desired
        roots_by_rank.setdefault(
            visual_rank[node.visual_id], []
        ).append(node.visual_id)

    for rank, root_ids in roots_by_rank.items():
        ordered_roots = sorted(
            root_ids,
            key=lambda visual_id: (
                root_desired[visual_id],
                node_by_visual[visual_id].semantics.source_index,
            ),
        )
        fitted = _fit_centres(
            [root_desired[visual_id] for visual_id in ordered_roots],
            [NODE_WIDTH] * len(ordered_roots),
            NODE_COLUMN_GAP,
        )
        for visual_id, center in zip(ordered_roots, fitted):
            node_centres[visual_id] = center

    for block in layout_ir.atomic_blocks:
        result_ids = list(block.result_state_ids)
        result_desired = [
            median(
                node_centres[parent_id]
                for parent_id in node_by_visual[state_id].semantics.parents
            )
            for state_id in result_ids
        ]
        # _fit_centres spreads a row left to right in the order it is given,
        # and result states arrive in declaration order. A state that several
        # of the block's events converge on therefore landed wherever its id
        # happened to appear -- for seven parallel credential thefts sharing
        # one result, that was the far right of the row, 800px from the
        # producers' median, and the seven edges crossed the page to reach it
        # (52 bends on one page). Ordering the row by where each state wants
        # to be puts a convergence node among the producers that feed it.
        order = sorted(range(len(result_ids)), key=lambda i: result_desired[i])
        ordered_centres = _bounded_row_centres(
            [result_desired[i] for i in order],
            centres[block.id],
            widths[block.id],
        )
        for slot, center in zip(order, ordered_centres):
            node_centres[result_ids[slot]] = center

    _separate_blocks_by_drawn_extent(ranks, members, node_centres)

    # Disconnected unused roots remain visible but outside the causal lanes.
    # Placed after the separation pass and measured against where the nodes
    # actually ended up: the reserved block widths are an estimate, and putting
    # these against the estimate risked dropping one on top of a block that
    # had grown past it.
    unanchored = [
        node.visual_id for node in layout_ir.nodes
        if node.visual_id not in node_centres
    ]
    current_right = max(
        (centre + NODE_WIDTH / 2 for centre in node_centres.values()),
        default=SIDE_MARGIN,
    )
    for visual_id in unanchored:
        current_right += NODE_COLUMN_GAP + NODE_WIDTH / 2
        node_centres[visual_id] = current_right
        current_right += NODE_WIDTH / 2

    # A rigid translation, so nothing above is undone: the separation pass may
    # have pushed the leftmost block past the margin.
    if node_centres:
        left_edge = min(node_centres.values()) - NODE_WIDTH / 2
        if left_edge != SIDE_MARGIN:
            drift = SIDE_MARGIN - left_edge
            node_centres = {
                visual_id: centre + drift
                for visual_id, centre in node_centres.items()
            }

    lane_lookup = {
        block_id: (index, len(rank))
        for rank in ranks.values()
        for index, block_id in enumerate(rank)
    }
    planned_nodes: list[PlannedNode] = []
    for node in layout_ir.nodes:
        block_id = visual_to_block.get(node.visual_id)
        lane_index = (
            lane_lookup[block_id][0] if block_id is not None else -1
        )
        planned_nodes.append(PlannedNode(
            visual_id=node.visual_id,
            canonical_id=node.canonical_id,
            kind=node.semantics.kind,
            role=node.role,
            block_id=block_id,
            visual_rank=visual_rank[node.visual_id],
            lane_index=lane_index,
            x=round(node_centres[node.visual_id] - NODE_WIDTH / 2),
            y=rank_y[visual_rank[node.visual_id]],
            width=NODE_WIDTH,
            height=heights[node.visual_id],
        ))
    planned_node_map = {node.visual_id: node for node in planned_nodes}

    planned_blocks: list[PlannedBlock] = []
    for block in layout_ir.atomic_blocks:
        local_nodes = [
            planned_node_map[visual_id] for visual_id in members[block.id]
        ]
        left = min(node.x for node in local_nodes) - BLOCK_PADDING
        top = min(node.y for node in local_nodes) - BLOCK_PADDING
        right = max(node.right for node in local_nodes) + BLOCK_PADDING
        bottom = max(node.bottom for node in local_nodes) + BLOCK_PADDING
        lane_index, lane_count = lane_lookup[block.id]
        input_visual_ids = tuple(
            node.visual_id for node in layout_ir.nodes
            if (
                visual_to_block.get(node.visual_id) == block.id
                and node.semantics.kind == "state"
                and not node.semantics.parents
            )
        )
        planned_blocks.append(PlannedBlock(
            id=block.id,
            module_id=block_to_module[block.id],
            component_index=component_index[block.id],
            causal_rank=block.rank,
            lane_index=lane_index,
            lane_count=lane_count,
            x=left,
            y=top,
            width=right - left,
            height=bottom - top,
            is_trunk=block.id in trunk_ids,
            event_ids=block.event_ids,
            result_state_ids=block.result_state_ids,
            input_visual_ids=input_visual_ids,
        ))

    planned_logic: list[PlannedLogic] = []
    for group in layout_ir.logic_groups:
        target = planned_node_map[group.target_visual_id]
        inputs = [
            planned_node_map[visual_id]
            for visual_id in group.input_visual_ids
        ]
        input_points = tuple((node.cx, node.bottom) for node in inputs)
        if group.logic == "AND":
            bus_y = round((max(node.bottom for node in inputs) + target.y) / 2)
            target_ports = ((target.cx, target.y),)
            # The drop into the target leaves the bus at the target's centre, so
            # the bus has to reach it. A target placed outside the span of its
            # own inputs -- which happens whenever several events share one AND
            # pair and fan out across the rank -- otherwise gets an arrowhead
            # whose line begins in empty space.
            bus_x = [node.cx for node in inputs] + [target.cx]
            shared_bus = ((min(bus_x), bus_y), (max(bus_x), bus_y))
        else:
            target_ports = tuple(
                (
                    round(
                        target.x
                        + target.width * (index + 1) / (len(inputs) + 1)
                    ),
                    target.y,
                )
                for index in range(len(inputs))
            )
            shared_bus = None
        planned_logic.append(PlannedLogic(
            group_id=group.id,
            logic=group.logic,
            target_visual_id=group.target_visual_id,
            input_visual_ids=group.input_visual_ids,
            input_points=input_points,
            target_ports=target_ports,
            shared_bus=shared_bus,
        ))

    right = max((node.right for node in planned_nodes), default=0)
    bottom = max((node.bottom for node in planned_nodes), default=0)
    plan = LayoutPlan(
        profile_id=layout_ir.profile_id,
        width=max(MIN_GRAPH_WIDTH, right + SIDE_MARGIN),
        height=bottom + BOTTOM_MARGIN,
        blocks=tuple(planned_blocks),
        nodes=tuple(planned_nodes),
        logic=tuple(planned_logic),
        trunk_block_ids=trunk_block_ids,
        macro_module_ids=tuple(module.id for module in macro.modules),
    )
    validate_layout_plan(layout_ir, plan)
    return plan


def _boxes_overlap(left: PlannedNode, right: PlannedNode) -> bool:
    return (
        left.x < right.right
        and right.x < left.right
        and left.y < right.bottom
        and right.y < left.bottom
    )


def validate_layout_plan(layout_ir: LayoutIR, plan: LayoutPlan) -> None:
    """Validate top-down geometry and complete Stage-A node coverage."""

    expected_visual_ids = {node.visual_id for node in layout_ir.nodes}
    actual_visual_ids = [node.visual_id for node in plan.nodes]
    if (
        len(actual_visual_ids) != len(set(actual_visual_ids))
        or set(actual_visual_ids) != expected_visual_ids
    ):
        raise LayoutPlanValidationError(
            "layout plan must place every visual occurrence exactly once"
        )

    expected_block_ids = {block.id for block in layout_ir.atomic_blocks}
    if {block.id for block in plan.blocks} != expected_block_ids:
        raise LayoutPlanValidationError(
            "layout plan must place every atomic block exactly once"
        )

    node_map = {node.visual_id: node for node in plan.nodes}
    for edge in layout_ir.edges:
        source = node_map[edge.source_visual_id]
        target = node_map[edge.target_visual_id]
        if source.bottom >= target.y:
            raise LayoutPlanValidationError(
                f"non-downward edge {source.visual_id!r} -> "
                f"{target.visual_id!r}"
            )

    for index, left in enumerate(plan.nodes):
        for right in plan.nodes[index + 1:]:
            if _boxes_overlap(left, right):
                raise LayoutPlanValidationError(
                    f"node overlap: {left.visual_id!r}, {right.visual_id!r}"
                )

    block_map = {block.id: block for block in plan.blocks}
    for index, left in enumerate(plan.blocks):
        for right in plan.blocks[index + 1:]:
            if (
                left.causal_rank == right.causal_rank
                and left.x < right.right
                and right.x < left.right
            ):
                raise LayoutPlanValidationError(
                    f"same-rank blocks overlap: {left.id!r}, {right.id!r}"
                )

    visual_to_block = {
        node.visual_id: node.block_id for node in plan.nodes
    }
    for block in layout_ir.atomic_blocks:
        for event_id in block.event_ids:
            if visual_to_block[event_id] != block.id:
                raise LayoutPlanValidationError(
                    f"event {event_id!r} left atomic block {block.id!r}"
                )
        for state_id in block.result_state_ids:
            if visual_to_block[state_id] != block.id:
                raise LayoutPlanValidationError(
                    f"result {state_id!r} left atomic block {block.id!r}"
                )

    ir_node_map = {node.visual_id: node for node in layout_ir.nodes}
    for visual_id, block_id in visual_to_block.items():
        anchor_event_id = ir_node_map[visual_id].anchor_event_id
        if anchor_event_id and block_id != visual_to_block[anchor_event_id]:
            raise LayoutPlanValidationError(
                f"root occurrence {visual_id!r} left its consumer block"
            )

    if plan.width <= 0 or plan.height <= 0:
        raise LayoutPlanValidationError("layout plan dimensions must be positive")
    if any(block.width <= 0 or block.height <= 0
           for block in block_map.values()):
        raise LayoutPlanValidationError("block dimensions must be positive")
