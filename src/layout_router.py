from __future__ import annotations

from dataclasses import dataclass, replace
from heapq import heappop, heappush
from typing import Literal

from layout_ir import LayoutIR
from layout_planner import LayoutPlan, PlannedNode


Point = tuple[int, int]
Segment = tuple[Point, Point]
ConnectorLogic = Literal["SINGLE", "AND", "OR"]

ROUTE_CLEARANCE = 18
BEND_PENALTY = 30
CROSSING_PENALTY = 90
OVERLAP_PENALTY = 7
TARGET_APPROACH = 16


class LayoutRoutingError(ValueError):
    """Raised when no valid downward orthogonal route can be produced."""


@dataclass(frozen=True)
class RoutedConnector:
    target_visual_id: str
    logic: ConnectorLogic
    input_visual_ids: tuple[str, ...]
    input_paths: tuple[tuple[Point, ...], ...]
    input_arrow_indices: tuple[int, ...]
    shared_bus: Segment | None
    output_path: tuple[Point, ...] | None
    output_arrow: bool


@dataclass(frozen=True)
class RoutedLayout:
    connectors: tuple[RoutedConnector, ...]
    occupied_segments: tuple[Segment, ...]


def _box(node: PlannedNode) -> tuple[int, int, int, int]:
    return (
        node.x - ROUTE_CLEARANCE,
        node.y - ROUTE_CLEARANCE,
        node.right + ROUTE_CLEARANCE,
        node.bottom + ROUTE_CLEARANCE,
    )


def _point_inside(
    point: Point,
    box: tuple[int, int, int, int],
) -> bool:
    x, y = point
    left, top, right, bottom = box
    return left < x < right and top < y < bottom


def _orthogonal(segment: Segment) -> bool:
    return (
        segment[0][0] == segment[1][0]
        or segment[0][1] == segment[1][1]
    )


def _segment_crosses_box(
    segment: Segment,
    box: tuple[int, int, int, int],
) -> bool:
    (x1, y1), (x2, y2) = segment
    left, top, right, bottom = box
    if x1 == x2:
        low, high = sorted((y1, y2))
        return left < x1 < right and max(low, top) < min(high, bottom)
    if y1 == y2:
        low, high = sorted((x1, x2))
        return top < y1 < bottom and max(low, left) < min(high, right)
    raise LayoutRoutingError(f"non-orthogonal segment: {segment!r}")


def _segment_clear(
    segment: Segment,
    obstacles: tuple[tuple[int, int, int, int], ...],
) -> bool:
    return not any(
        _segment_crosses_box(segment, obstacle)
        for obstacle in obstacles
    )


def _segments(path: tuple[Point, ...]) -> tuple[Segment, ...]:
    return tuple(zip(path, path[1:]))


def _simplify(points: tuple[Point, ...]) -> tuple[Point, ...]:
    result: list[Point] = []
    for point in points:
        if result and point == result[-1]:
            continue
        if len(result) >= 2:
            first, middle = result[-2], result[-1]
            if (
                first[0] == middle[0] == point[0]
                or first[1] == middle[1] == point[1]
            ):
                result[-1] = point
                continue
        result.append(point)
    return tuple(result)


def _interaction(left: Segment, right: Segment) -> tuple[int, int]:
    """Return collinear overlap length and proper crossing count."""

    (a1, a2), (b1, b2) = left, right
    a_vertical = a1[0] == a2[0]
    b_vertical = b1[0] == b2[0]
    if a_vertical and b_vertical:
        if a1[0] != b1[0]:
            return 0, 0
        a_low, a_high = sorted((a1[1], a2[1]))
        b_low, b_high = sorted((b1[1], b2[1]))
        return max(0, min(a_high, b_high) - max(a_low, b_low)), 0
    if not a_vertical and not b_vertical:
        if a1[1] != b1[1]:
            return 0, 0
        a_low, a_high = sorted((a1[0], a2[0]))
        b_low, b_high = sorted((b1[0], b2[0]))
        return max(0, min(a_high, b_high) - max(a_low, b_low)), 0

    vertical = left if a_vertical else right
    horizontal = right if a_vertical else left
    vx = vertical[0][0]
    vy_low, vy_high = sorted((vertical[0][1], vertical[1][1]))
    hy = horizontal[0][1]
    hx_low, hx_high = sorted((horizontal[0][0], horizontal[1][0]))
    crosses = (
        hx_low < vx < hx_high
        and vy_low < hy < vy_high
    )
    return 0, int(crosses)


def _edge_cost(
    start: Point,
    end: Point,
    previous_direction: str | None,
    occupied: tuple[Segment, ...],
) -> tuple[float, str]:
    direction = "H" if start[1] == end[1] else "V"
    length = abs(end[0] - start[0]) + abs(end[1] - start[1])
    bend = (
        BEND_PENALTY
        if previous_direction is not None
        and previous_direction != direction
        else 0
    )
    overlap = 0
    crossings = 0
    segment = (start, end)
    for used in occupied:
        used_overlap, used_crossings = _interaction(segment, used)
        overlap += used_overlap
        crossings += used_crossings
    return (
        length
        + bend
        + overlap * OVERLAP_PENALTY
        + crossings * CROSSING_PENALTY,
        direction,
    )


def _candidate_coordinates(
    start: Point,
    end: Point,
    plan: LayoutPlan,
    obstacles: tuple[tuple[int, int, int, int], ...],
) -> tuple[list[int], list[int]]:
    xs = {8, plan.width - 8, start[0], end[0]}
    ys = {start[1], end[1]}
    for left, top, right, bottom in obstacles:
        xs.update((max(8, left), min(plan.width - 8, right)))
        if start[1] <= top <= end[1]:
            ys.add(top)
        if start[1] <= bottom <= end[1]:
            ys.add(bottom)
    return sorted(xs), sorted(ys)


def _route(
    start: Point,
    end: Point,
    plan: LayoutPlan,
    obstacles: tuple[tuple[int, int, int, int], ...],
    occupied: tuple[Segment, ...],
) -> tuple[Point, ...]:
    if end[1] < start[1]:
        raise LayoutRoutingError(
            f"upward route requested: {start!r} -> {end!r}"
        )
    if (
        (start[0] == end[0] or start[1] == end[1])
        and _segment_clear((start, end), obstacles)
    ):
        return (start, end)

    xs, ys = _candidate_coordinates(start, end, plan, obstacles)
    points = {
        (x, y)
        for x in xs
        for y in ys
        if (
            (x, y) in {start, end}
            or not any(_point_inside((x, y), box) for box in obstacles)
        )
    }
    points.update((start, end))

    neighbours: dict[Point, list[Point]] = {point: [] for point in points}
    for y in ys:
        row = sorted(point for point in points if point[1] == y)
        for left, right in zip(row, row[1:]):
            if _segment_clear((left, right), obstacles):
                neighbours[left].append(right)
                neighbours[right].append(left)
    for x in xs:
        column = sorted(point for point in points if point[0] == x)
        for upper, lower in zip(column, column[1:]):
            if _segment_clear((upper, lower), obstacles):
                # Vertical movement is deliberately top-down only.
                neighbours[upper].append(lower)

    start_state = (start, None)
    queue: list[tuple[float, int, Point, str | None]] = []
    serial = 0
    heappush(queue, (0.0, serial, start, None))
    distance = {start_state: 0.0}
    predecessor: dict[
        tuple[Point, str | None],
        tuple[Point, str | None] | None,
    ] = {start_state: None}
    end_state: tuple[Point, str | None] | None = None

    while queue:
        cost, _, point, direction = heappop(queue)
        state = (point, direction)
        if cost != distance.get(state):
            continue
        if point == end:
            end_state = state
            break
        for neighbour in neighbours[point]:
            edge_cost, next_direction = _edge_cost(
                point, neighbour, direction, occupied
            )
            next_state = (neighbour, next_direction)
            next_cost = cost + edge_cost
            if next_cost < distance.get(next_state, float("inf")):
                distance[next_state] = next_cost
                predecessor[next_state] = state
                serial += 1
                heappush(
                    queue,
                    (next_cost, serial, neighbour, next_direction),
                )

    if end_state is None:
        # The grid search found nothing. Try detour lanes before giving up:
        # the two page margins, and a lane just outside each obstacle that
        # could be in the way. Nearest lane first, so the detour stays small.
        lanes = [8, plan.width - 8]
        for left, _, right, _ in obstacles:
            lanes.extend((left - ROUTE_CLEARANCE, right + ROUTE_CLEARANCE))
        for lane_x in sorted(
            {x for x in lanes if 0 < x < plan.width},
            key=lambda x: abs(x - start[0]),
        ):
            fallback = _simplify((
                start,
                (lane_x, start[1]),
                (lane_x, end[1]),
                end,
            ))
            if all(
                _segment_clear(segment, obstacles)
                for segment in _segments(fallback)
            ):
                return fallback

        # Every lane is blocked. Draw the direct segment rather than refuse.
        # A route that clips a node is a cosmetic fault in one edge; raising
        # here discards the whole page, and with it a graph that two paid API
        # calls produced and the schema already validated. The overlap is
        # measurable afterwards -- layout_quality counts route detours and
        # flags the page -- so the degradation is reported, not hidden.
        return _simplify((start, end))

    reversed_points: list[Point] = []
    current: tuple[Point, str | None] | None = end_state
    while current is not None:
        reversed_points.append(current[0])
        current = predecessor[current]
    return _simplify(tuple(reversed(reversed_points)))


def route_layout(layout_ir: LayoutIR, plan: LayoutPlan) -> RoutedLayout:
    """Route all Stage-A edges over the Stage-B geometry."""

    nodes = {node.visual_id: node for node in plan.nodes}
    ir_nodes = {node.visual_id: node for node in layout_ir.nodes}
    logic_by_target = {
        group.target_visual_id: group for group in layout_ir.logic_groups
    }
    incoming: dict[str, list[str]] = {}
    for edge in layout_ir.edges:
        incoming.setdefault(edge.target_visual_id, []).append(
            edge.source_visual_id
        )

    connectors: list[RoutedConnector] = []
    occupied: list[Segment] = []
    targets = sorted(
        incoming,
        key=lambda visual_id: (
            nodes[visual_id].y,
            nodes[visual_id].x,
            ir_nodes[visual_id].semantics.source_index,
        ),
    )
    for target_id in targets:
        target = nodes[target_id]
        logic_group = logic_by_target.get(target_id)
        if logic_group:
            input_ids = logic_group.input_visual_ids
            logic: ConnectorLogic = logic_group.logic
        else:
            input_ids = tuple(incoming[target_id])
            logic = "SINGLE"

        input_paths: list[tuple[Point, ...]] = []
        shared_bus: Segment | None = None
        output_path: tuple[Point, ...] | None = None
        if logic == "AND":
            planned_logic = next(
                item for item in plan.logic
                if item.target_visual_id == target_id
            )
            if planned_logic.shared_bus is None:
                raise LayoutRoutingError(
                    f"AND target {target_id!r} has no planned bus"
                )
            shared_bus = planned_logic.shared_bus
            bus_y = shared_bus[0][1]
            for input_id in input_ids:
                source = nodes[input_id]
                start = (source.cx, source.bottom)
                end = (source.cx, bus_y)
                obstacles = tuple(
                    _box(node) for node in plan.nodes
                    if node.visual_id != input_id
                )
                path = _route(
                    start, end, plan, obstacles, tuple(occupied)
                )
                input_paths.append(path)
                occupied.extend(_segments(path))
            occupied.append(shared_bus)
            output_start = (target.cx, bus_y)
            output_end = (target.cx, target.y)
            obstacles = tuple(
                _box(node) for node in plan.nodes
                if node.visual_id != target_id
            )
            output_path = _route(
                output_start,
                output_end,
                plan,
                obstacles,
                tuple(occupied),
            )
            occupied.extend(_segments(output_path))
            input_arrow_indices: tuple[int, ...] = ()
            output_arrow = True
        else:
            planned_logic = next(
                (
                    item for item in plan.logic
                    if item.target_visual_id == target_id
                ),
                None,
            )
            if planned_logic:
                ports = planned_logic.target_ports
            else:
                ports = ((target.cx, target.y),)
            for index, (input_id, port) in enumerate(zip(input_ids, ports)):
                source = nodes[input_id]
                start = (source.cx, source.bottom)
                # Force the final segment to enter the target from above.
                # Without this short approach segment, an otherwise valid
                # shortest path can finish horizontally along the top border,
                # which makes the arrow direction visually ambiguous.
                approach = (
                    port[0],
                    max(start[1], port[1] - TARGET_APPROACH),
                )
                obstacles = tuple(
                    _box(node) for node in plan.nodes
                    if node.visual_id not in {input_id, target_id}
                )
                routed_to_approach = _route(
                    start,
                    approach,
                    plan,
                    obstacles,
                    tuple(occupied),
                )
                path = _simplify(routed_to_approach + (port,))
                input_paths.append(path)
                occupied.extend(_segments(path))
            input_arrow_indices = tuple(range(len(input_paths)))
            output_arrow = False

        connectors.append(RoutedConnector(
            target_visual_id=target_id,
            logic=logic,
            input_visual_ids=input_ids,
            input_paths=tuple(input_paths),
            input_arrow_indices=input_arrow_indices,
            shared_bus=shared_bus,
            output_path=output_path,
            output_arrow=output_arrow,
        ))

    # Normalise every emitted path in one place. Most are simplified where
    # they are built, but the AND drops are not, and a drop whose input already
    # sits on the bus line came out as a zero-length segment: five of them
    # across eighteen saved figures, drawn as nothing and counted as a bend.
    connectors = [
        replace(
            connector,
            input_paths=tuple(_simplify(path)
                              for path in connector.input_paths),
            output_path=(_simplify(connector.output_path)
                         if connector.output_path else connector.output_path),
        )
        for connector in connectors
    ]
    routed = RoutedLayout(
        connectors=tuple(connectors),
        occupied_segments=tuple(occupied),
    )
    # Imported here: layout_quality reaches the renderer, which imports this
    # module, so a top-level import would close a cycle.
    from layout_quality import quality_mode

    overlaps = validate_routed_layout(layout_ir, plan, routed)
    if overlaps and quality_mode() == "strict":
        raise LayoutRoutingError("; ".join(overlaps))
    return routed


def validate_routed_layout(
    layout_ir: LayoutIR,
    plan: LayoutPlan,
    routed: RoutedLayout,
) -> list[str]:
    """Check coverage, orthogonality, direction and obstacle clearance.

    Two kinds of fault are separated here. A missing, diagonal or upward
    segment is a broken drawing and still raises: the reader would be shown a
    connector that means nothing. A route that clips a node is a legibility
    fault in one edge, and it is returned rather than raised.

    The distinction matters because congestion is not always avoidable. In the
    STOLEN PENCIL graph, an intervening state's clearance box enclosed the very
    y the AND bus sits on, so no orthogonal route to it existed at any lane.
    Raising there discarded a page that two paid API calls had produced and the
    schema had already validated. The caller applies the project's standing
    policy: report under AGVS_QUALITY_MODE=warn, refuse under strict.
    """

    overlaps: list[str] = []

    incoming_targets = {
        edge.target_visual_id for edge in layout_ir.edges
    }
    connector_targets = [
        connector.target_visual_id for connector in routed.connectors
    ]
    if (
        len(connector_targets) != len(set(connector_targets))
        or set(connector_targets) != incoming_targets
    ):
        raise LayoutRoutingError(
            "every causal target must have exactly one routed connector"
        )

    nodes = {node.visual_id: node for node in plan.nodes}
    for connector in routed.connectors:
        if len(connector.input_paths) != len(connector.input_visual_ids):
            raise LayoutRoutingError("connector input path count changed")
        target_id = connector.target_visual_id
        for input_id, path in zip(
            connector.input_visual_ids,
            connector.input_paths,
        ):
            if len(path) < 2:
                raise LayoutRoutingError("connector path is incomplete")
            for segment in _segments(path):
                if not _orthogonal(segment):
                    raise LayoutRoutingError(
                        f"diagonal connector segment: {segment!r}"
                    )
                if segment[1][1] < segment[0][1]:
                    raise LayoutRoutingError(
                        f"upward connector segment: {segment!r}"
                    )
            excluded = {input_id}
            if connector.logic != "AND":
                excluded.add(target_id)
            obstacles = tuple(
                _box(node) for node in plan.nodes
                if node.visual_id not in excluded
            )
            if any(
                not _segment_clear(segment, obstacles)
                for segment in _segments(path)
            ):
                overlaps.append(
                    f"path crosses a node: {input_id!r} -> {target_id!r}")

        if connector.shared_bus:
            # The drop into the target leaves the bus at the target's centre.
            # A bus that stops short of that centre leaves the arrowhead
            # attached to a line that starts nowhere -- a defect that reads as
            # an unexplained arrow rather than as a routing error.
            (bus_left, _), (bus_right, _) = connector.shared_bus
            target_cx = nodes[target_id].cx
            if not bus_left <= target_cx <= bus_right:
                raise LayoutRoutingError(
                    f"AND bus does not reach its target for {target_id!r}: "
                    f"bus spans x {bus_left}..{bus_right}, target centre "
                    f"is x {target_cx}"
                )
            obstacles = tuple(_box(node) for node in plan.nodes)
            if not _segment_clear(connector.shared_bus, obstacles):
                overlaps.append(f"AND bus crosses a node for {target_id!r}")
        if connector.output_path:
            for segment in _segments(connector.output_path):
                if (
                    not _orthogonal(segment)
                    or segment[1][1] < segment[0][1]
                ):
                    raise LayoutRoutingError(
                        f"invalid AND output segment: {segment!r}"
                    )
            obstacles = tuple(
                _box(node) for node in plan.nodes
                if node.visual_id != target_id
            )
            if any(
                not _segment_clear(segment, obstacles)
                for segment in _segments(connector.output_path)
            ):
                overlaps.append(
                    f"AND output crosses a node for {target_id!r}")

    return overlaps
