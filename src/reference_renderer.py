from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Mapping

import networkx as nx

from schema import ATTACK_TACTICS, AttackGraph
from visual_syntax import AGVS_SP_V1, project_visual_nodes

if TYPE_CHECKING:
    from attack_lookup import AttackResolver


WHITE = "#FFFFFF"
TEXT = "#222222"
BORDER = "#333333"
TACTIC = "#AFAFE9"
TECHNIQUE = "#FFAAAA"
LIKELIHOOD = "#37ABC8"
MITIGATION = "#FFCCAA"
TAG_BORDER = "#8D6B57"
CONTINUATION = "#666666"

NODE_W = 150
NODE_MIN_H = 92
BADGE_D = 26
SIDE_MARGIN = 14
TOP_MARGIN = 43
HORIZONTAL_GAP = 66
RANK_GAP = 62


@dataclass(frozen=True)
class _VisualNode:
    """One validated model object plus the geometry used to draw it."""

    id: str
    kind: str
    shape: str
    label: str
    code: str | None
    code_namespace: str
    technique: str | None
    mitigations: tuple[str, ...]
    likelihood: float | None
    parents: tuple[str, ...]
    join: str
    index: int
    level: int
    x: int = 0
    y: int = 0
    width: int = NODE_W
    height: int = NODE_MIN_H
    continuation: str | None = None

    @property
    def cx(self) -> int:
        return self.x + self.width // 2

    @property
    def bottom(self) -> int:
        return self.y + self.height


@dataclass(frozen=True)
class _ConnectorPlan:
    """Orthogonal paths for one target, before pixels are drawn."""

    target_id: str
    logic: str
    parent_ids: tuple[str, ...]
    paths: tuple[tuple[tuple[int, int], ...], ...]
    arrow_path_indices: tuple[int, ...]
    shared_bus: tuple[tuple[int, int], tuple[int, int]] | None = None


def _load_fonts():
    """Use Arial when present; fall back cleanly on non-Windows systems."""
    try:
        from PIL import ImageFont
    except ImportError as exc:  # pragma: no cover - shown to users at runtime
        raise RuntimeError(
            "PNG reference rendering needs Pillow. Run `pip install -r "
            "requirements.txt` and try again."
        ) from exc

    candidates = (
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
        "/usr/share/fonts/truetype/msttcorefonts/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    )

    def get(size: int):
        for path in candidates:
            if Path(path).is_file():
                return ImageFont.truetype(path, size=size)
        return ImageFont.load_default()

    return {
        "node": get(14),
        "badge": get(12),
        "tag": get(10),
        "legend": get(10),
    }


def _text_size(draw, text: str, font) -> tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=font)
    return box[2] - box[0], box[3] - box[1]


def _wrap(draw, text: str, font, width: int) -> list[str]:
    """Word-wrap labels deterministically instead of relying on Graphviz."""
    lines: list[str] = []
    for paragraph in str(text).splitlines() or [""]:
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        line = words[0]
        for word in words[1:]:
            candidate = f"{line} {word}"
            if _text_size(draw, candidate, font)[0] <= width:
                line = candidate
            else:
                lines.append(line)
                line = word
        lines.append(line)
    return lines


def _draw_centered_lines(draw, lines: Iterable[str], center_x: int, center_y: int,
                         font, fill: str = TEXT, gap: int = 2) -> None:
    lines = list(lines)
    heights = [_text_size(draw, line, font)[1] for line in lines]
    total = sum(heights) + max(0, len(lines) - 1) * gap
    y = round(center_y - total / 2)
    for line, height in zip(lines, heights):
        width, _ = _text_size(draw, line, font)
        draw.text((round(center_x - width / 2), y), line, font=font, fill=fill)
        y += height + gap


def _draw_badge(draw, center: tuple[int, int], text: str, fill: str, font) -> None:
    x, y = center
    r = BADGE_D // 2
    draw.ellipse((x - r, y - r, x + r, y + r), fill=fill)
    _draw_centered_lines(draw, [text], x, y, font, gap=0)


def _draw_tag(draw, right: int, top: int, text: str, fill: str, font) -> tuple[int, int]:
    """Draw one small square-cornered sticker and return its dimensions."""
    tw, th = _text_size(draw, text, font)
    width, height = tw + 8, th + 4
    left = right - width
    draw.rectangle((left, top, right, top + height), fill=fill,
                   outline=TAG_BORDER, width=1)
    draw.text((left + 4, top + 2), text, font=font, fill=TEXT)
    return width, height


def _draw_arrow(draw, start: tuple[int, int], end: tuple[int, int]) -> None:
    """Draw a small arrowhead aligned with the final edge segment."""
    sx, sy = start
    ex, ey = end
    if abs(ex - sx) >= abs(ey - sy):
        direction = 1 if ex >= sx else -1
        points = [(ex, ey), (ex - 8 * direction, ey - 4),
                  (ex - 8 * direction, ey + 4)]
    else:
        direction = 1 if ey >= sy else -1
        points = [(ex, ey), (ex - 4, ey - 8 * direction),
                  (ex + 4, ey - 8 * direction)]
    draw.polygon(points, fill=BORDER)


def _build_nodes(
    model: AttackGraph,
    continuation_labels: Mapping[str, str] | None = None,
) -> dict[str, _VisualNode]:
    """Build AGVS-SP nodes without changing the validated graph semantics."""
    continuation_labels = continuation_labels or {}
    raw: dict[str, dict] = {}
    for node in project_visual_nodes(model, AGVS_SP_V1):
        raw[node.id] = {
            "kind": node.kind,
            "shape": node.shape,
            "label": node.label,
            "code": node.badge_code,
            "code_namespace": node.badge_namespace,
            "technique": node.technique,
            "mitigations": node.mitigations,
            "likelihood": node.likelihood,
            "parents": node.parents,
            "join": node.join,
            "index": node.source_index,
            "continuation": continuation_labels.get(node.id),
        }

    graph = nx.DiGraph()
    graph.add_nodes_from(raw)
    for node_id, info in raw.items():
        graph.add_edges_from((parent, node_id) for parent in info["parents"])

    levels: dict[str, int] = {}
    for node_id in nx.topological_sort(graph):
        parents = raw[node_id]["parents"]
        levels[node_id] = 0 if not parents else max(levels[p] for p in parents) + 1

    return {
        node_id: _VisualNode(id=node_id, level=levels[node_id], **info)
        for node_id, info in raw.items()
    }


def _median(values: Iterable[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _branch_ordered_ranks(
    nodes: Mapping[str, _VisualNode],
) -> dict[int, list[_VisualNode]]:
    """Order ranks with repeated downward/upward barycentric sweeps.

    A single downward pass only places a child near its parents.  It does not
    keep a preparation branch coherent after that branch forks or converges.
    Alternating sweeps use both predecessors and successors and are the small,
    deterministic part of the Sugiyama layered-layout method needed here.
    """
    ranks: dict[int, list[_VisualNode]] = {}
    for node in nodes.values():
        ranks.setdefault(node.level, []).append(node)
    for rank in ranks.values():
        rank.sort(key=lambda node: node.index)

    children: dict[str, list[str]] = {node_id: [] for node_id in nodes}
    for target in nodes.values():
        for parent_id in target.parents:
            children[parent_id].append(target.id)

    def normalised_positions() -> dict[str, float]:
        positions: dict[str, float] = {}
        for rank in ranks.values():
            denominator = max(1, len(rank))
            for position, node in enumerate(rank):
                positions[node.id] = (position + 0.5) / denominator
        return positions

    levels = sorted(ranks)
    for _ in range(6):
        positions = normalised_positions()
        for level in levels[1:]:
            ranks[level].sort(key=lambda node: (
                _median(
                    positions[parent]
                    for parent in node.parents
                    if parent in positions
                ) if node.parents else positions[node.id],
                node.index,
            ))

        positions = normalised_positions()
        for level in reversed(levels[:-1]):
            ranks[level].sort(key=lambda node: (
                _median(
                    positions[child]
                    for child in children[node.id]
                    if child in positions
                ) if children[node.id] else positions[node.id],
                node.index,
            ))
    return ranks


def _isotonic(values: list[float]) -> list[float]:
    """Least-squares non-decreasing projection using pooled adjacent blocks."""
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
        projected.extend([value] * round(weight))
    return projected


def _separated_centres(
    desired: list[float],
    *,
    minimum: float,
    maximum: float,
    separation: float,
) -> list[float]:
    """Fit desired centres while guaranteeing rank nodes never overlap."""
    transformed = [
        value - position * separation
        for position, value in enumerate(desired)
    ]
    projected = _isotonic(transformed)
    centres = [
        value + position * separation
        for position, value in enumerate(projected)
    ]
    if centres[0] < minimum:
        shift = minimum - centres[0]
        centres = [value + shift for value in centres]
    if centres[-1] > maximum:
        shift = maximum - centres[-1]
        centres = [value + shift for value in centres]
    return centres


def _layout(draw, nodes: dict[str, _VisualNode], node_font,
            compact: bool) -> dict[str, _VisualNode]:
    """Place topological ranks in stable branch-aware horizontal lanes.

    Downward flow remains the hard constraint from Phase 2.  Within that
    constraint, repeated barycentric ordering reduces crossings and coordinate
    relaxation keeps action/result pairs aligned, distributes forks, and
    centres merge nodes beneath their contributing branches.
    """
    sized: dict[str, _VisualNode] = {}
    for node_id, node in nodes.items():
        node = nodes[node_id]
        label_lines = _wrap(draw, node.label, node_font, NODE_W - 20)
        label_h = sum(_text_size(draw, line, node_font)[1]
                      for line in label_lines)
        continuation_h = 16 if node.continuation else 0
        sized[node_id] = _VisualNode(
            **{
                **node.__dict__,
                "height": max(
                    NODE_MIN_H,
                    label_h + continuation_h + 34,
                ),
            }
        )

    ranks = _branch_ordered_ranks(sized)

    widest_rank = max((len(rank) for rank in ranks.values()), default=1)
    graph_width = max(
        828,
        widest_rank * NODE_W
        + max(0, widest_rank - 1) * HORIZONTAL_GAP
        + 42,
    )

    separation = NODE_W + HORIZONTAL_GAP
    minimum_center = SIDE_MARGIN + NODE_W / 2
    maximum_center = graph_width - SIDE_MARGIN - NODE_W / 2
    centres: dict[str, float] = {}
    initial_centres: dict[str, float] = {}
    for rank in ranks.values():
        rank_width = (
            len(rank) * NODE_W
            + max(0, len(rank) - 1) * HORIZONTAL_GAP
        )
        start = (graph_width - rank_width) / 2 + NODE_W / 2
        for position, node in enumerate(rank):
            value = start + position * separation
            centres[node.id] = value
            initial_centres[node.id] = value

    children: dict[str, list[str]] = {node_id: [] for node_id in sized}
    for target in sized.values():
        for parent_id in target.parents:
            children[parent_id].append(target.id)

    def relax(levels: Iterable[int], neighbour_ids, strength: float) -> None:
        for level in levels:
            rank = ranks[level]
            desired: list[float] = []
            for node in rank:
                neighbours = [
                    centres[neighbour]
                    for neighbour in neighbour_ids(node)
                    if neighbour in centres
                ]
                relational = (
                    _median(neighbours)
                    if neighbours
                    else centres[node.id]
                )
                target = (
                    strength * relational
                    + (1.0 - strength) * initial_centres[node.id]
                )
                desired.append(target)
            fitted = _separated_centres(
                desired,
                minimum=minimum_center,
                maximum=maximum_center,
                separation=separation,
            )
            for node, value in zip(rank, fitted):
                centres[node.id] = value

    levels = sorted(ranks)
    for _ in range(8):
        relax(
            levels[1:],
            lambda node: node.parents,
            0.82,
        )
        relax(
            reversed(levels[:-1]),
            lambda node: children[node.id],
            0.62,
        )
    for _ in range(2):
        relax(
            levels[1:],
            lambda node: node.parents,
            1.0,
        )

    positioned: dict[str, _VisualNode] = {}
    y = TOP_MARGIN
    for level in sorted(ranks):
        rank = ranks[level]
        rank_h = max(node.height for node in rank)
        for node in rank:
            x = round(centres[node.id] - NODE_W / 2)
            positioned[node.id] = _VisualNode(
                **{**node.__dict__, "x": x, "y": y}
            )
        y += rank_h + (48 if compact else RANK_GAP)

    for target in positioned.values():
        for parent_id in target.parents:
            parent = positioned[parent_id]
            if parent.bottom >= target.y:
                raise ValueError(
                    f"AGVS-SP layout is not downward: {parent.id} -> "
                    f"{target.id}")
    return positioned


def _dedupe_points(
    points: Iterable[tuple[int, int]],
) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for point in points:
        if not result or result[-1] != point:
            result.append(point)
    return tuple(result)


_Point = tuple[int, int]
_Segment = tuple[_Point, _Point]


def _simplify_points(points: Iterable[_Point]) -> tuple[_Point, ...]:
    """Remove duplicate and redundant collinear points from an orthogonal path."""
    result: list[_Point] = []
    for point in _dedupe_points(points):
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


def _path_segments(path: Iterable[_Point]) -> tuple[_Segment, ...]:
    points = tuple(path)
    return tuple(zip(points, points[1:]))


def _route_box(node: _VisualNode, clearance: int = 7) -> tuple[int, int, int, int]:
    """Return the node plus its visible external badge footprint.

    Technique and Mitigation stickers are right-aligned inside the node border.
    The circular tactic/score badges are the elements that materially overhang
    the node, so the old fixed 64-pixel right overhang was unnecessarily wide
    and caused distant detours.
    """
    badge_left = BADGE_D // 2 + 4 if node.code or node.likelihood is not None else 0
    badge_top = BADGE_D // 2 + 4 if node.code else 0
    badge_bottom = BADGE_D // 2 + 3 if node.likelihood is not None else 0
    return (
        node.x - badge_left - clearance,
        node.y - badge_top - clearance,
        node.x + node.width + clearance + 2,
        node.bottom + badge_bottom + clearance,
    )


def _segment_crosses_box(
    start: _Point,
    end: _Point,
    box: tuple[int, int, int, int],
) -> bool:
    left, top, right, bottom = box
    if start[0] == end[0]:
        x = start[0]
        low, high = sorted((start[1], end[1]))
        return left < x < right and max(low, top) < min(high, bottom)
    if start[1] == end[1]:
        y = start[1]
        low, high = sorted((start[0], end[0]))
        return top < y < bottom and max(low, left) < min(high, right)
    raise ValueError(f"connector segment is not orthogonal: {start} -> {end}")


def _path_obstacle_hits(
    path: Iterable[_Point],
    obstacles: Iterable[_VisualNode],
    excluded_ids: set[str],
) -> int:
    segments = _path_segments(path)
    return sum(
        _segment_crosses_box(start, end, _route_box(node))
        for node in obstacles
        if node.id not in excluded_ids
        for start, end in segments
    )


def _segment_interaction(left: _Segment, right: _Segment) -> tuple[int, int]:
    """Return ``(collinear overlap pixels, proper crossings)``."""
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

    vertical, horizontal = (left, right) if a_vertical else (right, left)
    vx = vertical[0][0]
    hy = horizontal[0][1]
    v_low, v_high = sorted((vertical[0][1], vertical[1][1]))
    h_low, h_high = sorted((horizontal[0][0], horizontal[1][0]))
    if h_low < vx < h_high and v_low < hy < v_high:
        return 0, 1
    return 0, 0


def _path_cost(
    path: tuple[_Point, ...],
    occupied_segments: Iterable[_Segment],
    *,
    separate: bool,
) -> int:
    segments = _path_segments(path)
    length = sum(
        abs(end[0] - start[0]) + abs(end[1] - start[1])
        for start, end in segments
    )
    turns = max(0, len(segments) - 1)
    overlap = 0
    crossings = 0
    for segment in segments:
        for occupied in occupied_segments:
            shared, crossed = _segment_interaction(segment, occupied)
            overlap += shared
            crossings += crossed
    overlap_weight = 80 if separate else 16
    return length + turns * 10 + overlap * overlap_weight + crossings * 180


def _candidate_paths(
    parent: _VisualNode,
    target: _VisualNode,
    port: _Point,
    obstacles: tuple[_VisualNode, ...],
    route_bounds: tuple[int, int],
    preferred_track_y: int | None,
) -> tuple[tuple[_Point, ...], ...]:
    """Generate short local routes before considering outside lanes."""
    start = (parent.cx, parent.bottom)
    end = port
    vertical_gap = max(1, end[1] - start[1])
    start_y = start[1] + min(16, max(1, vertical_gap // 3))
    finish_y = end[1] - min(16, max(1, vertical_gap // 3))
    middle_y = round((start[1] + end[1]) / 2)

    candidates: list[tuple[_Point, ...]] = []

    def add(points: Iterable[_Point]) -> None:
        path = _simplify_points(points)
        if len(path) >= 2 and path not in candidates:
            candidates.append(path)

    if start[0] == end[0]:
        add((start, end))
    add((start, (start[0], finish_y), (end[0], finish_y), end))
    add((start, (start[0], middle_y), (end[0], middle_y), end))
    add((start, (start[0], start_y), (end[0], start_y), end))
    if preferred_track_y is not None:
        add((
            start,
            (start[0], preferred_track_y),
            (end[0], preferred_track_y),
            end,
        ))

    minimum, maximum = route_bounds
    between = [
        node
        for node in obstacles
        if node.id not in {parent.id, target.id}
        and node.y < target.y
        and node.bottom > parent.bottom
    ]
    lane_values = {
        minimum + 2,
        maximum - 2,
        parent.x - 24,
        parent.x + parent.width + 24,
        target.x - 24,
        target.x + target.width + 24,
    }
    for node in between:
        left, _, right, _ = _route_box(node)
        lane_values.update((left - 12, right + 12))

    for lane in sorted(lane_values):
        if not minimum <= lane <= maximum:
            continue
        add((
            start,
            (start[0], start_y),
            (lane, start_y),
            (lane, finish_y),
            (end[0], finish_y),
            end,
        ))
    return tuple(candidates)


def _route_to_port(
    parent: _VisualNode,
    target: _VisualNode,
    port: tuple[int, int],
    *,
    obstacles: Iterable[_VisualNode],
    route_bounds: tuple[int, int],
    occupied_segments: Iterable[_Segment] = (),
    separate: bool = False,
    preferred_track_y: int | None = None,
) -> tuple[tuple[int, int], ...]:
    """Choose the shortest clear orthogonal route to one target port."""
    obstacle_nodes = tuple(obstacles)
    occupied = tuple(occupied_segments)
    candidates = _candidate_paths(
        parent,
        target,
        port,
        obstacle_nodes,
        route_bounds,
        preferred_track_y,
    )
    excluded = {parent.id, target.id}
    clear = [
        path
        for path in candidates
        if _path_obstacle_hits(path, obstacle_nodes, excluded) == 0
    ]
    pool = clear or list(candidates)
    if not pool:
        return ((parent.cx, parent.bottom), port)
    return min(
        pool,
        key=lambda path: (
            _path_obstacle_hits(path, obstacle_nodes, excluded) * 100_000,
            _path_cost(path, occupied, separate=separate),
            len(path),
            path,
        ),
    )


def _plan_connector(
    target: _VisualNode,
    parents: list[_VisualNode],
    *,
    obstacles: Iterable[_VisualNode] = (),
    route_bounds: tuple[int, int] | None = None,
    occupied_segments: Iterable[_Segment] = (),
) -> _ConnectorPlan:
    """Build the supervisor's unlabelled AND/OR connector syntax."""

    parents = sorted(parents, key=lambda node: (node.cx, node.index))
    obstacles = tuple(obstacles)
    occupied = list(occupied_segments)
    if route_bounds is None:
        all_nodes = obstacles or tuple(parents) + (target,)
        route_bounds = (
            SIDE_MARGIN,
            max((node.x + node.width for node in all_nodes), default=828)
            + SIDE_MARGIN,
        )
    parent_ids = tuple(parent.id for parent in parents)
    if not parents:
        return _ConnectorPlan(
            target.id, target.join, (), (), (), None)

    if len(parents) == 1:
        parent = parents[0]
        path = _route_to_port(
            parent,
            target,
            (target.cx, target.y),
            obstacles=obstacles,
            route_bounds=route_bounds,
            occupied_segments=occupied,
        )
        return _ConnectorPlan(
            target.id, target.join, parent_ids, (path,), (0,), None)

    if target.join == "AND":
        bus_y = target.y - 24
        bus_left = min(*(parent.cx for parent in parents), target.cx)
        bus_right = max(*(parent.cx for parent in parents), target.cx)
        paths = []
        for parent in parents:
            path = _route_to_port(
                parent,
                target,
                (parent.cx, bus_y),
                obstacles=obstacles,
                route_bounds=route_bounds,
                occupied_segments=occupied,
            )
            paths.append(path)
            occupied.extend(_path_segments(path))
        paths.append(_dedupe_points(((target.cx, bus_y),
                                     (target.cx, target.y))))
        return _ConnectorPlan(
            target.id,
            "AND",
            parent_ids,
            tuple(paths),
            (len(paths) - 1,),
            ((bus_left, bus_y), (bus_right, bus_y)),
        )

    max_bottom = max(parent.bottom for parent in parents)
    vertical_space = target.y - max_bottom
    lower = max_bottom + max(8, vertical_space // 5)
    upper = target.y - max(8, vertical_space // 5)
    paths = []
    for position, parent in enumerate(parents, start=1):
        fraction = position / (len(parents) + 1)
        track_y = round(lower + (upper - lower) * fraction)
        port_x = round(target.x + target.width * fraction)
        path = _route_to_port(
            parent,
            target,
            (port_x, target.y),
            obstacles=obstacles,
            route_bounds=route_bounds,
            occupied_segments=occupied,
            separate=True,
            preferred_track_y=track_y,
        )
        paths.append(path)
        occupied.extend(_path_segments(path))
    return _ConnectorPlan(
        target.id,
        "OR",
        parent_ids,
        tuple(paths),
        tuple(range(len(paths))),
        None,
    )


def _draw_connector_plan(draw, plan: _ConnectorPlan) -> None:
    if plan.shared_bus:
        draw.line(plan.shared_bus, fill=BORDER, width=1)
    for path_index, path in enumerate(plan.paths):
        if len(path) < 2:
            continue
        draw.line(path, fill=BORDER, width=1)
        if path_index in plan.arrow_path_indices:
            _draw_arrow(draw, path[-2], path[-1])


def _legend_lines(model: AttackGraph, resolver: "AttackResolver") -> list[str]:
    """Use the sample's plain, grouped code list instead of a boxed table."""
    techniques: dict[str, str] = {}
    mitigations: dict[str, str] = {}
    used_tactics: dict[str, str] = {}
    for event in model.events:
        used_tactics[event.tactic] = ATTACK_TACTICS.get(event.tactic, "Unknown tactic")
        if event.technique:
            techniques[event.technique] = resolver.resolve_technique(event.technique)
        for mitigation in event.mitigations:
            mitigations[mitigation] = resolver.resolve_mitigation(mitigation)

    lines = [f"{code}: {name}" for code, name in sorted(techniques.items())]
    if mitigations:
        lines.append("")
        lines.extend(f"{code}: {name}" for code, name in sorted(mitigations.items()))
    if used_tactics:
        lines.append("")
        lines.extend(f"{code}: {name}" for code, name in used_tactics.items())
    return lines


def render_reference_png(
    model: AttackGraph,
    out_path: str,
    resolver: "AttackResolver | None" = None,
    compact: bool = False,
    *,
    page_header: str | None = None,
    continuation_labels: Mapping[str, str] | None = None,
) -> str:
    """Render the validated graph in the ``SampleCyberAttackGraph`` style."""
    try:
        from PIL import Image, ImageDraw
    except ImportError as exc:  # pragma: no cover - shown to users at runtime
        raise RuntimeError(
            "PNG reference rendering needs Pillow. Run `pip install -r "
            "requirements.txt` and try again."
        ) from exc

    if resolver is None:
        from attack_lookup import AttackResolver
        resolver = AttackResolver()

    fonts = _load_fonts()
    measure = Image.new("RGBA", (8, 8), WHITE)
    measure_draw = ImageDraw.Draw(measure)
    nodes = _layout(
        measure_draw,
        _build_nodes(model, continuation_labels),
        fonts["node"],
        compact,
    )
    graph_right = max((node.x + node.width for node in nodes.values()),
                      default=828)
    sticker_w = max(
        (_text_size(measure_draw, text, fonts["tag"])[0] + 8
         for node in nodes.values()
         for text in ((node.technique,) if node.technique else ())
         + node.mitigations),
        default=0,
    )
    legend_x = max(860, graph_right + sticker_w + 20)
    legend = _legend_lines(model, resolver)
    legend_w = max(
        (_text_size(measure_draw, line, fonts["legend"])[0]
         for line in legend),
        default=0,
    )
    legend_h = len(legend) * 12
    graph_h = max((node.bottom for node in nodes.values()), default=0) + 44
    canvas_w = max(1248, legend_x + legend_w + 18)
    canvas_h = max(706, graph_h, 202 + legend_h + 18)

    image = Image.new("RGBA", (canvas_w, canvas_h), WHITE)
    draw = ImageDraw.Draw(image)

    if page_header:
        header_w, _ = _text_size(draw, page_header, fonts["node"])
        draw.text(
            (max(SIDE_MARGIN, graph_right - header_w), 10),
            page_header,
            font=fonts["node"],
            fill=TEXT,
        )

    occupied_segments: list[_Segment] = []
    for target in sorted(nodes.values(), key=lambda n: (n.level, n.index)):
        parents = [nodes[parent] for parent in target.parents if parent in nodes]
        if not parents:
            continue
        plan = _plan_connector(
            target,
            parents,
            obstacles=nodes.values(),
            route_bounds=(SIDE_MARGIN, legend_x - SIDE_MARGIN),
            occupied_segments=occupied_segments,
        )
        _draw_connector_plan(draw, plan)
        for path in plan.paths:
            occupied_segments.extend(_path_segments(path))
        if plan.shared_bus:
            occupied_segments.append(plan.shared_bus)

    for node in sorted(nodes.values(), key=lambda n: (n.level, n.index)):
        bbox = (node.x, node.y, node.x + node.width, node.bottom)
        if node.shape == "ellipse":
            draw.ellipse(bbox, fill=WHITE, outline=BORDER, width=2)
        else:
            draw.rectangle(bbox, fill=WHITE, outline=BORDER, width=1)

        lines = _wrap(draw, node.label, fonts["node"], node.width - 20)
        label_center_y = node.y + node.height // 2
        if node.continuation:
            label_center_y -= 8
        _draw_centered_lines(
            draw,
            lines,
            node.cx,
            label_center_y,
            fonts["node"],
        )
        if node.continuation:
            note_w, note_h = _text_size(
                draw,
                node.continuation,
                fonts["tag"],
            )
            draw.text(
                (
                    round(node.cx - note_w / 2),
                    node.bottom - note_h - 8,
                ),
                node.continuation,
                font=fonts["tag"],
                fill=CONTINUATION,
            )
        if node.code:
            _draw_badge(draw, (node.x - 2, node.y - 4), node.code, TACTIC,
                        fonts["badge"])

        if node.kind == "event":
            if node.technique:
                _draw_tag(draw, node.x + node.width + 1, node.y - 8,
                          node.technique, TECHNIQUE, fonts["tag"])
            if node.likelihood is not None:
                _draw_badge(draw, (node.x + 1, node.bottom - 1),
                            f"{node.likelihood:.1f}", LIKELIHOOD,
                            fonts["badge"])
            tag_y = node.bottom - 12
            for mitigation in reversed(node.mitigations):
                _, tag_h = _draw_tag(draw, node.x + node.width + 1, tag_y,
                                     mitigation, MITIGATION, fonts["tag"])
                tag_y -= tag_h + 1

    legend_y = 202
    for line in legend:
        if line:
            draw.text((legend_x, legend_y), line,
                      font=fonts["legend"], fill=TEXT)
        legend_y += 12

    output = Path(out_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG")
    return str(output)
