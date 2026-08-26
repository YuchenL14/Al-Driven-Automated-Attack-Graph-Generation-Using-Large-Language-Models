from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Iterable

from attack_lookup import AttackResolver
from schema import ATTACK_TACTICS, AttackGraph
from semantic_draft import IncidentSemanticDraft
from semantic_layout import (
    SemanticLayoutPlan,
    SemanticPageLayout,
    SemanticPlannedNode,
    plan_semantic_layout,
)


WHITE = "#FFFFFF"
TEXT = "#222222"
BORDER = "#303030"
TACTIC = "#B8B5EA"
LIKELIHOOD = "#31A8C4"
TECHNIQUE = "#F3B2B2"
MITIGATION = "#E7BE9B"
TAG_BORDER = "#8D6B57"
ANNOTATION = "#666666"

BADGE_DIAMETER = 26
LEGEND_GAP = 34
LEGEND_MIN_WIDTH = 360
LEGEND_LINE_HEIGHT = 13
MIN_CANVAS_WIDTH = 1248
MIN_CANVAS_HEIGHT = 710


def _load_fonts():
    try:
        from PIL import ImageFont
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Semantic PNG rendering requires Pillow."
        ) from exc
    candidates = (
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    )

    def get(size: int):
        for candidate in candidates:
            if Path(candidate).is_file():
                return ImageFont.truetype(candidate, size=size)
        return ImageFont.load_default()

    return {
        "node": get(14),
        "badge": get(11),
        "tag": get(9),
        "legend": get(10),
        "header": get(14),
    }


def _text_size(draw, text: str, font) -> tuple[int, int]:
    bounds = draw.textbbox((0, 0), text, font=font)
    return bounds[2] - bounds[0], bounds[3] - bounds[1]


def _wrap(draw, text: str, font, width: int) -> list[str]:
    lines: list[str] = []
    for paragraph in str(text).splitlines() or [""]:
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        current = words[0]
        for word in words[1:]:
            candidate = f"{current} {word}"
            if _text_size(draw, candidate, font)[0] <= width:
                current = candidate
            else:
                lines.append(current)
                current = word
        lines.append(current)
    return lines


def _draw_centered(
        draw, lines: Iterable[str], center_x: int, center_y: int, font,
        *, fill: str = TEXT, gap: int = 2) -> None:
    lines = list(lines)
    heights = [_text_size(draw, line, font)[1] for line in lines]
    total = sum(heights) + max(0, len(lines) - 1) * gap
    y = round(center_y - total / 2)
    for line, height in zip(lines, heights):
        width, _ = _text_size(draw, line, font)
        draw.text(
            (round(center_x - width / 2), y),
            line,
            font=font,
            fill=fill,
        )
        y += height + gap


def _draw_badge(draw, x: int, y: int, text: str, fill: str, font) -> None:
    radius = BADGE_DIAMETER // 2
    draw.ellipse(
        (x - radius, y - radius, x + radius, y + radius),
        fill=fill,
    )
    _draw_centered(draw, [text], x, y, font, gap=0)


def _draw_tag(draw, right: int, top: int, text: str, fill: str, font) -> int:
    text_width, text_height = _text_size(draw, text, font)
    width = text_width + 8
    height = text_height + 4
    left = right - width
    draw.rectangle(
        (left, top, right, top + height),
        fill=fill,
        outline=TAG_BORDER,
        width=1,
    )
    draw.text((left + 4, top + 2), text, font=font, fill=TEXT)
    return height


def _draw_dashed_line(draw, points, *, dash: int = 5, gap: int = 4) -> None:
    for start, end in zip(points, points[1:]):
        x1, y1 = start
        x2, y2 = end
        distance = abs(x2 - x1) + abs(y2 - y1)
        if distance == 0:
            continue
        horizontal = y1 == y2
        direction = 1 if (x2 >= x1 if horizontal else y2 >= y1) else -1
        cursor = 0
        while cursor < distance:
            length = min(dash, distance - cursor)
            if horizontal:
                segment = (
                    x1 + direction * cursor, y1,
                    x1 + direction * (cursor + length), y1,
                )
            else:
                segment = (
                    x1, y1 + direction * cursor,
                    x1, y1 + direction * (cursor + length),
                )
            draw.line(segment, fill=ANNOTATION, width=1)
            cursor += dash + gap


def _draw_dashed_rectangle(draw, bounds) -> None:
    left, top, right, bottom = bounds
    _draw_dashed_line(draw, [(left, top), (right, top)])
    _draw_dashed_line(draw, [(right, top), (right, bottom)])
    _draw_dashed_line(draw, [(right, bottom), (left, bottom)])
    _draw_dashed_line(draw, [(left, bottom), (left, top)])


def _draw_arrow(draw, start: tuple[int, int], end: tuple[int, int]) -> None:
    sx, sy = start
    ex, ey = end
    if abs(ex - sx) >= abs(ey - sy):
        direction = 1 if ex >= sx else -1
        points = [
            (ex, ey),
            (ex - 7 * direction, ey - 4),
            (ex - 7 * direction, ey + 4),
        ]
    else:
        direction = 1 if ey >= sy else -1
        points = [
            (ex, ey),
            (ex - 4, ey - 7 * direction),
            (ex + 4, ey - 7 * direction),
        ]
    draw.polygon(points, fill=BORDER)


def _draw_solid_path(draw, points, *, arrow: bool = True) -> None:
    draw.line(points, fill=BORDER, width=1)
    if arrow and len(points) >= 2:
        _draw_arrow(draw, points[-2], points[-1])


def _edge_path(
        source: SemanticPlannedNode,
        target: SemanticPlannedNode,
        page: SemanticPageLayout,
        *,
        lane_offset: int = 0) -> list[tuple[int, int]]:
    """Route long dependencies around nodes; short edges stay orthogonal."""

    start = (source.cx, source.bottom)
    end = (target.cx, target.y)
    if target.rank == source.rank + 1:
        middle = round((source.bottom + target.y) / 2)
        return [start, (source.cx, middle), (target.cx, middle), end]

    page_nodes = [
        node for node in page.nodes if node.id not in {source.id, target.id}
    ]
    vertical_top = source.bottom + 1
    vertical_bottom = target.y - 1
    padding = 9
    # Candidate channels sit just outside existing node columns.  The closest
    # channel that does not pass through an intermediate node is selected.
    candidates = {source.cx, target.cx, 8, page.width - 8}
    for node in page_nodes:
        candidates.add(node.x - padding)
        candidates.add(node.right + padding)

    def is_clear(x: int) -> bool:
        return not any(
            node.y < vertical_bottom
            and node.bottom > vertical_top
            and node.x - padding < x < node.right + padding
            for node in page_nodes
        )

    clear = [x for x in candidates if is_clear(x)]
    if clear:
        corridor = min(
            clear,
            key=lambda x: (
                abs(x - source.cx) + abs(x - target.cx),
                abs(x - (source.cx + target.cx) / 2),
            ),
        )
    else:
        corridor = (
            min(node.x for node in page.nodes) - 14
            if source.cx <= target.cx
            else max(node.right for node in page.nodes) + 14
        )
    corridor += lane_offset if corridor >= target.cx else -lane_offset
    return [
        start,
        (corridor, source.bottom),
        (corridor, target.y - 12),
        (target.cx, target.y - 12),
        end,
    ]


def _draw_connectors(draw, page: SemanticPageLayout) -> None:
    nodes = {node.id: node for node in page.nodes}
    causal_by_target = defaultdict(list)
    annotations = []
    for edge in page.edges:
        if edge.relation == "annotation":
            annotations.append(edge)
        else:
            causal_by_target[edge.target].append(edge)

    for target_id, edges in causal_by_target.items():
        target = nodes[target_id]
        if len(edges) > 1 and all(edge.logic == "AND" for edge in edges):
            sources = [nodes[edge.source] for edge in edges]
            bus_y = target.y - 12
            input_xs = []
            for index, source in enumerate(sources):
                path = _edge_path(
                    source, target, page, lane_offset=index * 8)
                # Stop at the shared bus; the bus has one arrow to the event.
                input_path = path[:-1]
                if input_path[-1][1] != bus_y:
                    input_path.append((input_path[-1][0], bus_y))
                _draw_solid_path(draw, input_path, arrow=False)
                input_xs.append(input_path[-1][0])
            draw.line(
                (min(input_xs), bus_y, max(input_xs), bus_y),
                fill=BORDER,
                width=1,
            )
            _draw_solid_path(
                draw, [(target.cx, bus_y), (target.cx, target.y)])
            continue

        # OR inputs remain visually separate; single inputs use the same route.
        for index, edge in enumerate(edges):
            source = nodes[edge.source]
            path = _edge_path(
                source, target, page, lane_offset=index * 8)
            _draw_solid_path(draw, path)

    outer_right = max(node.right for node in page.nodes) + 18
    for index, edge in enumerate(annotations):
        source = nodes[edge.source]
        target = nodes[edge.target]
        visual_anchor = target
        containing_group = next(
            (
                group for group in page.rank_groups
                if source.id in group
            ),
            (),
        )
        related_members = [
            nodes[node_id]
            for node_id in containing_group
            if (
                node_id != source.id
                and (node_id, target.id) in {
                    (candidate.source, candidate.target)
                    for candidate in page.edges
                    if candidate.relation == "causal"
                }
            )
        ]
        if related_members:
            visual_anchor = min(
                related_members,
                key=lambda node: abs(node.cx - source.cx),
            )
        if visual_anchor.rank == source.rank:
            if source.cx >= visual_anchor.cx:
                points = [
                    (source.x, source.cy),
                    (visual_anchor.right, visual_anchor.cy),
                ]
            else:
                points = [
                    (source.right, source.cy),
                    (visual_anchor.x, visual_anchor.cy),
                ]
            _draw_dashed_line(draw, points)
            continue
        corridor = outer_right + index * 8
        points = [
            (source.cx, source.bottom),
            (corridor, source.bottom),
            (corridor, visual_anchor.cy),
            (visual_anchor.right, visual_anchor.cy),
        ]
        _draw_dashed_line(draw, points)


def _page_legend(
        model: AttackGraph,
        page: SemanticPageLayout,
        resolver: AttackResolver) -> list[str]:
    event_by_id = {event.id: event for event in model.events}
    event_ids = {
        node.canonical_id for node in page.nodes if node.role == "event"
    }
    techniques = {}
    mitigations = {}
    tactics = {}
    for event_id in event_ids:
        event = event_by_id[event_id]
        tactics[event.tactic] = ATTACK_TACTICS[event.tactic]
        if event.technique:
            techniques[event.technique] = resolver.resolve_technique(
                event.technique)
        for mitigation in event.mitigations:
            mitigations[mitigation] = resolver.resolve_mitigation(mitigation)
    lines = [f"{code}: {name}" for code, name in sorted(techniques.items())]
    if mitigations:
        lines.append("")
        lines.extend(
            f"{code}: {name}" for code, name in sorted(mitigations.items()))
    if tactics:
        lines.append("")
        lines.extend(
            f"{code}: {name}" for code, name in tactics.items())
    return lines


def _draw_node(
        draw,
        node: SemanticPlannedNode,
        semantic_by_id,
        event_by_id,
        fonts) -> None:
    semantic = semantic_by_id[node.id]
    bounds = (node.x, node.y, node.right, node.bottom)
    if node.shape == "ellipse":
        draw.ellipse(bounds, fill=WHITE, outline=BORDER, width=2)
    elif node.shape == "annotation":
        _draw_dashed_rectangle(draw, bounds)
    else:
        draw.rectangle(bounds, fill=WHITE, outline=BORDER, width=1)

    continuation = (
        f"continued from part {semantic.continued_from_page}"
        if semantic.role == "continuation_state"
        else (
            f"continues in part {getattr(semantic, 'continues_on_page')}"
            if getattr(semantic, "continues_on_page", None) else None
        )
    )
    label_center_y = node.cy - (8 if continuation else 0)
    _draw_centered(
        draw,
        _wrap(draw, semantic.label, fonts["node"], node.width - 18),
        node.cx,
        label_center_y,
        fonts["node"],
    )
    if continuation:
        width, height = _text_size(draw, continuation, fonts["tag"])
        draw.text(
            (round(node.cx - width / 2), node.bottom - height - 5),
            continuation,
            font=fonts["tag"],
            fill=ANNOTATION,
        )

    if semantic.role != "event":
        return
    event = event_by_id[semantic.id]
    _draw_badge(
        draw, node.x - 2, node.y - 4,
        event.tactic, TACTIC, fonts["badge"])
    if event.technique:
        _draw_tag(
            draw, node.right + 1, node.y - 8,
            event.technique, TECHNIQUE, fonts["tag"])
    _draw_badge(
        draw, node.x + 1, node.bottom - 1,
        f"{event.likelihood:.1f}", LIKELIHOOD, fonts["badge"])
    tag_y = node.bottom - 12
    for mitigation in reversed(event.mitigations):
        tag_height = _draw_tag(
            draw, node.right + 1, tag_y,
            mitigation, MITIGATION, fonts["tag"])
        tag_y -= tag_height + 1


def render_semantic_layout(
        model: AttackGraph,
        draft: IncidentSemanticDraft,
        out_path: str,
        resolver: AttackResolver | None = None,
        *,
        dpi: int = 170) -> list[str]:
    """Plan and render every authored semantic page without model geometry."""

    try:
        from PIL import Image, ImageDraw
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Semantic PNG rendering requires Pillow."
        ) from exc

    resolver = resolver or AttackResolver()
    plan: SemanticLayoutPlan = plan_semantic_layout(draft)
    semantic_by_id = {node.id: node for node in draft.nodes}
    event_by_id = {event.id: event for event in model.events}
    fonts = _load_fonts()
    output = Path(out_path)
    paths: list[str] = []

    for page in plan.pages:
        measure = Image.new("RGBA", (8, 8), WHITE)
        measure_draw = ImageDraw.Draw(measure)
        legend = _page_legend(model, page, resolver)
        legend_width = max(
            (_text_size(measure_draw, line, fonts["legend"])[0]
             for line in legend),
            default=0,
        )
        legend_area_width = max(LEGEND_MIN_WIDTH, legend_width + 24)
        legend_x = page.width + LEGEND_GAP
        canvas_width = max(
            MIN_CANVAS_WIDTH, legend_x + legend_area_width)
        canvas_height = max(
            MIN_CANVAS_HEIGHT,
            page.height,
            88 + len(legend) * LEGEND_LINE_HEIGHT,
        )
        image = Image.new("RGBA", (canvas_width, canvas_height), WHITE)
        draw = ImageDraw.Draw(image)
        header = (
            f"{draft.title} — {page.title} "
            f"(Part {page.page} of {len(plan.pages)})"
        )
        draw.text(
            (12, 10), header, font=fonts["header"], fill=TEXT)

        _draw_connectors(draw, page)
        for node in sorted(
            page.nodes, key=lambda item: (item.rank, item.x, item.id)
        ):
            _draw_node(
                draw, node, semantic_by_id, event_by_id, fonts)

        legend_y = 70
        for line in legend:
            if line:
                draw.text(
                    (legend_x, legend_y),
                    line,
                    font=fonts["legend"],
                    fill=TEXT,
                )
            legend_y += LEGEND_LINE_HEIGHT

        if len(plan.pages) == 1:
            page_path = output
        else:
            page_path = output.with_name(
                f"{output.stem}_part{page.page}{output.suffix}")
        page_path.parent.mkdir(parents=True, exist_ok=True)
        image.save(page_path, format="PNG", dpi=(dpi, dpi))
        paths.append(str(page_path))
    return paths
