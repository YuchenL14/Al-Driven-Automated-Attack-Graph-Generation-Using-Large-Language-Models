"""Vector AGVS-SP output for the same plan the PNG renderer draws.

SVG and PDF previously fell through to Graphviz, which uses an unrelated
visual syntax. A figure exported for the dissertation therefore looked nothing
like the PNG shown in the application. This module consumes the identical
Stage-A semantics, Stage-B geometry and Stage-C routes, so the vector output
is the same drawing rather than a second interpretation of the graph.

Line breaking reuses the PNG renderer's font metrics, which keeps the two
backends character-for-character identical.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Mapping, Sequence, TYPE_CHECKING

from layout_ir import LayoutIR, build_layout_ir
from layout_planner import LayoutPlan, PlannedNode, plan_layout
from layout_renderer import (BADGE_DIAMETER, BORDER, GRAPH_RIGHT_PAD,
                             LEGEND_LINE_HEIGHT, LEGEND_MARGIN,
                             LIKELIHOOD, MIN_CANVAS_HEIGHT, MITIGATION,
                             STATE_PHASE, TACTIC, TAG_BORDER, TECHNIQUE,
                             TEXT, WHITE,
                             _load_fonts, _stroked_once, _text_size, _wrap,
                             legend_geometry, objective_label_for_page)
from layout_router import RoutedConnector, RoutedLayout, route_layout
from schema import AttackGraph
from visual_syntax import edge_relation, edge_style

if TYPE_CHECKING:
    from attack_lookup import AttackResolver


def _measure_draw():
    from PIL import Image, ImageDraw

    return ImageDraw.Draw(Image.new("RGBA", (8, 8), WHITE))


def _escape(value: str) -> str:
    return html.escape(str(value), quote=True)


_EDGE_DASH = {"dotted": ' stroke-dasharray="2 3"',
              "dashed": ' stroke-dasharray="7 5"'}


def _polyline(path, dx: int, arrow: bool, style: str = "solid") -> str:
    points = " ".join(f"{x + dx},{y}" for x, y in path)
    marker = ' marker-end="url(#agvs-arrow)"' if arrow else ""
    return (
        f'<polyline points="{points}" fill="none" stroke="{BORDER}" '
        f'stroke-width="1"{_EDGE_DASH.get(style, "")}{marker}/>'
    )


def _connector_svg(connector: RoutedConnector, dx: int,
                   roles: Mapping[str, str] | None = None,
                   styles: Mapping[str, str] | None = None,
                   already: set | None = None) -> list[str]:
    """Emit one target's incoming edges, each in its relation's texture.

    Matches the PNG backend exactly: only the individual approach paths are
    textured, because the bus and the segment into the target belong to several
    edges at once.
    """

    roles = roles or {}
    styles = styles or {}
    already = set() if already is None else already
    target_role = roles.get(connector.target_visual_id, "precondition")
    parts: list[str] = []
    for index, path in enumerate(connector.input_paths):
        if len(path) >= 2:
            source_id = connector.input_visual_ids[index]
            relation = edge_relation(
                roles.get(source_id, "precondition"), target_role)
            style = edge_style(relation, styles.get(source_id, "solid"))
            arrow = index in connector.input_arrow_indices
            if arrow or _stroked_once(path, style, already):
                parts.append(_polyline(path, dx, arrow, style))
    if connector.shared_bus and len(connector.shared_bus) >= 2:
        if _stroked_once(connector.shared_bus, "solid", already):
            parts.append(_polyline(connector.shared_bus, dx, False))
    if connector.output_path and len(connector.output_path) >= 2:
        if (connector.output_arrow
                or _stroked_once(connector.output_path, "solid", already)):
            parts.append(
                _polyline(connector.output_path, dx, connector.output_arrow)
            )
    return parts


def _centred_text(draw, lines, centre_x: float, centre_y: float, font,
                  size: int, fill: str = TEXT) -> list[str]:
    materialised = list(lines)
    heights = [_text_size(draw, line, font)[1] for line in materialised]
    total = sum(heights) + max(0, len(heights) - 1) * 2
    y = centre_y - total / 2
    parts: list[str] = []
    for line, height in zip(materialised, heights):
        baseline = y + height
        parts.append(
            f'<text x="{centre_x:.1f}" y="{baseline:.1f}" '
            f'text-anchor="middle" font-family="Arial, Helvetica, sans-serif" '
            f'font-size="{size}" fill="{fill}">{_escape(line)}</text>'
        )
        y += height + 2
    return parts


def _badge_svg(centre: tuple[float, float], text: str, fill: str,
               draw, font) -> list[str]:
    x, y = centre
    radius = BADGE_DIAMETER / 2
    return [
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}" fill="{fill}"/>',
        *_centred_text(draw, [text], x, y, font, 11),
    ]


def _tag_svg(left: float, top: float, text: str, fill: str,
             draw, font) -> tuple[list[str], float]:
    text_width, text_height = _text_size(draw, text, font)
    width = text_width + 8
    height = text_height + 4
    parts = [
        f'<rect x="{left:.1f}" y="{top:.1f}" width="{width:.1f}" '
        f'height="{height:.1f}" fill="{fill}" stroke="{TAG_BORDER}" '
        f'stroke-width="0.6"/>',
        f'<text x="{left + 4:.1f}" y="{top + 2 + text_height:.1f}" '
        f'font-family="Arial, Helvetica, sans-serif" font-size="9" '
        f'fill="{TEXT}">{_escape(text)}</text>',
    ]
    return parts, height


def _node_svg(node: PlannedNode, layout_ir: LayoutIR, draw, fonts,
              continuation_labels: Mapping[str, str], dx: int) -> list[str]:
    semantics = next(
        item.semantics for item in layout_ir.nodes
        if item.visual_id == node.visual_id
    )
    left = node.x + dx
    right = node.right + dx
    centre_x = node.cx + dx
    parts: list[str] = []
    style = getattr(semantics, "style", "solid")
    dash = {"dotted": ' stroke-dasharray="2 3"',
            "dashed": ' stroke-dasharray="7 5"'}.get(style, "")
    if semantics.shape == "ellipse":
        parts.append(
            f'<ellipse cx="{centre_x:.1f}" cy="{node.cy:.1f}" '
            f'rx="{node.width / 2:.1f}" ry="{node.height / 2:.1f}" '
            f'fill="{WHITE}" stroke="{BORDER}" stroke-width="1"{dash}/>'
        )
    else:
        parts.append(
            f'<rect x="{left:.1f}" y="{node.y:.1f}" width="{node.width}" '
            f'height="{node.height}" fill="{WHITE}" stroke="{BORDER}" '
            f'stroke-width="1"{dash}/>'
        )

    continuation = continuation_labels.get(node.canonical_id)
    label_centre_y = node.cy - (8 if continuation else 0)
    inner_width = node.width - (36 if semantics.shape == "ellipse" else 20)
    parts.extend(_centred_text(
        draw,
        _wrap(draw, semantics.label, fonts["node"], inner_width),
        centre_x,
        label_centre_y,
        fonts["node"],
        14,
    ))
    if continuation:
        _, note_height = _text_size(draw, continuation, fonts["tag"])
        parts.append(
            f'<text x="{centre_x:.1f}" y="{node.bottom - 7:.1f}" '
            f'text-anchor="middle" font-family="Arial, Helvetica, sans-serif" '
            f'font-size="9" fill="#666666">{_escape(continuation)}</text>'
        )

    if semantics.badge_code:
        parts.extend(_badge_svg(
            (left - 2, node.y - 4), semantics.badge_code,
            TACTIC if semantics.badge_namespace in
            ("attack_tactic", "kill_chain_phase")
            else STATE_PHASE,
            draw, fonts["badge"],
        ))
    if semantics.kind != "event":
        return parts

    tag_top = node.y - 8
    for technique in semantics.techniques:
        tag, tag_height = _tag_svg(
            right + 1, tag_top, technique, TECHNIQUE, draw, fonts["tag"],
        )
        parts.extend(tag)
        tag_top += tag_height + 1
    if semantics.likelihood is not None:
        parts.extend(_badge_svg(
            (left + 1, node.bottom - 1), f"{semantics.likelihood:.1f}",
            LIKELIHOOD, draw, fonts["badge"],
        ))
    tag_y = max(node.bottom - 12, tag_top)
    for mitigation in semantics.mitigations:
        tag, height = _tag_svg(
            right + 1, tag_y, mitigation, MITIGATION, draw, fonts["tag"],
        )
        parts.extend(tag)
        tag_y += height + 1
    return parts


def render_layout_plan_svg(
    model: AttackGraph,
    layout_ir: LayoutIR,
    plan: LayoutPlan,
    routed: RoutedLayout,
    out_path: str,
    resolver: "AttackResolver | None" = None,
    *,
    page_header: str | None = None,
    continuation_labels: Mapping[str, str] | None = None,
    extra_legend_lines: Sequence[str] = (),
    objective_id: str | None = None,
) -> str:
    """Write the planned page as SVG using the PNG backend's geometry."""

    if resolver is None:
        from attack_lookup import AttackResolver
        resolver = AttackResolver()
    continuation_labels = continuation_labels or {}
    fonts = _load_fonts()
    draw = _measure_draw()

    # The same key the PNG draws, aggregation lines included. Omitting them
    # here left the vector figure -- the one that goes in the dissertation --
    # showing a box labelled "6 grouped actions" with nothing saying which six.
    legend_lines, legend_area_width, graph_offset_x = legend_geometry(
        model, resolver, extra_legend_lines,
        objective_label_for_page(layout_ir, continuation_labels,
                                 objective_id),
    )
    legend_height = len(legend_lines) * LEGEND_LINE_HEIGHT + 88
    width = graph_offset_x + plan.width + GRAPH_RIGHT_PAD
    height = max(MIN_CANVAS_HEIGHT, plan.height, legend_height)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}">',
        '<defs><marker id="agvs-arrow" markerWidth="8" markerHeight="8" '
        'refX="7" refY="4" orient="auto" markerUnits="strokeWidth">'
        f'<path d="M0,0 L8,4 L0,8 z" fill="{BORDER}"/></marker></defs>',
        f'<rect width="{width}" height="{height}" fill="{WHITE}"/>',
    ]

    header = page_header or model.title
    if header:
        header_width, header_height = _text_size(draw, header, fonts["header"])
        x = max(graph_offset_x, width - header_width - 24)
        parts.append(
            f'<text x="{x:.1f}" y="{14 + header_height:.1f}" '
            f'font-family="Arial, Helvetica, sans-serif" font-size="14" '
            f'fill="{TEXT}">{_escape(header)}</text>'
        )

    node_roles = {node.semantics.id: node.semantics.role
                  for node in layout_ir.nodes}
    node_styles = {node.semantics.id: node.semantics.style
                   for node in layout_ir.nodes}
    already: set = set()
    for connector in routed.connectors:
        parts.extend(_connector_svg(connector, graph_offset_x, node_roles,
                                    node_styles, already))

    for node in sorted(
        plan.nodes,
        key=lambda item: (item.visual_rank, item.x, item.visual_id),
    ):
        parts.extend(_node_svg(
            node, layout_ir, draw, fonts, continuation_labels, graph_offset_x,
        ))

    legend_y = 70
    for line in legend_lines:
        if line:
            _, line_height = _text_size(draw, line, fonts["legend"])
            parts.append(
                f'<text x="{LEGEND_MARGIN}" y="{legend_y + line_height:.1f}" '
                f'font-family="Arial, Helvetica, sans-serif" font-size="10" '
                f'fill="{TEXT}">{_escape(line)}</text>'
            )
        legend_y += LEGEND_LINE_HEIGHT

    parts.append("</svg>")
    output = Path(out_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(parts), encoding="utf-8", newline="\n")
    return str(output)


def render_new_layout_svg(
    model: AttackGraph,
    out_path: str,
    resolver: "AttackResolver | None" = None,
    *,
    page_header: str | None = None,
    continuation_labels: Mapping[str, str] | None = None,
    extra_legend_lines: Sequence[str] = (),
    objective_id: str | None = None,
) -> str:
    """Build, plan, route and write the vector page."""

    layout_ir = build_layout_ir(model)
    plan = plan_layout(layout_ir, objective_id)
    routed = route_layout(layout_ir, plan)
    return render_layout_plan_svg(
        model,
        layout_ir,
        plan,
        routed,
        out_path,
        resolver,
        page_header=page_header,
        continuation_labels=continuation_labels,
        extra_legend_lines=extra_legend_lines,
        objective_id=objective_id,
    )
