from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable, Mapping, Sequence, TYPE_CHECKING

from layout_ir import LayoutIR, build_layout_ir
from layout_planner import LayoutPlan, PlannedNode, plan_layout
from layout_router import RoutedLayout, RoutedConnector, route_layout
from schema import (ATTACK_TACTICS, AttackGraph, KILL_CHAIN_PHASES,
                    kill_chain_phase)
from visual_syntax import (EDGE_RELATION_STYLES, STATE_BADGES,  # noqa: F401
                          EdgeStyle, active_profile, edge_relation, edge_style,
                          state_badge_code)

if TYPE_CHECKING:
    from attack_lookup import AttackResolver


WHITE = "#FFFFFF"
TEXT = "#222222"
BORDER = "#303030"
TACTIC = "#B8B5EA"
# A state code is a different concept from an adversary tactic, so it must not
# reuse the tactic badge's colour. Lallie, Debattista and Bal (2020) record
# that a difference in fill creates a perceptible visual distance while a
# difference in edge treatment does not.
STATE_PHASE = "#CFCFC7"
LIKELIHOOD = "#31A8C4"
TECHNIQUE = "#F3B2B2"
MITIGATION = "#E7BE9B"
TAG_BORDER = "#8D6B57"
CONTINUATION = "#666666"

BADGE_DIAMETER = 26
LEGEND_GAP = 34
# The key was one line per entry, and the column was set wide enough for the
# longest ATT&CK technique name to fit on one: 386px of the page, before the
# graph got any. Against the width budget below that is 40% of a page spent on
# text that reads perfectly well wrapped, and it was the difference between two
# and three drawn columns per page. So the key wraps and the width is fixed.
LEGEND_TEXT_WIDTH = 240
LEGEND_MIN_WIDTH = LEGEND_TEXT_WIDTH + 24
LEGEND_LINE_HEIGHT = 13
LEGEND_MARGIN = 14
# The canvas follows its content. A fixed floor of 710px sat here for most of
# the project, and on a small graph it was most of the figure: a page whose
# graph and key both ended around 420px was padded to 710, so 40% of what went
# into the document was blank.
#
# Nothing measured noticed, which is the part worth recording. The acceptance
# limit named "graph content leaves excessive vertical whitespace" reads
# `occupied_height_fraction`, and that is computed from the plan rather than
# from the canvas, so the check with exactly the right name could not see the
# whitespace a reader sees. Page width, and therefore the printed point size
# every figure is judged on, is unaffected by this constant, so removing the
# floor changes how the figures look without changing what was measured.
#
# The margin is zero because the planner already leaves room below the last
# rank, which is why the previous rule could take the plan height unchanged on
# every page tall enough to clear the floor and never clipped anything. A
# margin added on top of that padded the pages that were already correct.
CANVAS_BOTTOM_MARGIN = 0
# Technique and mitigation tags are drawn just outside the planned node box.
# The planner does not reserve that space, so the canvas adds it once.
GRAPH_RIGHT_PAD = 76

# Type sizes in pixels. Named because the page-width budget below is derived
# from the node size, and a silent edit to one without the other would move the
# budget without anyone deciding to.
NODE_FONT_PX = 14
BADGE_FONT_PX = 11
TAG_FONT_PX = 9
LEGEND_FONT_PX = 10
HEADER_FONT_PX = 14

# How wide a page may be before its type is too small to read in print.
#
# A figure in the dissertation is placed at some physical width and every pixel
# scales with it, so the printed size of a node label is decided by the ratio of
# the font to the whole canvas, not by the DPI stamped in the file. Placing a
# page across a landscape A4 text area gives about 250 mm, which is 708.7 pt;
# a label set at NODE_FONT_PX of a canvas W pixels wide prints at
# NODE_FONT_PX / W * 708.7 pt. Requiring 8 pt -- the usual floor for figure
# text -- gives W <= 1240.
#
# Before this budget existed the widest page produced by this tool was 3731 px,
# whose labels print at 1.7 pt.
FIGURE_PLACEMENT_WIDTH_PT = 250 / 25.4 * 72
MIN_PRINTED_LABEL_PT = 8.0
MAX_PAGE_WIDTH_PX = int(
    NODE_FONT_PX * FIGURE_PLACEMENT_WIDTH_PT / MIN_PRINTED_LABEL_PT
)


def _load_fonts():
    try:
        from PIL import ImageFont
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "The new PNG renderer requires Pillow. Install requirements.txt."
        ) from exc

    candidates = (
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
        "/usr/share/fonts/truetype/msttcorefonts/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    )

    def get(size: int):
        for candidate in candidates:
            if Path(candidate).is_file():
                return ImageFont.truetype(candidate, size=size)
        return ImageFont.load_default()

    return {
        "node": get(NODE_FONT_PX),
        "badge": get(BADGE_FONT_PX),
        "tag": get(TAG_FONT_PX),
        "legend": get(LEGEND_FONT_PX),
        "header": get(HEADER_FONT_PX),
    }


_DASH_PATTERN = {"dotted": (2.0, 3.0), "dashed": (7.0, 5.0)}


def _ellipse_points(bounds, steps: int = 96) -> list[tuple[float, float]]:
    left, top, right, bottom = bounds
    cx, cy = (left + right) / 2, (top + bottom) / 2
    rx, ry = (right - left) / 2, (bottom - top) / 2
    return [
        (cx + rx * math.cos(2 * math.pi * i / steps),
         cy + ry * math.sin(2 * math.pi * i / steps))
        for i in range(steps + 1)
    ]


def _rectangle_points(bounds) -> list[tuple[float, float]]:
    left, top, right, bottom = bounds
    return [(left, top), (right, top), (right, bottom), (left, bottom),
            (left, top)]


def _draw_broken_outline(draw, points, style: str) -> None:
    """Trace a polyline as dashes, since Pillow draws only solid lines.

    Lallie, Debattista and Bal (2020) record that outline texture is a weak
    visual variable, so it is used here only for the meaning the reference
    diagram gives it: an alternative or uncertain branch, and commentary.
    """

    on, off = _DASH_PATTERN[style]
    carried = 0.0
    pen_down = True
    for (x1, y1), (x2, y2) in zip(points, points[1:]):
        segment = math.hypot(x2 - x1, y2 - y1)
        if segment <= 0:
            continue
        position = 0.0
        while position < segment:
            span = (on if pen_down else off) - carried
            step = min(span, segment - position)
            if pen_down:
                t0, t1 = position / segment, (position + step) / segment
                draw.line(
                    [
                        (x1 + (x2 - x1) * t0, y1 + (y2 - y1) * t0),
                        (x1 + (x2 - x1) * t1, y1 + (y2 - y1) * t1),
                    ],
                    fill=BORDER,
                    width=1,
                )
            position += step
            carried += step
            if carried >= (on if pen_down else off) - 1e-9:
                carried = 0.0
                pen_down = not pen_down


def _text_size(draw, text: str, font) -> tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=font)
    return box[2] - box[0], box[3] - box[1]


def _split_token(draw, token: str, font, width: int) -> list[str]:
    """Break one token that is wider than the shape it has to sit inside."""

    if _text_size(draw, token, font)[0] <= width:
        return [token]
    pieces: list[str] = []
    current = ""
    for character in token:
        candidate = current + character
        if current and _text_size(draw, candidate, font)[0] > width:
            pieces.append(current)
            current = character
        else:
            current = candidate
    if current:
        pieces.append(current)
    return pieces


def _wrap(draw, text: str, font, width: int) -> list[str]:
    """Wrap a label so that no rendered line exceeds the node's inner width.

    Lallie et al. (2020) record that attack-graph labels are commonly allowed
    to bleed over the shape boundary, which weakens the perceptual distinction
    between one construct and the next. A compound token such as
    ``phishing/spear-phishing`` is therefore split at character level instead
    of being emitted intact and overflowing the ellipse or rectangle.
    """

    lines: list[str] = []
    for paragraph in str(text).splitlines() or [""]:
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        line = ""
        for word in words:
            pieces = _split_token(draw, word, font, width)
            if len(pieces) > 1 and line:
                lines.append(line)
                line = ""
            for piece in pieces:
                if not line:
                    line = piece
                elif _text_size(draw, f"{line} {piece}", font)[0] <= width:
                    line = f"{line} {piece}"
                else:
                    lines.append(line)
                    line = piece
        if line:
            lines.append(line)
    return lines


def _draw_centered_lines(
    draw,
    lines: Iterable[str],
    center_x: int,
    center_y: int,
    font,
    *,
    fill: str = TEXT,
    gap: int = 2,
) -> None:
    materialised = list(lines)
    heights = [
        _text_size(draw, line, font)[1] for line in materialised
    ]
    total = sum(heights) + max(0, len(heights) - 1) * gap
    y = round(center_y - total / 2)
    for line, height in zip(materialised, heights):
        width, _ = _text_size(draw, line, font)
        draw.text(
            (round(center_x - width / 2), y),
            line,
            font=font,
            fill=fill,
        )
        y += height + gap


def _draw_badge(draw, center: tuple[int, int], text: str, fill: str, font) -> None:
    x, y = center
    radius = BADGE_DIAMETER // 2
    draw.ellipse(
        (x - radius, y - radius, x + radius, y + radius),
        fill=fill,
    )
    _draw_centered_lines(draw, [text], x, y, font, gap=0)


def _draw_tag(draw, left: int, top: int, text: str, fill: str, font) -> int:
    """Draw one identifier tag whose left edge sits at ``left``.

    The tag hangs entirely outside its node. Drawing it inwards from the right
    edge, as an earlier revision did, let a long event label run underneath the
    mitigation stack.
    """

    text_width, text_height = _text_size(draw, text, font)
    width = text_width + 8
    height = text_height + 4
    draw.rectangle(
        (left, top, left + width, top + height),
        fill=fill,
        outline=TAG_BORDER,
        width=1,
    )
    draw.text(
        (left + 4, top + 2),
        text,
        font=font,
        fill=TEXT,
    )
    return height


def _draw_arrow(draw, start: tuple[int, int], end: tuple[int, int]) -> None:
    sx, sy = start
    ex, ey = end
    if abs(ex - sx) >= abs(ey - sy):
        direction = 1 if ex >= sx else -1
        points = [
            (ex, ey),
            (ex - 8 * direction, ey - 4),
            (ex - 8 * direction, ey + 4),
        ]
    else:
        direction = 1 if ey >= sy else -1
        points = [
            (ex, ey),
            (ex - 4, ey - 8 * direction),
            (ex + 4, ey - 8 * direction),
        ]
    draw.polygon(points, fill=BORDER)


def _shift(path: tuple[tuple[int, int], ...], dx: int) -> list[tuple[int, int]]:
    return [(x + dx, y) for x, y in path]


def _draw_broken_line(draw, points, style: EdgeStyle) -> None:
    """Draw a polyline in the given texture.

    Pillow has no dash support, so a non-solid line is traced segment by
    segment against the same dash pattern the node outlines use. Sharing the
    pattern keeps a dotted edge and a dotted outline visibly the same texture.
    """

    if style == "solid":
        draw.line(points, fill=BORDER, width=1)
        return
    on, off = _DASH_PATTERN[style]
    for (x1, y1), (x2, y2) in zip(points, points[1:]):
        length = math.hypot(x2 - x1, y2 - y1)
        if length <= 0:
            continue
        ux, uy = (x2 - x1) / length, (y2 - y1) / length
        position = 0.0
        while position < length:
            end = min(position + on, length)
            draw.line(
                [(x1 + ux * position, y1 + uy * position),
                 (x1 + ux * end, y1 + uy * end)],
                fill=BORDER, width=1,
            )
            position = end + off


def _draw_path(
    draw,
    path: tuple[tuple[int, int], ...],
    arrow: bool,
    dx: int = 0,
    style: EdgeStyle = "solid",
) -> None:
    if len(path) < 2:
        return
    shifted = _shift(path, dx)
    _draw_broken_line(draw, shifted, style)
    if arrow:
        _draw_arrow(draw, shifted[-2], shifted[-1])


def _stroked_once(path, style: str, already: set) -> bool:
    """Whether this run of segments still needs drawing.

    Two connectors can legitimately share a column, and the same segment then
    gets stroked twice. On paper that is a heavier, darker line in one place
    and nowhere else, which reads as a different kind of edge. It is not: it is
    the same pixel drawn twice. Keyed by style, because a dashed run over a
    solid one is two different statements about the same geometry and both
    have to stay visible.
    """

    key = (style, tuple(tuple(sorted((tuple(a), tuple(b))))
                        for a, b in zip(path, path[1:]) if a != b))
    if not key[1] or key in already:
        return False
    already.add(key)
    return True


def _draw_connector(draw, connector: RoutedConnector, dx: int = 0,
                    roles: Mapping[str, str] | None = None,
                    styles: Mapping[str, str] | None = None,
                    already: set | None = None) -> None:
    """Draw one target's incoming edges, each in its relation's texture.

    Only the individual approach paths are textured. The shared bus and the
    segment from it into the target are geometry belonging to several edges at
    once, so no single relation owns them and they stay solid.
    """

    roles = roles or {}
    styles = styles or {}
    already = set() if already is None else already
    target_role = roles.get(connector.target_visual_id, "precondition")
    for index, path in enumerate(connector.input_paths):
        source_id = connector.input_visual_ids[index]
        relation = edge_relation(
            roles.get(source_id, "precondition"), target_role)
        style = edge_style(relation, styles.get(source_id, "solid"))
        arrow = index in connector.input_arrow_indices
        # An arrowhead is never a duplicate: it says which way this particular
        # edge runs, and two edges sharing a column still arrive separately.
        if arrow or _stroked_once(path, style, already):
            _draw_path(draw, path, arrow, dx, style)
    if connector.shared_bus:
        if _stroked_once(connector.shared_bus, "solid", already):
            draw.line(_shift(connector.shared_bus, dx), fill=BORDER, width=1)
    if connector.output_path:
        if (connector.output_arrow
                or _stroked_once(connector.output_path, "solid", already)):
            _draw_path(draw, connector.output_path, connector.output_arrow, dx)


def _syntax_key_lines(model: AttackGraph,
                      has_aggregates: bool = False) -> list[str]:
    """State the visual syntax on the figure itself.

    Lallie, Debattista and Bal (2020) surveyed 180 published attack graphs and
    found the notation inconsistent between them and, more often than not,
    unexplained on the figure. A drawing that a reader cannot decode without
    the paper that defined it is the specific failure they report, and a
    dissertation figure is read exactly that way: lifted out of its chapter,
    printed beside a caption.

    Only symbols this page actually uses are listed. A key describing a
    construct that is not drawn is noise, which is the other half of the same
    complaint.
    """

    profile = active_profile()
    events = list(model.events)
    states = [node for node in model.preconditions
              if node.role != "annotation"]
    annotations = [node for node in model.preconditions
                   if node.role == "annotation"]
    dotted = [node for node in list(model.preconditions) + events
              if getattr(node, "style", "solid") == "dotted"]
    multi_parent = [event for event in events if len(event.parents) > 1]

    lines = ["How to read this figure"]
    if events:
        lines.append(f"{profile.event_shape.capitalize()}: an action the "
                     "adversary performed")
    if states:
        lines.append(f"{profile.state_shape.capitalize()}: a state the attack "
                     "required or established")
    if annotations:
        lines.append("Dashed outline: an observation beside the attack, not a "
                     "step in it")
    if dotted:
        lines.append("Dotted outline: the source reports this as uncertain")
    if events or states:
        lines.append("Arrows read downward: the node below depends on the "
                     "node above")
    if any(event.join == "AND" for event in multi_parent):
        lines.append("Shared horizontal line into an action: every input was "
                     "needed (AND)")
    if any(event.join == "OR" for event in multi_parent):
        lines.append("Separate arrows into an action: any one input was "
                     "enough (OR)")
    if any(event.tactic for event in events):
        badge = ("kill-chain phase" if profile.badge_source
                 == "kill_chain_phase" else "ATT&CK tactic")
        lines.append(f"Circle at an action's top-left corner: {badge}, keyed "
                     "below")
    # The state vocabulary is fixed at three symbols and derived from the
    # graph, so the same three mean the same three on every figure this tool
    # draws. Only the ones this page uses are stated, on the same rule as
    # every other line here.
    drawn_state_badges = {
        code for code in (
            state_badge_code(node.role, bool(node.parents))
            for node in states)
        if code
    }
    for code in ("PRE", "RES", "EXT"):
        if code in drawn_state_badges:
            lines.append(f"Circle at a state's top-left corner reading "
                         f"{code}: {STATE_BADGES[code]}")
    if any(event.techniques for event in events):
        lines.append("Tags at an action's top right: ATT&CK technique, keyed "
                     "below")
    if any(event.mitigations for event in events):
        lines.append("Tags at an action's bottom right: mitigation, keyed "
                     "below")
    if any(event.likelihood is not None for event in events):
        lines.append("Number at an action's bottom-left corner: how feasible "
                     "the step was judged to be, 0 to 10")
    if has_aggregates:
        # Without this a line above is false for one shape on the page, and
        # the reader has no way to know until the end of the key. Which shape
        # is deliberately not named: an action fold draws a rectangle and an
        # outcome fold draws an ellipse, and this one line is true of both.
        lines.append("One shape stands for several nodes folded together; "
                     "they are listed at the end of this key")
    return lines


def _legend_lines(
    model: AttackGraph,
    resolver: "AttackResolver",
    extra_lines: Sequence[str] = (),
    objective_label: str | None = None,
) -> list[str]:
    """Build the left-margin key.

    ``extra_lines`` carries what a collapsed node stands for. An aggregate is
    labelled by the rule that formed it, so without the list beside it the
    reader cannot tell which seven actions were folded together, and the
    drawing would be an abstraction the page does not explain.
    """

    techniques: dict[str, str] = {}
    mitigations: dict[str, str] = {}
    tactics: dict[str, str] = {}
    profile = active_profile()
    for event in model.events:
        if profile.badge_source == "kill_chain_phase":
            phase = kill_chain_phase(event.tactic)
            if phase:
                tactics[phase] = KILL_CHAIN_PHASES[phase]
        else:
            tactics[event.tactic] = ATTACK_TACTICS[event.tactic]
        for technique in event.techniques:
            techniques[technique] = resolver.resolve_technique(technique)
        for mitigation in event.mitigations:
            mitigations[mitigation] = resolver.resolve_mitigation(mitigation)

    lines = _syntax_key_lines(model, has_aggregates=bool(extra_lines))
    if objective_label:
        # The bottom of the figure, named. The placement already puts this node
        # on a row of its own, but a reader coming to the page cold should not
        # have to infer from position what the key can simply say.
        lines.append("")
        lines.append(f"The attack's objective, at the foot of the figure: "
                     f"{objective_label}")
    if techniques:
        lines.append("")
    lines.extend(
        f"{code}: {name}" for code, name in sorted(techniques.items())
    )
    if mitigations:
        lines.append("")
        lines.extend(
            f"{code}: {name}" for code, name in sorted(mitigations.items())
        )
    if tactics:
        lines.append("")
        lines.extend(
            f"{code}: {name}" for code, name in tactics.items()
        )
    if extra_lines:
        lines.append("")
        lines.extend(extra_lines)
    return lines


def objective_label_for_page(
    layout_ir: LayoutIR,
    continuation_labels: Mapping[str, str],
    objective_id: str | None = None,
) -> str | None:
    """The label to print as the objective, or None if this page has none.

    ``objective_id`` is the canonical id of the WHOLE graph's objective, which
    only the caller holding the whole graph can know. There is deliberately no
    fallback to the page's own convergence, and the reason is a defect this
    shipped with: on a split graph the page-local answer is a different node on
    every page, so part 1 of one British Library run announced "Privileged
    terminal server credentials obtained" as the attack's objective and part 4
    announced "Log files deleted to hinder forensics".

    Worse, a fallback cannot tell "nobody told me" from "there is no
    objective". Another run of the same report ends in a three-way tie --
    servers destroyed, recovery impaired and users locked out are each reached
    by thirteen of fourteen actions -- so `attack_objective` correctly returns
    None, and the fallback answered anyway, on two different pages, with two
    different nodes. A graph that does not converge has no objective to name,
    and the figure has to be able to say nothing.

    A node that continues onto another page is never the objective either. The
    renderer already knows which those are -- it prints "continues in part N"
    under them.
    """

    if objective_id is None:
        return None
    objective = next((item.visual_id for item in layout_ir.nodes
                      if item.canonical_id == objective_id), None)
    if objective is None:
        return None
    node = next((item for item in layout_ir.nodes
                 if item.visual_id == objective), None)
    if node is None or node.canonical_id in continuation_labels:
        return None
    return node.semantics.label


def legend_geometry(
    model: AttackGraph,
    resolver: "AttackResolver | None" = None,
    extra_legend_lines: Sequence[str] = (),
    objective_label: str | None = None,
) -> tuple[list[str], int, int]:
    """Return the legend lines, its column width, and the graph's left edge.

    The supervisor's Stolen Pencil reference places the technique, mitigation
    and tactic key down the left margin with the causal graph to its right.
    Both the renderer and its regression tests read that geometry from here so
    the two can never disagree about where the gutter is.
    """

    try:
        from PIL import Image, ImageDraw
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "The new PNG renderer requires Pillow. Install requirements.txt."
        ) from exc

    if resolver is None:
        from attack_lookup import AttackResolver
        resolver = AttackResolver()
    fonts = _load_fonts()
    measure = Image.new("RGBA", (8, 8), WHITE)
    measure_draw = ImageDraw.Draw(measure)
    lines: list[str] = []
    for line in _legend_lines(model, resolver, extra_legend_lines,
                              objective_label):
        if not line:
            lines.append(line)
            continue
        # Continuation indented, so a wrapped technique name cannot be mistaken
        # for the start of the next entry.
        wrapped = _wrap(measure_draw, line, fonts["legend"], LEGEND_TEXT_WIDTH)
        lines.append(wrapped[0])
        lines.extend(f"   {part}" for part in wrapped[1:])
    return lines, LEGEND_MIN_WIDTH, LEGEND_MIN_WIDTH + LEGEND_GAP


def _draw_node(
    draw,
    node: PlannedNode,
    layout_ir: LayoutIR,
    fonts,
    continuation_labels: Mapping[str, str],
    dx: int = 0,
    page_bottom: int | None = None,
) -> None:
    semantics = next(
        item.semantics
        for item in layout_ir.nodes
        if item.visual_id == node.visual_id
    )
    left = node.x + dx
    right = node.right + dx
    centre_x = node.cx + dx
    bounds = (left, node.y, right, node.bottom)
    # Lallie et al. (2020) find that edge weight is not a perceptible visual
    # variable. The construct distinction is therefore carried by the shape
    # alone, and every outline uses the same stroke width. Texture is reserved
    # for the separate question of how certain the branch is.
    style = getattr(semantics, "style", "solid")
    if semantics.shape == "ellipse":
        draw.ellipse(bounds, fill=WHITE,
                     outline=None if style != "solid" else BORDER, width=1)
        if style != "solid":
            _draw_broken_outline(draw, _ellipse_points(bounds), style)
    else:
        # An annotation is a box like an event, distinguished by its dashed
        # outline and by carrying no ATT&CK metadata at all.
        draw.rectangle(bounds, fill=WHITE,
                       outline=None if style != "solid" else BORDER, width=1)
        if style != "solid":
            _draw_broken_outline(draw, _rectangle_points(bounds), style)

    continuation = continuation_labels.get(node.canonical_id)
    label_center_y = node.cy - (8 if continuation else 0)
    # An ellipse only offers its full width across the middle, so its text
    # column is narrower than the bounding box.
    inner_width = node.width - (36 if semantics.shape == "ellipse" else 20)
    lines = _wrap(
        draw,
        semantics.label,
        fonts["node"],
        inner_width,
    )
    _draw_centered_lines(
        draw,
        lines,
        centre_x,
        label_center_y,
        fonts["node"],
    )
    if continuation:
        note_width, note_height = _text_size(
            draw, continuation, fonts["tag"]
        )
        draw.text(
            (
                round(centre_x - note_width / 2),
                node.bottom - note_height - 7,
            ),
            continuation,
            font=fonts["tag"],
            fill=CONTINUATION,
        )

    if semantics.badge_code:
        _draw_badge(
            draw,
            (left - 2, node.y - 4),
            semantics.badge_code,
            TACTIC if semantics.badge_namespace in
            ("attack_tactic", "kill_chain_phase")
            else STATE_PHASE,
            fonts["badge"],
        )

    if semantics.kind != "event":
        return
    # A stack, growing downward from the top-right corner. The reference
    # diagram puts up to seven techniques on one action, and showing only the
    # first would silently drop the rest.
    tag_top = node.y - 8
    for technique in semantics.techniques:
        tag_top += _draw_tag(
            draw,
            right + 1,
            tag_top,
            technique,
            TECHNIQUE,
            fonts["tag"],
        ) + 1
    if semantics.likelihood is not None:
        _draw_badge(
            draw,
            (left + 1, node.bottom - 1),
            f"{semantics.likelihood:.1f}",
            LIKELIHOOD,
            fonts["badge"],
        )
    # Mitigations hang from the bottom-right, but a long technique stack can
    # reach past the middle of the node. Growing them downward from whichever
    # is lower keeps the two stacks from printing over each other, which is
    # what happened with a seven-technique action.
    #
    # The stack grew without limit while the page height was computed from
    # node geometry alone, so the two never agreed. An aggregate node carrying
    # the union of seven actions' mitigations reached sixteen tags and ran off
    # the bottom of the page, where the identifiers could not be read at all.
    # An earlier fix for the same class only moved the starting point.
    #
    # Clip to the room that exists and say how many were hidden. Nothing is
    # lost: every mitigation is in the left-margin key, which is built from the
    # same list.
    tag_y = max(node.bottom - 12, tag_top)
    shown = list(semantics.mitigations)
    if page_bottom is not None and shown:
        pitch = _text_size(draw, shown[0], fonts["tag"])[1] + 4
        room = (page_bottom - tag_y) // max(1, pitch)
        if room < len(shown):
            keep = max(1, room - 1)
            hidden = len(shown) - keep
            shown = shown[:keep] + [f"+{hidden}"]
    for mitigation in shown:
        tag_y += _draw_tag(
            draw,
            right + 1,
            tag_y,
            mitigation,
            MITIGATION,
            fonts["tag"],
        ) + 1


def render_layout_plan_png(
    model: AttackGraph,
    layout_ir: LayoutIR,
    plan: LayoutPlan,
    routed: RoutedLayout,
    out_path: str,
    resolver: "AttackResolver | None" = None,
    *,
    dpi: int = 170,
    page_header: str | None = None,
    continuation_labels: Mapping[str, str] | None = None,
    extra_legend_lines: Sequence[str] = (),
    objective_id: str | None = None,
) -> str:
    """Draw an already validated Stage-A/B/C pipeline result."""

    try:
        from PIL import Image, ImageDraw
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "The new PNG renderer requires Pillow. Install requirements.txt."
        ) from exc

    if resolver is None:
        from attack_lookup import AttackResolver
        resolver = AttackResolver()
    continuation_labels = continuation_labels or {}
    fonts = _load_fonts()

    legend_lines, legend_area_width, graph_offset_x = legend_geometry(
        model, resolver, extra_legend_lines,
        objective_label_for_page(layout_ir, continuation_labels,
                                 objective_id),
    )
    legend_x = LEGEND_MARGIN
    legend_height = len(legend_lines) * LEGEND_LINE_HEIGHT + 88
    canvas_width = graph_offset_x + plan.width + GRAPH_RIGHT_PAD
    canvas_height = max(plan.height, legend_height) + CANVAS_BOTTOM_MARGIN

    image = Image.new("RGBA", (canvas_width, canvas_height), WHITE)
    draw = ImageDraw.Draw(image)

    header = page_header or model.title
    if header:
        header_width, _ = _text_size(draw, header, fonts["header"])
        draw.text(
            (
                max(graph_offset_x, canvas_width - header_width - 24),
                14,
            ),
            header,
            font=fonts["header"],
            fill=TEXT,
        )

    # One relation lookup for the page. The roles come from the same
    # projection the nodes were drawn from, so an edge can never be
    # classified against a construct the node does not actually have.
    node_roles = {node.semantics.id: node.semantics.role
                  for node in layout_ir.nodes}
    node_styles = {node.semantics.id: node.semantics.style
                   for node in layout_ir.nodes}
    already: set = set()
    for connector in routed.connectors:
        _draw_connector(draw, connector, graph_offset_x, node_roles,
                        node_styles, already)

    for node in sorted(
        plan.nodes,
        key=lambda item: (item.visual_rank, item.x, item.visual_id),
    ):
        _draw_node(
            draw,
            node,
            layout_ir,
            fonts,
            continuation_labels,
            graph_offset_x,
            page_bottom=plan.height,
        )

    legend_y = 70
    for line in legend_lines:
        if line:
            draw.text(
                (legend_x, legend_y),
                line,
                font=fonts["legend"],
                fill=TEXT,
            )
        legend_y += LEGEND_LINE_HEIGHT

    output = Path(out_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(dpi, dpi))
    return str(output)


def render_new_layout_png(
    model: AttackGraph,
    out_path: str,
    resolver: "AttackResolver | None" = None,
    *,
    dpi: int = 170,
    page_header: str | None = None,
    continuation_labels: Mapping[str, str] | None = None,
    extra_legend_lines: Sequence[str] = (),
    objective_id: str | None = None,
) -> str:
    """Build, plan, route and draw the replacement layout pipeline."""

    layout_ir = build_layout_ir(model)
    plan = plan_layout(layout_ir, objective_id)
    routed = route_layout(layout_ir, plan)
    return render_layout_plan_png(
        model,
        layout_ir,
        plan,
        routed,
        out_path,
        resolver,
        dpi=dpi,
        page_header=page_header,
        continuation_labels=continuation_labels,
        extra_legend_lines=extra_legend_lines,
        objective_id=objective_id,
    )
