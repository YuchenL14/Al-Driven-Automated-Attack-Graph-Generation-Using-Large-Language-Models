"""
attack_graph.py -- the rendering engine.

PIPELINE (Stage 4 of the tool)
------------------------------
    AttackGraph (validated schema)
        -> networkx.DiGraph        # structural model + DAG validation
        -> graphviz.Digraph        # visual model (Lallie 2020 syntax)
        -> PNG / PDF / SVG

WHY TWO GRAPH LIBRARIES?
  * networkx gives us a real directed graph we can *reason about*: we check it
    is acyclic (an attack path cannot loop back on itself), and the same object
    is the natural place to add path / centrality analysis later. This is what
    lifts the tool above "a script that draws boxes".
  * graphviz owns only the drawing. Keeping the two apart means the visual
    style can change (e.g. an SVG backend for pixel-perfect badges) without
    touching the logic.

VISUAL SYNTAX (grounded in Lallie, Debattista & Bal 2020)
  * Precondition -> ellipse, code badge top-left.
  * Event -> rectangle with four corner badges:
        top-left  = tactic (lavender)      top-right    = technique T# (red)
        bottom-left = likelihood (teal)     bottom-right = mitigation M# (orange)
  * Precondition logic -> connected shared bus for AND; separate input tracks
    for OR. No text label or diamond gate is added.
"""

from __future__ import annotations

import os
from pathlib import Path

import networkx as nx
from graphviz import Digraph

from visual_aggregation import (DEFAULT_MIN_AGGREGATE, aggregate_for_drawing,
                                aggregation_legend_lines)
from causal_split import (DEFAULT_MAX_PARALLEL_EVENTS,
                          DEFAULT_MAX_EVENTS_PER_PART, DEFAULT_MAX_RANKS,
                          attack_objective, continuation_labels,
                          materialize_split_part, plan_causal_split,
                          validate_lossless_split)
from schema import AttackGraph
from attack_lookup import AttackResolver
from layout_renderer import render_new_layout_png
from layout_svg import render_new_layout_svg
from reference_renderer import render_reference_png
from visual_syntax import state_badge_code
import html
import json
import re


def model_tag(provider: str | None, model: str | None) -> str:
    """Build a short, filename-safe tag for the model that produced a graph.

    The tag lets one report generate a separate output per model instead of
    overwriting a previous run. Examples:
        provider="anthropic", model="claude-sonnet-5" -> "anthropic-claude-sonnet-5"
        provider="ollama",    model="qwen3:8b"        -> "ollama-qwen3-8b"
        provider="mock",      model=None              -> "mock"
    """
    parts = [p for p in (provider, model) if p]
    raw = "-".join(parts) if parts else "unknown"
    # replace any character that is awkward in a file name with a hyphen
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", raw)
    return safe.strip("-.") or "unknown"


def tagged_output_path(outputs_dir: Path, report_stem: str,
                       provider: str | None, model: str | None) -> Path:
    """Return the next numbered PNG path for one report/rule/model combination.

    A generation run is an experimental observation.  Keeping it, rather than
    overwriting a previous run with the same settings, makes repeated LLM runs
    comparable and reproducible.  For example, the first two v1.4 Claude runs
    are saved as ``...__rules-v1.4__anthropic-claude-sonnet-5_1.png`` and
    ``..._2.png``.  The same reservation also detects the ``_part1`` / ``_part2``
    files produced by split rendering.
    """
    base = outputs_dir / f"{report_stem}__{model_tag(provider, model)}"
    run = 1
    while True:
        candidate = base.with_name(f"{base.name}_{run}.png")
        audit = candidate.with_suffix(".json")
        split_prefix = f"{base.name}_{run}_part"
        split_exists = any(
            path.name.startswith(split_prefix) and path.suffix == ".png"
            for path in outputs_dir.iterdir()
        )
        if not candidate.exists() and not audit.exists() and not split_exists:
            return candidate
        run += 1


def _esc(s) -> str:
    """Escape &, <, > so text is safe inside Graphviz HTML-like labels."""
    return html.escape(str(s), quote=False)

# --- palette (matches the existing four-colour badge scheme) ----------------
C_TACTIC = "#b6a8d6"      # lavender
C_TECH = "#e8918c"        # red
C_LIKELIHOOD = "#4ec9b0"  # teal
C_MITIG = "#f4b860"       # orange
C_BORDER = "#33415e"      # dark slate
C_TEXT = "#1a1a2e"
FONT = "Helvetica"


PNG_RENDERER_ENV = "AGVS_PNG_RENDERER"
DEFAULT_PNG_RENDERER = "new"
PNG_RENDERERS = frozenset({"new", "legacy"})


def selected_png_renderer(renderer: str | None = None) -> str:
    """Return the validated PNG backend name.

    The replacement AGVS-SP renderer is the default.  Operators retain one
    explicit rollback switch while the new runtime path is being evaluated:
    set ``AGVS_PNG_RENDERER=legacy`` before starting either Flask app.
    """

    selected = (
        renderer
        if renderer is not None
        else os.environ.get(PNG_RENDERER_ENV, DEFAULT_PNG_RENDERER)
    )
    selected = str(selected).strip().lower()
    if selected not in PNG_RENDERERS:
        choices = ", ".join(sorted(PNG_RENDERERS))
        raise ValueError(
            f"invalid PNG renderer {selected!r}; expected one of: {choices}"
        )
    return selected


# ---------------------------------------------------------------------------
# structural model + validation
# ---------------------------------------------------------------------------
def build_digraph(model: AttackGraph) -> nx.DiGraph:
    """Build the causal DiGraph and assert it is a DAG.

    Annotations are commentary beside a step, not part of the attack path, so
    they are kept out of the causal graph entirely: they must not lengthen a
    chain, create a rank, or influence where a long graph is paginated.
    """
    g = nx.DiGraph()
    for p in model.causal_preconditions:
        g.add_node(p.id, kind="precondition", role=p.role)
        for parent in p.parents:
            g.add_edge(parent, p.id)
    for e in model.events:
        g.add_node(e.id, kind="event")
        for parent in e.parents:
            g.add_edge(parent, e.id)
    if not nx.is_directed_acyclic_graph(g):
        cycle = nx.find_cycle(g)
        raise ValueError(f"attack graph is not acyclic; cycle found: {cycle}")
    return g


# ---------------------------------------------------------------------------
# HTML-like label helpers
# ---------------------------------------------------------------------------
def _badge(text: str, bg: str) -> str:
    """A small rounded colour badge (one-cell nested table)."""
    return (
        f'<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="3" '
        f'BGCOLOR="{bg}" STYLE="ROUNDED"><TR><TD>'
        f'<FONT POINT-SIZE="10" COLOR="{C_TEXT}"><B>{_esc(text)}</B></FONT>'
        f'</TD></TR></TABLE>'
    )


def _stacked_badges(items: list[str], bg: str) -> str:
    """Several badges stacked vertically (e.g. multiple M-numbers)."""
    if not items:
        return ""
    rows = "".join(f'<TR><TD ALIGN="RIGHT">{_badge(i, bg)}</TD></TR>' for i in items)
    return f'<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="2">{rows}</TABLE>'


def _event_label(e) -> str:
    tactic = _badge(e.tactic, C_TACTIC)
    tech = _badge(e.technique, C_TECH) if e.technique else ""
    like = _badge(f"{e.likelihood:.1f}", C_LIKELIHOOD) if e.likelihood is not None else ""
    mitig = _stacked_badges(e.mitigations, C_MITIG)
    body = f'<FONT POINT-SIZE="12" COLOR="{C_TEXT}">{_esc(e.label)}</FONT>'
    return (
        '<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="6">'
        f'<TR><TD ALIGN="LEFT">{tactic}</TD><TD></TD><TD ALIGN="RIGHT">{tech}</TD></TR>'
        f'<TR><TD COLSPAN="3" ALIGN="CENTER">{body}</TD></TR>'
        f'<TR><TD ALIGN="LEFT">{like}</TD><TD></TD><TD ALIGN="RIGHT">{mitig}</TD></TR>'
        '</TABLE>>'
    )


def _precondition_label(p) -> str:
    display_code = state_badge_code(p.code)
    code = _badge(display_code, C_TACTIC) if display_code else ""
    body = f'<FONT POINT-SIZE="12" COLOR="{C_TEXT}">{_esc(p.label)}</FONT>'
    return (
        '<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="4">'
        f'<TR><TD ALIGN="LEFT">{code}</TD></TR>'
        f'<TR><TD>{body}</TD></TR>'
        '</TABLE>>'
    )


def _legend_label(legend: dict) -> str:
    rows = []
    for group, items in legend.items():
        if not items:
            continue
        rows.append(
            f'<TR><TD ALIGN="LEFT" COLSPAN="2">'
            f'<FONT POINT-SIZE="11" COLOR="{C_BORDER}"><B>{_esc(group)}</B></FONT></TD></TR>'
        )
        for code, name in items.items():
            rows.append(
                f'<TR><TD ALIGN="LEFT"><FONT POINT-SIZE="10" COLOR="{C_TEXT}">{_esc(code)}</FONT></TD>'
                f'<TD ALIGN="LEFT"><FONT POINT-SIZE="10" COLOR="{C_TEXT}">{_esc(name)}</FONT></TD></TR>'
            )
    return (
        '<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="1" CELLPADDING="3" '
        f'COLOR="{C_BORDER}">' + "".join(rows) + '</TABLE>>'
    )


def _add_graphviz_edges(dot: Digraph, model: AttackGraph,
                        tight_pairs: set[tuple[str, str]]) -> None:
    """Apply the same unlabelled AND/OR semantics as the PNG renderer."""

    # Several events that can establish the same state are alternatives in the
    # current canonical contract, so their edges remain independent (OR).
    for precondition in model.preconditions:
        for parent in precondition.parents:
            attrs = {"weight": "12", "minlen": "1"} \
                if (parent, precondition.id) in tight_pairs else {}
            dot.edge(parent, precondition.id, **attrs)

    for event in model.events:
        if len(event.parents) <= 1 or event.join == "OR":
            for parent in event.parents:
                dot.edge(parent, event.id)
            continue

        # Connected inputs mean AND. The tiny invisible junction connects the
        # lines without adding a diamond or the text "AND".
        junction_id = f"__join_{event.id}"
        dot.node(junction_id, label="", shape="point", width="0.01",
                 height="0.01", fixedsize="true", style="invis")
        for parent in event.parents:
            dot.edge(parent, junction_id, arrowhead="none")
        dot.edge(junction_id, event.id)


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------
def _render_graphviz(model: AttackGraph, out_path: str, fmt: str = "png",
                     dpi: int = 170, resolver: AttackResolver | None = None,
                     compact: bool = False) -> str:
    """Validate, then render the attack graph. Returns the written file path.

    compact pairs each event with the precondition it produces on one rank and
    tightens the spacing, which roughly halves the height of a long alternating
    chain so the figure fits on a page. The default layout gives each node its
    own rank, which reads more clearly on its own.
    """
    build_digraph(model)                     # <-- raises if not a DAG
    if not model.events and not model.preconditions:
        raise ValueError(
            "the model produced no attack steps from this report. This usually "
            "means the source has little technical attack detail (for example a "
            "news article rather than a technical report). Try a report that "
            "describes the attack steps."
        )
    resolver = resolver or AttackResolver()

    dot = Digraph("attack_graph", format=fmt)
    if compact:
        # compact mode: very tight spacing for the shortest possible figure
        dot.attr(rankdir="TB", bgcolor="white", splines="true",
                 nodesep="0.28", ranksep="0.18", ratio="auto")
    else:
        # default mode: tightened rank separation so a long chain does not run
        # off the page, with ratio=auto letting dot settle a sensible height to
        # width balance. These follow the Graphviz guidance on compacting a
        # drawing by reducing ranksep and nodesep.
        dot.attr(rankdir="TB", bgcolor="white", splines="true",
                 nodesep="0.4", ranksep="0.4", ratio="auto")
    dot.attr("node", fontname=FONT)
    dot.attr("edge", color=C_BORDER, penwidth="1.2", arrowsize="0.8")

    # in compact mode, an event and the single precondition it produces are kept
    # tight and vertical, so the alternating chain reads like the target figure
    # rather than spreading across the page
    tight_pairs = set()
    if compact:
        event_ids = {e.id for e in model.events}
        produced = set()
        for p in model.preconditions:
            if len(p.parents) == 1 and p.parents[0] in event_ids \
                    and p.parents[0] not in produced:
                tight_pairs.add((p.parents[0], p.id))
                produced.add(p.parents[0])

    # preconditions (ellipses)
    for p in model.preconditions:
        dot.node(p.id, label=_precondition_label(p), shape="ellipse",
                 color=C_BORDER, penwidth="1.4")

    # events (rectangles)
    for e in model.events:
        dot.node(e.id, label=_event_label(e), shape="box",
                 color=C_BORDER, penwidth="1.6")

    # edges + unlabelled connected/disconnected precondition logic
    _add_graphviz_edges(dot, model, tight_pairs)

    # auto-generated legend (only if there is something to decode)
    legend = resolver.build_legend(model)
    if any(items for items in legend.values()):
        dot.node("__legend", label=_legend_label(legend), shape="plaintext")

    dot.attr(dpi=str(dpi))
    out = Path(out_path)
    written = dot.render(filename=out.stem, directory=str(out.parent), cleanup=True)
    return written


def _refuse_unsupported_constructs(model: AttackGraph) -> None:
    """Stop the legacy backend before it draws a graph it cannot represent.

    The legacy renderer predates ``role`` and ``style``. It does not read either
    one, so it does not fail on a v1.6 graph -- it draws a confident, wrong
    picture. Every outline comes out solid, which silently discards the
    alternative-branch distinction, and an annotation comes out as a plain
    rectangle, visually identical to an adversary action. A figure asserting
    that "staff awareness training" was an attacker step is worse than no
    figure, so this refuses instead.
    """

    unsupported = sorted(
        node.id for node in model.preconditions
        if node.role != "precondition" or node.style != "solid"
    ) + sorted(event.id for event in model.events if event.style != "solid")
    if not unsupported:
        return
    raise ValueError(
        "the legacy PNG backend cannot draw external resources, annotations or "
        "dotted branches, and would render them as ordinary attack steps. "
        f"Affected nodes: {', '.join(unsupported)}. Unset "
        f"{PNG_RENDERER_ENV} to use the AGVS-SP renderer, which supports them."
    )


def render(model: AttackGraph, out_path: str, fmt: str = "png",
           dpi: int = 170, resolver: AttackResolver | None = None,
           compact: bool = False, *,
           page_header: str | None = None,
           continuation_labels_by_id: dict[str, str] | None = None,
           extra_legend_lines: tuple[str, ...] = (),
           objective_id: str | None = None,
           renderer: str | None = None) -> str:
    """Render an attack graph without changing the extraction/data pipeline.

    PNG is the user-facing output.  The default ``new`` backend uses the
    reversible Visual IR, branch-aware planner and obstacle-aware router.
    ``legacy`` remains available as a temporary operational rollback and does
    not alter the graph model.

    SVG uses the same Visual IR, planner and router, so a vector figure is the
    same drawing as the PNG rather than a Graphviz reinterpretation of the
    graph.  Any other format is refused rather than silently handed to
    Graphviz, which draws a different notation; Graphviz remains reachable
    under the legacy backend.

    ``compact`` is retained for API compatibility and is used only by the
    legacy backend.  The new planner controls spacing and causal pagination
    deterministically.
    """
    requested = fmt.lower()
    if requested == "svg" and selected_png_renderer(renderer) == "new":
        build_digraph(model)
        return render_new_layout_svg(
            model,
            out_path,
            resolver=resolver,
            page_header=page_header,
            continuation_labels=continuation_labels_by_id,
            extra_legend_lines=extra_legend_lines,
            objective_id=objective_id,
        )
    if requested != "png":
        if selected_png_renderer(renderer) == "new":
            # Graphviz draws its own notation: different shapes, different
            # edge semantics, no badges. A PDF exported for the dissertation
            # would look nothing like the figure shown in the application, and
            # nothing warns the reader that the two disagree. Nothing asks for
            # another format -- both applications now write PNG and SVG, and
            # export_figure.py offers the same two -- so refusing costs no
            # capability and closes the trap.
            raise ValueError(
                f"the AGVS-SP renderer draws png and svg, not {requested!r}. "
                "Export svg for a vector figure; it uses the same geometry as "
                "the png. Graphviz output remains available under "
                f"{PNG_RENDERER_ENV}=legacy and uses a different notation."
            )
        return _render_graphviz(model, out_path, fmt=fmt, dpi=dpi,
                                resolver=resolver, compact=compact)

    build_digraph(model)
    if not model.events and not model.preconditions:
        raise ValueError(
            "the model produced no attack steps from this report. This usually "
            "means the source has little technical attack detail (for example a "
            "news article rather than a technical report). Try a report that "
            "describes the attack steps."
        )
    backend = selected_png_renderer(renderer)
    if backend == "new":
        return render_new_layout_png(
            model,
            out_path,
            resolver=resolver,
            dpi=dpi,
            page_header=page_header,
            continuation_labels=continuation_labels_by_id,
            extra_legend_lines=extra_legend_lines,
            objective_id=objective_id,
        )
    _refuse_unsupported_constructs(model)
    return render_reference_png(
        model,
        out_path,
        resolver=resolver,
        compact=compact,
        page_header=page_header,
        continuation_labels=continuation_labels_by_id,
    )


if __name__ == "__main__":
    # tiny smoke test
    from schema import Precondition, Event
    g = AttackGraph(
        title="smoke",
        preconditions=[Precondition(id="p1", label="Unpatched VPN", code="RS")],
        events=[Event(id="e1", label="Exploit VPN", tactic="IA",
                      technique="T1190", mitigations=["M1051"], likelihood=6.0,
                      parents=["p1"])],
    )
    print(render(g, "smoke_test.png"))

QUALITY_SUFFIX = ".layout-quality.json"


def measure_page_quality(page_model: AttackGraph) -> dict:
    """Measure one page's geometry without drawing it.

    Planning and routing are deterministic and side-effect free, so repeating
    them here reports exactly the geometry the renderer drew.
    """

    from dataclasses import asdict

    from layout_ir import build_layout_ir
    from layout_planner import plan_layout
    from layout_quality import (measure_layout_quality, quality_mode,
                                quality_warnings, validate_layout_quality)
    from layout_router import route_layout, validate_routed_layout

    layout_ir = build_layout_ir(page_model)
    plan = plan_layout(layout_ir)
    routed = route_layout(layout_ir, plan)
    if quality_mode() == "strict":
        # Callers run this before drawing, so a strict refusal costs no image.
        validate_layout_quality(layout_ir, plan, routed)
    quality = measure_layout_quality(layout_ir, plan, routed)
    # The geometry measurements cannot see a connector drawn over a box, so
    # pages went out reporting no warnings while a bus crossed a node. The
    # router already computes these and returns them without raising outside
    # strict mode; not reporting them made the quality file claim more than it
    # had checked.
    warnings = (quality_warnings(quality)
                + validate_routed_layout(layout_ir, plan, routed))
    return {**asdict(quality), "warnings": warnings}


def quality_report_path(out_path: str) -> Path:
    """Return the sidecar path that describes the pages drawn for ``out_path``."""

    path = Path(out_path).with_suffix("")
    return path.with_name(path.name + QUALITY_SUFFIX)


def write_quality_report(out_path: str, pages: list[dict]) -> Path:
    """Persist per-page layout metrics beside the images they describe.

    The acceptance limits were previously reachable only from the test suite,
    so a weak page could be produced at run time with nothing recorded. The
    report is written for every run and is the auditable record of the visual
    metrics.
    """

    path = quality_report_path(out_path)
    payload = {
        "page_count": len(pages),
        "warning_count": sum(len(page["warnings"]) for page in pages),
        "pages": [
            {"page": index, **page} for index, page in enumerate(pages, 1)
        ],
    }
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )
    return path


def _legend_for_page(groups, page) -> tuple[str, ...]:
    """Only explain the aggregates this page actually draws.

    Repeating every group on every page would put the longest explanation
    beside the pages that do not need it, and the legend column is already
    what makes a short page wide.
    """

    drawn = {event.id for event in page.events}
    return aggregation_legend_lines(
        tuple(group for group in groups if group.visual_id in drawn))


def render_split(model, out_path: str, fmt: str = "png", dpi: int = 170,
                 compact: bool = True,
                 threshold: int = DEFAULT_MAX_EVENTS_PER_PART,
                 max_ranks: int = DEFAULT_MAX_RANKS, *,
                 max_parallel_events: int = DEFAULT_MAX_PARALLEL_EVENTS,
                 min_aggregate: int = DEFAULT_MIN_AGGREGATE,
                 aggregate_wide_fans: bool = True,
                 renderer: str | None = None):
    """Render a long graph as lossless causal-boundary pages.

    ``threshold`` is retained for API compatibility and now means the maximum
    number of events desired on one page.  Unlike the former early/late tactic
    split, the planner may return any number of parts and cuts only through
    stable precondition/result states.  Every event appears exactly once;
    bridge states may appear on both adjacent causal pages.
    """
    # Collapse a fan too wide for any page before deciding where to cut. Doing
    # it the other way round asks pagination to solve a problem it cannot: a
    # divided fan puts its convergence on two pages at once, and every width
    # budget only trades page count against page shape. ``model`` is unchanged
    # and remains what the saved JSON, the measurements and any audit describe.
    #
    # The threshold was `max_parallel_events + 1`, which is the pagination
    # event budget restated as a fold rule. The two are not the same question:
    # pagination asks how many actions a page may carry, folding asks how many
    # nodes a rank may show, and `DEFAULT_MIN_AGGREGATE` is measured against
    # the page-width budget. Deriving one from the other meant retuning the
    # fold rule changed nothing here -- a teaching graph with four outcomes
    # went out at 1580px, labels at 6.3pt, because 4 was still short of 5.
    if aggregate_wide_fans:
        model, aggregated_groups = aggregate_for_drawing(
            model, min_size=min_aggregate)
    else:
        aggregated_groups = ()
    extra_legend = aggregation_legend_lines(aggregated_groups)
    # Decided once, from the whole graph, and handed to every page. A page
    # cannot work this out for itself: each one converges on something, and on
    # every page but the last that something is a bridge, not the objective.
    objective_id = attack_objective(model)

    plan = plan_causal_split(
        model,
        max_events_per_part=threshold,
        max_ranks=max_ranks,
        max_parallel_events=max_parallel_events,
    )
    validate_lossless_split(model, plan)
    measured = fmt.lower() == "png" and selected_png_renderer(renderer) == "new"
    if not plan.is_split:
        if measured:
            write_quality_report(out_path, [measure_page_quality(model)])
        return [render(
            model,
            out_path,
            fmt=fmt,
            dpi=dpi,
            compact=compact,
            extra_legend_lines=extra_legend,
            objective_id=objective_id,
            renderer=renderer,
        )]

    out = Path(out_path)
    paths = []
    pages: list[dict] = []
    materialized = [
        materialize_split_part(model, part, len(plan.parts))
        for part in plan.parts
    ]
    # A state with producers in more than one part is drawn in each of them,
    # which is the documented bridge behaviour and is not a duplicate. The
    # objective is named on the LAST of those pages only: that is where its
    # producers have all been seen, so it is where it is an ending rather than
    # a partial result. One saved run announced it twice, on parts 4 and 5.
    objective_page = max(
        (index for index, page in enumerate(materialized)
         if any(node.id == objective_id for node in page.preconditions)),
        default=None,
    )
    for part, page in zip(plan.parts, materialized):
        part_path = out.with_name(f"{out.stem}_part{part.index}{out.suffix}")
        if measured:
            pages.append(measure_page_quality(page))
        paths.append(
            render(
                page,
                str(part_path),
                fmt=fmt,
                dpi=dpi,
                compact=compact,
                page_header=f"Part {part.index} of {len(plan.parts)}",
                continuation_labels_by_id=continuation_labels(plan, part),
                extra_legend_lines=_legend_for_page(aggregated_groups, page),
                objective_id=(objective_id
                              if part.index - 1 == objective_page else None),
                renderer=renderer,
            )
        )
    if measured:
        write_quality_report(out_path, pages)
    return paths
