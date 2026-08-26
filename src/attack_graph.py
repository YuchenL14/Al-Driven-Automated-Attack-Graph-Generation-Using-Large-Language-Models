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
                          terminal_actions, terminal_outcomes,
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

    parts = [p for p in (provider, model) if p]
    raw = "-".join(parts) if parts else "unknown"
    # replace any character that is awkward in a file name with a hyphen
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", raw)
    return safe.strip("-.") or "unknown"


def tagged_output_path(outputs_dir: Path, report_stem: str,
                       provider: str | None, model: str | None) -> Path:

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
    display_code = state_badge_code(p.role, bool(p.parents))
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
        dot.attr(rankdir="TB", bgcolor="white", splines="true",
                 nodesep="0.28", ranksep="0.18", ratio="auto")
    else:
        dot.attr(rankdir="TB", bgcolor="white", splines="true",
                 nodesep="0.4", ranksep="0.4", ratio="auto")
    dot.attr("node", fontname=FONT)
    dot.attr("edge", color=C_BORDER, penwidth="1.2", arrowsize="0.8")

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
    warnings = (quality_warnings(quality)
                + validate_routed_layout(layout_ir, plan, routed))
    return {**asdict(quality), "warnings": warnings}


def quality_report_path(out_path: str) -> Path:
    """Return the sidecar path that describes the pages drawn for ``out_path``."""

    path = Path(out_path).with_suffix("")
    return path.with_name(path.name + QUALITY_SUFFIX)


def write_quality_report(out_path: str, pages: list[dict]) -> Path:

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
    if aggregate_wide_fans:
        model, aggregated_groups = aggregate_for_drawing(
            model, min_size=min_aggregate)
    else:
        aggregated_groups = ()
    extra_legend = aggregation_legend_lines(aggregated_groups)

    objective_id = attack_objective(model)

    no_objective_note: tuple[str, ...] = ()
    if objective_id is None:
        endings = terminal_outcomes(model)
        if endings:
            no_objective_note = (
                f"No single objective: the attack ends in {len(endings)} "
                "independent outcomes, so none is named as the objective.",)
        else:
            unresolved = terminal_actions(model)
            no_objective_note = (
                "No objective is named: the attack ends with "
                f"{'an action that produces' if len(unresolved) == 1 else 'actions that produce'}"
                " no state, so the graph does not say what was achieved.",)

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
            extra_legend_lines=tuple(extra_legend) + no_objective_note,
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

    objective_page = max(
        (index for index, page in enumerate(materialized)
         if any(node.id == objective_id
                for node in list(page.preconditions) + list(page.events))),
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
                # The tie note goes on the last page only, where the reader has
                # seen every ending the graph claims.
                extra_legend_lines=(
                    tuple(_legend_for_page(aggregated_groups, page))
                    + (no_objective_note
                       if part.index == len(plan.parts) else ())),
                objective_id=(objective_id
                              if part.index - 1 == objective_page else None),
                renderer=renderer,
            )
        )
    if measured:
        write_quality_report(out_path, pages)
    return paths
