"""Perceptual and structural quality metrics for rendered attack-graph plans.

The metrics are intentionally independent from attack extraction.  They make
the visual acceptance criteria quantitative: semantic preservation, strictly
downward causal flow, use of the available graph region, compactness and route
complexity can be regression-tested without asking an LLM to judge an image.
"""

from __future__ import annotations

import os

from dataclasses import dataclass
from statistics import median

from layout_ir import LayoutIR
from layout_planner import LayoutPlan
from layout_renderer import (FIGURE_PLACEMENT_WIDTH_PT, GRAPH_RIGHT_PAD,
                             LEGEND_GAP, LEGEND_MIN_WIDTH, MAX_PAGE_WIDTH_PX,
                             MIN_PRINTED_LABEL_PT, NODE_FONT_PX)
from layout_router import RoutedLayout


# The reader never sees the bare graph region. The rendered page also carries
# the key in its left margin -- how to read the syntax, then the technique,
# mitigation and tactic identifiers -- so page shape and page width are both
# measured against the full drawing area rather than the causal lanes alone.
LEGEND_RESERVE_WIDTH = LEGEND_MIN_WIDTH + LEGEND_GAP + GRAPH_RIGHT_PAD


def printed_label_pt_for_width(page_width_px: int) -> float:
    """What a node label measures once a page this wide is placed in a document.

    Kept as one definition with two callers: the quality record below, and the
    web front ends, which show the same figure to the person deciding whether
    to use it. A second copy of this arithmetic could report a page as legible
    in one place and illegible in the other.
    """

    return NODE_FONT_PX * FIGURE_PLACEMENT_WIDTH_PT / max(1, page_width_px)


@dataclass(frozen=True)
class LayoutQuality:
    node_count: int
    page_width_px: int
    canonical_duplicate_count: int
    downward_edge_fraction: float
    main_aspect_ratio: float
    page_aspect_ratio: float
    occupied_width_fraction: float
    occupied_height_fraction: float
    node_area_density: float
    median_horizontal_drift_fraction: float
    mean_route_detour: float
    bend_count: int
    has_parallel_structure: bool

    @property
    def printed_label_pt(self) -> float:
        """What a node label measures when this page is placed on a page."""

        return printed_label_pt_for_width(self.page_width_px)


def _path_length(path: tuple[tuple[int, int], ...]) -> int:
    return sum(
        abs(right[0] - left[0]) + abs(right[1] - left[1])
        for left, right in zip(path, path[1:])
    )


def measure_layout_quality(
    layout_ir: LayoutIR,
    plan: LayoutPlan,
    routed: RoutedLayout,
) -> LayoutQuality:
    """Measure one planned/routed page without mutating it."""

    node_map = {node.visual_id: node for node in plan.nodes}
    if plan.nodes:
        left = min(node.x for node in plan.nodes)
        right = max(node.right for node in plan.nodes)
        top = min(node.y for node in plan.nodes)
        bottom = max(node.bottom for node in plan.nodes)
        occupied_width = right - left
        occupied_height = bottom - top
        node_area = sum(node.width * node.height for node in plan.nodes)
    else:
        occupied_width = occupied_height = node_area = 0

    downward = [
        node_map[edge.source_visual_id].bottom
        < node_map[edge.target_visual_id].y
        for edge in layout_ir.edges
    ]
    drift = [
        abs(
            node_map[edge.source_visual_id].cx
            - node_map[edge.target_visual_id].cx
        ) / max(1, plan.width)
        for edge in layout_ir.edges
    ]

    detours: list[float] = []
    bend_count = 0
    for connector in routed.connectors:
        paths = list(connector.input_paths)
        if connector.output_path:
            paths.append(connector.output_path)
        for path in paths:
            if len(path) < 2:
                continue
            direct = (
                abs(path[-1][0] - path[0][0])
                + abs(path[-1][1] - path[0][1])
            )
            detours.append(_path_length(path) / max(1, direct))
            bend_count += max(0, len(path) - 2)

    canonical_ids = [node.canonical_id for node in layout_ir.nodes]
    return LayoutQuality(
        node_count=len(plan.nodes),
        # The width the reader is actually given, key included: the same sum
        # the renderer uses for its canvas.
        page_width_px=plan.width + LEGEND_RESERVE_WIDTH,
        canonical_duplicate_count=(
            len(canonical_ids) - len(set(canonical_ids))
        ),
        downward_edge_fraction=(
            sum(downward) / len(downward) if downward else 1.0
        ),
        main_aspect_ratio=plan.height / max(1, plan.width),
        page_aspect_ratio=(
            plan.height / max(1, plan.width + LEGEND_RESERVE_WIDTH)
        ),
        occupied_width_fraction=occupied_width / max(1, plan.width),
        occupied_height_fraction=occupied_height / max(1, plan.height),
        node_area_density=node_area / max(1, plan.width * plan.height),
        median_horizontal_drift_fraction=median(drift) if drift else 0.0,
        mean_route_detour=sum(detours) / len(detours) if detours else 1.0,
        bend_count=bend_count,
        has_parallel_structure=any(
            sum(node.visual_rank == rank for node in plan.nodes) >= 2
            for rank in {node.visual_rank for node in plan.nodes}
        ),
    )


def quality_warnings(quality: LayoutQuality) -> list[str]:
    """Return every acceptance limit this page misses, without raising.

    Separating the judgement from the exception lets the runtime report a
    weak page while still saving it. A sparse incident report can legitimately
    produce a thin page, so refusing to draw it would withhold a result the
    reviewer still needs to see.
    """

    warnings: list[str] = []
    if quality.canonical_duplicate_count:
        warnings.append(
            "a canonical state/event was drawn more than once on one page"
        )
    if quality.downward_edge_fraction != 1.0:
        warnings.append("all causal edges must flow strictly downward")
    if quality.occupied_height_fraction < 0.70:
        warnings.append("graph content leaves excessive vertical whitespace")
    if quality.has_parallel_structure and quality.occupied_width_fraction < 0.25:
        warnings.append(
            "parallel graph structure uses too little of the main graph width"
        )
    # The Stolen Pencil reference page is portrait (roughly 1.13 high per unit
    # wide). A page is flagged only when it is markedly taller than that
    # reference, not merely because the incident's causal structure is a chain.
    if quality.page_aspect_ratio > 1.65:
        warnings.append("one page is too tall for the agreed macro-layout budget")
    if quality.mean_route_detour > 2.5:
        warnings.append("orthogonal routes take excessive detours")
    # Reported rather than fixed here. Pagination narrows a page by carrying
    # fewer actions, and there are pages it cannot narrow: one action with a
    # long label and several results is already indivisible. Saying so is worth
    # more than a budget that quietly passes because nothing measured it.
    if quality.page_width_px > MAX_PAGE_WIDTH_PX:
        printed = quality.printed_label_pt
        warnings.append(
            f"one page is {quality.page_width_px}px wide against a "
            f"{MAX_PAGE_WIDTH_PX}px budget; its labels print at about "
            f"{printed:.1f}pt across a landscape page, below the "
            f"{MIN_PRINTED_LABEL_PT:.0f}pt figure-text floor"
        )
    return warnings


QUALITY_MODE_ENV = "AGVS_QUALITY_MODE"
QUALITY_MODES = frozenset({"warn", "strict"})
DEFAULT_QUALITY_MODE = "warn"


def quality_mode() -> str:
    """Return the acceptance mode, defaulting to reporting rather than refusing.

    ``warn`` is the default because a sparse incident report can legitimately
    produce a thin page, and withholding it would deny the reviewer a result
    they still need. ``strict`` exists so a regression run can fail on a page
    that misses an acceptance limit instead of quietly recording it in a
    sidecar nobody reads.
    """

    selected = os.environ.get(
        QUALITY_MODE_ENV, DEFAULT_QUALITY_MODE).strip().lower()
    if selected not in QUALITY_MODES:
        raise ValueError(
            f"invalid {QUALITY_MODE_ENV}={selected!r}; expected one of: "
            f"{', '.join(sorted(QUALITY_MODES))}")
    return selected


def validate_layout_quality(
    layout_ir: LayoutIR,
    plan: LayoutPlan,
    routed: RoutedLayout,
) -> LayoutQuality:
    """Enforce conservative regression limits for the AGVS-SP profile.

    The same limits `quality_warnings` reports. Keeping one definition means
    strict mode cannot drift into enforcing something warning mode never
    mentioned.
    """

    quality = measure_layout_quality(layout_ir, plan, routed)
    warnings = quality_warnings(quality)
    if warnings:
        raise ValueError("; ".join(warnings))
    return quality

