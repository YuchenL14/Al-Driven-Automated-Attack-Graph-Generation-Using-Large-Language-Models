"""Numbers the two web front ends show about a run they have just finished.

Nothing here measures anything. Every value is read from whatever already owns
it: the tactic order and membership come from ``schema.ATTACK_TACTICS``, which
is what validation enforces; the width budget and the print floor come from
``layout_renderer``; the per-page widths come from the ``.layout-quality.json``
sidecar the renderer writes for every run; and the printed point size comes
from ``layout_quality``. A constant restated here would be a second definition
free to disagree with the first, and the disagreement would surface as a page
reported legible on screen and illegible in the document.

A measurement that is absent stays absent. A run that failed before rendering
has no page width, and reporting that as ``0`` would print as a page
comfortably inside the budget.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from layout_quality import printed_label_pt_for_width
from layout_renderer import MAX_PAGE_WIDTH_PX, MIN_PRINTED_LABEL_PT
from schema import ATTACK_TACTICS, AttackGraph


@dataclass(frozen=True)
class TacticStop:
    """One of the fourteen ATT&CK tactics, and whether this graph reaches it."""

    abbreviation: str
    name: str
    present: bool


def tactic_progression(graph: AttackGraph) -> tuple[TacticStop, ...]:
    """The fourteen tactics in catalogue order, marking the ones reached.

    Order and membership both come from ``ATTACK_TACTICS``, so the strip cannot
    show a tactic the schema would have rejected, nor omit one it accepts.
    """

    reached = {event.tactic for event in graph.events}
    return tuple(
        TacticStop(abbreviation, name, abbreviation in reached)
        for abbreviation, name in ATTACK_TACTICS.items()
    )


def page_widths_px(quality_path: Path) -> tuple[int, ...]:
    """Per-page drawn width in pixels, read from the run's sidecar.

    Runs recorded before the renderer stored a page width have none, and an
    unreadable or absent sidecar is treated the same way. The caller decides
    what to show for a run with no widths; this returns nothing rather than a
    number nobody measured.
    """

    if not quality_path.is_file():
        return ()
    try:
        report = json.loads(quality_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    if not isinstance(report, dict):
        return ()
    return tuple(
        page["page_width_px"]
        for page in report.get("pages", [])
        if isinstance(page, dict) and isinstance(page.get("page_width_px"), int)
    )


@dataclass(frozen=True)
class RunMetrics:
    """What the front ends display about one generation.

    Every optional field is ``None`` when the run did not get far enough to
    produce it, which the template renders as an em dash rather than a zero.
    """

    pages: int | None
    nodes: int | None
    states: int | None
    actions: int | None
    widest_px: int | None
    printed_pt: float | None
    calls: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    limit_usd: float

    width_budget_px: int = MAX_PAGE_WIDTH_PX
    print_floor_pt: float = MIN_PRINTED_LABEL_PT

    @property
    def width_state(self) -> str:
        """``ok``, ``warn`` or ``none``, for the width cell's colour."""

        if self.widest_px is None:
            return "none"
        return "warn" if self.widest_px > self.width_budget_px else "ok"

    @property
    def print_state(self) -> str:
        """``ok``, ``warn`` or ``none``, for the printed point size cell."""

        if self.printed_pt is None:
            return "none"
        return "warn" if self.printed_pt < self.print_floor_pt else "ok"

    @property
    def cost_state(self) -> str:
        """``bad`` once the per-graph guard has nothing left to spend."""

        return "bad" if self.cost_usd >= self.limit_usd else "ok"


def run_metrics(
    graph: AttackGraph | None,
    quality_path: Path | None,
    page_count: int | None,
    usage: dict | None,
) -> RunMetrics:
    """Assemble the display numbers for one run.

    ``graph`` and ``quality_path`` are ``None`` for a run that failed before it
    produced them, so a failed run still reports what it did spend.
    """

    widths = page_widths_px(quality_path) if quality_path is not None else ()
    widest = max(widths) if widths else None
    usage = usage or {}
    return RunMetrics(
        pages=page_count,
        nodes=(len(graph.events) + len(graph.preconditions)
               if graph is not None else None),
        states=len(graph.preconditions) if graph is not None else None,
        actions=len(graph.events) if graph is not None else None,
        widest_px=widest,
        printed_pt=(printed_label_pt_for_width(widest)
                    if widest is not None else None),
        calls=usage.get("calls", 0),
        input_tokens=usage.get("input_tokens", 0),
        output_tokens=usage.get("output_tokens", 0),
        cost_usd=usage.get("estimated_cost_usd", 0.0),
        limit_usd=usage.get("limit_usd", 0.0),
    )
