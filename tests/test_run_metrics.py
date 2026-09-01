"""Tests for the numbers the web front ends report about a finished run.

The module under test deliberately computes nothing. These tests therefore
check two things: that it reads from the source that owns each value, and that
a measurement nobody took is reported as absent rather than as zero. The
second matters because a run that failed before rendering has no page width,
and a zero would display as a page comfortably inside the budget.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from layout_quality import LayoutQuality, printed_label_pt_for_width  # noqa: E402
from layout_renderer import MAX_PAGE_WIDTH_PX, MIN_PRINTED_LABEL_PT  # noqa: E402
from run_metrics import (RunMetrics, page_widths_px,  # noqa: E402
                         run_metrics, tactic_progression)
from schema import ATTACK_TACTICS, AttackGraph, Event, Precondition  # noqa: E402


def _graph() -> AttackGraph:
    """Two tactics reached out of fourteen, so absence is testable."""

    return AttackGraph(
        title="two tactics",
        preconditions=[
            Precondition(id="p0", label="Service reachable", code="IA"),
            Precondition(id="p1", label="Access established", code="IA",
                         parents=["e0"]),
            Precondition(id="p2", label="Systems encrypted", code="IM",
                         parents=["e1"]),
        ],
        events=[
            Event(id="e0", label="Use stolen credentials", tactic="IA",
                  parents=["p0"]),
            Event(id="e1", label="Encrypt systems", tactic="IM",
                  parents=["p1"]),
        ],
    )


def _sidecar(payload: object) -> Path:
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".layout-quality.json", delete=False, encoding="utf-8")
    with handle:
        handle.write(json.dumps(payload) if not isinstance(payload, str)
                     else payload)
    return Path(handle.name)


class TacticProgressionTests(unittest.TestCase):
    def test_reports_every_tactic_in_catalogue_order(self):
        stops = tactic_progression(_graph())
        self.assertEqual(len(ATTACK_TACTICS), len(stops))
        self.assertEqual(
            list(ATTACK_TACTICS), [stop.abbreviation for stop in stops],
            "the strip must follow the schema's order, not its own")
        self.assertEqual(
            list(ATTACK_TACTICS.values()), [stop.name for stop in stops])

    def test_marks_only_the_tactics_the_graph_reaches(self):
        present = {stop.abbreviation
                   for stop in tactic_progression(_graph()) if stop.present}
        self.assertEqual({"IA", "IM"}, present)

    def test_a_graph_with_no_events_reaches_nothing(self):
        empty = AttackGraph(title="empty", preconditions=[], events=[])
        stops = tactic_progression(empty)
        self.assertEqual(len(ATTACK_TACTICS), len(stops))
        self.assertFalse(any(stop.present for stop in stops))


class PageWidthTests(unittest.TestCase):
    def test_reads_the_widths_the_renderer_recorded(self):
        path = _sidecar({"pages": [{"page": 1, "page_width_px": 1010},
                                   {"page": 2, "page_width_px": 1738}]})
        try:
            self.assertEqual((1010, 1738), page_widths_px(path))
        finally:
            path.unlink()

    def test_a_missing_sidecar_yields_no_widths(self):
        self.assertEqual((), page_widths_px(Path("does-not-exist.json")))

    def test_unreadable_json_yields_no_widths(self):
        path = _sidecar("{not json")
        try:
            self.assertEqual((), page_widths_px(path))
        finally:
            path.unlink()

    def test_a_run_recorded_before_widths_existed_yields_none(self):
        path = _sidecar({"pages": [{"page": 1, "node_count": 12}]})
        try:
            self.assertEqual((), page_widths_px(path))
        finally:
            path.unlink()


class RunMetricsTests(unittest.TestCase):
    def _usage(self, cost: float = 0.31, limit: float = 0.90) -> dict:
        return {"calls": 3, "input_tokens": 61000, "output_tokens": 4000,
                "estimated_cost_usd": cost, "limit_usd": limit}

    def test_reports_shape_and_widest_page(self):
        path = _sidecar({"pages": [{"page": 1, "page_width_px": 1010},
                                   {"page": 2, "page_width_px": 1054}]})
        try:
            metrics = run_metrics(_graph(), path, 2, self._usage())
        finally:
            path.unlink()
        self.assertEqual(2, metrics.pages)
        self.assertEqual(5, metrics.nodes)
        self.assertEqual(3, metrics.states)
        self.assertEqual(2, metrics.actions)
        self.assertEqual(1054, metrics.widest_px)

    def test_a_failed_run_reports_spend_but_no_measurements(self):
        metrics = run_metrics(None, None, None, self._usage())
        self.assertIsNone(metrics.pages)
        self.assertIsNone(metrics.nodes)
        self.assertIsNone(metrics.widest_px)
        self.assertIsNone(metrics.printed_pt)
        self.assertEqual("none", metrics.width_state)
        self.assertEqual("none", metrics.print_state)
        self.assertEqual(3, metrics.calls)
        self.assertEqual(0.31, metrics.cost_usd)

    def test_a_run_with_no_usage_at_all_still_builds(self):
        metrics = run_metrics(None, None, None, None)
        self.assertEqual(0, metrics.calls)
        self.assertEqual(0.0, metrics.cost_usd)

    def test_printed_size_has_one_definition(self):
        quality = LayoutQuality(
            node_count=1, page_width_px=1738, canonical_duplicate_count=0,
            downward_edge_fraction=1.0, main_aspect_ratio=1.0,
            page_aspect_ratio=1.0, occupied_width_fraction=1.0,
            occupied_height_fraction=1.0, node_area_density=0.1,
            median_horizontal_drift_fraction=0.0, mean_route_detour=1.0,
            bend_count=0, has_parallel_structure=False)
        path = _sidecar({"pages": [{"page": 1, "page_width_px": 1738}]})
        try:
            metrics = run_metrics(_graph(), path, 1, self._usage())
        finally:
            path.unlink()
        self.assertEqual(quality.printed_label_pt, metrics.printed_pt)
        self.assertEqual(printed_label_pt_for_width(1738), metrics.printed_pt)

    def test_width_state_follows_the_renderer_budget(self):
        at_budget = RunMetrics(
            pages=1, nodes=1, states=0, actions=1,
            widest_px=MAX_PAGE_WIDTH_PX, printed_pt=MIN_PRINTED_LABEL_PT,
            calls=0, input_tokens=0, output_tokens=0,
            cost_usd=0.0, limit_usd=0.9)
        over = RunMetrics(
            pages=1, nodes=1, states=0, actions=1,
            widest_px=MAX_PAGE_WIDTH_PX + 1,
            printed_pt=MIN_PRINTED_LABEL_PT - 0.1,
            calls=0, input_tokens=0, output_tokens=0,
            cost_usd=0.0, limit_usd=0.9)
        self.assertEqual("ok", at_budget.width_state)
        self.assertEqual("ok", at_budget.print_state)
        self.assertEqual("warn", over.width_state)
        self.assertEqual("warn", over.print_state)

    def test_cost_state_turns_bad_only_at_the_limit(self):
        below = run_metrics(None, None, None, self._usage(0.89, 0.90))
        reached = run_metrics(None, None, None, self._usage(0.90, 0.90))
        self.assertEqual("ok", below.cost_state)
        self.assertEqual("bad", reached.cost_state)


if __name__ == "__main__":
    unittest.main()
