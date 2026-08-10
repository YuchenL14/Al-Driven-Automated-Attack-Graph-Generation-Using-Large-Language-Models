"""Quantitative AGVS-SP perceptual-quality regression tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from causal_split import materialize_split_part, plan_causal_split  # noqa: E402
from layout_ir import build_layout_ir  # noqa: E402
from layout_planner import plan_layout  # noqa: E402
from layout_quality import (measure_layout_quality,  # noqa: E402
                            validate_layout_quality)
from layout_router import route_layout  # noqa: E402
from test_phase3_causal_split import (_british_library_shape,  # noqa: E402
                                      _mands_shape,
                                      _wannacry_shape)


class LayoutQualityTests(unittest.TestCase):
    def test_report_oracles_meet_quantitative_page_quality_limits(self):
        for graph in (
            _british_library_shape(), _wannacry_shape(), _mands_shape()
        ):
            split = plan_causal_split(graph)
            for part in split.parts:
                with self.subTest(graph=graph.title, part=part.index):
                    page = materialize_split_part(
                        graph, part, len(split.parts)
                    )
                    layout_ir = build_layout_ir(page)
                    plan = plan_layout(layout_ir)
                    routed = route_layout(layout_ir, plan)
                    quality = validate_layout_quality(
                        layout_ir, plan, routed
                    )
                    self.assertEqual(0, quality.canonical_duplicate_count)
                    self.assertEqual(1.0, quality.downward_edge_fraction)

    def test_metric_is_deterministic(self):
        graph = _british_library_shape()
        part = plan_causal_split(graph).parts[0]
        page = materialize_split_part(graph, part, 2)
        layout_ir = build_layout_ir(page)
        plan = plan_layout(layout_ir)
        routed = route_layout(layout_ir, plan)
        self.assertEqual(
            measure_layout_quality(layout_ir, plan, routed),
            measure_layout_quality(layout_ir, plan, routed),
        )


if __name__ == "__main__":
    unittest.main()
