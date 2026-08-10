"""Stage C tests for downward obstacle-aware orthogonal routing."""

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
from layout_router import (_interaction, _segments, route_layout,  # noqa: E402
                           validate_routed_layout)
from test_layout_stage_b_planner import (_fork_merge_graph,  # noqa: E402
                                         _or_result_graph)
from test_phase3_causal_split import (_british_library_shape,  # noqa: E402
                                      _mands_shape,
                                      _wannacry_shape)


class LayoutStageCRouterTests(unittest.TestCase):
    def test_route_is_deterministic(self):
        layout_ir = build_layout_ir(_fork_merge_graph())
        plan = plan_layout(layout_ir)
        self.assertEqual(
            route_layout(layout_ir, plan),
            route_layout(layout_ir, plan),
        )

    def test_every_causal_target_has_exactly_one_connector(self):
        layout_ir = build_layout_ir(_fork_merge_graph())
        plan = plan_layout(layout_ir)
        routed = route_layout(layout_ir, plan)
        expected = {
            edge.target_visual_id for edge in layout_ir.edges
        }
        actual = [
            connector.target_visual_id
            for connector in routed.connectors
        ]
        self.assertEqual(expected, set(actual))
        self.assertEqual(len(actual), len(set(actual)))

    def test_every_segment_is_orthogonal_and_never_moves_up(self):
        layout_ir = build_layout_ir(_fork_merge_graph())
        plan = plan_layout(layout_ir)
        routed = route_layout(layout_ir, plan)
        for connector in routed.connectors:
            paths = list(connector.input_paths)
            if connector.output_path:
                paths.append(connector.output_path)
            for path in paths:
                for start, end in _segments(path):
                    self.assertTrue(
                        start[0] == end[0] or start[1] == end[1])
                    self.assertLessEqual(start[1], end[1])

    def test_and_and_or_keep_different_visual_syntax(self):
        and_ir = build_layout_ir(_fork_merge_graph())
        and_plan = plan_layout(and_ir)
        and_route = route_layout(and_ir, and_plan)
        merge = next(
            connector for connector in and_route.connectors
            if connector.target_visual_id == "e_merge"
        )
        self.assertEqual("AND", merge.logic)
        self.assertIsNotNone(merge.shared_bus)
        self.assertEqual((), merge.input_arrow_indices)
        self.assertTrue(merge.output_arrow)

        or_ir = build_layout_ir(_or_result_graph())
        or_plan = plan_layout(or_ir)
        or_route = route_layout(or_ir, or_plan)
        alternative = next(
            connector for connector in or_route.connectors
            if connector.target_visual_id == "p_result"
        )
        self.assertEqual("OR", alternative.logic)
        self.assertIsNone(alternative.shared_bus)
        self.assertIsNone(alternative.output_path)
        self.assertEqual((0, 1), alternative.input_arrow_indices)

    def test_or_inputs_do_not_share_tracks_or_cross(self):
        layout_ir = build_layout_ir(_or_result_graph())
        plan = plan_layout(layout_ir)
        routed = route_layout(layout_ir, plan)
        connector = next(
            item for item in routed.connectors
            if item.target_visual_id == "p_result"
        )
        left_segments = _segments(connector.input_paths[0])
        right_segments = _segments(connector.input_paths[1])
        overlap = 0
        crossings = 0
        for left in left_segments:
            for right in right_segments:
                segment_overlap, segment_crossings = _interaction(left, right)
                overlap += segment_overlap
                crossings += segment_crossings
        self.assertEqual(0, overlap)
        self.assertEqual(0, crossings)

    def test_validator_accepts_all_report_oracle_pages(self):
        for graph_factory in (
            _british_library_shape,
            _wannacry_shape,
            _mands_shape,
        ):
            graph = graph_factory()
            split = plan_causal_split(graph)
            for part in split.parts:
                page = materialize_split_part(
                    graph, part, len(split.parts)
                )
                layout_ir = build_layout_ir(page)
                plan = plan_layout(layout_ir)
                routed = route_layout(layout_ir, plan)
                validate_routed_layout(layout_ir, plan, routed)

    def test_report_oracle_pages_have_no_edge_crossings_or_overlaps(self):
        for graph_factory in (
            _british_library_shape,
            _wannacry_shape,
            _mands_shape,
        ):
            graph = graph_factory()
            split = plan_causal_split(graph)
            for part in split.parts:
                page = materialize_split_part(
                    graph, part, len(split.parts)
                )
                layout_ir = build_layout_ir(page)
                plan = plan_layout(layout_ir)
                routed = route_layout(layout_ir, plan)
                segments = []
                for connector in routed.connectors:
                    for path in connector.input_paths:
                        segments.extend(_segments(path))
                    if connector.output_path:
                        segments.extend(_segments(connector.output_path))
                    if connector.shared_bus:
                        segments.append(connector.shared_bus)
                for index, left in enumerate(segments):
                    for right in segments[index + 1:]:
                        overlap, crossings = _interaction(left, right)
                        self.assertEqual(0, overlap)
                        self.assertEqual(0, crossings)


if __name__ == "__main__":
    unittest.main()
