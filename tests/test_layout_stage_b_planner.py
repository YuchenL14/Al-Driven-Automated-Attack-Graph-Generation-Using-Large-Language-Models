"""Stage B tests for atomic-block lanes and local node geometry."""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from causal_split import materialize_split_part, plan_causal_split  # noqa: E402
from layout_ir import build_layout_ir  # noqa: E402
from layout_planner import plan_layout, validate_layout_plan  # noqa: E402
from layout_quality import LEGEND_RESERVE_WIDTH  # noqa: E402
from schema import AttackGraph  # noqa: E402
from test_phase3_causal_split import (_british_library_shape,  # noqa: E402
                                      _mands_shape,
                                      _wannacry_shape)


def _fork_merge_graph() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "Stage B fork and merge",
        "preconditions": [
            {"id": "p_a", "label": "Preparation A ready", "code": "RS"},
            {"id": "p_b", "label": "Preparation B ready", "code": "RS"},
            {"id": "p_global", "label": "Shared target reachable", "code": "R"},
            {
                "id": "s_a",
                "label": "Branch A established",
                "code": "R",
                "parents": ["e_a"],
            },
            {
                "id": "s_b",
                "label": "Branch B established",
                "code": "R",
                "parents": ["e_b"],
            },
            {
                "id": "s_merge",
                "label": "Combined access established",
                "code": "R",
                "parents": ["e_merge"],
            },
            {
                "id": "s_left",
                "label": "Left objective achieved",
                "code": "R",
                "parents": ["e_left"],
            },
            {
                "id": "s_right",
                "label": "Right objective achieved",
                "code": "R",
                "parents": ["e_right"],
            },
            {
                "id": "s_final",
                "label": "Final objective achieved",
                "code": "IM",
                "parents": ["e_final"],
            },
        ],
        "events": [
            {
                "id": "e_a",
                "label": "Perform preparation A",
                "tactic": "RS",
                "parents": ["p_a"],
            },
            {
                "id": "e_b",
                "label": "Perform preparation B",
                "tactic": "RS",
                "parents": ["p_b"],
            },
            {
                "id": "e_merge",
                "label": "Combine preparation branches",
                "tactic": "IA",
                "parents": ["s_a", "s_b", "p_global"],
                "join": "AND",
            },
            {
                "id": "e_left",
                "label": "Perform left branch action",
                "tactic": "CL",
                "parents": ["s_merge"],
            },
            {
                "id": "e_right",
                "label": "Perform right branch action",
                "tactic": "IM",
                "parents": ["s_merge"],
            },
            {
                "id": "e_final",
                "label": "Complete final objective",
                "tactic": "IM",
                "parents": ["s_left", "s_right", "p_global"],
                "join": "AND",
            },
        ],
    })


def _or_result_graph() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "Stage B alternatives",
        "preconditions": [
            {"id": "p_left", "label": "Left method ready", "code": "RS"},
            {"id": "p_right", "label": "Right method ready", "code": "RS"},
            {
                "id": "p_result",
                "label": "Access method obtained",
                "code": "R",
                "parents": ["e_left", "e_right"],
            },
        ],
        "events": [
            {
                "id": "e_left",
                "label": "Use left access method",
                "tactic": "IA",
                "parents": ["p_left"],
            },
            {
                "id": "e_right",
                "label": "Use right access method",
                "tactic": "IA",
                "parents": ["p_right"],
            },
        ],
    })


def _overlap(left, right) -> bool:
    return (
        left.x < right.right
        and right.x < left.right
        and left.y < right.bottom
        and right.y < left.bottom
    )


class LayoutStageBPlannerTests(unittest.TestCase):
    def test_plan_is_deterministic_and_does_not_mutate_inputs(self):
        graph = _fork_merge_graph()
        before = graph.model_dump()
        layout_ir = build_layout_ir(graph)
        first = plan_layout(layout_ir)
        second = plan_layout(layout_ir)
        self.assertEqual(first, second)
        self.assertEqual(before, graph.model_dump())
        validate_layout_plan(layout_ir, first)

    def test_every_display_edge_flows_downward(self):
        layout_ir = build_layout_ir(_fork_merge_graph())
        plan = plan_layout(layout_ir)
        nodes = {node.visual_id: node for node in plan.nodes}
        for edge in layout_ir.edges:
            self.assertLess(
                nodes[edge.source_visual_id].bottom,
                nodes[edge.target_visual_id].y,
            )

    def test_no_planned_node_boxes_overlap(self):
        plan = plan_layout(build_layout_ir(_fork_merge_graph()))
        for index, left in enumerate(plan.nodes):
            for right in plan.nodes[index + 1:]:
                self.assertFalse(
                    _overlap(left, right),
                    f"{left.visual_id} overlaps {right.visual_id}",
                )

    def test_parallel_blocks_receive_distinct_stable_lanes(self):
        plan = plan_layout(build_layout_ir(_fork_merge_graph()))
        blocks = {block.id: block for block in plan.blocks}
        self.assertEqual((0, 2), (
            blocks["block_000"].lane_index,
            blocks["block_000"].lane_count,
        ))
        self.assertEqual((1, 2), (
            blocks["block_001"].lane_index,
            blocks["block_001"].lane_count,
        ))
        self.assertEqual(2, blocks["block_003"].lane_count)
        self.assertEqual(2, blocks["block_004"].lane_count)

    def test_merge_blocks_are_between_their_parent_branches(self):
        plan = plan_layout(build_layout_ir(_fork_merge_graph()))
        blocks = {block.id: block for block in plan.blocks}
        first_parent_centres = [
            blocks["block_000"].cx,
            blocks["block_001"].cx,
        ]
        self.assertGreaterEqual(
            blocks["block_002"].cx, min(first_parent_centres))
        self.assertLessEqual(
            blocks["block_002"].cx, max(first_parent_centres))

        second_parent_centres = [
            blocks["block_003"].cx,
            blocks["block_004"].cx,
        ]
        self.assertGreaterEqual(
            blocks["block_005"].cx, min(second_parent_centres))
        self.assertLessEqual(
            blocks["block_005"].cx, max(second_parent_centres))

    def test_reused_global_condition_is_drawn_once_above_all_consumers(self):
        layout_ir = build_layout_ir(_fork_merge_graph())
        plan = plan_layout(layout_ir)
        nodes = {node.visual_id: node for node in plan.nodes}
        global_occurrences = [
            node for node in layout_ir.nodes
            if node.canonical_id == "p_global"
        ]
        self.assertEqual(1, len(global_occurrences))
        occurrence = global_occurrences[0]
        root = nodes[occurrence.visual_id]
        self.assertIsNone(root.block_id)
        consumer_ids = [
            edge.target_visual_id
            for edge in layout_ir.edges
            if edge.source_visual_id == occurrence.visual_id
        ]
        self.assertGreaterEqual(len(consumer_ids), 2)
        for consumer_id in consumer_ids:
            self.assertLess(root.bottom, nodes[consumer_id].y)

    def test_every_atomic_block_is_assigned_to_one_macro_module(self):
        plan = plan_layout(build_layout_ir(_fork_merge_graph()))
        self.assertTrue(plan.macro_module_ids)
        self.assertTrue(all(
            block.module_id in plan.macro_module_ids
            for block in plan.blocks
        ))

    def test_topological_projection_repairs_conflicting_preferred_rows(self):
        layout_ir = build_layout_ir(_fork_merge_graph())
        blocks = list(layout_ir.atomic_blocks)
        # Reproduce the class of conflict seen with a shared continuation
        # state: a child block arrives carrying the same preferred macro rank
        # as its parent. Geometry must still follow the canonical edge.
        child_index = next(
            index
            for index, block in enumerate(blocks)
            if block.parent_block_ids
        )
        parent_id = blocks[child_index].parent_block_ids[0]
        parent_rank = next(
            block.rank for block in blocks if block.id == parent_id
        )
        blocks[child_index] = replace(
            blocks[child_index],
            rank=parent_rank,
        )
        conflicted = replace(
            layout_ir,
            atomic_blocks=tuple(blocks),
        )
        plan = plan_layout(conflicted)
        nodes = {node.visual_id: node for node in plan.nodes}
        for edge in conflicted.edges:
            self.assertLess(
                nodes[edge.source_visual_id].bottom,
                nodes[edge.target_visual_id].y,
            )

    def test_post_extortion_state_flows_down_to_shared_publish_actions(self):
        graph = AttackGraph.model_validate({
            "title": "Post-extortion shared-state regression",
            "preconditions": [
                {"id": "p_data", "label": "Stolen data available", "code": "R"},
                {
                    "id": "p_after_e_extort",
                    "label": "Extortion leverage established",
                    "code": "IM",
                    "parents": ["e_extort"],
                },
                {
                    "id": "p_published",
                    "label": "Stolen data published",
                    "code": "IM",
                    "parents": ["e_publish_leak"],
                },
                {
                    "id": "p_auctioned",
                    "label": "Stolen data auctioned",
                    "code": "IM",
                    "parents": ["e_auction_data"],
                },
            ],
            "events": [
                {
                    "id": "e_extort",
                    "label": "Issue extortion demand",
                    "tactic": "IM",
                    "parents": ["p_data"],
                },
                {
                    "id": "e_publish_leak",
                    "label": "Publish stolen data",
                    "tactic": "IM",
                    "parents": ["p_after_e_extort"],
                },
                {
                    "id": "e_auction_data",
                    "label": "Auction stolen data",
                    "tactic": "IM",
                    "parents": ["p_after_e_extort"],
                },
            ],
        })
        layout_ir = build_layout_ir(graph)
        plan = plan_layout(layout_ir)
        nodes = {node.visual_id: node for node in plan.nodes}
        self.assertLess(
            nodes["p_after_e_extort"].bottom,
            nodes["e_publish_leak"].y,
        )
        self.assertLess(
            nodes["p_after_e_extort"].bottom,
            nodes["e_auction_data"].y,
        )

    def test_atomic_event_result_units_remain_in_one_block(self):
        layout_ir = build_layout_ir(_or_result_graph())
        plan = plan_layout(layout_ir)
        nodes = {node.visual_id: node for node in plan.nodes}
        block_ids = {
            nodes["e_left"].block_id,
            nodes["e_right"].block_id,
            nodes["p_result"].block_id,
        }
        self.assertEqual(1, len(block_ids))
        self.assertLess(nodes["e_left"].bottom, nodes["p_result"].y)
        self.assertLess(nodes["e_right"].bottom, nodes["p_result"].y)

    def test_and_uses_one_bus_and_or_uses_separate_ports(self):
        and_plan = plan_layout(build_layout_ir(_fork_merge_graph()))
        and_logic = {
            item.target_visual_id: item for item in and_plan.logic
        }["e_merge"]
        self.assertEqual("AND", and_logic.logic)
        self.assertIsNotNone(and_logic.shared_bus)
        self.assertEqual(1, len(and_logic.target_ports))

        or_plan = plan_layout(build_layout_ir(_or_result_graph()))
        or_logic = or_plan.logic[0]
        self.assertEqual("OR", or_logic.logic)
        self.assertIsNone(or_logic.shared_bus)
        self.assertEqual(2, len(or_logic.target_ports))
        self.assertEqual(2, len(set(or_logic.target_ports)))

    def test_longest_causal_spine_is_recorded_as_the_trunk(self):
        plan = plan_layout(build_layout_ir(_fork_merge_graph()))
        self.assertEqual(
            ("block_000", "block_002", "block_003", "block_005"),
            plan.trunk_block_ids,
        )
        marked = tuple(block.id for block in plan.blocks if block.is_trunk)
        self.assertEqual(plan.trunk_block_ids, marked)

    def test_report_oracle_pages_fit_the_landscape_canvas_budget(self):
        cases = (
            (_british_library_shape, 2),
            (_wannacry_shape, 2),
            (_mands_shape, 3),
        )
        for graph_factory, expected_parts in cases:
            graph = graph_factory()
            split = plan_causal_split(graph)
            self.assertEqual(expected_parts, len(split.parts))
            for part in split.parts:
                page = materialize_split_part(
                    graph, part, len(split.parts)
                )
                layout_ir = build_layout_ir(page)
                plan = plan_layout(layout_ir)
                validate_layout_plan(layout_ir, plan)
                # Read from the renderer rather than restated here. The
                # reserve was written as a literal 420 and stayed at 420 when
                # the key column was narrowed, so this measured a canvas the
                # renderer had stopped drawing.
                final_canvas_width = max(1248,
                                         plan.width + LEGEND_RESERVE_WIDTH)
                self.assertLessEqual(
                    plan.height / final_canvas_width,
                    1.2,
                )


if __name__ == "__main__":
    unittest.main()
