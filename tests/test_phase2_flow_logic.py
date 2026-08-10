"""Phase 2 checks for downward flow and unlabelled AND/OR syntax."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from graphviz import Digraph
from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import _add_graphviz_edges  # noqa: E402
from reference_renderer import (_build_nodes, _layout,  # noqa: E402
                                _plan_connector)
from schema import AttackGraph  # noqa: E402


def _logic_graph() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "Phase 2 logic",
        "preconditions": [
            {"id": "p_a", "label": "Condition A present", "code": "R"},
            {"id": "p_b", "label": "Condition B present", "code": "R"},
            {"id": "p_c", "label": "Alternative C present", "code": "R"},
            {"id": "p_d", "label": "Alternative D present", "code": "R"},
            {
                "id": "s_and",
                "label": "AND result established",
                "code": "R",
                "parents": ["e_and"],
            },
            {
                "id": "s_or",
                "label": "OR result established",
                "code": "R",
                "parents": ["e_or"],
            },
            {
                "id": "s_shared",
                "label": "Either result available",
                "code": "R",
                "parents": ["e_and", "e_or"],
            },
        ],
        "events": [
            {
                "id": "e_and",
                "label": "Perform conjunctive action",
                "tactic": "IA",
                "parents": ["p_a", "p_b"],
                "join": "AND",
            },
            {
                "id": "e_or",
                "label": "Perform alternative action",
                "tactic": "IA",
                "parents": ["p_c", "p_d"],
                "join": "OR",
            },
            {
                "id": "e_final",
                "label": "Complete final action",
                "tactic": "IM",
                "parents": ["s_and", "s_or"],
                "join": "AND",
            },
        ],
    })


def _positioned_nodes(graph: AttackGraph):
    image = Image.new("RGB", (8, 8), "white")
    draw = ImageDraw.Draw(image)
    return _layout(
        draw,
        _build_nodes(graph),
        ImageFont.load_default(),
        compact=False,
    )


class Phase2FlowLogicTests(unittest.TestCase):
    def test_every_causal_target_is_below_its_parent(self):
        nodes = _positioned_nodes(_logic_graph())
        checked = 0
        for target in nodes.values():
            for parent_id in target.parents:
                checked += 1
                self.assertLess(nodes[parent_id].bottom, target.y)
        self.assertGreaterEqual(checked, 10)

    def test_no_causal_parent_and_child_share_a_rank(self):
        nodes = _positioned_nodes(_logic_graph())
        for target in nodes.values():
            for parent_id in target.parents:
                self.assertLess(nodes[parent_id].level, target.level)
                self.assertNotEqual(nodes[parent_id].y, target.y)

    def test_and_inputs_share_one_bus_and_one_output_arrow(self):
        nodes = _positioned_nodes(_logic_graph())
        target = nodes["e_and"]
        plan = _plan_connector(
            target, [nodes[parent] for parent in target.parents])
        self.assertEqual("AND", plan.logic)
        self.assertIsNotNone(plan.shared_bus)
        self.assertEqual(1, len(plan.arrow_path_indices))
        bus_y = plan.shared_bus[0][1]
        self.assertTrue(all(path[-1][1] == bus_y
                            for path in plan.paths[:-1]))
        self.assertEqual((target.cx, target.y), plan.paths[-1][-1])

    def test_or_inputs_are_separate_and_have_individual_arrows(self):
        nodes = _positioned_nodes(_logic_graph())
        target = nodes["e_or"]
        plan = _plan_connector(
            target, [nodes[parent] for parent in target.parents])
        self.assertEqual("OR", plan.logic)
        self.assertIsNone(plan.shared_bus)
        self.assertEqual(len(target.parents), len(plan.paths))
        self.assertEqual(len(plan.paths), len(plan.arrow_path_indices))
        target_ports = {path[-1] for path in plan.paths}
        self.assertEqual(len(plan.paths), len(target_ports))
        self.assertTrue(all(point[1] == target.y for point in target_ports))

    def test_multiple_events_producing_one_state_are_or_alternatives(self):
        nodes = _positioned_nodes(_logic_graph())
        target = nodes["s_shared"]
        self.assertEqual("OR", target.join)
        plan = _plan_connector(
            target, [nodes[parent] for parent in target.parents])
        self.assertIsNone(plan.shared_bus)
        self.assertEqual(2, len(plan.arrow_path_indices))

    def test_graphviz_fallback_has_no_text_or_diamond_logic_gate(self):
        dot = Digraph("logic")
        _add_graphviz_edges(dot, _logic_graph(), set())
        source = dot.source
        self.assertIn("__join_e_and", source)
        self.assertNotIn("shape=diamond", source)
        self.assertNotIn("label=AND", source)
        self.assertNotIn("label=OR", source)
        self.assertIn("p_c -> e_or", source)
        self.assertIn("p_d -> e_or", source)


if __name__ == "__main__":
    unittest.main()
