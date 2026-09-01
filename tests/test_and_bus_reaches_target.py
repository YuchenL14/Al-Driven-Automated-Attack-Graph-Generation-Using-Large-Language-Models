"""An AND bus was drawn across its inputs and nowhere near its target.

The bus was spanned from the leftmost to the rightmost input centre. The drop
into the target, however, leaves the bus at the target's centre. Whenever the
target sat outside the span of its own inputs the drop began in empty space,
and the reader saw an arrowhead above the box with no line leading to it.

That happens routinely: several events sharing one pair of AND inputs fan out
across the rank, so most of them end up left or right of the pair. In a real
v1.6 run four events shared the same two states and the bus reached none of
them -- it spanned x 1061..1289 while the targets sat at x 430, 1026, 1324 and
1677.

The bus is not decoration. It is the drawing of the conjunction, so it has to
touch every endpoint the conjunction connects.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from layout_ir import build_layout_ir
from layout_planner import plan_layout
from layout_router import (LayoutRoutingError, route_layout,
                           validate_routed_layout)
from schema import AttackGraph


def _shared_and_inputs(consumer_count: int) -> AttackGraph:
    """`consumer_count` events, each requiring the same two states."""

    events = [
        {
            "id": f"e{i}",
            "label": f"Action {i} needing both inputs",
            "parents": ["p_tools", "p_certs"],
            "tactic": "EX",
            "techniques": ["T1059"],
        }
        for i in range(consumer_count)
    ]
    preconditions = [
        {"id": "p_tools", "label": "Toolkit staged", "parents": [], "code": "P0"},
        {"id": "p_certs", "label": "Signing certificate stolen", "parents": [],
         "code": "P1"},
    ] + [
        {"id": f"p{i}", "label": f"Result of action {i}", "parents": [f"e{i}"],
         "code": f"P{i + 2}"}
        for i in range(consumer_count)
    ]
    return AttackGraph.model_validate(
        {"goal": "Run the toolkit", "events": events,
         "preconditions": preconditions}
    )


class AndBusReachesTargetTests(unittest.TestCase):
    def _route(self, model: AttackGraph):
        ir = build_layout_ir(model)
        plan = plan_layout(ir)
        return ir, plan, route_layout(ir, plan)

    def test_bus_spans_every_target_it_feeds(self):
        ir, plan, routed = self._route(_shared_and_inputs(4))
        centres = {node.visual_id: node.cx for node in plan.nodes}
        buses = [c for c in routed.connectors if c.shared_bus is not None]
        self.assertTrue(buses, "the fixture must produce AND buses")
        for connector in buses:
            (left, _), (right, _) = connector.shared_bus
            target_cx = centres[connector.target_visual_id]
            self.assertLessEqual(
                left, target_cx,
                f"bus starts right of {connector.target_visual_id}")
            self.assertLessEqual(
                target_cx, right,
                f"bus ends left of {connector.target_visual_id}")

    def test_bus_still_covers_both_inputs(self):
        ir, plan, routed = self._route(_shared_and_inputs(4))
        centres = {node.visual_id: node.cx for node in plan.nodes}
        for connector in routed.connectors:
            if connector.shared_bus is None:
                continue
            (left, _), (right, _) = connector.shared_bus
            for input_id in connector.input_visual_ids:
                self.assertLessEqual(left, centres[input_id])
                self.assertLessEqual(centres[input_id], right)

    def test_validator_rejects_a_bus_that_stops_short(self):
        ir, plan, routed = self._route(_shared_and_inputs(4))
        centres = {node.visual_id: node.cx for node in plan.nodes}
        broken = None
        for index, connector in enumerate(routed.connectors):
            if connector.shared_bus is not None:
                (_, y), _ = connector.shared_bus
                left = centres[connector.target_visual_id] + 10
                broken = index, connector.__class__(
                    target_visual_id=connector.target_visual_id,
                    logic=connector.logic,
                    input_visual_ids=connector.input_visual_ids,
                    input_paths=connector.input_paths,
                    input_arrow_indices=connector.input_arrow_indices,
                    shared_bus=((left, y), (left + 20, y)),
                    output_path=connector.output_path,
                    output_arrow=connector.output_arrow,
                )
                break
        self.assertIsNotNone(broken, "the fixture must produce an AND bus")
        index, replacement = broken
        connectors = list(routed.connectors)
        connectors[index] = replacement
        damaged = routed.__class__(
            connectors=tuple(connectors),
            occupied_segments=routed.occupied_segments,
        )
        with self.assertRaises(LayoutRoutingError):
            validate_routed_layout(ir, plan, damaged)

    def test_a_single_consumer_is_unaffected(self):
        ir, plan, routed = self._route(_shared_and_inputs(1))
        self.assertEqual(validate_routed_layout(ir, plan, routed), [])


if __name__ == "__main__":
    unittest.main()
