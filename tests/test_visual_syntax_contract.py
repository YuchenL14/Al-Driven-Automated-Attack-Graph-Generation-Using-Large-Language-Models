"""Phase 1 tests for the AGVS-SP 1.0 visual-semantics contract."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import _precondition_label  # noqa: E402
from reference_renderer import _build_nodes  # noqa: E402
from schema import ATTACK_TACTICS, AttackGraph  # noqa: E402
from visual_syntax import (AGVS_SP_V1, project_visual_nodes,  # noqa: E402
                           state_badge_code)


def _sample_graph(precondition_code: str = "RS") -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "Visual contract",
        "preconditions": [{
            "id": "p1",
            "label": "Service reachable",
            "code": precondition_code,
        }],
        "events": [{
            "id": "e1",
            "label": "Exploit reachable service",
            "tactic": "IA",
            "technique": "T1190",
            "mitigations": ["M1051", "M1030"],
            "likelihood": 7.0,
            "parents": ["p1"],
        }],
    })


class VisualSyntaxProfileTests(unittest.TestCase):
    def test_profile_freezes_the_tre_configuration(self):
        self.assertEqual("AGVS-SP-1.0", AGVS_SP_V1.profile_id)
        self.assertEqual("top_down", AGVS_SP_V1.flow_direction)
        self.assertEqual("rectangle", AGVS_SP_V1.event_shape)
        self.assertEqual("ellipse", AGVS_SP_V1.state_shape)
        self.assertEqual("shared_bus", AGVS_SP_V1.and_notation)
        self.assertEqual("separate_edges", AGVS_SP_V1.or_notation)

    def test_event_projection_preserves_all_attack_metadata(self):
        event = {
            node.id: node
            for node in project_visual_nodes(_sample_graph())
        }["e1"]
        self.assertEqual("event", event.kind)
        self.assertEqual("rectangle", event.shape)
        self.assertEqual("IA", event.badge_code)
        self.assertEqual("attack_tactic", event.badge_namespace)
        self.assertEqual("T1190", event.technique)
        self.assertEqual(("M1051", "M1030"), event.mitigations)
        self.assertEqual(7.0, event.likelihood)

    def test_state_projection_is_an_ellipse_in_a_separate_namespace(self):
        # The state badge keeps its own namespace, so the renderer can give it
        # its own fill, but the value is now derived rather than read from the
        # stored code. A stored "R" is a kill-chain letter and would have been
        # drawn verbatim before; it is kept in the graph and not drawn.
        state = {
            node.id: node
            for node in project_visual_nodes(_sample_graph(
                precondition_code="R"))
        }["p1"]
        self.assertEqual("state", state.kind)
        self.assertEqual("ellipse", state.shape)
        self.assertEqual("PRE", state.badge_code)
        self.assertEqual("state_phase", state.badge_namespace)
        self.assertIsNone(state.technique)
        self.assertEqual((), state.mitigations)

    def test_no_attack_tactic_is_displayed_on_a_prerequisite(self):
        # A tactic classifies adversary behaviour, so a precondition cannot
        # hold one. Drawing tactics on ellipses also loaded the purple circle
        # with two concepts, which Lallie, Debattista and Bal (2020) treat as a
        # failure of semiotic clarity. The canonical value is retained for
        # audit; only its placement is suppressed.
        for tactic in ATTACK_TACTICS:
            with self.subTest(tactic=tactic):
                graph = _sample_graph(precondition_code=tactic)
                state = {
                    node.id: node for node in project_visual_nodes(graph)
                }["p1"]
                # The invariant is unchanged and now holds more strongly: the
                # badge is derived from role and parentage, so a state cannot
                # display an ATT&CK tactic whatever its stored code says. A
                # root precondition badges PRE, and the tactic stays in the
                # canonical graph for audit.
                self.assertEqual(tactic, graph.preconditions[0].code)
                self.assertEqual("PRE", state.badge_code)
                self.assertNotIn(state.badge_code, ATTACK_TACTICS)
                self.assertEqual("state_phase", state.badge_namespace)
                self.assertEqual(
                    "PRE", state_badge_code("precondition", has_parents=False))

    def test_projection_does_not_mutate_the_canonical_graph(self):
        graph = _sample_graph(precondition_code="IA")
        before = graph.model_dump()
        project_visual_nodes(graph)
        self.assertEqual(before, graph.model_dump())

    def test_png_renderer_consumes_the_versioned_projection(self):
        # The renderer reads the projection, not the stored code: a state
        # whose code says "IA" draws PRE, and the tactic reaches the rectangle
        # only.
        nodes = _build_nodes(_sample_graph(precondition_code="IA"))
        self.assertEqual("ellipse", nodes["p1"].shape)
        self.assertEqual("PRE", nodes["p1"].code)
        self.assertEqual("rectangle", nodes["e1"].shape)
        self.assertEqual("IA", nodes["e1"].code)

    def test_graphviz_fallback_also_suppresses_ia_on_state(self):
        label = _precondition_label(
            _sample_graph(precondition_code="IA").preconditions[0])
        self.assertNotIn(">IA<", label)


if __name__ == "__main__":
    unittest.main()
