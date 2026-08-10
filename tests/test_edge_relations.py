"""Edges carry a relation, derived from the constructs at their two ends.

Node roles were made enumerable so the notation could be checked for symbol
overload. Edges were left as one undifferentiated line, which made half the
notation unexaminable and made the reference diagram's dotted context edges and
dashed annotation edges impossible to draw.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from layout_ir import build_layout_ir
from layout_planner import plan_layout
from layout_router import route_layout
from layout_svg import _connector_svg
from schema import AttackGraph
from visual_syntax import (EDGE_RELATION_STYLES, edge_relation,
                           edge_style, project_visual_nodes)


def _graph() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "edge relations",
        "preconditions": [
            {"id": "r1", "label": "Stolen certificate", "code": "RS",
             "role": "external_resource", "parents": []},
            {"id": "s1", "label": "Lure delivered", "code": "D",
             "parents": []},
            {"id": "s2", "label": "Foothold established", "code": "IA",
             "parents": ["e1"]},
            {"id": "a1", "label": "Awareness training", "code": "-",
             "role": "annotation", "style": "dashed", "parents": ["e1"]},
        ],
        "events": [
            {"id": "e1", "label": "Execute payload", "tactic": "EX",
             "technique": "T1204.002", "mitigations": ["M1017"],
             "likelihood": 5.0, "parents": ["r1", "s1"], "join": "AND"},
        ],
    })


class TestRelationRule(unittest.TestCase):

    def test_external_resource_into_an_event_is_context(self):
        self.assertEqual(edge_relation("external_resource", "event"),
                         "context")

    def test_anything_into_an_annotation_is_annotation(self):
        for source in ("event", "precondition", "external_resource"):
            self.assertEqual(edge_relation(source, "annotation"), "annotation")

    def test_ordinary_state_into_an_event_is_causal(self):
        self.assertEqual(edge_relation("precondition", "event"), "causal")

    def test_the_annotation_rule_wins_over_the_context_rule(self):
        """A resource commented on is still commentary, not context."""
        self.assertEqual(edge_relation("external_resource", "annotation"),
                         "annotation")

    def test_each_relation_maps_to_a_distinct_texture(self):
        styles = set(EDGE_RELATION_STYLES.values())
        self.assertEqual(len(styles), len(EDGE_RELATION_STYLES))
        self.assertEqual(EDGE_RELATION_STYLES["causal"], "solid")


class TestProjectionCarriesRole(unittest.TestCase):

    def test_external_resource_is_distinguishable_after_projection(self):
        """``kind`` collapses it to "state"; the edge rule needs more."""
        roles = {n.id: n.role for n in project_visual_nodes(_graph())}
        self.assertEqual(roles["r1"], "external_resource")
        self.assertEqual(roles["s1"], "precondition")
        self.assertEqual(roles["e1"], "event")
        self.assertEqual(roles["a1"], "annotation")


class TestRenderedOutput(unittest.TestCase):

    def setUp(self):
        model = _graph()
        self.ir = build_layout_ir(model)
        plan = plan_layout(self.ir)
        self.routed = route_layout(self.ir, plan)
        self.roles = {n.semantics.id: n.semantics.role for n in self.ir.nodes}

    def _svg_for(self, target: str) -> str:
        connector = next(c for c in self.routed.connectors
                         if c.target_visual_id == target)
        return "\n".join(_connector_svg(connector, 0, self.roles))

    def test_the_context_edge_is_dotted(self):
        svg = self._svg_for("e1")
        self.assertIn('stroke-dasharray="2 3"', svg)

    def test_the_annotation_edge_is_dashed(self):
        self.assertIn('stroke-dasharray="7 5"', self._svg_for("a1"))

    def test_a_plain_causal_graph_draws_no_dashes(self):
        model = AttackGraph.model_validate({
            "title": "causal only",
            "preconditions": [{"id": "s1", "label": "Exposed service",
                               "code": "IA", "parents": []},
                              {"id": "s2", "label": "Foothold", "code": "IA",
                               "parents": ["e1"]}],
            "events": [{"id": "e1", "label": "Exploit", "tactic": "IA",
                        "technique": "T1190", "mitigations": ["M1051"],
                        "likelihood": 6.0, "parents": ["s1"], "join": "AND"}]})
        ir = build_layout_ir(model)
        routed = route_layout(ir, plan_layout(ir))
        roles = {n.semantics.id: n.semantics.role for n in ir.nodes}
        svg = "\n".join(part for c in routed.connectors
                        for part in _connector_svg(c, 0, roles))
        self.assertNotIn("stroke-dasharray", svg)

    def test_both_backends_agree_on_the_relation(self):
        """PNG and SVG must not diverge into two notations again."""
        from layout_renderer import _draw_connector
        recorded = []

        class Recorder:
            def line(self, points, **kw): recorded.append(kw)
            def polygon(self, *a, **kw): pass

        for connector in self.routed.connectors:
            _draw_connector(Recorder(), connector, 0, self.roles)
        # A dashed/dotted line is traced as many short segments; a solid one is
        # a single call. The annotation and context edges therefore produce
        # more line calls than a two-point solid edge would.
        self.assertGreater(len(recorded), len(self.routed.connectors))



class TestStyleAgainstTheFixture(unittest.TestCase):
    """The edge-style rule is checked against all 32 reference edges.

    Relation alone was not enough: the fixture has six dotted edges but only
    two context edges. The other four are ordinary causal edges leaving a step
    on the uncertain branch, so uncertainty propagates forward.
    """

    @classmethod
    def setUpClass(cls):
        import json
        fixture = (ROOT / "tests" / "fixtures" / "stolen_pencil_gold.json")
        gold = json.loads(fixture.read_text(encoding="utf-8"))
        cls.edges = gold["edges"]
        cls.role = {n["id"]: n["role"] for n in gold["nodes"]}
        cls.style = {n["id"]: n["style"] for n in gold["nodes"]}

    def test_every_reference_edge_relation_is_reproduced(self):
        for edge in self.edges:
            with self.subTest(edge=(edge["source"], edge["target"])):
                self.assertEqual(
                    edge_relation(self.role[edge["source"]],
                                  self.role[edge["target"]]),
                    edge["relation"])

    def test_every_reference_edge_style_is_reproduced(self):
        for edge in self.edges:
            with self.subTest(edge=(edge["source"], edge["target"])):
                self.assertEqual(
                    edge_style(edge["relation"], self.style[edge["source"]]),
                    edge["style"])

    def test_uncertainty_propagates_out_of_a_dotted_step(self):
        """A solid result of a dotted step is still reached by a dotted edge."""
        self.assertEqual(edge_style("causal", "dotted"), "dotted")

    def test_a_solid_step_into_a_dotted_one_stays_solid(self):
        self.assertEqual(edge_style("causal", "solid"), "solid")

if __name__ == "__main__":
    unittest.main()
