"""The legacy PNG backend must refuse what it cannot draw.

It predates `role` and `style` and reads neither, so a v1.6 graph does not
fail there -- it renders wrongly and silently. Verified by rendering: every
outline came out solid, and the dashed annotation "Staff awareness training"
came out as a plain rectangle, indistinguishable from an adversary action.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import _refuse_unsupported_constructs
from schema import AttackGraph


def _graph(**overrides) -> AttackGraph:
    precondition = {"id": "s1", "label": "Service exposed", "code": "IA",
                    "parents": []}
    precondition.update(overrides.pop("precondition", {}))
    extra = overrides.pop("extra_preconditions", [])
    event = {"id": "e1", "label": "Exploit the service", "tactic": "IA",
             "technique": "T1190", "mitigations": ["M1051"],
             "likelihood": 6.0, "parents": ["s1"], "join": "AND"}
    event.update(overrides.pop("event", {}))
    return AttackGraph.model_validate({
        "title": "guard", "preconditions": [precondition, *extra],
        "events": [event]})


class TestLegacyGuard(unittest.TestCase):

    def test_a_plain_v14_graph_still_renders(self):
        """The rollback must keep working for the frozen baseline."""
        self.assertIsNone(_refuse_unsupported_constructs(_graph()))

    def test_an_annotation_is_refused(self):
        graph = _graph(extra_preconditions=[
            {"id": "a1", "label": "Staff awareness training", "code": "-",
             "role": "annotation", "style": "dashed", "parents": ["e1"]}])
        with self.assertRaises(ValueError) as caught:
            _refuse_unsupported_constructs(graph)
        self.assertIn("a1", str(caught.exception))

    def test_an_external_resource_is_refused(self):
        graph = _graph(extra_preconditions=[
            {"id": "r1", "label": "Stolen certificate", "code": "RS",
             "role": "external_resource", "parents": []}])
        with self.assertRaises(ValueError):
            _refuse_unsupported_constructs(graph)

    def test_a_dotted_precondition_is_refused(self):
        with self.assertRaises(ValueError):
            _refuse_unsupported_constructs(
                _graph(precondition={"style": "dotted"}))

    def test_a_dotted_event_is_refused(self):
        with self.assertRaises(ValueError):
            _refuse_unsupported_constructs(_graph(event={"style": "dotted"}))

    def test_the_message_names_the_way_out(self):
        with self.assertRaises(ValueError) as caught:
            _refuse_unsupported_constructs(_graph(event={"style": "dotted"}))
        self.assertIn("AGVS_PNG_RENDERER", str(caught.exception))



class TestFormatGuard(unittest.TestCase):
    """The AGVS-SP backend must not hand a caller a Graphviz drawing.

    Graphviz uses different shapes, different edge semantics and no badges. A
    PDF exported for the dissertation would look nothing like the PNG shown in
    the application, with nothing to warn the reader that they disagree.
    """

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = str(Path(self.tmp.name) / "graph")

    def test_pdf_is_refused_by_the_agvs_backend(self):
        from attack_graph import render
        with self.assertRaises(ValueError) as caught:
            render(_graph(), self.target + ".pdf", fmt="pdf")
        self.assertIn("svg", str(caught.exception))

    def test_png_and_svg_are_still_drawn(self):
        from attack_graph import render
        for fmt in ("png", "svg"):
            with self.subTest(fmt=fmt):
                written = render(_graph(), f"{self.target}.{fmt}", fmt=fmt)
                self.assertTrue(Path(written).exists())

    def test_the_message_says_where_graphviz_went(self):
        from attack_graph import render
        with self.assertRaises(ValueError) as caught:
            render(_graph(), self.target + ".pdf", fmt="pdf")
        self.assertIn("AGVS_PNG_RENDERER", str(caught.exception))

if __name__ == "__main__":
    unittest.main()
