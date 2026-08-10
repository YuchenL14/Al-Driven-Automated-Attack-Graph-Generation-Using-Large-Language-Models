"""The strict acceptance gate must be reachable from the runtime.

`validate_layout_quality` was written, tested, and then referenced by nothing
outside the tests: the runtime only ever called `quality_warnings`. A gate no
caller can reach is not a gate. Warning mode stays the default, because a
sparse report can legitimately produce a thin page.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import measure_page_quality, render_split
from layout_quality import (DEFAULT_QUALITY_MODE, QUALITY_MODE_ENV,
                            quality_mode)
from schema import AttackGraph


def _thin_graph() -> AttackGraph:
    """A long single chain: the shape that trips the acceptance limits."""
    preconditions, events = [], []
    for index in range(9):
        preconditions.append({"id": f"s{index}", "label": f"State {index}",
                              "code": "IA",
                              "parents": [f"e{index - 1}"] if index else []})
        events.append({"id": f"e{index}", "label": f"Step {index}",
                       "tactic": "IA", "technique": "T1190",
                       "mitigations": ["M1051"], "likelihood": 5.0,
                       "parents": [f"s{index}"], "join": "AND"})
    return AttackGraph.model_validate(
        {"title": "chain", "preconditions": preconditions, "events": events})


def _wide_graph() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "wide",
        "preconditions": [
            {"id": "s1", "label": "First input", "code": "IA", "parents": []},
            {"id": "s2", "label": "Second input", "code": "IA", "parents": []},
            {"id": "s3", "label": "Result", "code": "IA", "parents": ["e1"]}],
        "events": [{"id": "e1", "label": "Exploit", "tactic": "IA",
                    "technique": "T1190", "mitigations": ["M1051"],
                    "likelihood": 6.0, "parents": ["s1", "s2"],
                    "join": "AND"}]})


class TestModeSelection(unittest.TestCase):

    def test_the_default_is_warn(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(QUALITY_MODE_ENV, None)
            self.assertEqual(quality_mode(), DEFAULT_QUALITY_MODE)
            self.assertEqual(quality_mode(), "warn")

    def test_strict_is_selectable(self):
        with patch.dict(os.environ, {QUALITY_MODE_ENV: "strict"}):
            self.assertEqual(quality_mode(), "strict")

    def test_an_invalid_mode_is_refused_rather_than_ignored(self):
        with patch.dict(os.environ, {QUALITY_MODE_ENV: "off"}):
            with self.assertRaises(ValueError):
                quality_mode()


class TestRuntimeReachesTheGate(unittest.TestCase):

    def test_warn_mode_records_the_problem_and_still_returns(self):
        with patch.dict(os.environ, {QUALITY_MODE_ENV: "warn"}):
            report = measure_page_quality(_thin_graph())
        self.assertTrue(report["warnings"])

    def test_strict_mode_raises_on_the_same_page(self):
        with patch.dict(os.environ, {QUALITY_MODE_ENV: "strict"}):
            with self.assertRaises(ValueError):
                measure_page_quality(_thin_graph())

    def test_strict_mode_passes_an_acceptable_page(self):
        with patch.dict(os.environ, {QUALITY_MODE_ENV: "strict"}):
            report = measure_page_quality(_wide_graph())
        self.assertEqual(report["warnings"], [])

    def test_strict_mode_refuses_before_any_image_is_written(self):
        """The refusal must cost no output, or it is just a late crash.

        The warning is injected rather than provoked by geometry. Causal
        pagination already breaks up the page shapes that trip the real limits,
        so a graph that reaches the renderer *and* fails is hard to construct
        and would make this test about the splitter instead of the gate.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "graph.png"
            with patch.dict(os.environ, {QUALITY_MODE_ENV: "strict"}),                     patch("layout_quality.quality_warnings",
                          return_value=["injected acceptance failure"]):
                with self.assertRaises(ValueError):
                    render_split(_wide_graph(), str(target), dpi=80)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_pagination_already_prevents_the_tall_page(self):
        """Recorded because it explains why strict mode rarely fires.

        A nine-step chain fails the acceptance limits when measured whole, but
        `render_split` never hands the renderer the whole graph: it cuts the
        chain into parts that each pass.
        """
        with patch.dict(os.environ, {QUALITY_MODE_ENV: "strict"}):
            with self.assertRaises(ValueError):
                measure_page_quality(_thin_graph())
            with tempfile.TemporaryDirectory() as tmp:
                paths = render_split(_thin_graph(),
                                     str(Path(tmp) / "g.png"), dpi=80)
        self.assertGreater(len(paths), 1)

    def test_warn_mode_still_draws_that_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "graph.png"
            with patch.dict(os.environ, {QUALITY_MODE_ENV: "warn"}):
                paths = render_split(_thin_graph(), str(target), dpi=80)
            self.assertTrue(paths)
            self.assertTrue(all(Path(p).exists() for p in paths))


if __name__ == "__main__":
    unittest.main()
