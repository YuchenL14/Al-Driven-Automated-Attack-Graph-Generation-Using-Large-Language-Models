"""The ellipse vocabulary is closed, and an absent objective says so.

Two defects this file exists to prevent:

1. The state code used to come from the model, which invented a fresh set per
   report: PRE1, RESULT2, EXT-RES, VULN, NET, COND, SVCSTOP, ENC-EXEC, XFER.
   Lallie, Debattista and Bal (2020) name inconsistent notation as the defect
   in published attack graphs, and their 2018 conjoint study (n=212) found the
   precondition attribute carries the largest share of practitioner preference
   at 38.5%, so the least consistent notation sat on the construct readers
   weight most.

2. A graph whose outcomes tie names no objective, and a page that says nothing
   about it is indistinguishable from one where the objective was forgotten.
   The note must come from the whole graph: computed per page it appeared on
   page 1 of a run whose objective was named on page 4.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import render_split  # noqa: E402
from causal_split import attack_objective, terminal_outcomes  # noqa: E402
from schema import (ATTACK_TACTICS, AttackGraph,  # noqa: E402
                    KILL_CHAIN_PHASES)
from visual_syntax import STATE_BADGES, project_visual_nodes  # noqa: E402

ACTION_VOCABULARY = frozenset(ATTACK_TACTICS) | frozenset(KILL_CHAIN_PHASES)


def _graph(*, tied: bool) -> AttackGraph:
    """One chain, ending either in one outcome or in two independent ones."""

    preconditions = [
        {"id": "s0", "label": "Service reachable", "code": "WHATEVER",
         "parents": []},
        {"id": "s1", "label": "Access obtained", "code": "MADE-UP",
         "parents": ["e0"]},
        {"id": "s2", "label": "Files encrypted", "code": "ALSO-MADE-UP",
         "parents": ["e1"]},
    ]
    events = [
        {"id": "e0", "label": "Use stolen credentials", "tactic": "IA",
         "technique": "T1078", "mitigations": ["M1032"], "likelihood": 8.0,
         "parents": ["s0"], "join": "AND"},
        {"id": "e1", "label": "Encrypt systems", "tactic": "IM",
         "technique": "T1486", "mitigations": ["M1053"], "likelihood": 8.0,
         "parents": ["s1"], "join": "AND"},
    ]
    if tied:
        events.append(
            {"id": "e2", "label": "Delete the backups", "tactic": "IM",
             "technique": "T1490", "mitigations": ["M1053"], "likelihood": 7.0,
             "parents": ["s1"], "join": "AND"})
        preconditions.append(
            {"id": "s3", "label": "Backups unavailable", "code": "ANOTHER",
             "parents": ["e2"]})
    return AttackGraph.model_validate(
        {"title": "vocabulary", "preconditions": preconditions,
         "events": events})


class StateVocabularyTests(unittest.TestCase):
    def test_every_ellipse_badge_is_one_of_three_symbols(self):
        for node in project_visual_nodes(_graph(tied=True)):
            if node.kind != "state":
                continue
            with self.subTest(node=node.id):
                self.assertIn(node.badge_code, STATE_BADGES)

    def test_an_invented_code_never_reaches_the_drawing(self):
        graph = _graph(tied=False)
        drawn = {node.badge_code for node in project_visual_nodes(graph)
                 if node.kind == "state"}
        stored = {node.code for node in graph.preconditions}
        self.assertEqual({"PRE", "RES"}, drawn)
        # The stored codes survive in the graph for audit, and none is drawn.
        self.assertTrue(stored.isdisjoint(drawn))
        self.assertIn("MADE-UP", stored)

    def test_a_state_never_borrows_an_action_symbol(self):
        for node in project_visual_nodes(_graph(tied=True)):
            if node.kind != "state" or node.badge_code is None:
                continue
            with self.subTest(node=node.id):
                self.assertNotIn(node.badge_code, ACTION_VOCABULARY)

    def test_an_annotation_badges_nothing(self):
        graph = AttackGraph.model_validate({
            "title": "note", "preconditions": [
                {"id": "s0", "label": "Service reachable", "code": "X",
                 "parents": []},
                {"id": "n0", "label": "AV blocked part of it", "code": "NOTE",
                 "role": "annotation", "style": "dashed", "parents": ["e0"]}],
            "events": [
                {"id": "e0", "label": "Use stolen credentials", "tactic": "IA",
                 "technique": "T1078", "mitigations": ["M1032"],
                 "likelihood": 8.0, "parents": ["s0"], "join": "AND"}]})
        note = next(node for node in project_visual_nodes(graph)
                    if node.id == "n0")
        # The dashed outline already says what it is; a badge would be the
        # symbol overload the profile exists to prevent.
        self.assertIsNone(note.badge_code)


class AbsentObjectiveTests(unittest.TestCase):
    def test_a_tie_is_stated_rather_than_left_silent(self):
        graph = _graph(tied=True)
        self.assertIsNone(attack_objective(graph))
        self.assertEqual(2, len(terminal_outcomes(graph)))

        with self._rendered(graph) as pages:
            last = Path(pages[-1]).read_text(encoding="utf-8")
            self.assertIn("No single objective", last)

    def test_a_graph_with_one_ending_says_nothing_about_a_tie(self):
        graph = _graph(tied=False)
        self.assertIsNotNone(attack_objective(graph))
        with self._rendered(graph) as pages:
            for path in pages:
                self.assertNotIn(
                    "No single objective",
                    Path(path).read_text(encoding="utf-8"))

    def test_terminal_outcomes_ignores_roots_and_annotations(self):
        graph = _graph(tied=False)
        # "Service reachable" is where the attack began, not where it ended.
        self.assertNotIn("Service reachable", terminal_outcomes(graph))
        self.assertEqual(("Files encrypted",), terminal_outcomes(graph))

    def _rendered(self, graph: AttackGraph):
        import contextlib
        import tempfile

        @contextlib.contextmanager
        def run():
            with tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / "page.svg"
                yield render_split(graph, str(out), fmt="svg")

        return run()


if __name__ == "__main__":
    unittest.main()
