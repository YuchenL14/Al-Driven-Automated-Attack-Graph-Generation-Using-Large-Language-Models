"""Regression tests for professional action-terminated objectives.

The normal attack-graph alternation is state -> action -> resulting state.
The supervisor's Stolen Pencil reference has one deliberate exception: its
final objective is an action rectangle.  These tests keep an omitted result
from silently reaching rendering while preserving that explicit exception.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from causal_split import attack_objective, terminal_actions  # noqa: E402
from extract import (_skeleton_graph_problems,  # noqa: E402
                     is_structural_stage_a_fault)
from schema import AttackGraph  # noqa: E402


def _skeleton(*, terminal_goal=False, second_result=False):
    preconditions = [
        {"id": "p0", "label": "Gateway exposed", "code": "RS",
         "parents": []},
        {"id": "p1", "label": "Gateway access obtained", "code": "IA",
         "parents": ["e1"]},
    ]
    if second_result:
        preconditions.append(
            {"id": "p2", "label": "Data exfiltrated", "code": "EF",
             "parents": ["e2"]})
    return {
        "title": "Terminal action test",
        "preconditions": preconditions,
        "events": [
            {"id": "e1", "label": "Enter exposed gateway", "tactic": "IA",
             "likelihood": 7, "parents": ["p0"], "join": "AND"},
            {"id": "e2", "label": "Exfiltrate data", "tactic": "EF",
             "likelihood": 8, "parents": ["p1"], "join": "AND",
             "terminal_goal": terminal_goal},
        ],
    }


class ProfessionalTerminalResultGateTests(unittest.TestCase):
    def test_unmarked_action_without_result_is_a_structural_fault(self):
        problems = _skeleton_graph_problems(
            _skeleton(), require_event_results=True)
        message = "; ".join(problems)
        self.assertIn("produce no resulting state: e2", message)
        self.assertTrue(is_structural_stage_a_fault(message))

    def test_one_explicit_action_goal_is_accepted(self):
        self.assertEqual([], _skeleton_graph_problems(
            _skeleton(terminal_goal=True), require_event_results=True))

    def test_goal_flag_cannot_hide_an_existing_result(self):
        message = "; ".join(_skeleton_graph_problems(
            _skeleton(terminal_goal=True, second_result=True),
            require_event_results=True))
        self.assertIn("terminal_goal is unnecessary", message)

    def test_legacy_gate_remains_unchanged_when_contract_is_off(self):
        self.assertEqual([], _skeleton_graph_problems(
            _skeleton(), require_event_results=False))


class ActionObjectiveTests(unittest.TestCase):
    def test_explicit_terminal_action_is_the_objective(self):
        graph = AttackGraph.model_validate(_skeleton(terminal_goal=True))
        self.assertEqual("e2", attack_objective(graph))
        self.assertEqual((), terminal_actions(graph))

    def test_unmarked_terminal_action_remains_a_diagnostic(self):
        graph = AttackGraph.model_validate(_skeleton())
        self.assertIsNone(attack_objective(graph))
        self.assertEqual(("Exfiltrate data",), terminal_actions(graph))


if __name__ == "__main__":
    unittest.main()
