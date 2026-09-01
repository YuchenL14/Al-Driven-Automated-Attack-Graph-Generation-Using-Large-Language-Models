"""A graph with a fringe is not a failed extraction.

A real v1.6 run returned forty-eight nodes, forty-six of which formed one
connected graph. The other two were an event and the state it produced, which
nothing consumed. The correction was spent, the model returned the same fringe,
and the whole answer was discarded -- two paid calls and forty-six good nodes,
for two strays.

A detached node contributes nothing to the causal structure; that is what
detached means. Dropping it costs the graph nothing it was using. Discarding
the answer costs everything. The salvage runs only after the correction has
been spent, and only when the surviving component is nearly the whole graph:
below that the model produced fragments, not a graph with a fringe, and there
is no honest repair.
"""

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (AttackGraph, _SALVAGE_MIN_SHARE, _extract_hierarchical,
                     get_last_salvaged_nodes, salvage_largest_component)


def _chain(n: int, prefix: str = "c") -> tuple[list, list]:
    preconditions = [
        {"id": f"{prefix}p{i}", "label": f"State {i}", "code": "IA",
         "style": "solid", "parents": [f"{prefix}e{i - 1}"] if i else []}
        for i in range(n)]
    events = [
        {"id": f"{prefix}e{i}", "label": f"Step {i}", "tactic": "IA",
         "likelihood": 5.0, "style": "solid", "parents": [f"{prefix}p{i}"],
         "join": "AND", "terminal_goal": i == n - 1}
        for i in range(n)]
    return preconditions, events


class TestWhatIsSalvaged(unittest.TestCase):

    def test_a_dominant_component_survives_its_fringe(self):
        preconditions, events = _chain(23)
        data = {
            "preconditions": preconditions + [
                {"id": "x1", "label": "Detached result", "code": "RS",
                 "style": "solid", "parents": ["x2"]}],
            "events": events + [
                {"id": "x2", "label": "Detached step", "tactic": "RS",
                 "likelihood": 5.0, "style": "solid", "parents": [],
                 "join": "AND"}]}
        pruned, dropped = salvage_largest_component(data)
        self.assertEqual(("x1", "x2"), dropped)
        self.assertEqual(46, len(pruned["preconditions"]) + len(pruned["events"]))

    def test_two_equal_components_are_refused(self):
        """Neither is "the graph"; choosing one would be arbitrary."""
        first, first_events = _chain(6, "a")
        second, second_events = _chain(6, "b")
        _, dropped = salvage_largest_component(
            {"preconditions": first + second,
             "events": first_events + second_events})
        self.assertEqual((), dropped)

    def test_a_field_of_fragments_is_refused(self):
        preconditions, events = [], []
        for i in range(10):
            preconditions += [
                {"id": f"i{i}", "label": "Start", "code": "RS", "parents": []},
                {"id": f"o{i}", "label": "Result", "code": "RS",
                 "parents": [f"z{i}"]}]
            events.append({"id": f"z{i}", "label": "Step", "tactic": "RS",
                           "likelihood": 5.0, "parents": [f"i{i}"]})
        _, dropped = salvage_largest_component(
            {"preconditions": preconditions, "events": events})
        self.assertEqual((), dropped)

    def test_a_connected_graph_is_left_alone(self):
        preconditions, events = _chain(10)
        data = {"preconditions": preconditions, "events": events}
        pruned, dropped = salvage_largest_component(data)
        self.assertEqual((), dropped)
        self.assertEqual(data, pruned)

    def test_the_threshold_is_a_real_majority(self):
        self.assertGreaterEqual(_SALVAGE_MIN_SHARE, 0.8)
        self.assertLess(_SALVAGE_MIN_SHARE, 1.0)

    def test_dangling_parent_references_are_cleaned_up(self):
        """A kept node must not point at something that was dropped."""
        preconditions, events = _chain(23)
        preconditions.append({"id": "x1", "label": "Detached", "code": "RS",
                              "style": "solid", "parents": ["x2"]})
        events.append({"id": "x2", "label": "Detached step", "tactic": "RS",
                       "likelihood": 5.0, "style": "solid", "parents": [],
                       "join": "AND"})
        pruned, _ = salvage_largest_component(
            {"preconditions": preconditions, "events": events})
        surviving = {item["id"] for item in
                     pruned["preconditions"] + pruned["events"]}
        for item in pruned["preconditions"] + pruned["events"]:
            for parent in item["parents"]:
                self.assertIn(parent, surviving)


class TestItRunsOnlyAsALastResort(unittest.TestCase):

    @staticmethod
    def _answer() -> dict:
        preconditions, events = _chain(23)
        preconditions.append({"id": "p3f", "label": "Detached result",
                              "code": "RS", "style": "solid",
                              "parents": ["e1x"]})
        events.append({"id": "e1x", "label": "Detached step", "tactic": "RS",
                       "likelihood": 5.0, "style": "solid", "parents": [],
                       "join": "AND"})
        return {"title": "fringe", "preconditions": preconditions,
                "events": events}

    def _run(self, ruleset: str):
        stage_a = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                tail = user.split("required ids are:")[-1]
                ids = sorted(set(re.findall(r"\b(ce\d+|e1x)\b", tail)))
                return json.dumps({"assignments": [
                    {"id": i, "techniques": ["T1190"]} for i in ids]})
            stage_a.append(user)
            return json.dumps(self._answer())

        return _extract_hierarchical("report", call, "model", ruleset), stage_a

    def test_the_correction_is_spent_before_anything_is_dropped(self):
        graph, stage_a = self._run("v1.6")
        self.assertEqual(3, len(stage_a),
                         "the model must get its chance to reconnect the node")
        self.assertEqual(("e1x", "p3f"), get_last_salvaged_nodes())
        self.assertNotIn("e1x", [event.id for event in graph.events])

    def test_the_graph_that_survives_is_the_connected_one(self):
        graph, _ = self._run("v1.6")
        self.assertEqual(23, len(graph.events))

    def test_what_was_dropped_is_reported(self):
        self._run("v1.6")
        self.assertTrue(get_last_salvaged_nodes(),
                        "a silent deletion would falsify the graph")


if __name__ == "__main__":
    unittest.main()
