"""A Stage A retry must repair the previous answer, not roll the dice again.

Every API call is stateless. The retry prompt sent the correction, the full
rule template and the whole report -- but never the JSON the model had just
returned. So corrections phrased as "keep every event and every state, change
only the parents lists" asked for something the model had no way to do: it
could not see the events it was being told to keep, and regenerated from the
report instead.

Three consecutive v1.6 runs failed the same way for this reason. The fault was
not the diagnosis, which by then named the right shape and the right ids; it
was that the instruction could not be followed.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import _extract_hierarchical, AttackGraph


def _fan(n: int = 5) -> dict:
    """Every event starts from nothing: the shape that kept coming back."""
    graph = {"title": "fan", "preconditions": [], "events": []}
    for i in range(1, n + 1):
        graph["preconditions"].append(
            {"id": f"p{i}", "label": f"Result {i}", "code": "RS",
             "style": "solid", "parents": [f"e{i}"]})
        graph["events"].append(
            {"id": f"e{i}", "label": f"Step {i}", "tactic": "RS",
             "likelihood": 5.0, "style": "solid", "parents": [],
             "join": "AND"})
    return graph


def _chained(n: int = 5) -> dict:
    graph = _fan(n)
    for i in range(2, n + 1):
        graph["events"][i - 1]["parents"] = [f"p{i - 1}"]
    return graph


class _Recorder:
    """Fails Stage A once with a fan, then returns the repaired graph."""

    def __init__(self, n: int = 5):
        self.prompts: list[str] = []
        self.n = n

    def __call__(self, system, user, model, response_model=AttackGraph):
        if "Assignment" in response_model.__name__:
            return json.dumps({"assignments": [
                {"id": f"e{i}", "techniques": ["T1587.001"]}
                for i in range(1, self.n + 1)]})
        self.prompts.append(user)
        return json.dumps(_fan(self.n) if len(self.prompts) == 1
                          else _chained(self.n))


class TestTheRetryCarriesThePreviousAnswer(unittest.TestCase):

    def setUp(self):
        self.calls = _Recorder()
        self.graph = _extract_hierarchical(
            "report text", self.calls, "model", "v1.6")
        self.retry = self.calls.prompts[1]

    def test_the_first_attempt_is_not_given_a_previous_answer(self):
        self.assertNotIn("you returned last time", self.calls.prompts[0])

    def test_the_retry_includes_the_json_the_model_returned(self):
        for node_id in ("e1", "e5", "p1", "p5"):
            with self.subTest(node_id=node_id):
                self.assertIn(f'"{node_id}"', self.retry)

    def test_the_retry_asks_for_an_edit_not_a_regeneration(self):
        self.assertIn("Edit that JSON", self.retry)
        self.assertIn("Do not start again from the report", self.retry)

    def test_the_retry_still_carries_the_diagnosis(self):
        self.assertIn("disconnected pieces", self.retry)

    def test_the_report_is_demoted_to_reference(self):
        """It stays available, but it is no longer the primary instruction."""
        self.assertIn("reference only", self.retry)
        self.assertLess(self.retry.index("Edit that JSON"),
                        self.retry.index("reference only"))

    def test_the_repair_is_accepted(self):
        self.assertEqual(5, len(self.graph.events))
        chained = [e for e in self.graph.events if e.parents]
        self.assertEqual(4, len(chained))

    def test_only_one_retry_is_spent(self):
        self.assertEqual(2, len(self.calls.prompts))


class TestGuardAgainstSilentRegression(unittest.TestCase):

    def test_the_answer_is_captured_on_every_attempt(self):
        """If the capture is dropped, the retry silently becomes a re-roll
        again and every test above still passes on the happy path."""
        source = (ROOT / "src" / "extract.py").read_text(encoding="utf-8")
        self.assertIn("last_answer = raw", source)
        self.assertIn("if last_answer:", source)



class TestStageBDoesNotRetryWhatItCannotFix(unittest.TestCase):
    """Stage B returns {id, techniques}. It cannot change the graph's shape.

    `_structure_problems` reports only skeleton properties: too few
    preconditions, no AND/OR gate, events that establish nothing. Raising them
    at Stage B bought a second paid call that could not change the answer, and
    then accepted the graph anyway. The finding is worth keeping; the retry was
    not.
    """

    @staticmethod
    def _chain(n: int = 3) -> dict:
        graph = {"title": "chain", "preconditions": [], "events": []}
        for i in range(1, n + 1):
            graph["preconditions"].append(
                {"id": f"p{i}", "label": f"State {i}", "code": "RS",
                 "style": "solid", "parents": [f"e{i}"]})
            graph["events"].append(
                {"id": f"e{i}", "label": f"Step {i}", "tactic": "RS",
                 "likelihood": 5.0, "style": "solid",
                 "parents": [] if i == 1 else [f"p{i - 1}"], "join": "AND"})
        return graph

    def setUp(self):
        self.calls: list[str] = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                self.calls.append("B")
                return json.dumps({"assignments": [
                    {"id": f"e{i}", "techniques": ["T1587.001"]}
                    for i in range(1, 4)]})
            self.calls.append("A")
            return json.dumps(self._chain())

        self.graph = _extract_hierarchical("report", call, "model", "v1.6")

    def test_stage_b_is_called_once(self):
        self.assertEqual(1, self.calls.count("B"),
                         "a second Stage B call was paid for and could not "
                         "have changed the shape it was asked to fix")

    def test_the_graph_is_still_returned(self):
        self.assertEqual(3, len(self.graph.events))

    def test_the_shape_finding_is_not_discarded(self):
        from extract import get_last_shape_notes
        notes = get_last_shape_notes()
        self.assertTrue(notes)
        self.assertIn("AND/OR", notes[0])


class TestStageBRepairsOnlyTheFailedEvent(unittest.TestCase):
    """One malformed T-number must not invalidate or regenerate neighbours."""

    def setUp(self):
        self.prompts: list[str] = []
        skeleton = TestStageBDoesNotRetryWhatItCannotFix._chain(2)

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" not in response_model.__name__:
                return json.dumps(skeleton)
            self.prompts.append(user)
            if len(self.prompts) == 1:
                return json.dumps({"assignments": [
                    {"id": "e1", "techniques": ["T1587.001"]},
                    {"id": "e2", "techniques": ["T9999"]},
                ]})
            return json.dumps({"assignments": [
                {"id": "e2", "techniques": ["T1587.001"]},
            ]})

        self.graph = _extract_hierarchical(
            "report", call, "model", "v1.6")

    def test_only_the_failed_event_is_requested_again(self):
        self.assertEqual(2, len(self.prompts))
        self.assertIn("EVENT-LOCAL STAGE B REPAIR", self.prompts[1])
        self.assertIn("Frozen accepted event ids: e1", self.prompts[1])
        self.assertIn('"id": "e2"', self.prompts[1])
        self.assertNotIn('"id": "e1"', self.prompts[1])

    def test_valid_neighbour_survives_the_local_repair(self):
        self.assertEqual(["e1", "e2"],
                         [event.id for event in self.graph.events])
        self.assertEqual(["T1587.001"], self.graph.events[0].techniques)
        self.assertEqual(["T1587.001"], self.graph.events[1].techniques)


class TestStageBRepairsOnlyTheFailedV14Mitigation(unittest.TestCase):
    """A bad mitigation is repaired without resending a valid neighbour."""

    def setUp(self):
        self.prompts: list[str] = []
        skeleton = TestStageBDoesNotRetryWhatItCannotFix._chain(2)

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" not in response_model.__name__:
                return json.dumps(skeleton)
            self.prompts.append(user)
            if len(self.prompts) == 1:
                return json.dumps({"assignments": [
                    {"id": "e1", "technique": "T1587.001",
                     "mitigations": ["M1013"]},
                    {"id": "e2", "technique": "T1587.001",
                     "mitigations": ["M9999"]},
                ]})
            return json.dumps({"assignments": [
                {"id": "e2", "technique": "T1587.001",
                 "mitigations": ["M1013"]},
            ]})

        self.graph = _extract_hierarchical(
            "report", call, "model", "v1.4")

    def test_only_the_bad_mitigation_record_is_requested_again(self):
        self.assertEqual(2, len(self.prompts))
        self.assertIn("Frozen accepted event ids: e1", self.prompts[1])
        self.assertIn('"id": "e2"', self.prompts[1])
        self.assertNotIn('"id": "e1"', self.prompts[1])

    def test_both_assignments_survive_the_local_repair(self):
        self.assertEqual(["e1", "e2"],
                         [event.id for event in self.graph.events])
        self.assertTrue(self.graph.events[0].mitigations)
        self.assertTrue(self.graph.events[1].mitigations)
        self.assertNotIn(
            "M9999",
            [mitigation for event in self.graph.events
             for mitigation in event.mitigations],
        )

if __name__ == "__main__":
    unittest.main()
