"""The shape review could see a graph that was too long, never one that leaked.

`measure_skeleton_shape` already computed `widest`, but only
`critical_path_share` opened a gate. A model could therefore satisfy the review
by splitting one long chain into many parallel branches that go nowhere -- and
one real run did exactly that: 24 events, 42% critical path (comfortably under
the threshold), and nine states established by an event and then consumed by
nothing. Six of those nine were recovered credentials, while the report states
plainly that the adversary's goal was "gaining access to compromised accounts
and systems via stolen credentials". The graph produced the credentials and
never used them.

Calibration. The supervisor's reference graph has zero unconsumed states. This
schema ends on a state rather than an action, so the final objective is always
one, and a report may record two or three genuine endings -- the WannaCry blind
run has exactly three (business impact, ransom C2, recovery denied) and all are
correct. The threshold sits above the largest correct reading and below the
incorrect one.

Width is deliberately not gated. A wide rank is what the counterfactual test is
supposed to produce when several steps needed nothing but a shared earlier
state; asking for a narrower one would contradict the test in the same prompt
and re-create the chain this review exists to catch. Width is a page-size
problem, solved by pagination.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (_MAX_CRITICAL_PATH_SHARE, _MAX_UNUSED_STATES,
                     _MIN_EVENTS_FOR_SHAPE_REVIEW, measure_skeleton_shape,
                     shape_revision_request)


def _graph(unused: int, events: int = 12) -> dict:
    """A chain ending in one loose end, plus `unused - 1` abandoned leaves."""

    assert 1 <= unused <= events
    chain = events - (unused - 1)
    evs, pres = [], [{"id": "p_root", "label": "Foothold", "parents": []}]
    for i in range(chain):
        evs.append({"id": f"e{i}", "label": f"Step {i}",
                    "parents": ["p_root" if i == 0 else f"p{i - 1}"]})
        pres.append({"id": f"p{i}", "label": f"State {i}",
                     "parents": [f"e{i}"]})
    for i in range(unused - 1):
        evs.append({"id": f"leaf{i}", "label": f"Side action {i}",
                    "parents": ["p_root"]})
        pres.append({"id": f"loose{i}", "label": f"Abandoned result {i}",
                     "parents": [f"leaf{i}"]})
    return {"events": evs, "preconditions": pres}


class UnusedStateMeasurementTests(unittest.TestCase):
    def test_an_unconsumed_result_is_counted(self):
        shape = measure_skeleton_shape({
            "events": [{"id": "e0", "label": "Act", "parents": ["p_in"]}],
            "preconditions": [
                {"id": "p_in", "label": "Start", "parents": []},
                {"id": "p_out", "label": "Result", "parents": ["e0"]},
            ],
        })
        self.assertEqual(shape["unused_states"], 1)
        self.assertEqual(shape["unused_state_ids"], ("p_out",))

    def test_an_initial_condition_is_not_counted(self):
        # p_in has no producing event, so it is an input, not an abandoned
        # branch.
        shape = measure_skeleton_shape({
            "events": [{"id": "e0", "label": "Act", "parents": ["p_in"]}],
            "preconditions": [{"id": "p_in", "label": "Start", "parents": []}],
        })
        self.assertEqual(shape["unused_states"], 0)

    def test_a_consumed_result_is_not_counted(self):
        shape = measure_skeleton_shape({
            "events": [{"id": "e0", "label": "A", "parents": ["p_in"]},
                       {"id": "e1", "label": "B", "parents": ["p_mid"]}],
            "preconditions": [
                {"id": "p_in", "label": "Start", "parents": []},
                {"id": "p_mid", "label": "Middle", "parents": ["e0"]},
                {"id": "p_end", "label": "End", "parents": ["e1"]},
            ],
        })
        self.assertEqual(shape["unused_state_ids"], ("p_end",))

    def test_annotations_are_excluded(self):
        shape = measure_skeleton_shape({
            "events": [{"id": "e0", "label": "Act", "parents": ["p_in"]}],
            "preconditions": [
                {"id": "p_in", "label": "Start", "parents": []},
                {"id": "a0", "label": "Detected on day 4", "parents": ["e0"],
                 "role": "annotation"},
            ],
        })
        self.assertEqual(shape["unused_states"], 0)

    def test_a_broken_graph_still_reports_the_key(self):
        # A cyclic graph short-circuits; the key must exist for the gate.
        shape = measure_skeleton_shape({
            "events": [{"id": "e0", "label": "A", "parents": ["p0"]}],
            "preconditions": [{"id": "p0", "label": "S", "parents": ["e0"]}],
        })
        self.assertEqual(shape["unused_states"], 0)
        self.assertEqual(shape["unused_state_ids"], ())


class UnusedStateGateTests(unittest.TestCase):
    def test_the_gate_stays_shut_at_the_threshold(self):
        shape = measure_skeleton_shape(_graph(_MAX_UNUSED_STATES))
        self.assertEqual(shape["unused_states"], _MAX_UNUSED_STATES)
        self.assertNotIn("consumed by nothing", shape_revision_request(shape))

    def test_the_gate_opens_above_the_threshold(self):
        shape = measure_skeleton_shape(_graph(_MAX_UNUSED_STATES + 3))
        self.assertIn("consumed by nothing", shape_revision_request(shape))

    def test_a_small_graph_is_never_reviewed(self):
        events = _MIN_EVENTS_FOR_SHAPE_REVIEW - 1
        shape = measure_skeleton_shape(_graph(events, events=events))
        self.assertGreater(shape["unused_states"], _MAX_UNUSED_STATES)
        self.assertEqual(shape_revision_request(shape), "")

    def test_the_request_permits_leaving_an_ending_alone(self):
        # Without this, a correct graph with several genuine outcomes would be
        # pushed into inventing consumers for them.
        request = shape_revision_request(
            measure_skeleton_shape(_graph(_MAX_UNUSED_STATES + 3)))
        self.assertIn("leave it as it is", request)
        self.assertIn("an attack has endings", request)

    def test_the_request_asks_the_report_rather_than_naming_a_shape(self):
        request = shape_revision_request(
            measure_skeleton_shape(_graph(_MAX_UNUSED_STATES + 3)))
        self.assertIn("ask the report", request)
        for shape_word in ("narrower", "wider", "fewer branches", "converge"):
            self.assertNotIn(shape_word, request)

    def test_both_observations_can_arrive_together(self):
        chain = {"events": [], "preconditions": [
            {"id": "p_root", "label": "Start", "parents": []}]}
        for i in range(12):
            chain["events"].append({
                "id": f"e{i}", "label": f"Step {i}",
                "parents": ["p_root" if i == 0 else f"p{i - 1}"]})
            chain["preconditions"].append(
                {"id": f"p{i}", "label": f"State {i}", "parents": [f"e{i}"]})
        # A pure chain: high critical-path share, but only one loose end.
        shape = measure_skeleton_shape(chain)
        self.assertGreater(shape["critical_path_share"],
                           _MAX_CRITICAL_PATH_SHARE)
        request = shape_revision_request(shape)
        self.assertIn("single dependency path", request)
        self.assertNotIn("consumed by nothing", request)
        # The closing instruction is emitted once, not once per observation.
        self.assertEqual(request.count("Change only parents lists"), 1)

    def test_width_is_measured_but_never_gated(self):
        wide = {"events": [], "preconditions": [
            {"id": "p_root", "label": "Start", "parents": []}]}
        for i in range(12):
            wide["events"].append({"id": f"e{i}", "label": f"Step {i}",
                                   "parents": ["p_root"]})
            wide["preconditions"].append(
                {"id": f"p{i}", "label": f"State {i}", "parents": [f"e{i}"]})
        shape = measure_skeleton_shape(wide)
        self.assertGreaterEqual(shape["widest"], 12)
        # Width alone must not produce a request; the loose ends here do.
        self.assertNotIn("wide", shape_revision_request(shape).lower())


class RealRunTests(unittest.TestCase):
    """The runs the threshold was calibrated against."""

    def _shape(self, name: str):
        path = ROOT / "outputs" / f"{name}.json"
        if not path.exists():
            self.skipTest(f"{name} not present")
        return measure_skeleton_shape(
            json.loads(path.read_text(encoding="utf-8")))

    def test_the_run_that_leaked_credentials_is_caught(self):
        shape = self._shape(
            "netscout-stolen-pencil__rules-v1.6__anthropic-claude-sonnet-5_6")
        self.assertGreater(shape["unused_states"], _MAX_UNUSED_STATES)
        self.assertIn("consumed by nothing", shape_revision_request(shape))

    def test_the_healthy_run_is_not_disturbed(self):
        shape = self._shape(
            "netscout-stolen-pencil__rules-v1.6__anthropic-claude-sonnet-5_5")
        self.assertEqual(shape_revision_request(shape), "")

    def test_the_blind_run_keeps_its_genuine_endings(self):
        shape = self._shape(
            "Case-Study_WannaCry__rules-v1.6__anthropic-claude-sonnet-5_1")
        self.assertLessEqual(shape["unused_states"], _MAX_UNUSED_STATES)
        self.assertNotIn("consumed by nothing", shape_revision_request(shape))


if __name__ == "__main__":
    unittest.main()
