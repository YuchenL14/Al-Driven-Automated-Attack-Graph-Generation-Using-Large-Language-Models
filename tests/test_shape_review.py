"""Validity is not plausibility, and only validity was ever checked.

A skeleton can satisfy every structural rule -- acyclic, connected, every id
resolved -- and still be an implausible reading. A real v1.6 run put all 23 of
its events on one dependency path, asserting that each step required the last,
including four credential dumps that need nothing from one another. Nothing in
the pipeline could see that, because nothing measured it.

This is the one thing a human reviewer did that the pipeline did not: measure
the output and feed the measurement back. The instruction that goes back is the
same dependency test the rules give, not a target shape -- describing a shape is
what produced both the fan and the chain.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (AttackGraph, _MAX_CRITICAL_PATH_SHARE,
                     _MIN_EVENTS_FOR_SHAPE_REVIEW, _extract_hierarchical,
                     _graph_response_tokens, _SMALL_RESPONSE_TOKENS,
                     _configured_max_cost_usd, _MAX_GENERATION_CALLS,
                     _SHAPE_REVIEW_CALLS,
                     get_last_shape_measure,
                     get_last_shape_notes, measure_skeleton_shape,
                     shape_revision_request)


def _chain(n: int) -> dict:
    """Every event requires the one before it."""
    graph = {"title": "chain", "preconditions": [], "events": []}
    for i in range(n):
        graph["preconditions"].append(
            {"id": f"p{i}", "label": f"State {i}", "code": "IA",
             "style": "solid", "parents": [f"e{i - 1}"] if i else []})
        graph["events"].append(
            {"id": f"e{i}", "label": f"Step {i}", "tactic": "IA",
             "likelihood": 5.0, "style": "solid", "parents": [f"p{i}"],
             "join": "AND", "terminal_goal": i == n - 1})
    return graph


def _relinked(n: int) -> dict:
    """What a real revision looks like: `_chain(n)`'s nodes, re-parented.

    The request permits one edit, a parents list, so a revision that renames
    or replaces nodes is not a revision. `_funnel` below is a different graph
    with different ids and labels; it is useful for measuring shape but cannot
    stand in for an answer to the shape review.
    """
    graph = _chain(n)
    by_id = {node["id"]: node for node in
             graph["preconditions"] + graph["events"]}
    by_id["p0"]["parents"] = []
    by_id["e0"]["parents"] = ["p0"]
    by_id["p1"]["parents"] = ["e0"]
    for i in range(1, n - 1):
        by_id[f"e{i}"]["parents"] = ["p1"]
        by_id[f"p{i + 1}"]["parents"] = [f"e{i}"]
    by_id[f"e{n - 1}"]["parents"] = [f"p{i}" for i in range(2, n)]
    return graph


def _funnel(n: int) -> dict:
    """A realistic improvement: a short stem, then independent work that
    shares one state, then a step that consumes what they produced.

    Not a flat fan. A fan -- every event on the same initial condition, with
    nothing consuming any result -- is itself rejected by the structural gate,
    so it is not what "less chained" should mean.
    """
    graph = {"title": "funnel", "preconditions": [], "events": []}
    graph["preconditions"].append(
        {"id": "p_start", "label": "Access obtained", "code": "IA",
         "style": "solid", "parents": []})
    graph["events"].append(
        {"id": "e0", "label": "Establish foothold", "tactic": "IA",
         "likelihood": 5.0, "style": "solid", "parents": ["p_start"],
         "join": "AND"})
    graph["preconditions"].append(
        {"id": "p_hold", "label": "Foothold on host", "code": "IA",
         "style": "solid", "parents": ["e0"]})
    for i in range(1, n - 1):
        graph["events"].append(
            {"id": f"e{i}", "label": f"Harvest {i}", "tactic": "CA",
             "likelihood": 5.0, "style": "solid", "parents": ["p_hold"],
             "join": "AND"})
        graph["preconditions"].append(
            {"id": f"r{i}", "label": f"Credential set {i}", "code": "CA",
             "style": "solid", "parents": [f"e{i}"]})
    graph["events"].append(
        {"id": f"e{n - 1}", "label": "Aggregate and move on", "tactic": "LM",
         "likelihood": 5.0, "style": "solid",
         "parents": [f"r{i}" for i in range(1, n - 1)], "join": "AND"})
    graph["preconditions"].append(
        {"id": "p_end", "label": "Lateral access gained", "code": "LM",
         "style": "solid", "parents": [f"e{n - 1}"]})
    return graph


class TestTheMeasurement(unittest.TestCase):

    def test_a_chain_is_all_critical_path(self):
        shape = measure_skeleton_shape(_chain(12))
        self.assertEqual(1.0, shape["critical_path_share"])

    def test_independent_work_is_not(self):
        shape = measure_skeleton_shape(_funnel(12))
        self.assertLess(shape["critical_path_share"],
                        _MAX_CRITICAL_PATH_SHARE)

    def test_it_separates_the_real_runs(self):
        """The three graphs this project has actually produced.

        This asserts the critical-path observation specifically rather than
        "a request was produced". A second gate was added later for states
        that nothing consumes, and run 1 trips it -- correctly, since two of
        its five loose ends are capabilities rather than endings. Testing the
        whole request would silently turn this into a test of both gates.
        """
        outputs = ROOT / "outputs"
        expected = {
            "netscout-stolen-pencil__rules-v1.6__anthropic-claude-sonnet-5_2":
                True,
            "netscout-stolen-pencil__rules-v1.6__anthropic-claude-sonnet-5_1":
                False,
        }
        for stem, should_fire in expected.items():
            path = outputs / f"{stem}.json"
            if not path.is_file():
                self.skipTest(f"{stem} not present")
            shape = measure_skeleton_shape(
                json.loads(path.read_text(encoding="utf-8")))
            fired = "single dependency path" in shape_revision_request(shape)
            self.assertEqual(
                should_fire, fired,
                f"{stem}: share was {shape['critical_path_share']:.0%}")

    def test_annotations_do_not_count_toward_the_shape(self):
        graph = _funnel(12)
        graph["preconditions"].append(
            {"id": "a1", "label": "Training", "code": "-",
             "role": "annotation", "style": "dashed", "parents": ["e0"]})
        self.assertLess(measure_skeleton_shape(graph)["critical_path_share"],
                        _MAX_CRITICAL_PATH_SHARE)


class TestWhenItAsks(unittest.TestCase):

    def test_a_short_sequential_attack_is_left_alone(self):
        """Four genuinely sequential steps are 100% and entirely correct."""
        shape = measure_skeleton_shape(_chain(4))
        self.assertEqual(1.0, shape["critical_path_share"])
        self.assertEqual("", shape_revision_request(shape))

    def test_the_threshold_is_below_a_full_chain_and_above_a_fan(self):
        self.assertGreater(_MAX_CRITICAL_PATH_SHARE, 0.5)
        self.assertLess(_MAX_CRITICAL_PATH_SHARE, 1.0)
        self.assertGreaterEqual(_MIN_EVENTS_FOR_SHAPE_REVIEW, 5)

    def test_the_request_asks_about_the_report_not_the_shape(self):
        request = shape_revision_request(measure_skeleton_shape(_chain(12)))
        self.assertIn("could the later one still have occurred", request)
        self.assertIn("Change only parents lists", request)
        for shape_target in ("wider", "more parallel", "hourglass", "tree",
                             "should have", "aim for"):
            self.assertNotIn(shape_target, request.lower())

    def test_the_request_names_the_measurement_as_evidence(self):
        request = shape_revision_request(measure_skeleton_shape(_chain(12)))
        self.assertIn("12 events, 12 lie on", request)


class TestItNeverCostsTheGraph(unittest.TestCase):

    def _run(self, first: dict, second: dict):
        calls = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                ids = [e["id"] for e in first["events"]]
                return json.dumps({"assignments": [
                    {"id": i, "techniques": ["T1190"]} for i in ids]})
            calls.append(user)
            return json.dumps(first if len(calls) == 1 else second)

        return _extract_hierarchical("report", call, "model", "v1.6"), calls

    def test_a_better_revision_is_adopted(self):
        graph, calls = self._run(_chain(12), _relinked(12))
        self.assertEqual(2, len(calls))
        self.assertLess(get_last_shape_measure()["critical_path_share"],
                        _MAX_CRITICAL_PATH_SHARE)

    def test_a_revision_that_invents_a_node_is_rejected(self):
        """The one edit permitted is a parents list.

        A real run answered "connect these five abandoned states" by adding a
        sixth state to consume them -- with no parents of its own. The five
        stayed abandoned, the new node floated, and only events were being
        checked, so it was accepted.
        """
        invented = _relinked(12)
        invented["preconditions"].append(
            {"id": "p_new", "label": "Everything gathered", "code": "CA",
             "style": "solid", "parents": []})
        graph, calls = self._run(_chain(12), invented)
        self.assertEqual(2, len(calls))
        self.assertEqual(1.0, get_last_shape_measure()["critical_path_share"],
                         "the original chain must have been kept")
        self.assertNotIn("p_new", {p.id for p in graph.preconditions})
        self.assertTrue(any("different set of nodes" in note
                            for note in get_last_shape_notes()))

    def test_a_revision_that_renames_a_node_is_rejected(self):
        renamed = _relinked(12)
        renamed["preconditions"][3]["label"] = "Something else entirely"
        graph, _ = self._run(_chain(12), renamed)
        self.assertEqual(1.0, get_last_shape_measure()["critical_path_share"])

    def test_a_revision_that_drops_events_is_rejected(self):
        """Widening by deleting steps is not an improvement."""
        graph, _ = self._run(_chain(12), _chain(4))
        self.assertEqual(12, len(graph.events))

    def test_a_revision_that_is_no_better_is_rejected(self):
        graph, _ = self._run(_chain(12), _chain(12))
        self.assertEqual(12, len(graph.events))
        self.assertEqual(1.0, get_last_shape_measure()["critical_path_share"])

    def test_a_broken_revision_leaves_the_valid_graph_standing(self):
        calls = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                return json.dumps({"assignments": [
                    {"id": e["id"], "techniques": ["T1190"]}
                    for e in _chain(12)["events"]]})
            calls.append(user)
            if len(calls) == 1:
                return json.dumps(_chain(12))
            return "{ this is not json"

        graph = _extract_hierarchical("report", call, "model", "v1.6")
        self.assertEqual(12, len(graph.events))

    def test_v14_is_not_shape_reviewed(self):
        """The baseline's mechanism must not change under it."""
        calls = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                return json.dumps({"assignments": [
                    {"id": e["id"], "technique": "T1190", "mitigations": []}
                    for e in _chain(12)["events"]]})
            calls.append(user)
            return json.dumps(_chain(12))

        _extract_hierarchical("report", call, "model", "v1.4")
        self.assertEqual(1, len(calls))


class TestTheBudgetIsFixed(unittest.TestCase):
    """One generation and one revision, whatever the revision is spent on."""

    def test_a_structural_repair_no_longer_consumes_the_review(self):
        """The review used to share Stage A's retry, so it rarely ran.

        This test previously asserted the opposite, and was right about the
        code at the time: a structural fault took the second call and the shape
        review was skipped. Measured across three real runs, that meant it
        never ran at all -- every one tripped the review's own gate, every one
        had spent its retry on a structural fault, and every one was saved
        unreviewed with 8, 9 and 14 states that nothing consumed.

        A budget saving that removes the mechanism in exactly the cases it
        exists for is not a saving. The review now has its own call: one
        structural retry, then the review, so three Stage A calls at worst.
        """
        fan = {"title": "fan", "preconditions": [], "events": []}
        for i in range(12):
            fan["preconditions"].append(
                {"id": f"p{i}", "label": f"Result {i}", "code": "RS",
                 "style": "solid", "parents": [f"e{i}"]})
            fan["events"].append(
                {"id": f"e{i}", "label": f"Step {i}", "tactic": "RS",
                 "likelihood": 5.0, "style": "solid", "parents": [],
                 "join": "AND"})
        calls = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                return json.dumps({"assignments": [
                    {"id": f"e{i}", "techniques": ["T1587.001"]}
                    for i in range(12)]})
            calls.append(user)
            return json.dumps(fan if len(calls) == 1 else _chain(12))

        _extract_hierarchical("report", call, "model", "v1.6")
        self.assertEqual(3, len(calls),
                         "the structural correction and the shape review each "
                         "get one call; the review must not be skipped because "
                         "the retry was spent")

    def test_the_budget_is_still_bounded(self):
        """Its own call, not an open-ended loop."""
        chain = _chain(12)
        calls = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                return json.dumps({"assignments": [
                    {"id": e["id"], "techniques": ["T1190"]}
                    for e in chain["events"]]})
            calls.append(user)
            return json.dumps(chain)

        _extract_hierarchical("report", call, "model", "v1.6")
        self.assertLessEqual(len(calls), 3)

    def test_the_mandatory_path_fits_the_cost_guard(self):
        """What must never be stopped by the budget: generate and correct.

        The shape review is deliberately excluded from this sum. Adding its
        call to the pessimistic bound pushes the total past the limit, but the
        guard raises before sending and the review catches that, so the effect
        is a skipped review rather than a lost graph. Requiring the optional
        pass to fit the worst case would mean either raising the ceiling until
        it stopped being one, or dropping a review that is cheap in practice --
        a real five-call run of the STOLEN PENCIL report costs about US$0.42.
        """
        rate_in, rate_out = 3e-6, 15e-6
        worst = 2 * (12000 * rate_in + _graph_response_tokens() * rate_out)
        worst += 2 * (6000 * rate_in + _SMALL_RESPONSE_TOKENS * rate_out)
        self.assertLess(worst, _configured_max_cost_usd())

    def test_the_call_ceiling_admits_the_review(self):
        self.assertGreaterEqual(_MAX_GENERATION_CALLS, 4 + _SHAPE_REVIEW_CALLS)

    def test_a_budget_refusal_during_the_review_keeps_the_graph(self):
        """The review may be skipped. It may never cost the graph."""
        chain = _chain(12)
        calls = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                return json.dumps({"assignments": [
                    {"id": e["id"], "techniques": ["T1190"]}
                    for e in chain["events"]]})
            calls.append(user)
            if len(calls) > 1:
                raise RuntimeError(
                    "API cost guard stopped the next model call before it "
                    "was sent")
            return json.dumps(chain)

        graph = _extract_hierarchical("report", call, "model", "v1.6")
        self.assertEqual(12, len(graph.events),
                         "the valid graph must survive a refused review")
        self.assertEqual(1.0,
                         get_last_shape_measure()["critical_path_share"])


if __name__ == "__main__":
    unittest.main()
