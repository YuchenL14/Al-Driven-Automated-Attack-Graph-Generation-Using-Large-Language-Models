"""Aggregating a fan the page cannot hold, without touching the graph.

Pagination alone could not make the STOLEN PENCIL credential fan readable.
Seven password-dumping tools sit at one causal depth because the report says
they do, and every setting of the width budget only traded page count against
page shape: the widest setting gave one page at 0.20, the narrowest gave seven
pages, and dividing the fan put its convergence on two pages at once.

The literature answers a wide fan by aggregating rather than paginating -- Noel
and Jajodia (VizSEC/DMSEC 2004) collapse subgraphs to single vertices under
rules based on common attribute values or connectedness, and Homer et al.
(VizSec 2008) group attacks for the same reason. The supervisor's reference
graph does it by hand: "GREASE malware executed" is one rectangle.

The safety property these tests exist to protect is that aggregation is a
drawing decision and nothing else. The extracted graph keeps every event, its
evidence and its ATT&CK mapping; the aggregate carries the union of what its
members carried; every member is named in the legend; and nothing another node
depends on is ever folded away.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from schema import AttackGraph
from causal_split import plan_causal_split, validate_lossless_split
from visual_aggregation import (aggregate_for_drawing,
                                aggregation_legend_lines,
                                find_aggregatable_groups)


# Real identifiers: the schema refuses invented ones, and rightly so.
_TECHNIQUES = ("T1003.001", "T1555.003", "T1040")
_MITIGATIONS = ("M1017", "M1027")


def _fan_sharing_a_result(n: int, tactic: str = "CA") -> dict:
    """`n` sibling events, each with a private result, all feeding one state."""

    events = [
        {"id": f"e{i}", "label": f"Run tool {i} to dump passwords",
         "parents": ["p_access"], "tactic": tactic,
         "techniques": [_TECHNIQUES[i % len(_TECHNIQUES)]],
         "mitigations": [_MITIGATIONS[i % len(_MITIGATIONS)]]}
        for i in range(n)
    ]
    preconditions = [
        {"id": "p_access", "label": "Remote access obtained", "code": "P0",
         "parents": []},
    ] + [
        {"id": f"p{i}", "label": f"Result of tool {i}", "code": f"P{i + 1}",
         "parents": [f"e{i}"]}
        for i in range(n)
    ] + [
        {"id": "p_all", "label": "Credentials held by actor", "code": "PX",
         "parents": [f"e{i}" for i in range(n)]},
    ]
    # Something must consume the shared state, or it is a dead end rather than
    # the convergence the group exists to produce.
    events.append({"id": "e_use", "label": "Move laterally with credentials",
                   "parents": ["p_all"], "tactic": "LM",
                   "techniques": ["T1021"], "mitigations": []})
    preconditions.append({"id": "p_moved", "label": "Other hosts reached",
                          "code": "PY", "parents": ["e_use"]})
    return {"events": events, "preconditions": preconditions}


class FindingGroupsTests(unittest.TestCase):
    def test_a_fan_wider_than_a_page_is_found(self):
        model = AttackGraph.model_validate(_fan_sharing_a_result(7))
        groups = find_aggregatable_groups(model, min_size=5)
        self.assertEqual(1, len(groups))
        self.assertEqual(7, len(groups[0]))

    def test_a_fan_that_fits_is_left_alone(self):
        model = AttackGraph.model_validate(_fan_sharing_a_result(4))
        self.assertEqual([], find_aggregatable_groups(model, min_size=5))

    def test_a_different_tactic_is_not_swept_in(self):
        """The keylogger was Collection, not Credential Access."""
        data = _fan_sharing_a_result(7)
        # The schema checks technique against tactic, so both must move.
        data["events"][0]["tactic"] = "CL"
        data["events"][0]["techniques"] = ["T1185"]
        model = AttackGraph.model_validate(data)
        groups = find_aggregatable_groups(model, min_size=5)
        self.assertEqual(1, len(groups))
        self.assertNotIn("e0", groups[0])

    def test_a_different_parent_is_not_swept_in(self):
        data = _fan_sharing_a_result(7)
        data["preconditions"].append(
            {"id": "p_other", "label": "Another state", "code": "PZ",
             "parents": []})
        data["events"][0]["parents"] = ["p_other"]
        model = AttackGraph.model_validate(data)
        groups = find_aggregatable_groups(model, min_size=5)
        self.assertNotIn("e0", groups[0])

    def test_siblings_with_no_shared_result_are_not_a_group(self):
        """Without a common result they are separate stories, not one."""
        data = _fan_sharing_a_result(7)
        data["preconditions"] = [
            p for p in data["preconditions"] if p["id"] != "p_all"]
        data["events"] = [e for e in data["events"] if e["id"] != "e_use"]
        data["preconditions"] = [
            p for p in data["preconditions"] if p["id"] != "p_moved"]
        model = AttackGraph.model_validate(data)
        self.assertEqual([], find_aggregatable_groups(model, min_size=5))

    def test_min_size_is_validated(self):
        model = AttackGraph.model_validate(_fan_sharing_a_result(7))
        with self.assertRaises(ValueError):
            find_aggregatable_groups(model, min_size=1)


class AggregatingTests(unittest.TestCase):
    def setUp(self):
        self.model = AttackGraph.model_validate(_fan_sharing_a_result(7))
        self.drawn, self.groups = aggregate_for_drawing(
            self.model, min_size=5)

    def test_the_extracted_graph_is_untouched(self):
        self.assertEqual(8, len(self.model.events))
        self.assertEqual(
            {f"e{i}" for i in range(7)} | {"e_use"},
            {event.id for event in self.model.events})

    def test_the_drawn_graph_replaces_the_group_with_one_node(self):
        self.assertEqual(2, len(self.drawn.events))
        self.assertEqual(1, len(self.groups))

    def test_the_aggregate_carries_the_union_of_the_techniques(self):
        group = self.groups[0]
        expected = []
        for event in self.model.events:
            if event.id in group.event_ids:
                for technique in event.techniques:
                    if technique not in expected:
                        expected.append(technique)
        self.assertEqual(tuple(expected), group.techniques)
        drawn = next(e for e in self.drawn.events if e.id == group.visual_id)
        self.assertEqual(list(expected), list(drawn.techniques))

    def test_the_label_states_the_rule_rather_than_a_summary(self):
        # Nothing here is written by the tool about what the attack "means".
        self.assertEqual("7 grouped Credential Access actions",
                         self.groups[0].label)

    def test_private_dead_end_results_are_folded_in(self):
        self.assertEqual(7, len(self.groups[0].folded_state_ids))
        drawn_ids = {p.id for p in self.drawn.preconditions}
        for state_id in self.groups[0].folded_state_ids:
            self.assertNotIn(state_id, drawn_ids)

    def test_the_shared_result_survives(self):
        self.assertIn("p_all", {p.id for p in self.drawn.preconditions})
        shared = next(p for p in self.drawn.preconditions if p.id == "p_all")
        self.assertEqual([self.groups[0].visual_id], list(shared.parents))

    def test_a_consumed_state_is_never_folded_away(self):
        # p_all is consumed by e_use, so folding it would delete a dependency.
        self.assertNotIn("p_all", self.groups[0].folded_state_ids)

    def test_the_drawn_graph_still_paginates_losslessly(self):
        plan = plan_causal_split(self.drawn)
        validate_lossless_split(self.drawn, plan)

    def test_the_legend_names_every_member_verbatim(self):
        lines = aggregation_legend_lines(self.groups)
        for event in self.model.events:
            if event.id in self.groups[0].event_ids:
                self.assertTrue(
                    any(event.label in line for line in lines),
                    f"{event.label!r} is not explained anywhere")

    def test_the_legend_names_every_folded_state(self):
        lines = aggregation_legend_lines(self.groups)
        for label in self.groups[0].folded_state_labels:
            self.assertTrue(any(label in line for line in lines))

    def test_nothing_happens_when_no_group_qualifies(self):
        """Content unchanged, not object identity.

        The graph is now always rebuilt, because a graph with nothing to group
        at the event level can still have one action carrying more results than
        a page holds, and that pass has to run.
        """
        model = AttackGraph.model_validate(_fan_sharing_a_result(3))
        drawn, groups = aggregate_for_drawing(model, min_size=5)
        self.assertEqual((), groups)
        self.assertEqual(model.model_dump(), drawn.model_dump())


class RealRunTests(unittest.TestCase):
    def test_the_stolen_pencil_credential_fan_collapses(self):
        path = (ROOT / "outputs" /
                "netscout-stolen-pencil__rules-v1.6__anthropic-claude-sonnet-5_8.json")
        if not path.is_file():
            self.skipTest("run 8 not present")
        model = AttackGraph.model_validate(
            json.loads(path.read_text(encoding="utf-8")))
        drawn, groups = aggregate_for_drawing(model)
        self.assertEqual(1, len(groups))
        self.assertEqual(7, len(groups[0].event_ids))
        self.assertEqual("CA", groups[0].tactic)
        # The keylogger shares the tactic family but not the tactic or parents.
        self.assertNotIn("e_keylog", groups[0].event_ids)
        # Fewer pages, and the pagination is still lossless over what is drawn.
        before = plan_causal_split(model)
        after = plan_causal_split(drawn)
        validate_lossless_split(drawn, after)
        self.assertLess(len(after.parts), len(before.parts))


if __name__ == "__main__":
    unittest.main()


class OutcomeFoldingTests(unittest.TestCase):
    """One action can establish any number of results, each drawn beside the last.

    Bounding the width of an event rank never reached this. A teaching graph
    put six outcomes under one ransomware deployment and came out at an aspect
    ratio of 0.17, worse than the fan that prompted the width work. Pagination
    cannot help either: an action and the state it establishes are one
    indivisible visual block, so the cut has nowhere to go.
    """

    @staticmethod
    def _one_step_many_outcomes(count: int) -> AttackGraph:
        return AttackGraph.model_validate({
            "events": [{"id": "e1", "label": "Deploy the ransomware",
                        "parents": ["p_in"], "tactic": "IM",
                        "techniques": ["T1486"]}],
            "preconditions": [
                {"id": "p_in", "label": "Access obtained", "code": "P0",
                 "parents": []},
            ] + [
                {"id": f"o{i}", "label": f"Consequence {i}", "code": "IM",
                 "parents": ["e1"]}
                for i in range(count)
            ],
        })

    def test_more_outcomes_than_a_page_holds_are_folded(self):
        model = self._one_step_many_outcomes(6)
        drawn, groups = aggregate_for_drawing(model, min_size=5)
        self.assertEqual(1, len(groups))
        self.assertEqual("6 recorded outcomes", groups[0].label)
        # One root, one action, one aggregate.
        self.assertEqual(2, len(drawn.preconditions))

    def test_a_number_a_page_holds_is_left_alone(self):
        model = self._one_step_many_outcomes(3)
        drawn, groups = aggregate_for_drawing(model, min_size=5)
        self.assertEqual((), groups)
        self.assertEqual(4, len(drawn.preconditions))

    def test_every_folded_outcome_is_named_in_the_legend(self):
        model = self._one_step_many_outcomes(6)
        _, groups = aggregate_for_drawing(model, min_size=5)
        lines = aggregation_legend_lines(groups)
        for index in range(6):
            self.assertTrue(
                any(f"Consequence {index}" in line for line in lines),
                f"Consequence {index} is not explained anywhere")

    def test_a_consumed_result_is_never_folded(self):
        """Folding it would cut the dependency that runs through it."""
        data = self._one_step_many_outcomes(7).model_dump()
        data["events"].append({
            "id": "e2", "label": "Use the first consequence",
            "parents": ["o0"], "tactic": "IM", "techniques": ["T1486"]})
        model = AttackGraph.model_validate(data)
        drawn, groups = aggregate_for_drawing(model, min_size=5)
        self.assertEqual(1, len(groups))
        self.assertNotIn("o0", groups[0].state_ids)
        self.assertIn("o0", {p.id for p in drawn.preconditions})

    def test_a_result_with_two_producers_is_not_this_steps_to_fold(self):
        """It belongs to both steps, so neither may fold it alone."""
        data = self._one_step_many_outcomes(7).model_dump()
        data["events"].append({
            "id": "e2", "label": "Another action", "parents": ["p_in"],
            "tactic": "IM", "techniques": ["T1486"]})
        shared = data["preconditions"][-1]["id"]
        data["preconditions"][-1]["parents"] = ["e1", "e2"]
        model = AttackGraph.model_validate(data)
        drawn, groups = aggregate_for_drawing(model, min_size=5)
        self.assertEqual(1, len(groups))
        self.assertNotIn(shared, groups[0].state_ids)
        self.assertIn(shared, {p.id for p in drawn.preconditions})

    def test_the_extracted_graph_is_untouched(self):
        model = self._one_step_many_outcomes(6)
        aggregate_for_drawing(model, min_size=5)
        self.assertEqual(7, len(model.preconditions))

    def test_the_drawn_graph_still_paginates_losslessly(self):
        model = self._one_step_many_outcomes(6)
        drawn, _ = aggregate_for_drawing(model, min_size=5)
        validate_lossless_split(drawn, plan_causal_split(drawn))
