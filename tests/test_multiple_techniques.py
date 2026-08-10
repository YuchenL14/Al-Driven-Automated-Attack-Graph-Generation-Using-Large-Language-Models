"""An event may carry several techniques, as the reference diagram does.

Two nodes of the supervisor's Stolen Pencil graph carry seven techniques each.
While the schema held one, no score against that graph could be measuring what
it claimed to measure, and no rendering of it could be complete.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attack_lookup import AttackResolver
from schema import AttackGraph, Event
from visual_syntax import project_visual_nodes

SEVEN = ["T1204.002", "T1056.001", "T1547.001", "T1555.003", "T1059.001",
         "T1041", "T1070.004"]


def _event(**over) -> dict:
    base = {"id": "e1", "label": "Malware executed", "tactic": "EX",
            "mitigations": ["M1038"], "likelihood": 5.0,
            "parents": ["s1"], "join": "AND"}
    base.update(over)
    return base


def _graph(event: dict) -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "multi", "preconditions": [
            {"id": "s1", "label": "Payload delivered", "code": "D",
             "parents": []}],
        "events": [event]})


class TestBackwardCompatibility(unittest.TestCase):
    """v1.4 data writes the singular key and must keep validating."""

    def test_a_singular_technique_key_is_accepted(self):
        graph = _graph(_event(technique="T1204.002"))
        self.assertEqual(graph.events[0].techniques, ["T1204.002"])

    def test_the_singular_reader_still_works(self):
        self.assertEqual(_graph(_event(technique="T1204.002")
                                ).events[0].technique, "T1204.002")

    def test_a_null_technique_stays_an_abstention(self):
        # No mitigations: the graph contract already forbids mitigating a
        # technique the event does not claim.
        graph = _graph(_event(technique=None, mitigations=[]))
        self.assertEqual(graph.events[0].techniques, [])
        self.assertIsNone(graph.events[0].technique)

    def test_an_event_with_neither_key_is_valid(self):
        self.assertEqual(
            _graph(_event(mitigations=[])).events[0].techniques, [])

    def test_a_saved_run_round_trips(self):
        graph = _graph(_event(technique="T1204.002"))
        reloaded = AttackGraph.model_validate(
            json.loads(graph.model_dump_json()))
        self.assertEqual(reloaded.events[0].technique, "T1204.002")


class TestMultiple(unittest.TestCase):

    def test_seven_techniques_validate(self):
        graph = _graph(_event(techniques=SEVEN))
        self.assertEqual(len(graph.events[0].techniques), 7)

    def test_technique_returns_the_first_of_many(self):
        self.assertEqual(_graph(_event(techniques=SEVEN)
                                ).events[0].technique, SEVEN[0])

    def test_duplicates_are_rejected(self):
        with self.assertRaises(Exception):
            Event.model_validate(_event(techniques=["T1190", "T1190"]))

    def test_an_invented_id_is_still_rejected_anywhere_in_the_list(self):
        with self.assertRaises(Exception):
            Event.model_validate(_event(techniques=["T1190", "T9999"]))

    def test_every_technique_reaches_the_projection(self):
        node = next(n for n in project_visual_nodes(_graph(
            _event(techniques=SEVEN))) if n.id == "e1")
        self.assertEqual(list(node.techniques), SEVEN)

    def test_every_technique_reaches_the_legend(self):
        legend = AttackResolver().build_legend(_graph(_event(techniques=SEVEN)))
        self.assertEqual(len(legend["Techniques"]), 7)

    def test_all_seven_are_drawn_not_just_the_first(self):
        from layout_ir import build_layout_ir
        from layout_planner import plan_layout
        from layout_router import route_layout
        from layout_svg import render_layout_plan_svg
        import tempfile

        model = _graph(_event(techniques=SEVEN))
        ir = build_layout_ir(model)
        plan = plan_layout(ir)
        with tempfile.TemporaryDirectory() as tmp:
            out = render_layout_plan_svg(
                model, ir, plan, route_layout(ir, plan),
                str(Path(tmp) / "m.svg"))
            svg = Path(out).read_text(encoding="utf-8")
        for technique in SEVEN:
            self.assertIn(technique, svg)


if __name__ == "__main__":
    unittest.main()


class TestPrecedenceWhenBothKeysArrive(unittest.TestCase):
    """Stage B writes `technique` onto a skeleton that already has `techniques`.

    The student and evidence paths dump an already-validated graph as their
    Stage A skeleton, so both keys reach the validator together. Letting the
    list win discarded Stage B's assignment and silently overrode an
    abstention -- both invisible, both wrong.
    """

    def test_stage_b_reassignment_wins(self):
        # Both ids are Execution techniques: the point under test is which
        # key wins, not the separate tactic-consistency rule.
        event = Event.model_validate(_event(techniques=["T1204.002"],
                                            technique="T1059.001"))
        self.assertEqual(event.techniques, ["T1059.001"])

    def test_stage_b_abstention_wins(self):
        event = Event.model_validate(_event(techniques=["T1204.002"],
                                            technique=None, mitigations=[]))
        self.assertEqual(event.techniques, [])

    def test_a_list_arriving_alone_is_untouched(self):
        event = Event.model_validate(_event(techniques=SEVEN))
        self.assertEqual(event.techniques, SEVEN)


class TestV16GranularityIsNotForced(unittest.TestCase):
    """v1.6 offers multi-technique events as a capability, not a target.

    Collapsing behaviours to match the reference diagram's node count would be
    tuning on the graph the tool is then evaluated against. So the rule and the
    prompt supply a determination test grounded in the report's wording, and
    neither states a preferred number of techniques, actions, or ranks.
    """

    @classmethod
    def setUpClass(cls):
        from extract import STAGE_B_V16_USER
        cls.prompt = STAGE_B_V16_USER
        cls.rules = (ROOT / "rules" / "ruleset_v1.6.md").read_text(
            encoding="utf-8")

    def test_the_prompt_gives_a_test_not_a_number(self):
        self.assertIn("Decision test", self.prompt)
        for forbidden in ("aim for", "should have about", "target of",
                          "roughly 14", "no more than 6 ranks"):
            self.assertNotIn(forbidden, self.prompt)

    def test_the_prompt_says_most_actions_carry_one(self):
        """Otherwise the capability reads as an instruction to merge."""
        self.assertIn("Most actions have exactly one", self.prompt)

    def test_the_prompt_forbids_merging_what_the_report_separates(self):
        self.assertIn("do not merge", self.prompt.lower())

    def test_the_rules_record_why_no_target_is_given(self):
        self.assertIn("would measure the tuning, not", self.rules)

    def test_rule_2_and_rule_7_agree_rather_than_override(self):
        """A declared override still leaves a false claim in the prompt.

        Rule 7 used to say it SUPERSEDED Rule 2's "exactly one technique id".
        That is honest bookkeeping, but the model reads Rule 2 first and has
        to hold a hard, wrong claim until it reaches Rule 7 much later in the
        same prompt. Rule 2 now says "at least one, and Rule 7 decides whether
        more", so there is nothing to un-believe.
        """
        self.assertNotIn("SUPERSEDES", self.rules)
        self.assertNotIn("carries exactly one", self.rules)
        self.assertIn("at least one", self.rules)
        self.assertIn("Rule 7 decides whether it", self.rules)


class TestPrimaryTechniqueCarriesTheTactic(unittest.TestCase):
    """Only the first technique is held to the event's tactic.

    The reference's "GREASE malware executed" carries seven techniques across
    five tactics on one node. Checking every technique against the single
    tactic would make that node inexpressible.
    """

    def test_a_secondary_technique_from_another_tactic_is_accepted(self):
        from extract import _technique_tactic_mismatches
        # T1204.002 is Execution; T1056.001 is Collection/Credential Access.
        events = [{"id": "e1", "tactic": "EX",
                   "techniques": ["T1204.002", "T1056.001"]}]
        self.assertEqual({}, _technique_tactic_mismatches(events))

    def test_a_wrong_primary_technique_is_still_caught(self):
        from extract import _technique_tactic_mismatches
        events = [{"id": "e1", "tactic": "EX",
                   "techniques": ["T1056.001", "T1204.002"]}]
        self.assertIn("e1", _technique_tactic_mismatches(events))

    def test_the_singular_key_is_still_checked(self):
        from extract import _technique_tactic_mismatches
        events = [{"id": "e1", "tactic": "EX", "technique": "T1056.001"}]
        self.assertIn("e1", _technique_tactic_mismatches(events))


class TestReconciliationHandlesTheListForm(unittest.TestCase):
    """Tactic reconciliation must clear whichever key the rule set uses.

    When Stage B returns a technique whose ATT&CK tactic does not match the one
    Stage A chose, the pipeline repairs it: adopt the tactic if the catalogue
    names exactly one, otherwise withhold the technique and keep the graph.

    The repair wrote only the singular `technique` key. A v1.6 event carries
    `techniques`, so the list survived untouched, the mismatch check still saw
    it, and a graph v1.4 recovers from was discarded after both paid calls.
    """

    @staticmethod
    def _graph() -> dict:
        return {"title": "g", "preconditions": [
            {"id": "p1", "label": "Exposed service", "code": "IA",
             "style": "solid", "parents": []},
            {"id": "p2", "label": "Foothold", "code": "IA",
             "style": "solid", "parents": ["e1"]}],
            "events": [{"id": "e1", "label": "Log in with stolen account",
                        "tactic": "EX", "likelihood": 5.0, "style": "solid",
                        "parents": ["p1"], "join": "AND"}]}

    def _run(self, ruleset: str, technique: str):
        from extract import _extract_hierarchical, AttackGraph

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                if ruleset.startswith("v1.6"):
                    return json.dumps({"assignments": [
                        {"id": "e1", "techniques": [technique]}]})
                return json.dumps({"assignments": [
                    {"id": "e1", "technique": technique, "mitigations": []}]})
            return json.dumps(self._graph())

        return _extract_hierarchical("report", call, "model", ruleset)

    def test_v16_withholds_an_ambiguous_technique_instead_of_failing(self):
        """T1078 spans DE/PS/PE/IA; none is EX, and none can be chosen."""
        graph = self._run("v1.6", "T1078")
        self.assertEqual([], graph.events[0].techniques)
        self.assertEqual("EX", graph.events[0].tactic)

    def test_v16_adopts_the_tactic_when_the_catalogue_names_only_one(self):
        graph = self._run("v1.6", "T1190")
        self.assertEqual(["T1190"], graph.events[0].techniques)
        self.assertEqual("IA", graph.events[0].tactic)

    def test_v14_behaves_the_same_way(self):
        """The two versions must not diverge on a repair neither rule mentions."""
        graph = self._run("v1.4", "T1078")
        self.assertEqual([], graph.events[0].techniques)
        self.assertEqual("EX", graph.events[0].tactic)
