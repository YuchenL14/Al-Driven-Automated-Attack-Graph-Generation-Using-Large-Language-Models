"""Stage A referential-integrity tests.

A dangling or wrongly typed parent id is a Stage A fault. It used to surface
only when the merged graph was validated during Stage B, where the correction
loop could not repair it: Stage B returns technique and mitigation identifiers
only. These tests pin the check to the stage that can act on it.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from extract import _skeleton_graph_problems  # noqa: E402


def _valid_skeleton() -> dict:
    return {
        "title": "Reference fixture",
        "preconditions": [
            {"id": "p1", "label": "Remote service exposed", "code": "RS",
             "parents": []},
            {"id": "p2", "label": "Foothold obtained", "code": "IA",
             "parents": ["e1"]},
        ],
        "events": [
            {"id": "e1", "label": "Gain entry via remote service",
             "tactic": "IA", "parents": ["p1"], "join": "AND"},
        ],
    }


class StageAReferenceTests(unittest.TestCase):
    def test_consistent_skeleton_reports_no_problem(self):
        self.assertEqual([], _skeleton_graph_problems(_valid_skeleton()))

    def test_missing_events_are_reported_as_one_grouped_diagnosis(self):
        data = _valid_skeleton()
        data["preconditions"][1]["parents"] = ["e2"]
        data["preconditions"].append(
            {"id": "p3", "label": "Later state", "code": "R",
             "parents": ["e3"]})
        problems = _skeleton_graph_problems(data)
        grouped = [p for p in problems if "events array is missing" in p]
        self.assertEqual(1, len(grouped))
        self.assertIn("missing 2 event(s)", grouped[0])
        self.assertIn("e2, e3", grouped[0])

    def test_event_naming_a_missing_precondition_is_reported(self):
        data = _valid_skeleton()
        data["events"][0]["parents"] = ["p9"]
        problems = _skeleton_graph_problems(data)
        grouped = [p for p in problems if "preconditions array is missing" in p]
        self.assertEqual(1, len(grouped))
        self.assertIn("p9", grouped[0])

    def test_event_pointing_straight_at_another_event_is_reported(self):
        data = _valid_skeleton()
        data["events"].append({
            "id": "e2", "label": "Move laterally", "tactic": "LM",
            "parents": ["e1"], "join": "AND",
        })
        problems = _skeleton_graph_problems(data)
        self.assertEqual(1, len(problems))
        self.assertIn("an event consumes preconditions", problems[0])

    def test_precondition_chained_to_a_precondition_is_reported(self):
        data = _valid_skeleton()
        data["preconditions"][1]["parents"] = ["p1"]
        problems = _skeleton_graph_problems(data)
        self.assertEqual(1, len(problems))
        self.assertIn("established by an event", problems[0])

    def test_duplicate_ids_across_node_types_are_reported(self):
        data = _valid_skeleton()
        data["events"][0]["id"] = "p1"
        data["preconditions"][1]["parents"] = ["p1"]
        problems = _skeleton_graph_problems(data)
        self.assertTrue(
            any("must be unique" in problem for problem in problems)
        )

    def test_event_consuming_nothing_is_reported(self):
        data = _valid_skeleton()
        data["events"][0]["parents"] = []
        problems = _skeleton_graph_problems(data)
        self.assertEqual(1, len(problems))
        self.assertIn("consume no precondition", problems[0])
        self.assertIn("e1", problems[0])

    def test_cycle_is_reported(self):
        data = _valid_skeleton()
        data["preconditions"][0]["parents"] = ["e1"]
        problems = _skeleton_graph_problems(data)
        self.assertEqual(1, len(problems))
        self.assertIn("contains a cycle", problems[0])

    def test_acyclic_diamond_is_accepted(self):
        data = _valid_skeleton()
        data["preconditions"].append(
            {"id": "p3", "label": "Credentials held", "code": "CA",
             "parents": []})
        data["events"].append({
            "id": "e2", "label": "Move laterally", "tactic": "LM",
            "parents": ["p2", "p3"], "join": "AND",
        })
        self.assertEqual([], _skeleton_graph_problems(data))

    def test_private_root_per_event_is_reported_as_disconnected(self):
        data = {
            "title": "One isolated pair per event",
            "preconditions": [], "events": [],
        }
        for index in (1, 2, 3):
            data["preconditions"].append(
                {"id": f"r{index}", "label": f"Root {index}", "code": "R",
                 "parents": []})
            data["preconditions"].append(
                {"id": f"s{index}", "label": f"Result {index}", "code": "R",
                 "parents": [f"e{index}"]})
            data["events"].append(
                {"id": f"e{index}", "label": f"Step {index}", "tactic": "IA",
                 "parents": [f"r{index}"], "join": "AND"})
        problems = _skeleton_graph_problems(data)
        self.assertTrue(
            any("3 disconnected pieces" in problem for problem in problems),
            problems,
        )

    def test_flat_fan_on_one_root_is_reported(self):
        data = {
            "title": "Flat fan",
            "preconditions": [P_ROOT := {"id": "r1", "label": "Exposure",
                                         "code": "R", "parents": []}],
            "events": [],
        }
        for index in (1, 2, 3):
            data["events"].append(
                {"id": f"e{index}", "label": f"Step {index}", "tactic": "IA",
                 "parents": ["r1"], "join": "AND"})
            data["preconditions"].append(
                {"id": f"s{index}", "label": f"Result {index}", "code": "R",
                 "parents": [f"e{index}"]})
        problems = _skeleton_graph_problems(data)
        self.assertEqual(1, len(problems))
        self.assertIn("no step follows from another", problems[0])

    def test_parallel_branches_that_reconverge_are_accepted(self):
        data = {
            "title": "Two branches then a merge",
            "preconditions": [
                {"id": "r1", "label": "Exposure", "code": "R", "parents": []},
                {"id": "s1", "label": "Foothold", "code": "R",
                 "parents": ["e1"]},
                {"id": "s2", "label": "Credentials", "code": "R",
                 "parents": ["e2"]},
                {"id": "s3", "label": "Impact", "code": "R",
                 "parents": ["e3"]},
            ],
            "events": [
                {"id": "e1", "label": "Gain entry", "tactic": "IA",
                 "parents": ["r1"], "join": "AND"},
                {"id": "e2", "label": "Take credentials", "tactic": "CA",
                 "parents": ["r1"], "join": "AND"},
                {"id": "e3", "label": "Encrypt", "tactic": "IM",
                 "parents": ["s1", "s2"], "join": "AND"},
            ],
        }
        self.assertEqual([], _skeleton_graph_problems(data))

    def test_single_connected_graph_is_accepted(self):
        data = _valid_skeleton()
        data["events"].append({
            "id": "e2", "label": "Move laterally", "tactic": "LM",
            "parents": ["p2"], "join": "AND",
        })
        data["preconditions"].append(
            {"id": "p3", "label": "Wide access held", "code": "R",
             "parents": ["e2"]})
        self.assertEqual([], _skeleton_graph_problems(data))

    def test_evidence_variant_allows_a_root_event(self):
        data = _valid_skeleton()
        data["events"][0]["parents"] = []
        data["preconditions"][0]["parents"] = ["e1"]
        self.assertEqual(
            [],
            _skeleton_graph_problems(data, require_event_parents=False),
        )

    def test_evidence_variant_still_rejects_isolated_pairs(self):
        data = {"title": "Isolated pairs", "preconditions": [], "events": []}
        for index in (1, 2, 3):
            data["events"].append(
                {"id": f"e{index}", "label": f"Step {index}", "tactic": "IA",
                 "parents": []})
            data["preconditions"].append(
                {"id": f"s{index}", "label": f"Result {index}", "code": "R",
                 "parents": [f"e{index}"]})
        problems = _skeleton_graph_problems(data, require_event_parents=False)
        self.assertTrue(
            any("disconnected pieces" in problem for problem in problems),
            problems,
        )

    def test_malformed_entries_do_not_raise(self):
        data = {"preconditions": ["not a mapping"], "events": [None]}
        self.assertEqual([], _skeleton_graph_problems(data))


if __name__ == "__main__":
    unittest.main()


class TestDisconnectedDiagnosis(unittest.TestCase):
    """The message must describe the fault that actually occurred.

    A real v1.6 run returned one connected graph of 47 nodes plus six floating
    single events. The message told the model that "every event has its own
    separate starting condition", which was not what happened and could not be
    acted on. Only one Stage A retry is permitted, so a misdiagnosis spends the
    entire repair budget on the wrong instruction.
    """

    @staticmethod
    def _chain(n: int) -> dict:
        pre = [{"id": f"s{i}", "label": f"State {i}", "code": "IA",
                "parents": [f"e{i-1}"] if i else []} for i in range(n)]
        ev = [{"id": f"e{i}", "label": f"Step {i}", "tactic": "IA",
               "likelihood": 5.0, "parents": [f"s{i}"], "join": "AND"}
              for i in range(n)]
        return {"preconditions": pre, "events": ev}

    def test_a_few_strays_are_named_and_the_main_graph_is_not_dumped(self):
        data = self._chain(8)
        data["events"].append({"id": "e_orphan", "label": "Acquire cert",
                               "tactic": "RS", "likelihood": 5.0,
                               "parents": [], "join": "AND"})
        problems = " ".join(_skeleton_graph_problems(
            data, require_event_parents=False))
        self.assertIn("e_orphan", problems)
        self.assertIn("detached", problems)
        self.assertNotIn("s4", problems)

    def test_the_stray_message_permits_a_root_event(self):
        data = self._chain(8)
        data["events"].append({"id": "e_orphan", "label": "Acquire cert",
                               "tactic": "RS", "likelihood": 5.0,
                               "parents": [], "join": "AND"})
        problems = " ".join(_skeleton_graph_problems(
            data, require_event_parents=False))
        self.assertIn("root event with no parents is fine", problems)

    def test_many_pairs_are_diagnosed_as_fragmentation_not_strays(self):
        """The real v1.6 failure: 24 isolated pairs plus one graph of 11.

        A size-ratio test alone chose the "a few detached nodes" branch and
        listed forty-nine ids, which the model cannot act on. The number of
        pieces is what distinguishes the two faults.
        """
        pre, ev = [], []
        for i in range(5):
            pre.append({"id": f"c{i}", "label": f"State {i}", "code": "IA",
                        "parents": [f"ce{i-1}"] if i else []})
            ev.append({"id": f"ce{i}", "label": f"Step {i}", "tactic": "IA",
                       "likelihood": 5.0, "parents": [f"c{i}"], "join": "AND"})
        pre.append({"id": "c5", "label": "Final", "code": "IA",
                    "parents": ["ce4"]})
        for i in range(24):
            pre += [{"id": f"p{i}", "label": f"Start {i}", "code": "RS",
                     "parents": []},
                    {"id": f"r{i}", "label": f"Result {i}", "code": "RS",
                     "parents": [f"e{i}"]}]
            ev.append({"id": f"e{i}", "label": f"Iso {i}", "tactic": "RS",
                       "likelihood": 5.0, "parents": [f"p{i}"], "join": "AND"})
        problems = _skeleton_graph_problems(
            {"preconditions": pre, "events": ev}, require_event_parents=False)
        message = "; ".join(problems)
        self.assertIn("disconnected pieces", message)
        self.assertNotIn("detached from the attack", message)
        self.assertLess(len(message), 900,
                        "a correction the model cannot read is not a correction")

    def test_only_one_shape_fault_is_reported_at_a_time(self):
        """Two corrections in one message dilute each other."""
        pre, ev = [], []
        for i in range(4):
            pre += [{"id": f"p{i}", "label": f"Start {i}", "code": "RS",
                     "parents": []},
                    {"id": f"r{i}", "label": f"Result {i}", "code": "RS",
                     "parents": [f"e{i}"]}]
            ev.append({"id": f"e{i}", "label": f"Iso {i}", "tactic": "RS",
                       "likelihood": 5.0, "parents": [f"p{i}"], "join": "AND"})
        message = "; ".join(_skeleton_graph_problems(
            {"preconditions": pre, "events": ev}, require_event_parents=False))
        self.assertIn("disconnected pieces", message)
        self.assertNotIn("no step follows from another", message)

    def test_the_fan_correction_names_ids_and_the_exact_edit(self):
        """A generic instruction produced the same fan on the retry.

        The real v1.6 run returned thirty isolated event/result pairs, was
        told to "join them into a single path", and returned the same shape.
        The correction now names the model's own ids and the one field to
        change, because an instruction that must be interpreted before it can
        be applied is another thing that can fail on the only retry there is.
        """
        pre, ev = [], []
        for name in ("build", "click", "install", "escalate"):
            pre.append({"id": f"p_{name}", "label": f"{name} done",
                        "code": "RS", "parents": [f"e_{name}"]})
            ev.append({"id": f"e_{name}", "label": name, "tactic": "RS",
                       "likelihood": 5.0, "parents": [], "join": "AND"})
        message = "; ".join(_skeleton_graph_problems(
            {"preconditions": pre, "events": ev},
            require_event_parents=False))
        self.assertIn("4 of your 4 events start from nothing", message)
        self.assertIn("change only the parents lists", message)
        self.assertIn("e_click", message)
        self.assertIn("p_build", message)
        self.assertLess(len(message), 900)

    def test_the_fan_correction_bounds_the_permitted_roots(self):
        """The prompt allows root events; without a bound the model used it
        for every event. The correction has to state the bound too."""
        pre, ev = [], []
        for name in ("a", "b", "c"):
            pre.append({"id": f"p_{name}", "label": f"{name} done",
                        "code": "RS", "parents": [f"e_{name}"]})
            ev.append({"id": f"e_{name}", "label": name, "tactic": "RS",
                       "likelihood": 5.0, "parents": [], "join": "AND"})
        message = "; ".join(_skeleton_graph_problems(
            {"preconditions": pre, "events": ev},
            require_event_parents=False))
        self.assertIn("two to four preparation events", message)

    def test_uniform_fragmentation_keeps_the_original_diagnosis(self):
        """Isolated pairs are a different fault and keep their own wording."""
        data = {"preconditions": [], "events": []}
        for i in range(4):
            data["preconditions"] += [
                {"id": f"s{i}", "label": f"Start {i}", "code": "IA",
                 "parents": []},
                {"id": f"r{i}", "label": f"Result {i}", "code": "IA",
                 "parents": [f"e{i}"]}]
            data["events"].append({"id": f"e{i}", "label": f"Step {i}",
                                   "tactic": "IA", "likelihood": 5.0,
                                   "parents": [f"s{i}"], "join": "AND"})
        problems = " ".join(_skeleton_graph_problems(
            data, require_event_parents=False))
        self.assertIn("private starting state", problems)
        self.assertIn("change only the parents lists", problems)

    def test_both_wordings_still_route_to_the_structural_correction(self):
        from extract import is_structural_stage_a_fault
        self.assertTrue(is_structural_stage_a_fault(
            "3 node(s) are detached from the attack graph: e_a, e_b, e_c"))


class TestLabelLengthGate(unittest.TestCase):
    """A ten-word label is a Stage A fault and must be caught at Stage A.

    A real v1.6 run produced 'Off-the-shelf attack toolkit staged (Mimikatz,
    Procdump, PsExec, EternalBlue, Nirsoft tools, KPortScan)' -- eleven words
    by the same whitespace split schema.py uses.
    schema.py rejected it, but only after Stage B had merged its identifiers,
    where nothing can rename a node. Both paid calls and an otherwise complete
    graph were discarded over a label.
    """

    REAL = ("Off-the-shelf attack toolkit staged (Mimikatz, Procdump, "
            "PsExec, EternalBlue, Nirsoft tools, KPortScan)")

    @staticmethod
    def _graph(label: str) -> dict:
        return {
            "preconditions": [
                {"id": "s0", "label": "Toolkit needed", "code": "RS",
                 "parents": []},
                {"id": "s1", "label": label, "code": "RS",
                 "parents": ["e0"]},
                {"id": "s2", "label": "Foothold", "code": "IA",
                 "parents": ["e1"]}],
            "events": [
                {"id": "e0", "label": "Stage tooling", "tactic": "RS",
                 "likelihood": 5.0, "parents": ["s0"], "join": "AND"},
                {"id": "e1", "label": "Deploy tooling", "tactic": "EX",
                 "likelihood": 5.0, "parents": ["s1"], "join": "AND"}]}

    def test_the_real_failing_label_is_caught(self):
        problems = " ".join(_skeleton_graph_problems(
            self._graph(self.REAL), require_event_parents=False))
        self.assertIn("s1", problems)
        self.assertIn("11 words", problems)

    def test_the_same_limit_as_the_canonical_contract(self):
        """The gate and schema.py must not drift apart."""
        from extract import _MAX_LABEL_WORDS
        from schema import Precondition
        ten = " ".join(f"w{i}" for i in range(_MAX_LABEL_WORDS))
        Precondition.model_validate({"id": "s", "label": ten, "code": "IA"})
        with self.assertRaises(Exception):
            Precondition.model_validate(
                {"id": "s", "label": ten + " extra", "code": "IA"})

    def test_exactly_ten_words_is_accepted(self):
        ten = " ".join(f"word{i}" for i in range(10))
        self.assertEqual([], [p for p in _skeleton_graph_problems(
            self._graph(ten), require_event_parents=False)
            if "ellipse" in p])

    def test_it_routes_to_the_structural_correction(self):
        from extract import is_structural_stage_a_fault
        problems = "; ".join(_skeleton_graph_problems(
            self._graph(self.REAL), require_event_parents=False))
        self.assertTrue(is_structural_stage_a_fault(problems))

    def test_the_correction_names_the_offending_label(self):
        problems = " ".join(_skeleton_graph_problems(
            self._graph(self.REAL), require_event_parents=False))
        self.assertIn("Mimikatz", problems)
        self.assertIn("Change nothing else", problems)


class TestNothingIsFabricated(unittest.TestCase):
    """_sanitize must never add a node the model did not return.

    It used to. Where one precondition parented another, it inserted an event
    labelled "Transition from the previous state" to restore the alternation,
    and Stage B then gave that invented step a real ATT&CK technique. Run 5
    shipped T1059.003 on a step the STOLEN PENCIL report never describes.

    A graph that asserts an action nobody performed is worse than no graph.
    Both faults are structural, the model can fix either, and the gate now
    asks it to.
    """

    @staticmethod
    def _skipped_alternation() -> dict:
        return {"preconditions": [
            {"id": "p1", "label": "Start", "code": "IA", "parents": []},
            {"id": "p2", "label": "Persistent access", "code": "IA",
             "parents": ["p1"]}],
            "events": [
            {"id": "e1", "label": "Exploit", "tactic": "IA",
             "likelihood": 5.0, "parents": ["p1"], "join": "AND"},
            {"id": "e2", "label": "Move", "tactic": "LM", "likelihood": 5.0,
             "parents": ["e1"], "join": "AND"}]}

    def test_sanitize_adds_no_nodes(self):
        from extract import _sanitize
        before = self._skipped_alternation()
        after = json.loads(_sanitize(json.dumps(before)))
        self.assertEqual(len(before["events"]), len(after["events"]))
        self.assertEqual(len(before["preconditions"]),
                         len(after["preconditions"]))

    def test_sanitize_invents_no_labels(self):
        from extract import _sanitize
        after = _sanitize(json.dumps(self._skipped_alternation()))
        for invented in ("Transition from the previous state",
                         "State produced by the previous step"):
            self.assertNotIn(invented, after)

    def test_both_faults_are_reported_instead(self):
        from extract import _normalise_constructs
        problems = "; ".join(_skeleton_graph_problems(
            _normalise_constructs(self._skipped_alternation()),
            require_event_parents=False))
        self.assertIn("'e2' lists event 'e1' as a parent", problems)
        self.assertIn("'p2' lists precondition 'p1' as a parent", problems)

    def test_the_report_routes_to_the_structural_correction(self):
        from extract import _normalise_constructs, is_structural_stage_a_fault
        problems = "; ".join(_skeleton_graph_problems(
            _normalise_constructs(self._skipped_alternation()),
            require_event_parents=False))
        self.assertTrue(is_structural_stage_a_fault(problems))

    def test_no_bridge_builder_survives_anywhere(self):
        """A guard: the repair was convenient, and may look tempting again."""
        source = (ROOT / "src" / "extract.py").read_text(encoding="utf-8")
        for banned in ("_repair_alternation",
                       "Transition from the previous state",
                       "State produced by the previous step"):
            self.assertNotIn(banned, source)
