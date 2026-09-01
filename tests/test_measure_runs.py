"""The measurement script is a result in the write-up, so it is tested.

Every figure this project reported before it -- dead-end counts, reachability,
page proportions -- came from a script written on the spot and discarded. One
of those measured a badge stack with the wrong line pitch and reported an
overflow that did not exist, and code was written for the overflow. A number
that appears in a dissertation needs a definition that can be run and checked,
not retyped.

These tests fix two things. First, that the script reports what the pipeline
reports: it must call the product's own functions, so a disagreement between
the two is impossible rather than merely unlikely. Second, that the checks
which are pass/fail really are contracts, and the ones that merely describe a
graph are not dressed up as failures -- an early version failed a run because
none of its actions happened to carry two techniques, which violates nothing.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import measure_runs
from measure_runs import (SYNTAX_CHECKS, check_syntax, main, measure_structure,
                          read_layout, score_against_gold)
from extract import measure_skeleton_shape
from schema import AttackGraph

CHAIN = {
    "events": [
        {"id": "e1", "label": "Exploit the public service", "parents": ["p0"],
         "tactic": "IA", "techniques": ["T1190"]},
        {"id": "e2", "label": "Dump credentials from memory",
         "parents": ["p1"], "tactic": "CA", "techniques": ["T1003.001"]},
    ],
    "preconditions": [
        {"id": "p0", "label": "Service reachable", "code": "P0",
         "parents": []},
        {"id": "p1", "label": "Foothold on host", "code": "P1",
         "parents": ["e1"]},
        {"id": "p2", "label": "Credentials held", "code": "P2",
         "parents": ["e2"]},
        {"id": "a1", "label": "Detected on day 4", "code": "A1",
         "role": "annotation", "style": "dashed", "parents": ["e2"]},
    ],
}


class StructureTests(unittest.TestCase):
    def test_it_reports_what_the_pipeline_reports(self):
        """No second implementation of the shape metrics."""
        structure = measure_structure(CHAIN)
        shape = measure_skeleton_shape(CHAIN)
        self.assertEqual(shape["unused_states"], structure.unused_states)
        self.assertEqual(shape["critical_path_share"],
                         structure.critical_path_share)
        self.assertEqual(shape["widest"], structure.widest)
        self.assertEqual(shape["ranks"], structure.ranks)

    def test_annotations_are_counted_but_kept_out_of_the_path(self):
        structure = measure_structure(CHAIN)
        self.assertEqual(1, structure.annotations)
        self.assertEqual(3, structure.states)
        self.assertEqual(1, structure.terminals)

    def test_convergence_is_the_share_reaching_one_ending(self):
        structure = measure_structure(CHAIN)
        self.assertEqual(1.0, structure.convergence)
        self.assertEqual("Credentials held", structure.convergence_label)

    def test_an_empty_graph_does_not_divide_by_zero(self):
        structure = measure_structure({"events": [], "preconditions": []})
        self.assertEqual(0, structure.events)
        self.assertEqual(0.0, structure.convergence)


class SyntaxTests(unittest.TestCase):
    def test_a_conforming_graph_passes_every_check(self):
        result = check_syntax(AttackGraph.model_validate(CHAIN))
        for check in SYNTAX_CHECKS:
            self.assertTrue(result[check], check)

    def test_every_listed_check_is_actually_computed(self):
        """A check named but never set would silently read as a failure."""
        result = check_syntax(AttackGraph.model_validate(CHAIN))
        for check in SYNTAX_CHECKS:
            self.assertIn(check, result)

    def test_technique_count_is_described_not_failed(self):
        """One technique per action violates nothing; Rule 7 decides.

        An earlier version listed "several techniques can be shown" among the
        pass/fail checks, and a real run failed it for having exactly one
        technique on every action.
        """
        self.assertNotIn("several techniques can be shown", SYNTAX_CHECKS)
        self.assertEqual(1, measure_structure(CHAIN).max_techniques)


class GoldTests(unittest.TestCase):
    def setUp(self):
        if not measure_runs.GOLD.is_file():
            self.skipTest("gold fixture missing")

    def test_both_scoring_rules_are_reported(self):
        model = AttackGraph.model_validate(CHAIN)
        scores = score_against_gold(model, measure_runs.GOLD)
        self.assertEqual({"strict", "parent"}, {s.rule for s in scores})

    def test_the_parent_rule_is_never_stricter_than_exact_matching(self):
        """Collapsing sub-techniques can only merge ids, never split them."""
        model = AttackGraph.model_validate(CHAIN)
        strict, parent = score_against_gold(model, measure_runs.GOLD)
        self.assertGreaterEqual(parent.recall, strict.recall)

    def test_disagreements_are_listed_rather_than_hidden(self):
        """The score alone would bury the abstraction difference.

        The reference omits whole branches the reports describe, so techniques
        read from those branches lower precision without being wrong. The
        report has to show which ones.
        """
        model = AttackGraph.model_validate(CHAIN)
        strict = score_against_gold(model, measure_runs.GOLD)[0]
        self.assertTrue(strict.only_gold)
        self.assertIn("T1003.001", strict.only_ours)


class LayoutTests(unittest.TestCase):
    def test_a_missing_report_is_not_an_error(self):
        layout = read_layout(ROOT / "outputs" / "does-not-exist.json")
        self.assertIsNone(layout.pages)

    def test_it_reads_the_runs_own_report(self):
        reports = sorted((ROOT / "outputs").glob("*.layout-quality.json"))
        if not reports:
            self.skipTest("no runs present")
        graph = reports[0].with_name(
            reports[0].name.replace(".layout-quality.json", ".json"))
        if not graph.is_file():
            self.skipTest("no matching graph")
        expected = json.loads(reports[0].read_text(encoding="utf-8"))
        layout = read_layout(graph)
        self.assertEqual(expected["page_count"], layout.pages)
        self.assertEqual(expected["warning_count"], layout.warnings)


class CommandLineTests(unittest.TestCase):
    KNOWN_HISTORICAL = {
        "netscout-stolen-pencil__rules-v1.6__anthropic-claude-sonnet-5_4":
            ["every action has a technique"],
    }

    def test_every_saved_run_conforms_or_is_a_recorded_exception(self):
        """The regression this whole session has been protecting."""
        runs = sorted((ROOT / "outputs").glob("*rules-v1.6*.json"))
        runs = [p for p in runs if not p.name.endswith((
            ".layout-quality.json",
            ".reproducibility.json",
        ))]
        if not runs:
            self.skipTest("no runs present")
        for path in runs:
            with self.subTest(run=path.stem):
                model = AttackGraph.model_validate(
                    json.loads(path.read_text(encoding="utf-8")))
                result = check_syntax(model)
                failed = [c for c in SYNTAX_CHECKS if not result[c]]
                self.assertEqual(
                    self.KNOWN_HISTORICAL.get(path.stem, []), failed)

    def test_the_recorded_exceptions_are_still_real(self):
        """A stale allowance is worse than none: it hides a fixed problem."""
        for stem, expected in self.KNOWN_HISTORICAL.items():
            path = ROOT / "outputs" / f"{stem}.json"
            if not path.is_file():
                continue
            model = AttackGraph.model_validate(
                json.loads(path.read_text(encoding="utf-8")))
            result = check_syntax(model)
            self.assertEqual(
                expected, [c for c in SYNTAX_CHECKS if not result[c]],
                f"{stem} no longer fails what it is recorded as failing")

    def test_it_exits_non_zero_when_a_check_fails(self):
        self.assertEqual(1, main([str(ROOT / "outputs" / "missing.json")]))


if __name__ == "__main__":
    unittest.main()


class ContractSelectionTests(unittest.TestCase):
    """A teaching graph measured against the professional contract reads wrong.

    v1.6 Rule 2 requires a technique on every action. The student rule sets
    answer the same question with abstention, because a narrative a student
    wrote may genuinely not support a defensible mapping, and a blank badge is
    the honest result rather than a guess. The M&S teaching run says in so many
    words that the source does not state how entry was achieved; reporting that
    as a failed check would be reporting the rule set working.
    """

    def test_the_professional_contract_is_the_default(self):
        from measure_runs import SYNTAX_CHECKS, checks_for
        self.assertEqual(SYNTAX_CHECKS, checks_for(student=False))

    def test_the_teaching_contract_drops_only_what_it_should(self):
        from measure_runs import (PROFESSIONAL_ONLY_CHECKS, SYNTAX_CHECKS,
                                  checks_for)
        student = checks_for(student=True)
        self.assertEqual(
            set(SYNTAX_CHECKS) - set(PROFESSIONAL_ONLY_CHECKS), set(student))
        self.assertIn("every action has a technique", PROFESSIONAL_ONLY_CHECKS)

    def test_every_visual_rule_still_applies_to_a_teaching_graph(self):
        """Only the mapping contract differs. The drawing contract does not."""
        from measure_runs import checks_for
        student = checks_for(student=True)
        for check in ("actions are rectangles", "states are ellipses",
                      "annotations are dashed", "every edge runs downward",
                      "AND drawn as a shared bus",
                      "OR drawn as separate edges",
                      "no connector crosses a node"):
            self.assertIn(check, student)

    def test_an_abstaining_graph_passes_the_teaching_contract(self):
        from measure_runs import check_syntax, checks_for
        data = {
            "events": [{"id": "e1", "label": "Gain access to systems",
                        "parents": ["p0"], "tactic": "IA", "techniques": []}],
            "preconditions": [
                {"id": "p0", "label": "Systems reachable", "code": "P0",
                 "parents": []},
                {"id": "p1", "label": "Access obtained", "code": "P1",
                 "parents": ["e1"]},
            ],
        }
        result = check_syntax(AttackGraph.model_validate(data))
        self.assertFalse(result["every action has a technique"])
        self.assertEqual(
            [], [c for c in checks_for(student=True) if not result[c]])
