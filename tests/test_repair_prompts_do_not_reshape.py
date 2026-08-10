"""A repair prompt was asking for a topology it had no reason to ask for.

`is_structural_stage_a_fault` fires for thirteen markers. Eleven of them are
referential or label problems -- a duplicate id, a parent that names no node, a
precondition label too long for its ellipse, a blank field. Two are genuinely
topological. The single correction sent for all thirteen ended with "giving one
connected path from the initial conditions to the final impact", so a label
that did not fit an ellipse instructed the model to restring the whole attack
into a line.

That is the same defect twice over: a gate that repairs one thing while
demanding another, and an instruction that names a target shape instead of a
test. The checks enforce connectivity. They have never enforced a single path,
and a v1.6 graph is explicitly a directed acyclic AND-OR graph, so a repair
prompt must not ask for one.

v1.4's Stage A prompt is the frozen comparison baseline and still contains its
own chain wording. That is deliberate: rewording it would break the comparison
the two-version design exists to make.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (STAGE_A_USER, STAGE_A_V16_USER,
                     _STRUCTURAL_FAULT_MARKERS, is_structural_stage_a_fault)

SOURCE = (ROOT / "src" / "extract.py").read_text(encoding="utf-8")

# Everything except the frozen v1.4 prompt, which keeps its original wording.
SOURCE_WITHOUT_V14_PROMPT = SOURCE.replace(STAGE_A_USER, "")


class RepairPromptsDoNotReshapeTests(unittest.TestCase):
    def test_no_live_prompt_demands_a_single_path(self):
        for phrase in ("one connected path", "Chain the whole attack",
                       "Chain the steps", "must chain"):
            self.assertNotIn(
                phrase, SOURCE_WITHOUT_V14_PROMPT,
                f"{phrase!r} asks for a line, not for the test that decides "
                f"whether two steps are linked")

    def test_the_v14_baseline_keeps_its_own_wording(self):
        # Not an endorsement of the wording: v1.4 is frozen so that v1.4 and
        # v1.6 runs stay comparable.
        self.assertIn("chained into one connected path", STAGE_A_USER)

    def test_v16_prompt_never_had_the_chain_demand(self):
        self.assertNotIn("one connected path", STAGE_A_V16_USER)

    def test_most_structural_markers_are_not_topological(self):
        # If this ever inverts, a blanket topological correction might be
        # defensible. Today it is not: the majority are naming problems.
        topological = {"disconnected pieces", "detached from the attack",
                       "no step follows from another", "contains a cycle"}
        naming = [m for m in _STRUCTURAL_FAULT_MARKERS if m not in topological]
        self.assertGreater(
            len(naming), len(topological),
            "the shared correction is sent to whichever kind dominates")

    def test_a_label_length_fault_still_routes_to_the_structural_repair(self):
        # The routing is unchanged; only what the repair asks for changed.
        self.assertTrue(is_structural_stage_a_fault(
            "this label will not fit inside an ellipse"))
        self.assertTrue(is_structural_stage_a_fault(
            "the graph falls into disconnected pieces"))

    def test_the_structural_repair_still_forbids_dropping_nodes(self):
        # Loosening the topology demand must not loosen the anti-evasion rule.
        self.assertIn("Do not delete a node", SOURCE)

    def test_the_structural_repair_permits_a_report_backed_merge(self):
        # The blanket "Keep every node you already found" made the granularity
        # rule unreachable from the repair path: a model that had split one
        # tool run into two events was forbidden to put it back together.
        self.assertNotIn("Keep every node you already found", SOURCE)
        self.assertIn("You may merge", SOURCE)

    def test_the_merge_permission_matches_the_rule_it_comes_from(self):
        # Prompt and ruleset have to name the same condition, or the prompt is
        # a second, competing rule.
        # The rule set is hard-wrapped, so compare on normalised whitespace.
        ruleset = " ".join((ROOT / "rules" / "ruleset_v1.6.md").read_text(
            encoding="utf-8").split())
        prompt = " ".join(SOURCE.split())
        self.assertIn("One action is one event", ruleset)
        for phrase in ("one tool run", "one command"):
            self.assertIn(phrase, ruleset)
            self.assertIn(phrase, prompt)


if __name__ == "__main__":
    unittest.main()
