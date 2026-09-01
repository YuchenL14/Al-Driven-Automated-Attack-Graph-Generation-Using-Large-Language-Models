"""Scaffolding, chosen over simplification because simplification was tested.

Sherzhanov, Atlam, Azad and Lallie (2024) built a visually enhanced attack
graph -- brighter hues, denser line structures, varied shapes -- and evaluated
it with 83 participants, 37 expert and 46 not. The enhancements did not
significantly improve comprehension among the non-experts, and the paper
recommends structural clarity and conceptual scaffolding instead of appearance.

So the teaching version keeps the professional visual syntax unchanged and adds
two explanations beside the figure. Neither alters the graph, and neither makes
a decision on the student's behalf.

The shortlist is deliberately partial. Persistence carries 113 techniques in
this catalogue and printing all of them would be noise, which is precisely what
the study above found does not help. It narrows by a rule the reader can see
and reject: candidates whose names share a word with what the student wrote.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import _tech_lines_for_tactic
from schema import AttackGraph
from student_feedback import (MAX_SHORTLIST, restate_graph,
                              technique_shortlist)


class ShortlistTests(unittest.TestCase):
    def _for(self, label, evidence, tactic, suggested=None):
        return technique_shortlist(label, evidence, tactic,
                                   _tech_lines_for_tactic(tactic), suggested)

    def test_it_narrows_a_long_list_to_a_readable_one(self):
        """Credential Access alone would otherwise be dozens of lines."""
        full = len([l for l in _tech_lines_for_tactic("CA").splitlines()
                    if l.strip()])
        lines = self._for("Dump LSASS process memory",
                          "dumped LSASS memory for credentials", "CA")
        offered = [l for l in lines if l.strip().startswith("T")]
        self.assertGreater(full, 20, "the fixture must actually be long")
        self.assertLessEqual(len(offered), MAX_SHORTLIST)
        self.assertTrue(offered)

    def test_the_obvious_candidate_is_in_it(self):
        lines = self._for("Dump LSASS process memory",
                          "dumped LSASS memory", "CA")
        self.assertTrue(any("T1003.001" in line for line in lines))

    def test_the_tools_own_suggestion_is_named_as_such(self):
        lines = self._for("Encrypt the file servers", "encrypted servers",
                          "IM", suggested="T1486")
        self.assertIn("Stage B suggested T1486: Data Encrypted for Impact",
                      lines[0])
        self.assertIn("not a choice confirmed on your behalf", lines[0])

    def test_no_suggestion_means_no_such_line(self):
        lines = self._for("Send a phishing email with a link",
                          "sent a phishing email", "IA")
        self.assertFalse(any("the tool suggested" in line for line in lines))

    def test_an_absence_of_overlap_is_reported_rather_than_padded(self):
        """Offering arbitrary candidates would be deciding, quietly."""
        lines = self._for("Move to a file server", "moved", "LM")
        joined = " ".join(lines)
        self.assertIn("no candidate", joined)
        self.assertIn("worth revisiting", joined)
        self.assertFalse(any(line.strip().startswith("T") for line in lines))

    def test_common_words_do_not_drag_everything_in(self):
        """"The attacker used the system" must not match half the catalogue."""
        lines = self._for("The attacker used the system", "used", "PS")
        self.assertIn("no candidate", " ".join(lines))

    def test_it_reads_the_list_stage_b_was_given(self):
        candidates = _tech_lines_for_tactic("IA")
        lines = technique_shortlist("Send a phishing email", "phishing", "IA",
                                    candidates)
        for line in lines:
            if line.strip().startswith("T"):
                self.assertIn(line.strip(), candidates)


CHAIN = AttackGraph.model_validate({
    "events": [
        {"id": "e1", "label": "Sign in to the gateway", "parents": ["p_mfa"],
         "tactic": "IA", "techniques": ["T1133"]},
        {"id": "e2", "label": "Move to a file server", "parents": ["p_in"],
         "tactic": "LM", "techniques": ["T1021.001"]},
    ],
    "preconditions": [
        {"id": "p_mfa", "label": "Gateway lacked MFA", "code": "P0",
         "parents": []},
        {"id": "p_in", "label": "Remote access obtained", "code": "P1",
         "parents": ["e1"]},
        {"id": "p_fs", "label": "File server reached", "code": "P2",
         "parents": ["e2"]},
        {"id": "a1", "label": "Detected on day 4", "code": "A1",
         "role": "annotation", "style": "dashed", "parents": ["e2"]},
    ],
})


class RestatementTests(unittest.TestCase):
    def test_one_sentence_per_action(self):
        lines = restate_graph(CHAIN)
        self.assertEqual(3, len(lines))

    def test_it_names_what_enabled_the_step_and_what_it_produced(self):
        first = restate_graph(CHAIN)[0]
        self.assertIn("Gateway lacked MFA", first)
        self.assertIn("Sign in to the gateway", first)
        self.assertIn("Remote access obtained", first)

    def test_an_and_reads_as_together(self):
        data = CHAIN.model_dump()
        data["events"][0]["parents"] = ["p_mfa", "p_in"]
        data["events"][0]["join"] = "AND"
        data["preconditions"][1]["parents"] = []
        lines = restate_graph(AttackGraph.model_validate(data))
        self.assertIn("together made", lines[0])

    def test_an_or_reads_as_either(self):
        data = CHAIN.model_dump()
        data["events"][0]["parents"] = ["p_mfa", "p_in"]
        data["events"][0]["join"] = "OR"
        data["preconditions"][1]["parents"] = []
        lines = restate_graph(AttackGraph.model_validate(data))
        self.assertIn("either of", lines[0])
        self.assertIn("was enough", lines[0])

    def test_a_root_action_says_it_needed_nothing_in_the_graph(self):
        data = CHAIN.model_dump()
        data["events"][0]["parents"] = []
        lines = restate_graph(AttackGraph.model_validate(data))
        self.assertIn("needed nothing already in the graph", lines[0])

    def test_an_annotation_is_reported_as_beside_the_attack(self):
        lines = restate_graph(CHAIN)
        self.assertIn("Beside the attack, not part of it", lines[-1])
        self.assertIn("Detected on day 4", lines[-1])

    def test_an_annotation_is_never_read_as_a_result(self):
        """It hangs off e2 and must not appear as something e2 produced."""
        second = [l for l in restate_graph(CHAIN)
                  if "Move to a file server" in l][0]
        self.assertNotIn("Detected on day 4", second)

    def test_it_adds_no_claim_the_graph_does_not_make(self):
        """Every quoted phrase must be a label that exists."""
        import re
        labels = {node.label for node in CHAIN.preconditions}
        labels |= {event.label for event in CHAIN.events}
        for line in restate_graph(CHAIN):
            for quoted in re.findall(r'"([^"]+)"', line):
                self.assertIn(quoted, labels)

    def test_an_empty_graph_produces_nothing(self):
        empty = AttackGraph.model_validate({"events": [],
                                            "preconditions": []})
        self.assertEqual((), restate_graph(empty))


if __name__ == "__main__":
    unittest.main()
