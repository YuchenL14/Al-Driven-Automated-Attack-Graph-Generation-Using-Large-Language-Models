"""The prompt and the rule set gave opposite answers about the same example.

Rule 6.2 says to apply the causal test first and only then ask whether the
subject is defensive, and it names "No egress filtering" as a precondition of
exfiltration succeeding. The Stage A prompt asked the defensive question first
-- "does the node describe what the defender does or could have done? That is
an annotation" -- and listed "no egress filtering" among its annotation
examples.

The same phrase, classified two ways, in the two documents the model reads
together. The prompt wins that argument in practice, because it is the
instruction and the rule set is reference material, so absent controls were
being pushed out of the causal graph and into commentary. An annotation takes
no part in the dependency structure, so every such misclassification silently
removes a reason the attack worked.

Both now state the same test in the same order, and neither uses "no egress
filtering" as an annotation.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import STAGE_A_V16_USER, load_ruleset

PROMPT = " ".join(STAGE_A_V16_USER.split())
RULES = " ".join(load_ruleset("v1.6").split())


class AnnotationTestAgreesWithRulesTests(unittest.TestCase):
    def test_the_causal_question_comes_first_in_the_prompt(self):
        causal = PROMPT.index("Would removing this node")
        held = PROMPT.index("already hold it before touching")
        self.assertLess(
            causal, held,
            "Rule 6.2 requires the causal test before any other question")

    def test_the_defender_first_test_is_gone(self):
        self.assertNotIn("defender does or could have done", PROMPT)

    def test_absent_controls_are_preconditions_in_both_documents(self):
        self.assertIn('egress filtering" are preconditions', PROMPT)
        self.assertIn("No egress filtering", RULES)
        self.assertIn("is a precondition of exfiltration", RULES)

    def test_neither_document_offers_an_absent_control_as_an_annotation(self):
        # The failure this guards against is subtle: the phrase may legitimately
        # appear, but never inside the annotation examples.
        for document in (PROMPT, RULES):
            annotation_examples = document[document.index("Examples of annotation")
                                           if "Examples of annotation" in document
                                           else 0:]
            self.assertNotIn('"no egress filtering", "detected',
                             annotation_examples)

    def test_both_documents_say_the_subject_does_not_settle_it(self):
        for document in (PROMPT, RULES):
            self.assertIn("subject being defensive does not settle it", document)

    def test_the_three_roles_are_still_offered(self):
        for role in ("precondition", "external_resource", "annotation"):
            self.assertIn(role, PROMPT)


if __name__ == "__main__":
    unittest.main()
