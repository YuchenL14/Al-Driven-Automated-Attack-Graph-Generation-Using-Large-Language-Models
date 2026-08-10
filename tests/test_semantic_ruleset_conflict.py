"""Selecting v1.6 and the semantic pipeline together must not fail silently.

`extract_attack_graph_semantic` takes no ruleset argument at all, so ticking
the semantic checkbox discards whichever version the dropdown shows. For v1.4
and v1.5 that is a documented experimental override. For v1.6 it is a
contradiction: the semantic draft has no external resource, no annotation and
no dotted branch, which is the whole of v1.6.
"""

import inspect
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import app
from extract import extract_attack_graph_semantic, is_construct_ruleset


class TestConstructRulesetPredicate(unittest.TestCase):

    def test_v16_needs_the_constructs(self):
        self.assertTrue(is_construct_ruleset("v1.6"))

    def test_earlier_versions_do_not(self):
        for ruleset in ("v1", "v1.3", "v1.4", "v1.5", "student-v1.2"):
            with self.subTest(ruleset=ruleset):
                self.assertFalse(is_construct_ruleset(ruleset))


class TestTheConflictIsReal(unittest.TestCase):

    def test_the_semantic_entry_point_takes_no_ruleset(self):
        """If it ever gains one, this guard should be revisited."""
        self.assertNotIn(
            "ruleset",
            inspect.signature(extract_attack_graph_semantic).parameters)


class TestAppRefusesTheCombination(unittest.TestCase):

    def setUp(self):
        app.app.config["TESTING"] = True
        self.client = app.app.test_client()

    def _post(self, ruleset: str, semantic: bool):
        data = {"ruleset": ruleset, "report_name": "does-not-exist.pdf"}
        if semantic:
            data["semantic_mode"] = "1"
        return self.client.post("/generate", data=data)

    def test_v16_plus_semantic_is_reported_to_the_user(self):
        body = self._post("v1.6", semantic=True).get_data(as_text=True)
        self.assertIn("semantic", body.lower())

    def test_the_message_says_how_to_resolve_it(self):
        body = self._post("v1.6", semantic=True).get_data(as_text=True)
        self.assertTrue("untick" in body.lower() or "v1.4" in body,
                        "the refusal must name a way forward")

    def test_v14_plus_semantic_is_not_blocked_by_this_rule(self):
        """The documented experimental override stays available."""
        body = self._post("v1.4", semantic=True).get_data(as_text=True)
        self.assertNotIn("cannot express the v1.6 constructs", body)


if __name__ == "__main__":
    unittest.main()
