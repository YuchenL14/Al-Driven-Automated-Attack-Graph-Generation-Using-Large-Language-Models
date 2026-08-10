import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from schema import AttackGraph  # noqa: E402
from student_coverage import audit_source_coverage  # noqa: E402
import student_app  # noqa: E402


class StudentSourceCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        graph_path = ROOT / "outputs" / (
            "student_submission_18__rules-student-v1.3__"
            "anthropic-claude-sonnet-5_1.json"
        )
        cls.graph = AttackGraph.model_validate_json(
            graph_path.read_text(encoding="utf-8")
        )
        cls.narrative = (ROOT / "reports" / "student_submission_18.txt").read_text(
            encoding="utf-8"
        )

    def test_real_run_18_classifies_every_source_statement(self):
        audit = audit_source_coverage(self.narrative, self.graph)

        self.assertEqual(10, len(audit.items))
        self.assertEqual(2, audit.count("event"))
        self.assertEqual(7, audit.count("state"))
        self.assertEqual(1, audit.count("context"))
        self.assertEqual(0, audit.count("unrepresented"))

    def test_actor_action_drawn_only_as_root_state_is_flagged(self):
        audit = audit_source_coverage(self.narrative, self.graph)
        first = audit.items[0]

        self.assertEqual("state", first.kind)
        self.assertEqual(("Initial access to M&S systems",), first.graph_labels)
        self.assertTrue(first.needs_action_review)
        self.assertEqual((first,), audit.warnings)

    def test_report_limitation_is_context_not_missing_action(self):
        audit = audit_source_coverage(self.narrative, self.graph)
        limitation = next(item for item in audit.items
                          if "does not state how" in item.source)

        self.assertEqual("context", limitation.kind)
        self.assertFalse(limitation.needs_action_review)

    def test_attack_ids_and_filename_do_not_split_sentences(self):
        audit = audit_source_coverage(self.narrative, self.graph)
        ntds = next(item for item in audit.items if "T1003.003" in item.source)

        self.assertIn("NTDS.dit", ntds.source)
        self.assertEqual("event", ntds.kind)
        self.assertEqual(("Steal NTDS.dit file",), ntds.graph_labels)

    def test_audit_does_not_mutate_graph(self):
        before = self.graph.model_dump_json()
        audit_source_coverage(self.narrative, self.graph)
        self.assertEqual(before, self.graph.model_dump_json())

    def test_student_page_displays_non_blocking_state_only_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            rendered = outputs / "student-test.png"
            with patch.object(student_app, "REPORTS_DIR", reports), patch.object(
                    student_app, "OUTPUTS_DIR", outputs), patch.object(
                    student_app, "extract_attack_graph", return_value=self.graph), patch.object(
                    student_app, "render_split", return_value=[str(rendered)]):
                response = student_app.app.test_client().post(
                    "/generate", data={"scenario": self.narrative})

        self.assertEqual(200, response.status_code)
        self.assertIn(b"Check the source coverage", response.data)
        self.assertIn(b"represents it only as the state", response.data)
        self.assertIn(b"Initial access to M&amp;S systems", response.data)
        self.assertIn(b"non-blocking teaching check", response.data)

    def test_professional_application_does_not_import_student_coverage(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("student_coverage", source)


if __name__ == "__main__":
    unittest.main()


class NormalisationTests(unittest.TestCase):
    """Two faults in one three-line function, found by reading it rather than
    by a failing test, because both were silent.

    The first was dead. An expansion for one named organisation matched on an
    ampersand that the line above had already replaced, so it could never fire.
    It is gone rather than repaired: hard-coding a single company into a
    general teaching tool is not something a dead line earns back, and the
    statement pair it was meant to join still matches on other words.

    The second was worse than dead, because it fired when it should not have.
    "AD" expanded to Active Directory regardless of case, so "a malicious ad
    network" became "a malicious active directory network". Malvertising is a
    real intrusion route and one of this project's own sample reports carries a
    malicious advert, so the substitution could corrupt a genuine match.
    Expansion now happens before case is discarded, which is the only signal
    that separates the initialism from the English word.
    """

    def test_the_initialism_still_expands(self):
        from student_coverage import _normalise_text
        self.assertIn("active directory",
                      _normalise_text("AD password hashes"))

    def test_the_english_word_is_left_alone(self):
        from student_coverage import _normalise_text
        for phrase in ("a malicious ad network", "the ad was malicious",
                       "an ad server"):
            self.assertNotIn("active directory", _normalise_text(phrase),
                             f"{phrase!r} is about advertising")

    def test_a_longer_word_beginning_with_ad_is_untouched(self):
        from student_coverage import _normalise_text
        self.assertNotIn("active directory", _normalise_text("ADMIN account"))
        self.assertNotIn("active directory", _normalise_text("adware found"))

    def test_no_organisation_is_hard_coded_any_more(self):
        import student_coverage
        source = Path(student_coverage.__file__).read_text(encoding="utf-8")
        body = source.split('"""', 2)[-1]
        for name in ("marks and spencer", "m&s"):
            self.assertNotIn(name, body.lower(),
                             "a single company must not be wired in")

    def test_the_pair_it_used_to_join_still_matches(self):
        """Deleting it changed nothing, which is why deleting it was safe."""
        from student_coverage import _tokens
        shared = (_tokens("Initial access to M&S systems")
                  & _tokens("Attackers first gained access to Marks and "
                            "Spencer systems"))
        self.assertGreaterEqual(len(shared), 2)

    def test_no_canonical_entry_maps_a_word_to_itself(self):
        from student_coverage import _CANONICAL
        self.assertEqual(
            [], [k for k, v in _CANONICAL.items() if k == v],
            "an identity mapping does nothing and hides the table's purpose")
