"""What reaches the model must be rules, not notes to whoever edits the file.

Every rule file opens with an HTML comment holding its changelog, guidance for
the next maintainer, and the history of abandoned versions. All of it was being
sent as part of the system prompt: 4,596 characters of v1.4's prompt, about a
third of it, none addressed to the model. Before reading Rule 1 the model read
why v1.2 had been abandoned for returning an empty graph, and this project's
own notes about what the supervisor's diagram does.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import load_ruleset

VERSIONS = sorted(p.stem.replace("ruleset_", "")
                  for p in (ROOT / "rules").glob("ruleset_*.md"))
COMMENT = re.compile(r"<!--.*?-->", re.S)


class TestNoMaintainerCommentaryReachesTheModel(unittest.TestCase):

    def test_every_ruleset_loads_without_comment_markers(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                self.assertNotIn("<!--", load_ruleset(
                    version, include_full_catalogue=False))

    def test_the_commentary_stays_in_the_file(self):
        """It is documentation; it belongs on disk, just not in the prompt."""
        raw = (ROOT / "rules" / "ruleset_v1.4.md").read_text(encoding="utf-8")
        self.assertIn("<!--", raw)
        self.assertIn("CHANGELOG", raw)

    def test_abandoned_version_history_is_not_sent(self):
        """v1.4's prompt told the model that v1.2 had returned an empty graph."""
        loaded = load_ruleset("v1.4", include_full_catalogue=False)
        for leaked in ("Why v1.2 was set aside", "Planned next step",
                       "CHANGELOG"):
            self.assertNotIn(leaked, loaded)

    def test_v16_never_describes_the_target_graph_to_the_model(self):
        """The model must not be told what the reference graph looks like.

        Rule 7 carried "the supervisor's reference diagram carries seven
        techniques on one node", Rule 6.1 named its external-resource
        metadata, and Rule 4 named its five terminal states. Each was a
        description of the answer, handed to the model that produces the
        answer, in a tool then evaluated against that same graph.

        An earlier version of this test searched only the text BEFORE Rule 7
        and passed while the leak sat inside it, so the whole prompt is
        searched here.
        """
        loaded = load_ruleset("v1.6", include_full_catalogue=False)
        for leak in ("Note for the dissertation", "would measure the tuning",
                     "supervisor", "reference diagram", "ends in five",
                     "seven techniques"):
            self.assertNotIn(leak, loaded,
                             f"{leak!r} describes the target graph to the model")

    def test_naming_the_notation_is_still_allowed(self):
        """The distinction is what is being described, not that the sample is
        mentioned. "Preconditions are ellipses" is a notation instruction and
        belongs in the rules; "the reference has ten roots" is the answer."""
        loaded = load_ruleset("v1.5", include_full_catalogue=False)
        self.assertIn("visual contract", loaded)

    def test_the_rules_themselves_all_survive(self):
        """Stripping must remove commentary and nothing else."""
        loaded = load_ruleset("v1.6", include_full_catalogue=False)
        for heading in ("## Rule 1", "## Rule 2", "## Rule 3", "## Rule 4",
                        "## Rule 5", "## Rule 6", "## Rule 7"):
            self.assertIn(heading, loaded)
        self.assertIn("Return only the structured object", loaded)

    def test_placeholders_are_still_substituted(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                loaded = load_ruleset(version, include_full_catalogue=False)
                self.assertIsNone(
                    re.search(r"\{(tactic|tech|miti)_lines\}", loaded))

    def test_a_ruleset_never_arrives_empty(self):
        """A stripping bug that ate the rules would otherwise pass silently.

        Professional versions head their sections "## Rule 1"; the student
        versions use "## 1." instead, so the check is for numbered sections
        rather than for one project's wording.
        """
        for version in VERSIONS:
            with self.subTest(version=version):
                loaded = load_ruleset(version, include_full_catalogue=False)
                self.assertGreater(len(loaded), 2000)
                sections = re.findall(r"^## (?:Rule )?\d", loaded, re.M)
                self.assertGreaterEqual(
                    len(sections), 4,
                    f"{version} kept only {len(sections)} numbered sections")


class TestSavings(unittest.TestCase):

    def test_the_versions_that_carried_commentary_got_shorter(self):
        for version in ("v1.4", "v1.6"):
            with self.subTest(version=version):
                raw = (ROOT / "rules" / f"ruleset_{version}.md").read_text(
                    encoding="utf-8")
                removed = len("".join(COMMENT.findall(raw)))
                self.assertGreater(removed, 4000)


if __name__ == "__main__":
    unittest.main()
