"""Every rule set on disk must reach the pipeline it was written for.

v1.6 was written entirely as a hierarchical rule set, but the dispatcher used
an allowlist of hierarchical versions and nobody added it. The run reached the
single-stage path, put the whole ATT&CK catalogue into one prompt, and died on
an HTTP read timeout that looked like a network fault. These tests fail if the
routing table and the rules folder ever disagree again.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import extract
from extract import (AttackGraph, AttackGraphSkeleton,
                     ConstructAttackGraphSkeleton, EvidenceGraphWire,
                     StudentEvidenceGraph, TechniqueAssignmentsWire,
                     _ASSIGNMENT_MODELS, _graph_response_tokens,
                     _SMALL_RESPONSE_TOKENS, is_single_stage_ruleset)


def _rulesets_on_disk() -> list[str]:
    return sorted(path.stem.replace("ruleset_", "")
                  for path in (ROOT / "rules").glob("ruleset_*.md"))


class TestRouting(unittest.TestCase):

    def test_every_ruleset_after_v13_is_hierarchical(self):
        legacy = {"v1", "v1.1", "v1.2", "v1.3"}
        for ruleset in _rulesets_on_disk():
            with self.subTest(ruleset=ruleset):
                self.assertEqual(is_single_stage_ruleset(ruleset),
                                 ruleset in legacy)

    def test_v16_is_hierarchical(self):
        self.assertFalse(is_single_stage_ruleset("v1.6"))

    def test_the_frozen_legacy_versions_stay_legacy(self):
        for ruleset in ("v1", "v1.1", "v1.2", "v1.3"):
            self.assertTrue(is_single_stage_ruleset(ruleset))

    def test_a_prefix_of_a_legacy_name_is_not_legacy(self):
        """'v1.4'.startswith('v1') is true; the test must be equality."""
        for ruleset in ("v1.4", "v1.5", "v1.6", "v1.10"):
            self.assertFalse(is_single_stage_ruleset(ruleset))

    def test_an_unknown_future_version_defaults_to_hierarchical(self):
        for ruleset in ("v1.7", "v2", "v3.1", "student-v1.3"):
            self.assertFalse(is_single_stage_ruleset(ruleset))

    def test_app_offers_no_ruleset_the_router_mishandles(self):
        import app
        for ruleset in app.RULESETS:
            with self.subTest(ruleset=ruleset):
                self.assertIn(ruleset, _rulesets_on_disk())


class TestOutputBudget(unittest.TestCase):
    """A graph-shaped response must never be given the assignment budget."""

    def test_graph_models_are_not_in_the_small_table(self):
        for model in (AttackGraph, AttackGraphSkeleton,
                      ConstructAttackGraphSkeleton, EvidenceGraphWire,
                      StudentEvidenceGraph):
            with self.subTest(model=model.__name__):
                self.assertNotIn(model, _ASSIGNMENT_MODELS)

    def test_assignment_models_are_listed(self):
        self.assertIn(TechniqueAssignmentsWire, _ASSIGNMENT_MODELS)

    def test_an_unregistered_model_gets_the_generous_default(self):
        """Omission must cost tokens, never truncate a graph mid-structure."""

        class FutureGraphWire:
            pass

        self.assertNotIn(FutureGraphWire, _ASSIGNMENT_MODELS)
        self.assertGreater(_graph_response_tokens(), _SMALL_RESPONSE_TOKENS)

    def test_timeout_allows_a_full_length_graph_response(self):
        self.assertGreaterEqual(extract._REQUEST_TIMEOUT_S, 300.0)


if __name__ == "__main__":
    unittest.main()
