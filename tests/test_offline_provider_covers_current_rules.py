"""The offline provider must be able to run the rule set the project uses.

The mock exists so the pipeline can be exercised with no API key and no
network. That is only worth anything if it can run the version the work
actually reports. It could not: the mock answered Stage B for v1.4 and for the
evidence path but had no branch for v1.6's construct assignments, so it fell
through to the finished graph, which is not an assignment list, and every
offline v1.6 run died in Stage B.

The defect stayed invisible because the interface offered v1.4 by default, so
the failing combination was reachable but never the one anybody took.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import app  # noqa: E402
from extract import extract_attack_graph  # noqa: E402

REPORT = ("An externally reachable service was exploited. The attacker moved "
          "to other hosts and encrypted them for ransom.")


class OfflineProviderTests(unittest.TestCase):
    def test_every_offered_ruleset_runs_offline(self):
        # Whatever the selector offers, the offline provider must complete it.
        # A version the interface can select but the mock cannot run is a dead
        # combination the user finds only by choosing it.
        for ruleset in app.RULESETS:
            with self.subTest(ruleset=ruleset):
                graph = extract_attack_graph(
                    REPORT, provider="mock", ruleset=ruleset)
                self.assertGreaterEqual(len(graph.events), 1)
                for event in graph.events:
                    self.assertTrue(
                        event.technique or event.techniques,
                        f"{ruleset}: {event.id} came back with no technique")

    def test_the_default_ruleset_is_one_of_the_offered_ones(self):
        self.assertIn(app.DEFAULT_RULESET, app.RULESETS)

    def test_the_frozen_baseline_is_still_offered(self):
        # The comparison baseline has to stay reachable, or the v1.4/v1.6
        # comparison that is the research method cannot be run from the page.
        self.assertIn(app.COMPARISON_BASELINE, app.RULESETS)


if __name__ == "__main__":
    unittest.main()
