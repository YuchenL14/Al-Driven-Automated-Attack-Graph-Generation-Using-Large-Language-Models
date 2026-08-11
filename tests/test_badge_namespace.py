"""The event badge speaks a chosen vocabulary, not an assumed one.

The supervisor's fixture records `supervisor_visual_phase: R W D E I C A` on 26
of its 32 nodes and an ATT&CK tactic on 2. That is the Lockheed Martin Cyber
Kill Chain. This tool badged the ATT&CK tactic unconditionally, so the two
notations disagreed on most of the diagram with no way to reconcile them.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from schema import (ATTACK_TACTICS, AttackGraph, KILL_CHAIN_PHASES,
                    TACTIC_TO_KILL_CHAIN, kill_chain_phase)
from visual_syntax import (AGVS_SP_V1, AGVS_SP_V1_KILL_CHAIN, active_profile,
                           project_visual_nodes)


def _graph() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "badges",
        "preconditions": [{"id": "s1", "label": "Service exposed",
                           "code": "IA", "parents": []}],
        "events": [{"id": "e1", "label": "Exploit the service", "tactic": "IA",
                    "technique": "T1190", "mitigations": ["M1051"],
                    "likelihood": 6.0, "parents": ["s1"], "join": "AND"}]})


class TestMapping(unittest.TestCase):

    def test_every_attack_tactic_has_a_phase(self):
        self.assertEqual(set(TACTIC_TO_KILL_CHAIN), set(ATTACK_TACTICS))

    def test_every_phase_used_is_a_real_kill_chain_phase(self):
        self.assertTrue(
            set(TACTIC_TO_KILL_CHAIN.values()) <= set(KILL_CHAIN_PHASES))

    def test_the_mapping_matches_the_fixtures_vocabulary(self):
        """R W D E I C A, exactly the letters the reference uses."""
        self.assertEqual(set(KILL_CHAIN_PHASES),
                         {"R", "W", "D", "E", "I", "C", "A"})

    def test_it_is_many_to_one_as_the_two_models_require(self):
        self.assertLess(len(set(TACTIC_TO_KILL_CHAIN.values())),
                        len(TACTIC_TO_KILL_CHAIN))

    def test_an_unknown_tactic_yields_no_phase(self):
        self.assertIsNone(kill_chain_phase("ZZ"))


class TestProfileSelection(unittest.TestCase):

    def test_the_default_badges_the_supervisor_s_vocabulary(self):
        # This assertion used to read AGVS_SP_V1, because the tool badged the
        # ATT&CK tactic and the kill chain was the option. The reference
        # diagram badges the kill-chain phase on 26 of its 32 nodes and a
        # tactic on 2, so conformance to that figure means the kill chain is
        # the default and the tactic is the option. The constant and this test
        # were changed together rather than leaving a test asserting a default
        # the tool no longer has.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGVS_BADGE_SOURCE", None)
            self.assertIs(active_profile(), AGVS_SP_V1_KILL_CHAIN)

    def test_the_attack_tactic_profile_is_still_selectable(self):
        # The v1.4/v1.6 comparison needs both vocabularies reachable.
        with patch.dict(os.environ, {"AGVS_BADGE_SOURCE": "attack_tactic"}):
            self.assertIs(active_profile(), AGVS_SP_V1)

    def test_the_kill_chain_profile_is_selectable(self):
        with patch.dict(os.environ,
                        {"AGVS_BADGE_SOURCE": "kill_chain_phase"}):
            self.assertIs(active_profile(), AGVS_SP_V1_KILL_CHAIN)

    def test_an_invalid_selection_is_refused(self):
        with patch.dict(os.environ, {"AGVS_BADGE_SOURCE": "nonsense"}):
            with self.assertRaises(ValueError):
                active_profile()

    def test_only_the_badge_differs_between_the_profiles(self):
        for field in ("flow_direction", "event_shape", "state_shape",
                      "and_notation", "or_notation"):
            self.assertEqual(getattr(AGVS_SP_V1, field),
                             getattr(AGVS_SP_V1_KILL_CHAIN, field))


class TestProjection(unittest.TestCase):

    def test_the_tactic_badge_is_the_default(self):
        node = next(n for n in project_visual_nodes(_graph(), AGVS_SP_V1)
                    if n.id == "e1")
        self.assertEqual((node.badge_code, node.badge_namespace),
                         ("IA", "attack_tactic"))

    def test_the_kill_chain_badge_replaces_it(self):
        node = next(n for n in project_visual_nodes(
            _graph(), AGVS_SP_V1_KILL_CHAIN) if n.id == "e1")
        self.assertEqual((node.badge_code, node.badge_namespace),
                         ("D", "kill_chain_phase"))

    def test_the_canonical_tactic_is_untouched_either_way(self):
        """The badge is presentation; the graph still records IA."""
        graph = _graph()
        project_visual_nodes(graph, AGVS_SP_V1_KILL_CHAIN)
        self.assertEqual(graph.events[0].tactic, "IA")

    def test_a_kill_chain_letter_is_never_drawn_on_a_state(self):
        """Same overload argument that removed tactics from ellipses.

        The state now badges its own three-symbol vocabulary, so the check is
        no longer that an ellipse badges nothing but that it never badges a
        letter belonging to the action vocabulary. A stored ``W`` is kept in
        the canonical graph and not drawn.
        """
        graph = AttackGraph.model_validate({
            "title": "overload", "preconditions": [
                {"id": "s1", "label": "Weaponised payload", "code": "W",
                 "parents": []}],
            "events": [{"id": "e1", "label": "Deliver payload", "tactic": "IA",
                        "technique": "T1190", "mitigations": ["M1051"],
                        "likelihood": 6.0, "parents": ["s1"], "join": "AND"}]})
        node = next(n for n in project_visual_nodes(
            graph, AGVS_SP_V1_KILL_CHAIN) if n.id == "s1")
        self.assertEqual("PRE", node.badge_code)
        self.assertNotIn(node.badge_code, KILL_CHAIN_PHASES)
        self.assertEqual("W", graph.preconditions[0].code)

    def test_every_state_badge_comes_from_the_closed_vocabulary(self):
        """Two graphs cannot disagree about what an ellipse badge means."""
        graph = AttackGraph.model_validate({
            "title": "vocabulary", "preconditions": [
                {"id": "s1", "label": "Service reachable", "code": "ANYTHING",
                 "parents": []},
                {"id": "s2", "label": "Access obtained", "code": "RESULT7",
                 "parents": ["e1"]},
                {"id": "s3", "label": "Stolen certificate held",
                 "code": "EXT-RES", "role": "external_resource",
                 "parents": []},
                {"id": "s4", "label": "AV blocked part of it", "code": "NOTE9",
                 "role": "annotation", "style": "dashed",
                 "parents": ["e1"]}],
            "events": [{"id": "e1", "label": "Deliver payload", "tactic": "IA",
                        "technique": "T1190", "mitigations": ["M1051"],
                        "likelihood": 6.0, "parents": ["s1"], "join": "AND"}]})
        badges = {node.id: node.badge_code
                  for node in project_visual_nodes(graph)
                  if node.kind in {"state", "annotation"}}
        self.assertEqual(
            {"s1": "PRE", "s2": "RES", "s3": "EXT", "s4": None}, badges)


if __name__ == "__main__":
    unittest.main()
