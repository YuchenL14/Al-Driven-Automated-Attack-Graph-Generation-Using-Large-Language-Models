"""One join, one logic, and some events need two.

`join` sits on the event, so every input of that event shares one relation.
That is enough while all the inputs play the same part. A British Library run
produced a remote login that needed a credential obtained EITHER by phishing OR
by brute force, AND a reachable server, AND a missing MFA control, and marked
the whole event OR. Read literally, the graph then claims the missing control
alone was enough to log in. Marking it AND would have claimed the adversary had
to phish and brute-force both. Neither value is right, so this is not a wrong
choice by the model: it is a shape that cannot be written that way at all.

It can be written the other way, and the literature says how. Logical attack
graphs (MulVAL, Ou et al. 2005) put conjunction on the action and disjunction
on the state: a derivation node needs all of its inputs, a derived fact is
established by any of its producers. Alternatives therefore belong in a shared
state that each alternative produces, and the consuming event is AND. This
schema already expresses that -- several runs have states with three and eight
producers -- so no change to the data model was needed, only a rule that says
where an OR lives and a gate that enforces it.

The test is mechanical: a state with no producer is an initial condition of the
incident, and cannot be an alternative to anything, because nothing in the graph
could have produced it instead. An OR event consuming one is mixing "either of
these routes" with "and this had to hold". Measured over five real runs, that
separates the one wrong graph from six correct ORs.
"""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (_mixed_join_problems, is_mixed_join_fault,
                     is_structural_stage_a_fault)

CORRECT = {
    "events": [
        {"id": "e_phish", "label": "Phish for privileged credentials",
         "parents": [], "tactic": "CA", "techniques": ["T1566"]},
        {"id": "e_brute", "label": "Brute force the account password",
         "parents": [], "tactic": "CA", "techniques": ["T1110"]},
        {"id": "e_login", "label": "Authenticate to the server remotely",
         "parents": ["p_creds", "p_reachable", "p_no_mfa"],
         "tactic": "IA", "techniques": ["T1133"], "join": "AND"},
    ],
    "preconditions": [
        {"id": "p_reachable", "label": "Server reachable externally",
         "code": "P1", "parents": []},
        {"id": "p_no_mfa", "label": "MFA not enabled on the server",
         "code": "P2", "parents": []},
        {"id": "p_creds", "label": "Privileged credentials obtained",
         "code": "P3", "parents": ["e_phish", "e_brute"]},
        {"id": "p_in", "label": "Foothold on the network",
         "code": "P4", "parents": ["e_login"]},
    ],
}


def _broken() -> dict:
    """The shape the run actually produced: two states, OR on the consumer."""

    data = copy.deepcopy(CORRECT)
    data["preconditions"] = [
        node for node in data["preconditions"] if node["id"] != "p_creds"
    ] + [
        {"id": "p_creds_a", "label": "Credentials obtained by phishing",
         "code": "P3", "parents": ["e_phish"]},
        {"id": "p_creds_b", "label": "Credentials guessed by brute force",
         "code": "P5", "parents": ["e_brute"]},
    ]
    login = next(e for e in data["events"] if e["id"] == "e_login")
    login["parents"] = ["p_creds_a", "p_creds_b", "p_reachable", "p_no_mfa"]
    login["join"] = "OR"
    return data


class MixedJoinTests(unittest.TestCase):
    def test_the_shape_rule_3_asks_for_is_accepted(self):
        self.assertEqual([], _mixed_join_problems(CORRECT))

    def test_an_or_over_initial_conditions_is_rejected(self):
        problems = _mixed_join_problems(_broken())
        self.assertEqual(1, len(problems))
        self.assertIn("e_login", problems[0])
        self.assertIn("initial condition", problems[0])

    def test_the_correction_names_the_repair(self):
        problem = _mixed_join_problems(_broken())[0]
        self.assertIn("join to AND", problem)
        self.assertIn("merge them into ONE state", problem)

    def test_a_genuine_or_between_two_produced_states_is_left_alone(self):
        """WannaCry's lateral transfer: either compromise route will do."""
        data = {
            "events": [
                {"id": "e_smb", "label": "Exploit SMB on discovered hosts",
                 "parents": ["p_hosts"], "tactic": "LM",
                 "techniques": ["T1210"]},
                {"id": "e_rdp", "label": "Propagate via remote services",
                 "parents": ["p_hosts"], "tactic": "LM",
                 "techniques": ["T1210"]},
                {"id": "e_move", "label": "Transfer malware copies laterally",
                 "parents": ["p_smb_hosts", "p_rdp_hosts"], "tactic": "LM",
                 "techniques": ["T1570"], "join": "OR"},
            ],
            "preconditions": [
                {"id": "p_hosts", "label": "Hosts enumerated", "code": "P0",
                 "parents": []},
                {"id": "p_smb_hosts", "label": "Hosts compromised via SMB",
                 "code": "P1", "parents": ["e_smb"]},
                {"id": "p_rdp_hosts", "label": "Hosts compromised via RDP",
                 "code": "P2", "parents": ["e_rdp"]},
                {"id": "p_moved", "label": "Malware copies transferred",
                 "code": "P3", "parents": ["e_move"]},
            ],
        }
        self.assertEqual([], _mixed_join_problems(data))

    def test_a_single_input_or_is_not_flagged(self):
        """One input cannot be a mix of anything."""
        data = copy.deepcopy(CORRECT)
        login = next(e for e in data["events"] if e["id"] == "e_login")
        login["parents"] = ["p_reachable"]
        login["join"] = "OR"
        self.assertEqual([], _mixed_join_problems(data))

    def test_an_and_event_is_never_flagged(self):
        data = copy.deepcopy(CORRECT)
        login = next(e for e in data["events"] if e["id"] == "e_login")
        login["join"] = "AND"
        self.assertEqual([], _mixed_join_problems(data))


class RoutingTests(unittest.TestCase):
    def test_it_routes_to_its_own_correction(self):
        message = "; ".join(_mixed_join_problems(_broken()))
        self.assertTrue(is_mixed_join_fault(message))

    def test_it_does_not_route_to_the_structural_repair(self):
        """Those two corrections contradict each other.

        The structural repair says "do not delete a node". Repairing a mixed
        join means merging two states into one, which removes a node. Sending
        this fault there would hand the model both instructions at once.
        """
        message = "; ".join(_mixed_join_problems(_broken()))
        self.assertFalse(is_structural_stage_a_fault(message))


class RealRunTests(unittest.TestCase):
    """Five runs: one wrong graph, six correct ORs."""

    CASES = {
        "Case-Study_WannaCry__rules-v1.6__anthropic-claude-sonnet-5_1": False,
        "Case-Study_WannaCry__rules-v1.6__anthropic-claude-sonnet-5_2": False,
        "netscout-stolen-pencil__rules-v1.6__anthropic-claude-sonnet-5_8": False,
        "netscout-stolen-pencil__rules-v1.6__anthropic-claude-sonnet-5_9": False,
        "british-library-cyber-incident-review-8-march-2024__rules-v1.6"
        "__anthropic-claude-sonnet-5_1": True,
    }

    def test_it_separates_the_real_runs(self):
        seen = 0
        for stem, should_fire in self.CASES.items():
            path = ROOT / "outputs" / f"{stem}.json"
            if not path.is_file():
                continue
            seen += 1
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(should_fire, bool(_mixed_join_problems(data)),
                             f"{stem}")
        if not seen:
            self.skipTest("no runs present")


if __name__ == "__main__":
    unittest.main()
