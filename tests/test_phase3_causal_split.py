"""Phase 3 causal-pagination tests.

The fixtures are small structural oracles derived from the three evaluation
reports. They do not claim to be new LLM extractions of those reports; they
exercise the graph shapes that the reports contribute to the test plan:

* British Library: alternative entry methods and parallel impacts;
* WannaCry: a long propagation chain followed by several consequences;
* M&S: incident-specific evidence separated from unrelated actor context.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import networkx as nx


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from causal_split import (continuation_labels, materialize_split_part,  # noqa: E402
                          plan_causal_split, validate_lossless_split)
from attack_graph import build_digraph  # noqa: E402
from schema import AttackGraph  # noqa: E402


def _british_library_shape() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "British Library structural oracle",
        "preconditions": [
            {"id": "p_remote", "label": "Legacy remote access server", "code": "R"},
            {"id": "p_no_mfa", "label": "Legacy system without MFA", "code": "R"},
            {"id": "p_phish", "label": "Phishing route available", "code": "RS"},
            {"id": "p_brute", "label": "Brute force route available", "code": "RS"},
            {
                "id": "p_credentials",
                "label": "Valid credentials obtained",
                "code": "R",
                "parents": ["e_phish", "e_brute"],
            },
            {
                "id": "p_foothold",
                "label": "Internal foothold established",
                "code": "R",
                "parents": ["e_login"],
            },
            {
                "id": "p_scope",
                "label": "Broad internal access established",
                "code": "R",
                "parents": ["e_discover"],
            },
            {
                "id": "p_data",
                "label": "Sensitive data collected",
                "code": "R",
                "parents": ["e_collect"],
            },
            {
                "id": "p_exfiltrated",
                "label": "Data exfiltrated",
                "code": "R",
                "parents": ["e_exfiltrate"],
            },
            {
                "id": "p_encrypted",
                "label": "Systems encrypted",
                "code": "R",
                "parents": ["e_encrypt"],
            },
            {
                "id": "p_extorted",
                "label": "Extortion demand issued",
                "code": "R",
                "parents": ["e_extort"],
            },
        ],
        "events": [
            {
                "id": "e_phish",
                "label": "Attempt phishing for credentials",
                "tactic": "IA",
                "parents": ["p_phish"],
            },
            {
                "id": "e_brute",
                "label": "Attempt brute force for credentials",
                "tactic": "CA",
                "technique": "T1110",
                "mitigations": ["M1027"],
                "likelihood": 4.0,
                "parents": ["p_brute"],
            },
            {
                "id": "e_login",
                "label": "Authenticate to remote access server",
                "tactic": "IA",
                "technique": "T1078",
                "mitigations": ["M1032"],
                "likelihood": 7.0,
                "parents": ["p_remote", "p_no_mfa", "p_credentials"],
                "join": "AND",
            },
            {
                "id": "e_discover",
                "label": "Discover internal network",
                "tactic": "DS",
                "parents": ["p_foothold"],
            },
            {
                "id": "e_collect",
                "label": "Collect sensitive data",
                "tactic": "CL",
                "parents": ["p_scope"],
            },
            {
                "id": "e_exfiltrate",
                "label": "Exfiltrate collected data",
                "tactic": "EF",
                "parents": ["p_data"],
            },
            {
                "id": "e_encrypt",
                "label": "Encrypt systems",
                "tactic": "IM",
                "technique": "T1486",
                "mitigations": ["M1053"],
                "likelihood": 8.0,
                "parents": ["p_scope"],
            },
            {
                "id": "e_extort",
                "label": "Issue extortion demand",
                "tactic": "IM",
                "parents": ["p_exfiltrated"],
            },
        ],
    })


def _wannacry_shape() -> AttackGraph:
    preconditions = [
        {"id": "p_vulnerable", "label": "Unpatched SMB service", "code": "RS"},
    ]
    events = []
    chain = [
        ("exploit", "Exploit vulnerable SMB service", "IA", "p_initial"),
        ("service", "Execute malware as service", "EX", "p_executing"),
        ("discover", "Enumerate network hosts", "DS", "p_hosts"),
        ("propagate", "Propagate to vulnerable hosts", "LM", "p_multiple"),
        ("transfer", "Transfer malware copies", "LM", "p_copies"),
        ("encrypt", "Encrypt files and shares", "IM", "p_encrypted"),
    ]
    parent = "p_vulnerable"
    for event_id, label, tactic, result_id in chain:
        events.append({
            "id": f"e_{event_id}",
            "label": label,
            "tactic": tactic,
            "parents": [parent],
        })
        preconditions.append({
            "id": result_id,
            "label": {
                "p_initial": "Initial host compromised",
                "p_executing": "Malware executing on initial host",
                "p_hosts": "Vulnerable hosts identified",
                "p_multiple": "Malware running on multiple hosts",
                "p_copies": "Malware copies available",
                "p_encrypted": "Files encrypted",
            }[result_id],
            "code": "R",
            "parents": [f"e_{event_id}"],
        })
        parent = result_id
    events.extend([
        {
            "id": "e_persist",
            "label": "Create registry persistence",
            "tactic": "PS",
            "parents": ["p_executing"],
        },
        {
            "id": "e_delete",
            "label": "Delete volume shadow copies",
            "tactic": "IM",
            "parents": ["p_encrypted"],
        },
        {
            "id": "e_c2",
            "label": "Maintain TOR command channel",
            "tactic": "C2",
            "parents": ["p_executing"],
        },
    ])
    preconditions.extend([
        {
            "id": "p_persistent",
            "label": "Registry persistence established",
            "code": "R",
            "parents": ["e_persist"],
        },
        {
            "id": "p_recovery",
            "label": "Recovery inhibited",
            "code": "R",
            "parents": ["e_delete"],
        },
        {
            "id": "p_channel",
            "label": "TOR channel maintained",
            "code": "R",
            "parents": ["e_c2"],
        },
    ])
    return AttackGraph.model_validate({
        "title": "WannaCry structural oracle",
        "preconditions": preconditions,
        "events": events,
    })


def _mands_shape() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "M&S structural oracle",
        "preconditions": [
            {"id": "p_actor", "label": "Actor capability profile", "code": "RS"},
            {
                "id": "p_possible_social",
                "label": "Possible social engineering route",
                "code": "R",
                "parents": ["e_context"],
            },
            {"id": "p_access", "label": "Domain access available", "code": "R"},
            {
                "id": "p_ntds",
                "label": "NTDS file obtained",
                "code": "R",
                "parents": ["e_ntds"],
            },
            {
                "id": "p_credentials",
                "label": "Administrative credentials recovered",
                "code": "R",
                "parents": ["e_crack"],
            },
            {
                "id": "p_esxi",
                "label": "ESXi access established",
                "code": "R",
                "parents": ["e_lateral"],
            },
            {
                "id": "p_ransomware",
                "label": "DragonForce deployed",
                "code": "R",
                "parents": ["e_deploy"],
            },
            {
                "id": "p_encrypted",
                "label": "Virtual machines encrypted",
                "code": "R",
                "parents": ["e_encrypt"],
            },
            {
                "id": "p_online",
                "label": "Online services disrupted",
                "code": "R",
                "parents": ["e_online"],
            },
            {
                "id": "p_logistics",
                "label": "Logistics operations disrupted",
                "code": "R",
                "parents": ["e_logistics"],
            },
        ],
        "events": [
            {
                "id": "e_context",
                "label": "Describe actor social engineering capability",
                "tactic": "RS",
                "parents": ["p_actor"],
            },
            {
                "id": "e_ntds",
                "label": "Obtain NTDS database",
                "tactic": "CA",
                "technique": "T1003.003",
                "mitigations": ["M1027"],
                "likelihood": 6.0,
                "parents": ["p_access"],
            },
            {
                "id": "e_crack",
                "label": "Crack password hashes",
                "tactic": "CA",
                "parents": ["p_ntds"],
            },
            {
                "id": "e_lateral",
                "label": "Move laterally to ESXi",
                "tactic": "LM",
                "parents": ["p_credentials"],
            },
            {
                "id": "e_deploy",
                "label": "Deploy DragonForce ransomware",
                "tactic": "IM",
                "parents": ["p_esxi"],
            },
            {
                "id": "e_encrypt",
                "label": "Encrypt virtual machines",
                "tactic": "IM",
                "parents": ["p_ransomware"],
            },
            {
                "id": "e_online",
                "label": "Disrupt online services",
                "tactic": "IM",
                "parents": ["p_encrypted"],
            },
            {
                "id": "e_logistics",
                "label": "Disrupt logistics operations",
                "tactic": "IM",
                "parents": ["p_encrypted"],
            },
        ],
    })


class Phase3CausalSplitTests(unittest.TestCase):
    def test_british_library_or_producers_and_state_stay_atomic(self):
        graph = _british_library_shape()
        plan = plan_causal_split(
            graph, max_events_per_part=3, max_ranks=7)
        validate_lossless_split(graph, plan)
        event_parts = {
            event_id: part.index
            for part in plan.parts
            for event_id in part.event_ids
        }
        self.assertEqual(event_parts["e_phish"], event_parts["e_brute"])
        producer_part = next(
            part for part in plan.parts if "e_phish" in part.event_ids)
        self.assertIn("p_credentials", producer_part.precondition_ids)

    def test_british_library_metadata_is_byte_for_byte_preserved(self):
        graph = _british_library_shape()
        plan = plan_causal_split(
            graph, max_events_per_part=3, max_ranks=7)
        original = {event.id: event.model_dump() for event in graph.events}
        seen = {}
        for part in plan.parts:
            page = materialize_split_part(graph, part, len(plan.parts))
            seen.update({event.id: event.model_dump() for event in page.events})
        self.assertEqual(original, seen)

    def test_wannacry_long_chain_uses_state_bridges(self):
        graph = _wannacry_shape()
        plan = plan_causal_split(
            graph, max_events_per_part=3, max_ranks=7)
        self.assertGreaterEqual(len(plan.parts), 3)
        self.assertTrue(any(part.bridge_out_ids for part in plan.parts[:-1]))
        self.assertTrue(any(part.bridge_in_ids for part in plan.parts[1:]))
        self.assertTrue(all(
            bridge_id.startswith("p_")
            for part in plan.parts
            for bridge_id in part.bridge_in_ids + part.bridge_out_ids
        ))
        validate_lossless_split(graph, plan)

    def test_mands_unrelated_actor_context_is_a_separate_component(self):
        graph = _mands_shape()
        plan = plan_causal_split(
            graph, max_events_per_part=3, max_ranks=7)
        context_part = next(
            part for part in plan.parts if "e_context" in part.event_ids)
        incident_events = {
            "e_ntds", "e_crack", "e_lateral", "e_deploy", "e_encrypt",
            "e_online", "e_logistics",
        }
        self.assertTrue(
            incident_events.isdisjoint(context_part.event_ids)
        )
        validate_lossless_split(graph, plan)

    def test_every_event_occurs_on_exactly_one_page(self):
        for graph in (
            _british_library_shape(), _wannacry_shape(), _mands_shape()
        ):
            with self.subTest(graph=graph.title):
                plan = plan_causal_split(
                    graph, max_events_per_part=3, max_ranks=7)
                page_events = [
                    event_id
                    for part in plan.parts
                    for event_id in part.event_ids
                ]
                self.assertCountEqual(
                    [event.id for event in graph.events],
                    page_events,
                )
                self.assertEqual(len(page_events), len(set(page_events)))

    def test_every_test_page_stays_within_the_rank_budget(self):
        for graph in (
            _british_library_shape(), _wannacry_shape(), _mands_shape()
        ):
            with self.subTest(graph=graph.title):
                plan = plan_causal_split(
                    graph, max_events_per_part=3, max_ranks=7)
                for part in plan.parts:
                    page = materialize_split_part(
                        graph, part, len(plan.parts))
                    page_graph = build_digraph(page)
                    levels = {}
                    for node_id in nx.topological_sort(page_graph):
                        parents = list(page_graph.predecessors(node_id))
                        levels[node_id] = (
                            0 if not parents
                            else max(levels[parent] for parent in parents) + 1
                        )
                    self.assertLessEqual(
                        max(levels.values(), default=-1) + 1,
                        7,
                    )

    def test_bridge_state_identity_is_unchanged_across_pages(self):
        graph = _wannacry_shape()
        plan = plan_causal_split(
            graph, max_events_per_part=3, max_ranks=7)
        original = {
            precondition.id: (precondition.label, precondition.code)
            for precondition in graph.preconditions
        }
        for part in plan.parts:
            page = materialize_split_part(graph, part, len(plan.parts))
            page_states = {
                precondition.id: (precondition.label, precondition.code)
                for precondition in page.preconditions
            }
            for bridge_id in part.bridge_in_ids + part.bridge_out_ids:
                self.assertEqual(original[bridge_id], page_states[bridge_id])

    def test_bridge_notes_identify_the_adjacent_parts_without_mutation(self):
        graph = _wannacry_shape()
        before = graph.model_dump()
        plan = plan_causal_split(
            graph,
            max_events_per_part=3,
            max_ranks=7,
        )
        self.assertGreaterEqual(len(plan.parts), 3)

        notes_by_part = {
            part.index: continuation_labels(plan, part)
            for part in plan.parts
        }
        for part in plan.parts:
            for state_id in part.bridge_in_ids:
                self.assertIn("continued from part", notes_by_part[part.index][state_id])
            for state_id in part.bridge_out_ids:
                self.assertIn("continues in part", notes_by_part[part.index][state_id])

        self.assertEqual(before, graph.model_dump())

    def test_default_rank_budget_is_nine(self):
        graph = _wannacry_shape()
        plan = plan_causal_split(graph)
        for part in plan.parts:
            page = materialize_split_part(graph, part, len(plan.parts))
            page_graph = build_digraph(page)
            levels = {}
            for node_id in nx.topological_sort(page_graph):
                parents = list(page_graph.predecessors(node_id))
                levels[node_id] = (
                    0
                    if not parents
                    else max(levels[parent] for parent in parents) + 1
                )
            self.assertLessEqual(max(levels.values(), default=-1) + 1, 9)

    def test_unsplit_small_graph_remains_identical(self):
        graph = _british_library_shape()
        plan = plan_causal_split(
            graph, max_events_per_part=100, max_ranks=100)
        self.assertFalse(plan.is_split)
        page = materialize_split_part(graph, plan.parts[0], 1)
        self.assertEqual(graph.model_dump(), page.model_dump())

    def test_default_pages_keep_branch_siblings_together(self):
        graph = _british_library_shape()
        plan = plan_causal_split(graph)
        event_parts = {
            event_id: part.index
            for part in plan.parts
            for event_id in part.event_ids
        }
        self.assertEqual(event_parts["e_phish"], event_parts["e_brute"])
        self.assertEqual(event_parts["e_collect"], event_parts["e_encrypt"])


if __name__ == "__main__":
    unittest.main()
