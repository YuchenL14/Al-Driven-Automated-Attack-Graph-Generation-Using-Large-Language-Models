"""Integrity tests for the agreed two-page British Library gold graph."""

from __future__ import annotations

import json
import unittest
from collections import Counter, defaultdict, deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "british_library_two_page_gold.json"


class BritishLibraryTwoPageGoldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gold = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.nodes = cls.gold["nodes"]
        cls.edges = cls.gold["edges"]
        cls.node_by_id = {node["id"]: node for node in cls.nodes}
        cls.evidence_by_id = {
            item["id"]: item for item in cls.gold["evidence"]
        }

    def test_fixture_is_an_evaluation_oracle_not_a_production_template(self):
        self.assertEqual(
            "development_and_regression_only",
            self.gold["source"]["known_case_role"],
        )
        self.assertIn(
            "not a production template",
            self.gold["purpose"],
        )

    def test_nodes_and_evidence_ids_are_unique(self):
        node_counts = Counter(node["id"] for node in self.nodes)
        evidence_counts = Counter(
            item["id"] for item in self.gold["evidence"])
        self.assertFalse([key for key, count in node_counts.items()
                          if count != 1])
        self.assertFalse([key for key, count in evidence_counts.items()
                          if count != 1])

    def test_every_node_is_evidence_linked(self):
        for node in self.nodes:
            with self.subTest(node=node["id"]):
                self.assertIn(node["evidence_id"], self.evidence_by_id)
                evidence = self.evidence_by_id[node["evidence_id"]]
                self.assertTrue(evidence["quote"].strip())
                self.assertGreaterEqual(evidence["page"], 1)

    def test_shapes_encode_semantics_consistently(self):
        for node in self.nodes:
            with self.subTest(node=node["id"]):
                if node["role"] == "event":
                    self.assertEqual("rectangle", node["shape"])
                    self.assertIsNotNone(node["tactic"])
                elif node["role"] in {"state", "continuation_state"}:
                    self.assertEqual("ellipse", node["shape"])
                    self.assertIsNone(node["tactic"])
                elif node["role"] == "annotation":
                    self.assertEqual("annotation", node["shape"])
                    self.assertIsNone(node["tactic"])
                else:
                    self.fail(f"unknown semantic role {node['role']!r}")

    def test_only_events_may_display_attack_metadata(self):
        offenders = [
            node["id"] for node in self.nodes
            if node["role"] != "event"
            and (node["tactic"] is not None or node["technique"] is not None)
        ]
        self.assertEqual([], offenders)

    def test_edges_reference_known_nodes_and_annotations_are_dashed(self):
        for edge in self.edges:
            with self.subTest(edge=edge):
                self.assertIn(edge["source"], self.node_by_id)
                self.assertIn(edge["target"], self.node_by_id)
                source_role = self.node_by_id[edge["source"]]["role"]
                if edge["relation"] == "annotation":
                    self.assertEqual("annotation", source_role)
                    self.assertEqual("dashed", edge["style"])
                else:
                    self.assertEqual("causal", edge["relation"])
                    self.assertEqual("solid", edge["style"])

    def test_possible_access_methods_are_separate_or_branches(self):
        incoming = [
            edge for edge in self.edges
            if edge["target"] == "bl_access_method"
        ]
        self.assertEqual(
            {"bl_phishing", "bl_bruteforce"},
            {edge["source"] for edge in incoming},
        )
        self.assertEqual({"OR"}, {edge["logic"] for edge in incoming})
        for node_id in ("bl_phishing", "bl_bruteforce"):
            self.assertEqual(
                "possible", self.node_by_id[node_id]["evidence_status"])

    def test_report_does_not_force_unsupported_specific_techniques(self):
        for node_id in ("bl_recon", "bl_expand_access",
                        "bl_discover_data", "bl_copy_data",
                        "bl_exfiltrate"):
            with self.subTest(node=node_id):
                self.assertIsNone(self.node_by_id[node_id]["technique"])

    def test_exact_two_page_causal_boundary_is_lossless(self):
        contract = self.gold["visual_contract"]
        self.assertEqual(2, contract["page_count"])
        self.assertEqual("bl_broad_access", contract["split_state"])
        self.assertTrue(contract["lossless_recomposition_required"])

        original = self.node_by_id["bl_broad_access"]
        continuation = self.node_by_id["bl_broad_access_continuation"]
        self.assertEqual(1, original["page"])
        self.assertEqual(2, original["continues_on_page"])
        self.assertEqual(2, continuation["page"])
        self.assertEqual(original["id"], continuation["canonical_id"])
        self.assertEqual(original["label"], continuation["label"])

    def test_user_confirmed_page_one_same_row_is_frozen(self):
        page_one = self.gold["page_layout"][0]
        self.assertEqual(
            {
                "bl_target_info",
                "bl_no_mfa",
                "bl_security_gap",
                "bl_flat_topology",
                "bl_segmentation_note",
            },
            set(page_one["same_row_groups"][0]),
        )

    def test_user_confirmed_page_two_same_row_is_frozen(self):
        page_two = self.gold["page_layout"][1]
        self.assertEqual(
            {
                "bl_discover_data",
                "bl_encrypt_data",
                "bl_continuity_note",
                "bl_destroy_servers",
            },
            set(page_two["same_row_groups"][0]),
        )

    def test_same_row_may_mix_shapes_without_changing_causality(self):
        for page in self.gold["page_layout"]:
            group = page["same_row_groups"][0]
            shapes = {self.node_by_id[node_id]["shape"]
                      for node_id in group}
            self.assertIn("ellipse" if page["page"] == 1 else "rectangle",
                          shapes)
            self.assertIn("annotation", shapes)

    def test_each_page_preserves_top_down_causal_acyclicity(self):
        for page_number in (1, 2):
            page_nodes = {
                node["id"] for node in self.nodes
                if node["page"] == page_number
            }
            adjacency = defaultdict(list)
            indegree = {node_id: 0 for node_id in page_nodes}
            for edge in self.edges:
                if edge["relation"] != "causal":
                    continue
                if edge["source"] in page_nodes and edge["target"] in page_nodes:
                    adjacency[edge["source"]].append(edge["target"])
                    indegree[edge["target"]] += 1
            queue = deque(
                node_id for node_id, degree in indegree.items()
                if degree == 0
            )
            seen = 0
            while queue:
                node_id = queue.popleft()
                seen += 1
                for child in adjacency[node_id]:
                    indegree[child] -= 1
                    if indegree[child] == 0:
                        queue.append(child)
            self.assertEqual(
                len(page_nodes), seen,
                f"page {page_number} must remain a top-down DAG",
            )

    def test_page_two_parallel_actions_share_the_same_causal_parent(self):
        parents = defaultdict(set)
        for edge in self.edges:
            if edge["relation"] == "causal":
                parents[edge["target"]].add(edge["source"])
        for event_id in (
            "bl_discover_data", "bl_encrypt_data", "bl_destroy_servers"
        ):
            with self.subTest(event=event_id):
                self.assertIn(
                    "bl_broad_access_continuation", parents[event_id])

    def test_destruction_branch_is_not_falsely_forced_into_publication(self):
        outgoing = defaultdict(set)
        for edge in self.edges:
            if edge["relation"] == "causal":
                outgoing[edge["source"]].add(edge["target"])
        self.assertEqual(
            {"bl_recovery_inhibited"},
            outgoing["bl_destroy_servers"],
        )
        self.assertNotIn("bl_extort", outgoing["bl_recovery_inhibited"])

    def test_uncertainties_are_explicit_and_reviewable(self):
        uncertainties = self.gold["uncertainties"]
        self.assertGreaterEqual(len(uncertainties), 5)
        self.assertTrue(all(item["field"] and item["detail"]
                            for item in uncertainties))


if __name__ == "__main__":
    unittest.main()
