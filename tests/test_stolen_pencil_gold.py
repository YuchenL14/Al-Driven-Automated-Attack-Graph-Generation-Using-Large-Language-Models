"""Offline integrity checks for the supervisor's Stolen Pencil gold image."""

from __future__ import annotations

import json
import re
import statistics
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "stolen_pencil_gold.json"
TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
MITIGATION_ID = re.compile(r"^M\d{4}$")


class StolenPencilGoldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gold = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.nodes = cls.gold["nodes"]
        cls.edges = cls.gold["edges"]
        cls.node_by_id = {node["id"]: node for node in cls.nodes}
        cls.logic_by_id = {
            group["id"]: group for group in cls.gold["logic_groups"]
        }

    def test_reference_identity_is_frozen(self):
        source = self.gold["source"]
        self.assertEqual("StolenPencil.png", source["filename"])
        self.assertEqual(927, source["width_px"])
        self.assertEqual(1075, source["height_px"])
        self.assertEqual(
            "03ccb30b7d67325dc5810928bf48bc1fa5399a30a87dc6cb6274b53398b3e8e6",
            source["sha256"],
        )

    def test_node_and_logic_ids_are_unique(self):
        node_counts = Counter(node["id"] for node in self.nodes)
        logic_counts = Counter(
            group["id"] for group in self.gold["logic_groups"])
        self.assertFalse(
            [node_id for node_id, count in node_counts.items() if count > 1])
        self.assertFalse(
            [group_id for group_id, count in logic_counts.items() if count > 1])
        self.assertEqual(len(self.nodes), len(self.node_by_id))
        self.assertGreaterEqual(len(self.nodes), 30)

    def test_all_edges_reference_known_nodes_and_logic_groups(self):
        for edge in self.edges:
            with self.subTest(edge=edge):
                self.assertIn(edge["source"], self.node_by_id)
                self.assertIn(edge["target"], self.node_by_id)
                if edge["logic_group"] is not None:
                    self.assertIn(edge["logic_group"], self.logic_by_id)

    def test_shapes_match_semantic_roles(self):
        ellipse_roles = {
            "precondition", "postcondition", "external_resource"
        }
        for node in self.nodes:
            with self.subTest(node=node["id"]):
                if node["role"] == "event":
                    self.assertEqual("rectangle", node["shape"])
                elif node["role"] in ellipse_roles:
                    self.assertEqual("ellipse", node["shape"])
                elif node["role"] == "annotation":
                    self.assertEqual("annotation", node["shape"])
                    self.assertEqual("dashed", node["style"])
                elif node["role"] == "goal":
                    self.assertEqual("rectangle", node["shape"])
                else:
                    self.fail(f"unknown role {node['role']!r}")

    def test_annotations_have_only_dashed_annotation_edges(self):
        annotation_ids = {
            node["id"] for node in self.nodes
            if node["role"] == "annotation"
        }
        self.assertEqual(
            {"sp_training_annotation", "sp_av_annotation"}, annotation_ids)
        for edge in self.edges:
            if edge["target"] in annotation_ids:
                with self.subTest(edge=edge):
                    self.assertEqual("annotation", edge["relation"])
                    self.assertEqual("dashed", edge["style"])

    def test_visual_codes_use_their_declared_namespace(self):
        namespaces = self.gold["code_namespaces"]
        for node in self.nodes:
            with self.subTest(node=node["id"]):
                namespace = node["code_namespace"]
                self.assertIn(namespace, namespaces)
                code = node["visual_code"]
                if namespace == "none":
                    self.assertIsNone(code)
                else:
                    self.assertIn(code, namespaces[namespace])

    def test_ia_never_appears_on_an_ellipse(self):
        offenders = [
            node["id"] for node in self.nodes
            if node["shape"] == "ellipse" and node["visual_code"] == "IA"
        ]
        self.assertEqual([], offenders)

    def test_attack_ids_are_valid_unique_per_node_and_have_legend_entries(self):
        technique_legend = self.gold["technique_legend"]
        mitigation_legend = self.gold["mitigation_legend"]
        for node in self.nodes:
            with self.subTest(node=node["id"]):
                techniques = node["techniques"]
                mitigations = node["mitigations"]
                self.assertEqual(len(techniques), len(set(techniques)))
                self.assertEqual(len(mitigations), len(set(mitigations)))
                for technique in techniques:
                    self.assertRegex(technique, TECHNIQUE_ID)
                    self.assertIn(technique, technique_legend)
                for mitigation in mitigations:
                    self.assertRegex(mitigation, MITIGATION_ID)
                    self.assertIn(mitigation, mitigation_legend)

    def test_logic_groups_and_edges_describe_the_same_parents(self):
        for group in self.gold["logic_groups"]:
            with self.subTest(group=group["id"]):
                self.assertIn(group["logic"], {"AND", "OR"})
                self.assertIn(group["target"], self.node_by_id)
                self.assertGreaterEqual(len(group["parents"]), 2)
                self.assertEqual(
                    len(group["parents"]), len(set(group["parents"])))
                edge_parents = {
                    edge["source"] for edge in self.edges
                    if edge["logic_group"] == group["id"]
                    and edge["target"] == group["target"]
                }
                self.assertEqual(set(group["parents"]), edge_parents)

    def test_sequential_causal_edges_run_down_the_reference_page(self):
        for edge in self.edges:
            if edge["relation"] != "causal":
                continue
            source_y = self.node_by_id[edge["source"]][
                "reference_center_px"][1]
            target_y = self.node_by_id[edge["target"]][
                "reference_center_px"][1]
            with self.subTest(edge=edge):
                self.assertGreater(
                    target_y, source_y,
                    "A sequential causal edge must not run sideways/upwards.")

    def test_reference_macro_layout_has_a_wide_top_preparation_band(self):
        source_width = self.gold["source"]["width_px"]
        top_nodes = [
            node for node in self.nodes
            if node["reference_center_px"][1] <= 180
        ]
        self.assertGreaterEqual(len(top_nodes), 5)
        horizontal_span = (
            max(node["reference_center_px"][0] for node in top_nodes)
            - min(node["reference_center_px"][0] for node in top_nodes)
        )
        self.assertGreaterEqual(horizontal_span / source_width, 0.60)

    def test_reference_prefers_vertical_local_continuity(self):
        horizontal_drifts = [
            abs(
                self.node_by_id[edge["source"]]["reference_center_px"][0]
                - self.node_by_id[edge["target"]]["reference_center_px"][0]
            )
            for edge in self.edges
            if edge["relation"] == "causal"
        ]
        self.assertLessEqual(statistics.median(horizontal_drifts), 1)
        self.assertGreaterEqual(
            sum(drift <= 1 for drift in horizontal_drifts)
            / len(horizontal_drifts),
            0.55,
        )

    def test_reference_final_merge_is_between_its_major_branches(self):
        final_group = self.logic_by_id["lg_final_objective"]
        parent_x = [
            self.node_by_id[parent_id]["reference_center_px"][0]
            for parent_id in final_group["parents"]
        ]
        target_x = self.node_by_id[
            final_group["target"]
        ]["reference_center_px"][0]
        self.assertGreaterEqual(target_x, min(parent_x))
        self.assertLessEqual(target_x, max(parent_x))

    def test_gold_contains_the_distinctive_reference_capabilities(self):
        multi_technique_nodes = [
            node for node in self.nodes if len(node["techniques"]) > 1
        ]
        metadata_ellipses = [
            node for node in self.nodes
            if node["shape"] == "ellipse"
            and (node["techniques"] or node["mitigations"])
        ]
        dotted_nodes = [
            node for node in self.nodes if node["style"] == "dotted"
        ]
        self.assertGreaterEqual(len(multi_technique_nodes), 3)
        self.assertEqual(
            ["sp_stolen_certificates"],
            [node["id"] for node in metadata_ellipses],
        )
        self.assertGreaterEqual(len(dotted_nodes), 4)

    def test_two_major_branches_converge_on_the_final_objective(self):
        final_group = self.logic_by_id["lg_final_objective"]
        self.assertEqual("sp_exfiltrate", final_group["target"])
        self.assertEqual("AND", final_group["logic"])
        self.assertEqual(
            {"sp_browser_permissions", "sp_full_control"},
            set(final_group["parents"]),
        )
        self.assertNotEqual(
            self.node_by_id["sp_browser_permissions"]["branch"],
            self.node_by_id["sp_full_control"]["branch"],
        )

    def test_the_reference_has_exactly_one_causal_terminal(self):
        """The rule set cites this count; a v1.6 changelog entry once got it wrong.

        The withdrawn claim was that the reference "ends in five distinct
        terminal states", and it was used to justify relaxing Rule 4's
        convergence requirement. The reference in fact converges completely.
        The relaxation stands on other grounds -- a report may record several
        genuine outcomes -- but the citation had to stop being false, and this
        pins the number so it cannot drift again.
        """
        outgoing = {edge["source"] for edge in self.gold["edges"]}
        terminals = [node for node in self.gold["nodes"]
                     if node["id"] not in outgoing]
        annotations = [n for n in terminals if n["shape"] == "annotation"]
        causal = [n for n in terminals if n["shape"] != "annotation"]

        self.assertEqual(3, len(terminals))
        self.assertEqual(2, len(annotations))
        self.assertEqual(["sp_exfiltrate"], [n["id"] for n in causal])

    def test_no_state_in_the_reference_is_left_unconsumed(self):
        """The calibration point for the Stage A unused-state review."""
        outgoing = {edge["source"] for edge in self.gold["edges"]}
        incoming = {edge["target"] for edge in self.gold["edges"]}
        abandoned = [
            node["id"] for node in self.gold["nodes"]
            if node["shape"] == "ellipse"
            and node["id"] in incoming
            and node["id"] not in outgoing
        ]
        self.assertEqual([], abandoned)

    def test_transcription_uncertainties_are_explicit(self):
        uncertainties = self.gold["transcription_uncertainties"]
        self.assertGreaterEqual(len(uncertainties), 4)
        self.assertTrue(all(item["field"] and item["detail"]
                            for item in uncertainties))


if __name__ == "__main__":
    unittest.main()
