"""Layout Stage A: reversible visual intermediate representation tests."""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from layout_ir import (LayoutIRValidationError, build_layout_ir,  # noqa: E402
                       canonical_topology, reconstruct_canonical_topology,
                       validate_layout_ir)
from schema import AttackGraph  # noqa: E402


def _stage_a_graph() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "Stage A structural oracle",
        "preconditions": [
            {"id": "p_target", "label": "Target service exposed", "code": "RS"},
            {"id": "p_no_mfa", "label": "Legacy service without MFA", "code": "IA"},
            {"id": "p_security", "label": "Security controls ineffective", "code": "DE"},
            {
                "id": "p_information",
                "label": "Target information gathered",
                "code": "R",
                "parents": ["e_recon"],
            },
            {
                "id": "p_credentials",
                "label": "Valid credentials obtained",
                "code": "R",
                "parents": ["e_phish", "e_brute"],
            },
            {
                "id": "p_foothold",
                "label": "Initial foothold established",
                "code": "R",
                "parents": ["e_login"],
            },
            {
                "id": "p_scope",
                "label": "Broad internal access established",
                "code": "R",
                "parents": ["e_move"],
            },
            {
                "id": "p_impact",
                "label": "Critical services unavailable",
                "code": "IM",
                "parents": ["e_encrypt", "e_destroy"],
            },
        ],
        "events": [
            {
                "id": "e_recon",
                "label": "Conduct reconnaissance",
                "tactic": "RE",
                "parents": ["p_target"],
            },
            {
                "id": "e_phish",
                "label": "Phish for credentials",
                "tactic": "CA",
                "parents": ["p_information"],
            },
            {
                "id": "e_brute",
                "label": "Brute force credentials",
                "tactic": "CA",
                "technique": "T1110",
                "mitigations": ["M1027"],
                "likelihood": 5.0,
                "parents": ["p_information"],
            },
            {
                "id": "e_login",
                "label": "Authenticate to exposed service",
                "tactic": "IA",
                "parents": ["p_target", "p_no_mfa", "p_credentials"],
                "join": "AND",
            },
            {
                "id": "e_move",
                "label": "Move across internal network",
                "tactic": "LM",
                "parents": ["p_foothold", "p_security"],
                "join": "AND",
            },
            {
                "id": "e_encrypt",
                "label": "Encrypt critical services",
                "tactic": "IM",
                "parents": ["p_scope"],
            },
            {
                "id": "e_destroy",
                "label": "Destroy critical services",
                "tactic": "IM",
                "parents": ["p_scope"],
            },
        ],
    })


class LayoutStageAIRTests(unittest.TestCase):
    def test_projection_is_exactly_reconstructable(self):
        graph = _stage_a_graph()
        layout_ir = build_layout_ir(graph)
        self.assertEqual(
            canonical_topology(graph),
            reconstruct_canonical_topology(layout_ir),
        )
        self.assertEqual(
            len(canonical_topology(graph).edges),
            len(layout_ir.edges),
        )

    def test_projection_is_pure_and_deterministic(self):
        graph = _stage_a_graph()
        before = graph.model_dump()
        first = build_layout_ir(graph)
        second = build_layout_ir(graph)
        self.assertEqual(first, second)
        self.assertEqual(before, graph.model_dump())

    def test_reused_root_condition_has_one_shared_visual_occurrence(self):
        layout_ir = build_layout_ir(_stage_a_graph())
        target_nodes = [
            node for node in layout_ir.nodes
            if node.canonical_id == "p_target"
        ]
        self.assertEqual(1, len(target_nodes))
        primary = target_nodes[0]
        self.assertEqual("canonical", primary.role)
        self.assertIsNone(primary.anchor_event_id)

        login_edge = next(
            edge for edge in layout_ir.edges
            if edge.source_canonical_id == "p_target"
            and edge.target_canonical_id == "e_login"
        )
        self.assertEqual("p_target", login_edge.source_visual_id)
        self.assertEqual("p_target", login_edge.source_canonical_id)

    def test_single_late_root_is_anchored_without_becoming_an_event(self):
        layout_ir = build_layout_ir(_stage_a_graph())
        security = next(
            node for node in layout_ir.nodes
            if node.visual_id == "p_security"
        )
        self.assertEqual("canonical", security.role)
        self.assertEqual("state", security.semantics.kind)
        self.assertEqual("ellipse", security.semantics.shape)
        self.assertEqual("e_move", security.anchor_event_id)

    def test_event_result_alternatives_form_one_atomic_block(self):
        layout_ir = build_layout_ir(_stage_a_graph())
        credentials = next(
            block for block in layout_ir.atomic_blocks
            if "p_credentials" in block.result_state_ids
        )
        self.assertEqual(
            ("e_phish", "e_brute"),
            credentials.event_ids,
        )
        impact = next(
            block for block in layout_ir.atomic_blocks
            if "p_impact" in block.result_state_ids
        )
        self.assertEqual(
            ("e_encrypt", "e_destroy"),
            impact.event_ids,
        )

    def test_logic_groups_preserve_and_or_and_parent_order(self):
        layout_ir = build_layout_ir(_stage_a_graph())
        groups = {
            group.target_canonical_id: group
            for group in layout_ir.logic_groups
        }
        self.assertEqual("AND", groups["e_login"].logic)
        self.assertEqual(
            ("p_target", "p_no_mfa", "p_credentials"),
            groups["e_login"].canonical_parent_ids,
        )
        self.assertEqual(
            "p_target",
            groups["e_login"].input_visual_ids[0],
        )
        self.assertEqual("OR", groups["p_credentials"].logic)
        self.assertEqual(
            ("e_phish", "e_brute"),
            groups["p_credentials"].canonical_parent_ids,
        )
        self.assertEqual("OR", groups["p_impact"].logic)

    def test_attack_metadata_and_state_badge_rules_are_unchanged(self):
        graph = _stage_a_graph()
        layout_ir = build_layout_ir(graph)
        brute = next(
            node for node in layout_ir.nodes
            if node.visual_id == "e_brute"
        )
        self.assertEqual("T1110", brute.semantics.technique)
        self.assertEqual(("M1027",), brute.semantics.mitigations)
        self.assertEqual(5.0, brute.semantics.likelihood)

        no_mfa = next(
            node for node in layout_ir.nodes
            if node.visual_id == "p_no_mfa"
        )
        # The stored code stays "IA" for audit; the drawing shows the derived
        # state symbol, so an ATT&CK tactic still never reaches an ellipse.
        self.assertEqual("IA", graph.preconditions[1].code)
        self.assertEqual("PRE", no_mfa.semantics.badge_code)
        self.assertEqual("state_phase", no_mfa.semantics.badge_namespace)

    def test_validator_rejects_semantic_edge_loss(self):
        graph = _stage_a_graph()
        layout_ir = build_layout_ir(graph)
        damaged = replace(layout_ir, edges=layout_ir.edges[:-1])
        with self.assertRaises(LayoutIRValidationError):
            validate_layout_ir(graph, damaged)


if __name__ == "__main__":
    unittest.main()
