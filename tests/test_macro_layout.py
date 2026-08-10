"""Tests for deterministic macro-module analysis."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from layout_ir import build_layout_ir
from macro_layout import analyze_macro_layout, validate_macro_layout
from schema import AttackGraph, Event, Precondition


def _branch_merge_graph() -> AttackGraph:
    return AttackGraph(
        title="macro branch merge",
        preconditions=[
            Precondition(id="p0", label="Target reachable", code="RS"),
            Precondition(id="p1", label="Initial access established", code="IA",
                         parents=["e0"]),
            Precondition(id="p2", label="Data located", code="DS",
                         parents=["e1"]),
            Precondition(id="p3", label="Backups located", code="DS",
                         parents=["e2"]),
            Precondition(id="p4", label="Data staged", code="CL",
                         parents=["e3"]),
            Precondition(id="p5", label="Data exfiltrated", code="EF",
                         parents=["e4"]),
        ],
        events=[
            Event(id="e0", label="Gain initial access", tactic="IA",
                  parents=["p0"]),
            Event(id="e1", label="Discover data", tactic="DS",
                  parents=["p1"]),
            Event(id="e2", label="Discover backups", tactic="DS",
                  parents=["p1"]),
            Event(id="e3", label="Stage discovered data", tactic="CL",
                  parents=["p2", "p3"], join="AND"),
            Event(id="e4", label="Exfiltrate staged data", tactic="EF",
                  parents=["p4"]),
        ],
    )


class MacroLayoutTests(unittest.TestCase):
    def test_projection_is_deterministic_and_lossless(self):
        layout_ir = build_layout_ir(_branch_merge_graph())
        first = analyze_macro_layout(layout_ir)
        second = analyze_macro_layout(layout_ir)
        self.assertEqual(first, second)
        validate_macro_layout(layout_ir, first)
        self.assertEqual(
            {block.id for block in layout_ir.atomic_blocks},
            {
                block_id
                for module in first.modules
                for block_id in module.block_ids
            },
        )

    def test_branch_and_merge_boundaries_are_explicit(self):
        macro = analyze_macro_layout(build_layout_ir(_branch_merge_graph()))
        module_by_block = {
            block_id: module
            for module in macro.modules
            for block_id in module.block_ids
        }
        source = module_by_block["block_000"]
        left = module_by_block["block_001"]
        right = module_by_block["block_002"]
        merge = module_by_block["block_003"]
        tail = module_by_block["block_004"]

        self.assertEqual("fork", source.kind)
        self.assertNotEqual(left.id, right.id)
        self.assertEqual("merge", merge.kind)
        self.assertEqual(merge.id, tail.id)
        self.assertEqual(
            {left.id, right.id},
            set(merge.parent_module_ids),
        )

    def test_module_boundaries_expose_entry_and_exit_states(self):
        macro = analyze_macro_layout(build_layout_ir(_branch_merge_graph()))
        module_by_block = {
            block_id: module
            for module in macro.modules
            for block_id in module.block_ids
        }
        left = module_by_block["block_001"]
        merge = module_by_block["block_003"]
        self.assertIn("p1", left.entry_state_ids)
        self.assertIn("p2", left.exit_state_ids)
        self.assertIn("p2", merge.entry_state_ids)
        self.assertIn("p3", merge.entry_state_ids)
        self.assertIn("p5", merge.exit_state_ids)


if __name__ == "__main__":
    unittest.main()
