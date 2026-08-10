"""No schema rule may first fail after Stage B has been paid for.

Stage B returns technique and mitigation identifiers. It cannot rename a node,
relink a parent, or shorten a label. So any contract violation that survives
Stage A is unfixable by the only correction left, and the run is discarded with
both calls already billed. That is exactly what an eleven-word precondition
label did on a real v1.6 run.

Every rule schema.py can reject must therefore be either
  * refused by the Stage A wire model (the provider enforces it), or
  * repaired deterministically by the normaliser, or
  * reported by the Stage A gate in a message that routes to the structural
    correction, which is the one that can rewrite the skeleton.

This test enumerates them and fails if any new rule slips through.
"""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (ConstructAttackGraphSkeleton, _normalise_constructs,
                     _skeleton_graph_problems, is_structural_stage_a_fault)
from schema import AttackGraph

BASE = {
    "title": "baseline",
    "preconditions": [
        {"id": "p0", "label": "Toolkit needed", "code": "RS", "parents": []},
        {"id": "p1", "label": "Tooling staged", "code": "RS",
         "parents": ["e0"]},
        {"id": "p2", "label": "Foothold", "code": "IA", "parents": ["e1"]}],
    "events": [
        {"id": "e0", "label": "Stage tooling", "tactic": "RS",
         "likelihood": 5.0, "parents": ["p0"], "join": "AND"},
        {"id": "e1", "label": "Deploy tooling", "tactic": "EX",
         "likelihood": 5.0, "parents": ["p1"], "join": "AND"}],
}

# name -> mutation. Each corresponds to a rejection in schema.py.
VIOLATIONS = {
    "over_long_label":
        lambda d: d["preconditions"][1].update(
            label=" ".join(f"w{i}" for i in range(11))),
    "duplicate_node_ids":
        lambda d: d["preconditions"][1].update(id="p0"),
    "unknown_parent":
        lambda d: d["events"][1].update(parents=["p_missing"]),
    "duplicate_parent_ids":
        lambda d: d["events"][1].update(parents=["p1", "p1"]),
    "empty_parent_id":
        lambda d: d["events"][1].update(parents=["p1", ""]),
    "whitespace_label":
        lambda d: d["preconditions"][1].update(label="   "),
    "whitespace_code":
        lambda d: d["preconditions"][1].update(code="  "),
    "whitespace_id":
        lambda d: d["preconditions"][1].update(id=" "),
    "invalid_tactic":
        lambda d: d["events"][1].update(tactic="ZZ"),
    "cycle":
        lambda d: d["preconditions"][0].update(parents=["e1"]),
    "detached_event":
        lambda d: d["events"].append(
            {"id": "e9", "label": "Orphan", "tactic": "RS",
             "likelihood": 5.0, "parents": [], "join": "AND"}),
    "likelihood_out_of_range":
        lambda d: d["events"][1].update(likelihood=99),
}


def _mutated(mutate) -> dict:
    data = copy.deepcopy(BASE)
    mutate(data)
    return data


def _accepts(model, data) -> bool:
    try:
        model.model_validate(data)
        return True
    except Exception:
        return False


class TestEveryViolationIsCaughtBeforeStageB(unittest.TestCase):

    def test_the_baseline_itself_is_valid(self):
        """Otherwise every case below would pass for the wrong reason."""
        self.assertTrue(_accepts(ConstructAttackGraphSkeleton, BASE))
        self.assertEqual([], _skeleton_graph_problems(
            _normalise_constructs(BASE), require_event_parents=False))
        self.assertTrue(_accepts(AttackGraph, _normalise_constructs(BASE)))

    def test_no_violation_survives_stage_a(self):
        survivors = []
        for name, mutate in VIOLATIONS.items():
            data = _mutated(mutate)
            refused_by_wire = not _accepts(ConstructAttackGraphSkeleton, data)
            normalised = _normalise_constructs(data)
            repaired = _accepts(AttackGraph, normalised)
            gated = bool(_skeleton_graph_problems(
                normalised, require_event_parents=False))
            if not (refused_by_wire or repaired or gated):
                survivors.append(name)
        self.assertEqual(
            [], survivors,
            "these reach Stage B and fail where nothing can repair them")

    def test_every_gated_violation_routes_to_the_structural_correction(self):
        misrouted = []
        for name, mutate in VIOLATIONS.items():
            problems = _skeleton_graph_problems(
                _normalise_constructs(_mutated(mutate)),
                require_event_parents=False)
            if problems and not is_structural_stage_a_fault("; ".join(problems)):
                misrouted.append((name, problems))
        self.assertEqual([], misrouted,
                         "gated but sent the generic correction, which cannot "
                         "rewrite the skeleton")

    def test_a_repaired_graph_satisfies_the_canonical_contract(self):
        """Local repair must produce something the renderer accepts."""
        for name in ("duplicate_parent_ids", "empty_parent_id"):
            with self.subTest(name=name):
                normalised = _normalise_constructs(_mutated(VIOLATIONS[name]))
                AttackGraph.model_validate(normalised)

    def test_deduplication_preserves_order_and_content(self):
        data = _mutated(lambda d: d["events"][1].update(
            parents=["p1", "p1", "p0"]))
        event = next(e for e in _normalise_constructs(data)["events"]
                     if e["id"] == "e1")
        self.assertEqual(["p1", "p0"], event["parents"])


class TestStageACannotCarryMitigations(unittest.TestCase):
    """Why `mitigations without a technique` cannot arise from Stage A.

    schema.py rejects it, and neither the gate nor the normaliser handles it.
    That is safe only because the Stage A wire model has no mitigations field
    at all, so the key is dropped before the skeleton is ever merged. If a
    mitigations field is ever added to Stage A, this test fails and the gate
    needs the corresponding check.
    """

    def test_the_field_is_dropped_by_the_wire_model(self):
        data = copy.deepcopy(BASE)
        data["events"][0]["mitigations"] = ["M1051"]
        dumped = ConstructAttackGraphSkeleton.model_validate(
            data).model_dump(exclude_none=True)
        self.assertNotIn("mitigations", dumped["events"][0])


if __name__ == "__main__":
    unittest.main()
