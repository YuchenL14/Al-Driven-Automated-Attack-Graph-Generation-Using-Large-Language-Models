"""Annotations were stripped before the gate, so their rules went unchecked.

An annotation must not join the causal checks: it is consumed by nothing,
which connectivity would read as a dangling state, and it must never create a
rank or lengthen a path. So the v1.6 Stage A gate builds a causal copy with
annotations removed and validates that.

Removing them also removed them from the rules that are *not* causal -- what a
node may attach to, and that ids are unique. Those bind every node. A real run
of the STOLEN PENCIL report attached "No evidence of data theft" to a state
rather than to the step it comments on, passed Stage A, and failed inside Stage
B, where only technique and mitigation identifiers come back and nothing can be
relinked. Both calls had been paid for and the graph was lost.

The remaining cases here were found by writing one violation per schema rule
and asking which stage caught it, not by waiting for the next failed run. That
matrix also showed a correction pointing the wrong way: when an event consumed
an annotation, the causal gate could only report a missing state, which invites
the model to invent one.
"""

import copy
import sys
import unittest
from pathlib import Path

from pydantic import ValidationError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (_annotation_problems, _skeleton_graph_problems,
                     is_structural_stage_a_fault)
from schema import AttackGraph

VALID = {
    "events": [
        {"id": "e1", "label": "Step one", "parents": ["p0"],
         "tactic": "IA", "techniques": ["T1190"]},
        {"id": "e2", "label": "Step two", "parents": ["p1"],
         "tactic": "EX", "techniques": ["T1059"]},
    ],
    "preconditions": [
        {"id": "p0", "label": "Start", "code": "P0", "parents": []},
        {"id": "p1", "label": "Middle", "code": "P1", "parents": ["e1"]},
        {"id": "p2", "label": "End", "code": "P2", "parents": ["e2"]},
        {"id": "a1", "label": "Detected on day 4", "code": "A1",
         "role": "annotation", "style": "dashed", "parents": ["e2"]},
    ],
}


def _stage_a(data: dict) -> list[str]:
    """What the v1.6 Stage A gate sees, in the order it reports it."""

    causal = {
        **data,
        "preconditions": [
            node for node in data["preconditions"]
            if node.get("role") != "annotation"
        ],
    }
    return (_annotation_problems(data)
            + _skeleton_graph_problems(causal, require_event_parents=False))


def _stage_b_rejects(data: dict) -> bool:
    try:
        AttackGraph.model_validate(data)
    except (ValidationError, ValueError):
        return True
    return False


class AnnotationGateTests(unittest.TestCase):
    def test_a_correct_graph_is_not_disturbed(self):
        self.assertEqual([], _stage_a(VALID))
        self.assertFalse(_stage_b_rejects(VALID))

    def _broken(self, mutate) -> dict:
        data = copy.deepcopy(VALID)
        mutate(data)
        return data

    def test_an_annotation_attached_to_a_state_is_caught_at_stage_a(self):
        """The failure that prompted this: the parent must be a step."""
        def mutate(data):
            data["preconditions"][3]["parents"] = ["p1"]
        data = self._broken(mutate)
        problems = _stage_a(data)
        self.assertTrue(problems)
        self.assertIn("comments on a step", problems[0])
        self.assertTrue(_stage_b_rejects(data),
                        "the fixture must really be invalid")

    def test_an_annotation_reusing_an_id_is_caught_at_stage_a(self):
        """Uniqueness was checked on the causal copy, which excludes these."""
        def mutate(data):
            data["preconditions"][3]["id"] = "e1"
        data = self._broken(mutate)
        problems = _stage_a(data)
        self.assertTrue(problems)
        self.assertIn("reuses the id", problems[0])
        self.assertTrue(_stage_b_rejects(data))

    def test_an_annotation_with_an_unknown_parent_is_caught(self):
        def mutate(data):
            data["preconditions"][3]["parents"] = ["ghost"]
        problems = _stage_a(self._broken(mutate))
        self.assertTrue(problems)
        self.assertIn("no node has that id", problems[0])

    def test_consuming_an_annotation_is_named_precisely_and_first(self):
        """The causal gate could only call it a missing state."""
        def mutate(data):
            data["events"][1]["parents"] = ["a1"]
            data["preconditions"][3]["parents"] = ["e1"]
        data = self._broken(mutate)
        problems = _stage_a(data)
        self.assertIn("consumes annotation", problems[0])
        self.assertIn("never part of the attack path", problems[0])
        self.assertTrue(_stage_b_rejects(data))

    def test_every_annotation_fault_routes_to_the_structural_repair(self):
        """A gate that cannot reach a correction is a gate that loses graphs."""
        mutations = [
            lambda d: d["preconditions"][3].__setitem__("parents", ["p1"]),
            lambda d: d["preconditions"][3].__setitem__("id", "e1"),
            lambda d: d["preconditions"][3].__setitem__("parents", ["ghost"]),
            lambda d: d["events"][1].__setitem__("parents", ["a1"]),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                problems = _stage_a(self._broken(mutate))
                self.assertTrue(problems)
                self.assertTrue(
                    is_structural_stage_a_fault("; ".join(problems)))

    def test_annotations_still_take_no_part_in_the_causal_checks(self):
        """The reason they are stripped in the first place must survive.

        An annotation is consumed by nothing. If it reached the connectivity
        check it would read as an abandoned state on every correct graph.
        """
        causal_only = [
            node for node in VALID["preconditions"]
            if node.get("role") != "annotation"
        ]
        self.assertEqual(
            [],
            _skeleton_graph_problems(
                {**VALID, "preconditions": causal_only},
                require_event_parents=False),
        )

    def test_a_graph_with_no_annotations_is_unaffected(self):
        data = copy.deepcopy(VALID)
        data["preconditions"] = data["preconditions"][:3]
        self.assertEqual([], _annotation_problems(data))


if __name__ == "__main__":
    unittest.main()
