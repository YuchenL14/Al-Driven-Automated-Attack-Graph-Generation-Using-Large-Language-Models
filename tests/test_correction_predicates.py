"""Every correction selector is a named predicate with a covering test.

These routings used to be substring tests written inline at the call site.
That is how `"must be unique"` once failed to match Pydantic's `"must be
globally unique"`, silently disabling a targeted correction: the retry still
happened, but with no guidance, so the model repeated its mistake and the run
was paid for twice.
"""

import sys
import unittest
from pathlib import Path

from pydantic import ValidationError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (AttackGraphSkeleton, ConstructAttackGraphSkeleton,
                     EvidenceGraphWire, is_empty_graph_fault,
                     is_grounded_action_fault, is_structural_stage_a_fault,
                     is_student_identifier_coverage_fault,
                     is_verbatim_evidence_fault)

# Copied from the raise sites, so a reworded message fails this file rather
# than silently disabling a correction in production.
EMPTY_GRAPH_MESSAGES = [
    "the graph has no events: the report narrates an attack (entry, "
    "credential theft, impact) so the graph must contain those steps",
    "stage A returned no events; extract the attack steps the report "
    "describes, each with a tactic",
]
VERBATIM_MESSAGE = (
    "e3: source_evidence is not a verbatim extract of the supplied report")
GROUNDED_MESSAGE = (
    "e2: label does not contain the grounded action named by action_evidence")


def _pydantic_empty_events(model) -> str:
    """The provider's own wording for an empty events array."""
    try:
        model.model_validate({
            "preconditions": [{"id": "s1", "label": "x", "code": "IA",
                               "parents": []}],
            "events": []})
    except ValidationError as error:
        return str(error)
    raise AssertionError(f"{model.__name__} accepted an empty events array")


class TestEmptyGraph(unittest.TestCase):

    def test_every_raise_site_message_is_recognised(self):
        for message in EMPTY_GRAPH_MESSAGES:
            with self.subTest(message=message[:40]):
                self.assertTrue(is_empty_graph_fault(message))

    def test_the_providers_own_wording_is_recognised(self):
        """`minItems` surfaces as `too_short`, not as prose."""
        for model in (AttackGraphSkeleton, ConstructAttackGraphSkeleton,
                      EvidenceGraphWire):
            with self.subTest(model=model.__name__):
                self.assertTrue(
                    is_empty_graph_fault(_pydantic_empty_events(model)))

    def test_an_unrelated_failure_does_not_match(self):
        self.assertFalse(is_empty_graph_fault(
            "event e1 references unknown parent s9"))


class TestOtherSelectors(unittest.TestCase):

    def test_the_verbatim_message_is_recognised(self):
        self.assertTrue(is_verbatim_evidence_fault(VERBATIM_MESSAGE))

    def test_the_grounded_action_message_is_recognised(self):
        self.assertTrue(is_grounded_action_fault(GROUNDED_MESSAGE))

    def test_the_selectors_do_not_claim_each_others_faults(self):
        self.assertFalse(is_verbatim_evidence_fault(GROUNDED_MESSAGE))
        self.assertFalse(is_grounded_action_fault(VERBATIM_MESSAGE))
        self.assertFalse(is_empty_graph_fault(VERBATIM_MESSAGE))

    def test_student_identifier_coverage_has_a_named_route(self):
        message = (
            "student identifier coverage missing from Stage A events: "
            "techniques T1486; mitigations M1040, M1053")
        self.assertTrue(is_student_identifier_coverage_fault(message))
        self.assertFalse(is_student_identifier_coverage_fault(
            "technique T1486 belongs to tactic IM"))

    def test_a_structural_fault_is_not_read_as_an_empty_graph(self):
        """They lead to different prompts, so overlap would misdirect one."""
        structural = "the skeleton contains a cycle: e1 -> s1 -> e1"
        self.assertTrue(is_structural_stage_a_fault(structural))
        self.assertFalse(is_empty_graph_fault(structural))


class TestNoRawSubstringRoutingRemains(unittest.TestCase):
    """A guard, like the AST check that protects the defensive wiring."""

    def test_extract_routes_only_through_named_predicates(self):
        source = (ROOT / "src" / "extract.py").read_text(encoding="utf-8")
        for banned in ('in str(ex)', 'in str(e)'):
            self.assertNotIn(
                banned, source,
                f"{banned!r} is an inline substring routing test; add a "
                "predicate beside the markers it depends on instead")


if __name__ == "__main__":
    unittest.main()
