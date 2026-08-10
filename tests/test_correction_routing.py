"""Every structural Stage A failure must reach the structural correction.

Control flow here depends on matching a fragment of a human-readable error
message. That has already disconnected a correction twice: once because the
gate said "must be unique" while Pydantic said "must be globally unique", and
once because the router looked for a marker no message contained.

These tests generate the real messages from both producers, so a rewording on
either side fails here instead of silently costing a paid run.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from extract import (_skeleton_graph_problems,  # noqa: E402
                     is_structural_stage_a_fault)
from schema import AttackGraph  # noqa: E402


def _base() -> dict:
    return {
        "title": "Routing fixture",
        "preconditions": [
            {"id": "p1", "label": "Service exposed", "code": "R",
             "parents": []},
            {"id": "p2", "label": "Foothold obtained", "code": "R",
             "parents": ["e1"]},
        ],
        "events": [
            {"id": "e1", "label": "Gain entry", "tactic": "IA",
             "parents": ["p1"]},
        ],
    }


def _with(**mutation):
    data = _base()
    for key, fn in mutation.items():
        fn(data)
    return data


# Each case must make the gate emit at least one message.
GATE_CASES = {
    "duplicate id": lambda d: d["events"][0].__setitem__("id", "p1"),
    "missing events": lambda d: d["preconditions"][1].__setitem__(
        "parents", ["e9"]),
    "missing preconditions": lambda d: d["events"][0].__setitem__(
        "parents", ["p9"]),
    "event parents an event": lambda d: d["events"].append(
        {"id": "e2", "label": "Next", "tactic": "LM", "parents": ["e1"]}),
    "precondition parents a precondition": lambda d: d["preconditions"][1]
    .__setitem__("parents", ["p1"]),
    "event consumes nothing": lambda d: d["events"][0].__setitem__(
        "parents", []),
    "cycle": lambda d: d["preconditions"][0].__setitem__("parents", ["e1"]),
}


class GateMessageRoutingTests(unittest.TestCase):
    def test_every_gate_message_routes_to_the_structural_correction(self):
        for name, mutate in GATE_CASES.items():
            with self.subTest(case=name):
                problems = _skeleton_graph_problems(_with(m=mutate))
                self.assertTrue(
                    problems, f"{name!r} produced no diagnosis at all")
                joined = "; ".join(problems)
                self.assertTrue(
                    is_structural_stage_a_fault(joined),
                    f"{name!r} would fall through to the generic correction: "
                    f"{joined}",
                )

    def test_the_disconnected_message_routes(self):
        """Isolated pairs report fragmentation, and only that.

        This used to assert that the flat-fan message appeared alongside it.
        Both describe the same shape, and stacking two corrections into the
        single permitted Stage A retry dilutes each of them, so the
        connectivity fault now reports alone.
        """
        data = {"title": "Isolated pairs", "preconditions": [], "events": []}
        for index in (1, 2, 3):
            data["events"].append(
                {"id": f"e{index}", "label": f"Step {index}", "tactic": "IA",
                 "parents": []})
            data["preconditions"].append(
                {"id": f"s{index}", "label": f"Result {index}", "code": "R",
                 "parents": [f"e{index}"]})
        joined = "; ".join(
            _skeleton_graph_problems(data, require_event_parents=False))
        self.assertIn("disconnected pieces", joined)
        self.assertNotIn("no step follows from another", joined)
        self.assertTrue(is_structural_stage_a_fault(joined))

    def test_the_flat_fan_message_routes(self):
        """A fan can be connected and still have no attack path through it.

        Every event here consumes the same shared root, so the graph is one
        connected component, the connectivity check stays silent, and the
        flat-fan check is the only one that can name the fault.
        """
        data = {"title": "Connected fan",
                "preconditions": [{"id": "s0", "label": "Shared start",
                                   "code": "R", "parents": []}],
                "events": []}
        for index in (1, 2, 3):
            data["events"].append(
                {"id": f"e{index}", "label": f"Step {index}", "tactic": "IA",
                 "parents": ["s0"]})
            data["preconditions"].append(
                {"id": f"r{index}", "label": f"Result {index}", "code": "R",
                 "parents": [f"e{index}"]})
        joined = "; ".join(
            _skeleton_graph_problems(data, require_event_parents=False))
        self.assertIn("no step follows from another", joined)
        self.assertTrue(is_structural_stage_a_fault(joined))


class ContractMessageRoutingTests(unittest.TestCase):
    """schema.py words the same faults differently; both must route."""

    def _message(self, data: dict) -> str:
        with self.assertRaises(ValidationError) as caught:
            AttackGraph.model_validate(data)
        return str(caught.exception)

    def test_contract_duplicate_id_routes(self):
        data = _base()
        data["events"][0]["id"] = "p1"
        data["preconditions"][1]["parents"] = ["p1"]
        message = self._message(data)
        self.assertIn("globally unique", message)
        self.assertTrue(is_structural_stage_a_fault(message))

    def test_contract_unknown_parent_routes(self):
        data = _base()
        data["preconditions"][1]["parents"] = ["e9"]
        self.assertTrue(is_structural_stage_a_fault(self._message(data)))

    def test_contract_wrong_direction_routes(self):
        data = _base()
        data["events"].append(
            {"id": "e2", "label": "Next", "tactic": "LM", "parents": ["e1"]})
        message = self._message(data)
        self.assertIn("must consume preconditions", message)
        self.assertTrue(is_structural_stage_a_fault(message))

    def test_contract_precondition_chain_routes(self):
        data = _base()
        data["preconditions"][1]["parents"] = ["p1"]
        message = self._message(data)
        self.assertIn("must be produced by events", message)
        self.assertTrue(is_structural_stage_a_fault(message))


class UserFacingClassificationTests(unittest.TestCase):
    """The page must not blame the provider for this pipeline's own refusals."""

    def setUp(self):
        sys.path.insert(0, str(ROOT))
        import app
        self.friendly = app._friendly_error

    def test_a_rejected_quotation_is_not_reported_as_a_spend_limit(self):
        # "quota" sits inside "quotation": the substring test used to fire the
        # rate-limit branch and told the user to check Settings > Limits.
        message = self.friendly(
            RuntimeError(
                "stage A failed: e5: source_evidence is not a verbatim extract "
                'of the supplied report. You wrote: "paraphrased text"'),
            "anthropic",
        )
        self.assertNotIn("rate/spend limit", message)
        self.assertNotIn("Settings > Limits", message)
        self.assertIn("word for word", message)

    def test_a_structural_failure_is_not_reported_as_a_thin_report(self):
        message = self.friendly(
            RuntimeError(
                "stage A failed: precondition 'p2' references unknown parent "
                "'e2'"),
            "anthropic",
        )
        self.assertNotIn("little technical detail", message)
        self.assertIn("structural failure", message)

    def test_a_real_rate_limit_still_reports_as_one(self):
        message = self.friendly(
            RuntimeError("rate_limit_error: quota exceeded for this workspace"),
            "anthropic",
        )
        self.assertIn("rate/spend limit", message)


class NonStructuralFailuresDoNotRouteTests(unittest.TestCase):
    def test_unrelated_failures_use_the_generic_correction(self):
        for message in (
            "the model returned malformed JSON",
            "Anthropic could not authenticate the configured API key",
            "stage A returned no events; extract the attack steps",
            "event e1 has tactic 'ZZ'; use one of the 14 tactic abbreviations",
        ):
            with self.subTest(message=message):
                self.assertFalse(is_structural_stage_a_fault(message))


if __name__ == "__main__":
    unittest.main()
