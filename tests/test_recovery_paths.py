"""The correction loops must actually fire when the provider rejects an answer.

Both stages of the hierarchical pipeline carry a retry that feeds the failure
back to the model. Both were unreachable: the model call sat outside its own
``try``, and the provider validates inside that call, so a schema violation
escaped as a hard failure instead of being corrected. Nothing in the suite
noticed, because every other double returned pre-validated JSON.

These tests drive the loops through the real seam.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from extract import (AttackGraphSkeleton, _TECHNIQUE_MITIGATIONS,  # noqa: E402
                     _extract_hierarchical)
from support_seam import seam_accurate_call  # noqa: E402


VALID_SKELETON = json.dumps({
    "title": "Seam fixture",
    "preconditions": [
        {"id": "p1", "label": "Remote service exposed", "code": "R",
         "parents": []},
        {"id": "p2", "label": "Foothold obtained", "code": "R",
         "parents": ["e1"]},
        {"id": "p3", "label": "Data encrypted", "code": "R",
         "parents": ["e2"]},
    ],
    "events": [
        {"id": "e1", "label": "Gain entry via remote service", "tactic": "IA",
         "likelihood": 7, "parents": ["p1"], "join": "AND"},
        {"id": "e2", "label": "Encrypt data across estate", "tactic": "IM",
         "likelihood": 8, "parents": ["p2"], "join": "AND"},
    ],
})

EMPTY_EVENT_SKELETON = json.dumps({
    "title": "Seam fixture",
    "preconditions": [
        {"id": "p1", "label": "Remote service exposed", "code": "R",
         "parents": []},
    ],
    "events": [],
})

VALID_ASSIGNMENTS = json.dumps({"assignments": [
    {"id": "e1", "technique": "T1133", "mitigations": []},
    {"id": "e2", "technique": "T1486", "mitigations": []},
]})

UNKNOWN_TECHNIQUE_ASSIGNMENTS = json.dumps({"assignments": [
    {"id": "e1", "technique": "T9999", "mitigations": []},
    {"id": "e2", "technique": "T1486", "mitigations": []},
]})


class RecoveryPathTests(unittest.TestCase):
    def test_stage_a_recovers_from_a_schema_rejection(self):
        calls: list[type] = []
        attempts = {"skeleton": 0}

        def payload(system, user, model, response_model):
            if response_model is AttackGraphSkeleton:
                attempts["skeleton"] += 1
                return (EMPTY_EVENT_SKELETON if attempts["skeleton"] == 1
                        else VALID_SKELETON)
            return VALID_ASSIGNMENTS

        graph = _extract_hierarchical(
            "A report describing entry and encryption.",
            seam_accurate_call(payload, calls), "none", "v1.4")

        self.assertEqual(2, attempts["skeleton"])
        self.assertEqual(["e1", "e2"], [e.id for e in graph.events])
        self.assertEqual(3, len(calls))

    def test_stage_a_correction_prompt_reaches_the_model(self):
        prompts: list[str] = []
        attempts = {"skeleton": 0}

        def payload(system, user, model, response_model):
            if response_model is AttackGraphSkeleton:
                attempts["skeleton"] += 1
                prompts.append(user)
                return (EMPTY_EVENT_SKELETON if attempts["skeleton"] == 1
                        else VALID_SKELETON)
            return VALID_ASSIGNMENTS

        _extract_hierarchical(
            "A report describing entry and encryption.",
            seam_accurate_call(payload), "none", "v1.4")

        self.assertEqual(2, len(prompts))
        self.assertNotIn("IMPORTANT", prompts[0])
        self.assertIn("contained no events", prompts[1])

    def test_stage_b_recovers_from_an_out_of_catalogue_technique(self):
        calls: list[type] = []
        attempts = {"assignments": 0}

        def payload(system, user, model, response_model):
            if response_model is AttackGraphSkeleton:
                return VALID_SKELETON
            attempts["assignments"] += 1
            return (UNKNOWN_TECHNIQUE_ASSIGNMENTS
                    if attempts["assignments"] == 1 else VALID_ASSIGNMENTS)

        graph = _extract_hierarchical(
            "A report describing entry and encryption.",
            seam_accurate_call(payload, calls), "none", "v1.4")

        self.assertEqual(2, attempts["assignments"])
        self.assertEqual(["T1133", "T1486"],
                         [e.technique for e in graph.events])
        self.assertEqual(3, len(calls))

    def test_recovered_graph_still_gets_official_mitigations(self):
        attempts = {"assignments": 0}

        def payload(system, user, model, response_model):
            if response_model is AttackGraphSkeleton:
                return VALID_SKELETON
            attempts["assignments"] += 1
            return (UNKNOWN_TECHNIQUE_ASSIGNMENTS
                    if attempts["assignments"] == 1 else VALID_ASSIGNMENTS)

        graph = _extract_hierarchical(
            "A report describing entry and encryption.",
            seam_accurate_call(payload), "none", "v1.4")

        for event in graph.events:
            self.assertEqual(
                set(_TECHNIQUE_MITIGATIONS.get(event.technique, ())),
                set(event.mitigations),
            )

    def test_seam_double_refuses_to_return_an_invalid_payload(self):
        call = seam_accurate_call(
            lambda system, user, model, response_model: EMPTY_EVENT_SKELETON
        )
        with self.assertRaises(Exception):
            call("system", "user", "none", AttackGraphSkeleton)


if __name__ == "__main__":
    unittest.main()
