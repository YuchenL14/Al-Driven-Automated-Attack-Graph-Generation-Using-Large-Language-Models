"""Offline regression tests for the v1.5 evidence-handling iteration."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import app  # noqa: E402
import student_app  # noqa: E402
from extract import (AttackGraph, AttackGraphSkeleton,  # noqa: E402
                     EvidenceTechniqueAssignments,
                     EvidenceTechniqueAssignmentsWire, TechniqueAssignments,
                     IncidentSemanticDraft, StudentEvidenceGraph,
                     StudentEvidenceGraphWire,
                     _AnthropicCostBudget, _TECHNIQUE_MITIGATIONS,
                     _call_anthropic, _extract_hierarchical,
                     _enforce_student_v12_attack_mappings,
                     _normalise_student_structure,
                     _sanitize_student_v19_assignments,
                     _student_evidence_problems, _student_structure_problems,
                     extract_attack_graph,
                     load_ruleset)


# The evidence Stage B is requested through a wire model whose vocabulary the
# provider can enforce, then validated locally against the strict model. A test
# double must recognise the schema actually sent, not only the strict one.
_STAGE_B_MODELS = {
    EvidenceTechniqueAssignments,
    EvidenceTechniqueAssignmentsWire,
}


class V15ContractTests(unittest.TestCase):
    def test_runtime_ruleset_is_discoverable(self):
        self.assertIn("Evidence threshold for an event", load_ruleset("v1.5"))
        self.assertEqual("v1.4", app.PROFESSIONAL_RULESET)

    def test_student_app_uses_isolated_teaching_rules(self):
        # The invariant is isolation: the teaching app must never run the
        # research rule set. The version is pinned as well so a bump is a
        # deliberate edit here rather than a silent change of what students see.
        self.assertTrue(student_app.RULESET.startswith("student-"))
        self.assertEqual("student-v1.3", student_app.RULESET)
        rules = load_ruleset(student_app.RULESET)
        self.assertIn("Evidence threshold for an event", rules)
        self.assertIn("Technique-scoped mitigations", rules)
        self.assertIn("Remote Services T1021", rules)

    def test_student_v13_keeps_the_students_own_identifiers(self):
        """v1.2 chose the technique itself; v1.3 gives that back to them."""
        rules = load_ruleset("student-v1.3")
        self.assertIn("Identifiers you supply", rules)
        self.assertIn("An identifier you supply is kept", rules)
        self.assertNotIn("Use only mitigation ids supplied by Stage B", rules)
        # v1.2 stays available and unchanged as the comparison point.
        self.assertIn("Use only mitigation ids supplied by Stage B",
                      load_ruleset("student-v1.2"))

    def test_student_v11_rules_remain_available(self):
        rules = load_ruleset("student-v1.1")
        self.assertIn("Evidence comes before graph completion", rules)
        self.assertIn("An event may have zero or\none technique", rules)

    def test_student_v1_baseline_remains_available(self):
        self.assertIn("one weakly connected graph", load_ruleset("student-v1"))

    def test_v14_mock_behaviour_has_not_gained_required_evidence(self):
        graph = extract_attack_graph(
            "Mock report text.", provider="mock", ruleset="v1.4")
        self.assertTrue(graph.events)
        self.assertIsNone(graph.events[0].source_evidence)

    def test_v15_mock_adds_auditable_evidence(self):
        graph = extract_attack_graph(
            "Mock report text.", provider="mock", ruleset="v1.5")
        self.assertTrue(graph.events)
        self.assertEqual("Mock report text.", graph.events[0].source_evidence)
        self.assertEqual("reported", graph.events[0].evidence_status)
        self.assertEqual(85, graph.events[0].evidence_confidence)

    def test_cost_ceiling_is_configurable_but_cannot_be_disabled(self):
        # A longer report legitimately costs more, so the ceiling has to be
        # raisable on purpose. A missing or nonsensical value must fall back to
        # the default rather than removing the guard.
        import os
        from extract import _MAX_GENERATION_COST_USD, _configured_max_cost_usd

        # The fallback cases name the constant rather than a literal. The
        # default has been raised once already, and a test asserting the old
        # number would have failed for the wrong reason: what matters is that
        # a bad value falls back to whatever the default is, not what it is.
        default = _MAX_GENERATION_COST_USD
        cases = {
            "0.70": 0.70,
            "": default,
            "abc": default,
            "-1": default,
            "0": default,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                with patch.dict(
                    os.environ, {"ATTACK_GRAPH_MAX_COST_USD": value}
                ):
                    self.assertEqual(expected, _configured_max_cost_usd())
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ATTACK_GRAPH_MAX_COST_USD", None)
            self.assertEqual(default, _configured_max_cost_usd())
            # The default is what a budget built with no arguments uses, which
            # is how both production call sites build it.
            self.assertEqual(default, _AnthropicCostBudget().max_usd)
            # It remains a real ceiling, not a removed one.
            self.assertGreater(default, 0)
            self.assertLess(default, 5.0)

    def test_v15_can_abstain_from_technique(self):
        result = EvidenceTechniqueAssignments.model_validate({
            "assignments": [{
                "id": "ev_exfil",
                "technique": None,
                "mitigations": [],
            }]
        })
        self.assertIsNone(result.assignments[0].technique)

    def test_student_v11_mock_is_grounded_and_can_render(self):
        report = (
            "An unpatched service was reachable. The attacker exploited it, "
            "spread to other hosts, and encrypted files for ransom.")
        graph = extract_attack_graph(
            report, provider="mock", ruleset="student-v1.1")
        self.assertTrue(graph.events)
        for event in graph.events:
            self.assertEqual("adversary", event.actor)
            self.assertIn(event.source_evidence, report)
            self.assertIn(event.action_evidence, event.source_evidence)

    def test_student_v11_rejects_unsupported_action_label(self):
        report = "Flowers accessed an online tool selling breached credentials."
        events = [{
            "id": "ev_obtain",
            "label": "Obtain breached credentials",
            "actor": "adversary",
            "source_evidence": report,
            "action_evidence": "accessed",
            "evidence_status": "reported",
            "evidence_confidence": 90,
        }]
        problems = _student_evidence_problems(events, report)
        self.assertTrue(any("grounded action" in problem for problem in problems))

    def test_student_v11_repairs_descriptive_grounded_action_labels(self):
        cases = [
            (
                "Maintain access to Capita systems",
                "The attacker exploited Capita's systems.",
                "exploited Capita's systems",
                "Exploited Capita's systems",
            ),
            (
                "Obtain administrator access",
                "The attacker gained administrator permissions.",
                "gained administrator permissions",
                "Gained administrator permissions",
            ),
            (
                "Steal nearly one terabyte of data",
                "Nearly one terabyte of data was exfiltrated.",
                "was exfiltrated",
                "Nearly one terabyte of data was exfiltrated",
            ),
            (
                "Encrypt Capita systems",
                "Ransomware was deployed on Capita's systems.",
                "ransomware was deployed",
                "Ransomware was deployed",
            ),
            (
                "Remove employee access",
                "The attacker reset all user passwords.",
                "reset all user passwords",
                "Reset all user passwords",
            ),
        ]
        for index, (label, report, action, expected_label) in enumerate(cases):
            with self.subTest(action=action):
                event = {
                    "id": f"e{index}", "label": label,
                    "actor": "adversary", "source_evidence": report,
                    "action_evidence": action,
                    "evidence_status": "reported",
                    "evidence_confidence": 90,
                }
                self.assertEqual(
                    [], _student_evidence_problems([event], report))
                self.assertEqual(expected_label, event["label"])

    def test_student_v11_rejects_victim_actor(self):
        report = "TfL required employees to reset their passwords."
        events = [{
            "id": "ev_reset",
            "label": "Reset employee passwords",
            "actor": "victim",
            "source_evidence": report,
            "action_evidence": "reset",
            "evidence_status": "reported",
            "evidence_confidence": 90,
        }]
        problems = _student_evidence_problems(events, report)
        self.assertTrue(any("actor must be adversary" in problem
                            for problem in problems))

    def test_student_v11_accepts_passive_action_evidence(self):
        report = "TfL’s network was infiltrated and Oyster data was accessed."
        events = [
            {
                "id": "e1", "label": "Infiltrate TfL network",
                "actor": "adversary", "source_evidence": report,
                "action_evidence": "was infiltrated",
                "evidence_status": "reported", "evidence_confidence": 90,
            },
            {
                "id": "e2", "label": "Access Oyster data",
                "actor": "adversary", "source_evidence": report,
                "action_evidence": "was accessed",
                "evidence_status": "reported", "evidence_confidence": 90,
            },
        ]
        self.assertEqual([], _student_evidence_problems(events, report))

    def test_student_v11_accepts_actor_leading_label(self):
        report = "Videos showed Jubair accessing TfL systems during the attack."
        events = [{
            "id": "e1", "label": "Jubair accessing TfL systems",
            "actor": "adversary", "source_evidence": report,
            "action_evidence": "accessing",
            "evidence_status": "reported", "evidence_confidence": 90,
        }]
        self.assertEqual([], _student_evidence_problems(events, report))

    def test_student_v11_normalises_accessing_without_dropping_s(self):
        report = "Videos showed Jubair accessing TfL systems during the attack."
        events = [{
            "id": "e4", "label": "Access TfL systems during attack",
            "actor": "adversary", "source_evidence": report,
            "action_evidence": "accessing",
            "evidence_status": "reported", "evidence_confidence": 90,
        }]
        self.assertEqual([], _student_evidence_problems(events, report))

    def test_student_v11_matches_regular_action_inflections(self):
        cases = [
            ("Persuade help-desk worker",
             "They persuaded the help-desk worker.", "persuaded"),
            ("Stop online services",
             "The attackers stopped online services.", "stopped"),
            ("Process stolen records",
             "The attackers were processing stolen records.", "processing"),
            ("Attempt to access banking information",
             "They attempted to access banking information.",
             "attempted to access"),
            ("Steal customer data",
             "Customer data was stolen.", "was stolen"),
        ]
        for index, (label, report, action) in enumerate(cases):
            with self.subTest(action=action):
                events = [{
                    "id": f"e{index}", "label": label,
                    "actor": "adversary", "source_evidence": report,
                    "action_evidence": action,
                    "evidence_status": "reported",
                    "evidence_confidence": 90,
                }]
                self.assertEqual(
                    [], _student_evidence_problems(events, report))

    def test_student_v11_repairs_bare_passive_auxiliary(self):
        report = "TfL’s network was infiltrated and Oyster data was accessed."
        events = [
            {
                "id": "e1", "label": "Infiltrate TfL network",
                "actor": "adversary", "source_evidence": report,
                "action_evidence": "was", "evidence_status": "reported",
                "evidence_confidence": 90,
            },
            {
                "id": "e2", "label": "Access Oyster data",
                "actor": "adversary", "source_evidence": report,
                "action_evidence": "was", "evidence_status": "reported",
                "evidence_confidence": 90,
            },
        ]
        self.assertEqual([], _student_evidence_problems(events, report))
        self.assertEqual("infiltrated", events[0]["action_evidence"])
        self.assertEqual("accessed", events[1]["action_evidence"])

    def test_student_v11_does_not_repair_access_into_obtain(self):
        report = "Flowers accessed an online tool selling breached credentials."
        events = [{
            "id": "e1", "label": "Obtain breached credentials",
            "actor": "adversary", "source_evidence": report,
            "action_evidence": "was", "evidence_status": "reported",
            "evidence_confidence": 90,
        }]
        problems = _student_evidence_problems(events, report)
        self.assertTrue(any("exact phrase" in problem
                            for problem in problems))
        self.assertEqual("was", events[0]["action_evidence"])

    def test_student_v11_stage_a_schema_rejects_empty_events(self):
        with self.assertRaises(ValidationError):
            StudentEvidenceGraph.model_validate({
                "title": "Empty graph",
                "preconditions": [],
                "events": [],
            })

    def test_student_v11_abstains_from_retired_attack_id(self):
        raw = json.dumps({
            "assignments": [{
                "id": "e_disable",
                "technique": "T1562",
                "mitigations": ["M1040"],
            }]
        })
        repaired = EvidenceTechniqueAssignments.model_validate_json(
            _sanitize_student_v19_assignments(raw))
        self.assertIsNone(repaired.assignments[0].technique)
        self.assertEqual([], repaired.assignments[0].mitigations)

    def test_student_v11_pipeline_uses_v19_and_keeps_graph_on_old_id(self):
        report = "The threat actor disabled Windows Defender."
        stage_b_prompts = []

        def fake_call(system, user, model, response_model=AttackGraph):
            if response_model in _STAGE_B_MODELS:
                stage_b_prompts.append(user)
                return (
                    '{"assignments":[{"id":"e_disable",'
                    '"technique":"T1562","mitigations":["M1040"]}]}')
            return (
                '{"title":"DPP incident","preconditions":[],"events":['
                '{"id":"e_disable","label":"Disable Windows Defender",'
                '"tactic":"DE","likelihood":7,"parents":[],"join":"AND",'
                '"actor":"adversary","source_evidence":'
                '"The threat actor disabled Windows Defender.",'
                '"action_evidence":"disabled Windows Defender",'
                '"evidence_status":"reported","evidence_confidence":90}]}')

        graph = _extract_hierarchical(
            report, fake_call, "none", "student-v1.1")
        self.assertEqual(1, len(graph.events))
        self.assertIsNone(graph.events[0].technique)
        self.assertEqual([], graph.events[0].mitigations)
        self.assertIn("ATT&CK\nv19 catalogue", stage_b_prompts[0])
        self.assertIn("retired T1562", stage_b_prompts[0])
        self.assertIn("T1685", stage_b_prompts[0])

    def test_student_v12_filters_mitigations_by_official_relationship(self):
        events = [{
            "id": "e_stop",
            "technique": "T1489",
            "mitigations": ["M1018", "M1022", "M1026"],
            "source_evidence":
                "The attacker stopped Microsoft Exchange services.",
            "action_evidence": "stopped",
        }]
        _enforce_student_v12_attack_mappings(events)
        self.assertEqual("T1489", events[0]["technique"])
        self.assertEqual(["M1018", "M1022"], events[0]["mitigations"])

    def test_student_v12_rejects_generic_lateral_move_as_remote_services(self):
        report = "The attacker moved laterally across the network."
        stage_a_prompts = []

        def fake_call(system, user, model, response_model=AttackGraph):
            if response_model in _STAGE_B_MODELS:
                return json.dumps({"assignments": [{
                    "id": "e_move", "technique": "T1021",
                    "mitigations": ["M1030"],
                }]})
            stage_a_prompts.append(user)
            return json.dumps({
                "title": "Lateral movement",
                "preconditions": [],
                "events": [{
                    "id": "e_move", "label": "Move laterally",
                    "tactic": "LM", "likelihood": 7,
                    "parents": [], "join": "AND", "actor": "adversary",
                    "source_evidence": report,
                    "action_evidence": "moved laterally",
                    "evidence_status": "reported",
                    "evidence_confidence": 90,
                }],
            })

        graph = _extract_hierarchical(
            report, fake_call, "none", "student-v1.2")
        self.assertIsNone(graph.events[0].technique)
        self.assertEqual([], graph.events[0].mitigations)
        self.assertIn("perform this coverage check", stage_a_prompts[0])

    def test_student_v12_rejects_cleanup_as_masquerading(self):
        events = [{
            "id": "e_cleanup",
            "technique": "T1036",
            "mitigations": ["M1049"],
            "source_evidence":
                "The attacker downloaded and ran antivirus cleanup software.",
            "action_evidence": "downloaded and ran",
        }]
        _enforce_student_v12_attack_mappings(events)
        self.assertIsNone(events[0]["technique"])
        self.assertEqual([], events[0]["mitigations"])

    def test_student_v12_accepts_v19_disable_or_modify_tools(self):
        events = [{
            "id": "e_disable",
            "technique": "T1685",
            "mitigations": ["M1038", "M1040"],
            "source_evidence":
                "The threat actor disabled Windows Defender.",
            "action_evidence": "disabled Windows Defender",
        }]
        _enforce_student_v12_attack_mappings(events)
        self.assertEqual("T1685", events[0]["technique"])
        self.assertEqual(["M1038"], events[0]["mitigations"])

    def test_student_v11_repairs_empty_stage_a_with_high_level_action(self):
        report = "The pair compromised TfL’s network."
        calls = []

        def fake_call(system, user, model, response_model=AttackGraph):
            calls.append(response_model)
            if len(calls) == 1:
                return '{"title":"TfL","preconditions":[],"events":[]}'
            if response_model in _STAGE_B_MODELS:
                return ('{"assignments":[{"id":"ev_compromise",'
                        '"technique":null,"mitigations":[]}]}')
            return (
                '{"title":"TfL","preconditions":['
                '{"id":"p_target","label":"TfL network targeted",'
                '"code":"IA","parents":[]},'
                '{"id":"p_compromised","label":"TfL network compromised",'
                '"code":"IA","parents":["ev_compromise"]}],"events":['
                '{"id":"ev_compromise","label":"Compromise TfL network",'
                '"tactic":"IA","likelihood":7,"parents":["p_target"],'
                '"join":"AND","actor":"adversary",'
                '"source_evidence":"The pair compromised TfL’s network.",'
                '"action_evidence":"compromised",'
                '"evidence_status":"reported",'
                '"evidence_confidence":95}]}')

        graph = _extract_hierarchical(
            report, fake_call, "none", "student-v1.1")
        self.assertEqual(1, len(graph.events))
        self.assertIsNone(graph.events[0].technique)
        # The wire model is what the provider is asked for; the strict
        # StudentEvidenceGraph still validates the answer locally. Sending the
        # strict model made every evidence field optional in the schema.
        self.assertEqual(
            [StudentEvidenceGraphWire, StudentEvidenceGraphWire,
             EvidenceTechniqueAssignments], calls)

    def test_student_pipeline_normalises_sample_syntax_before_stage_b(self):
        report = (
            "The attackers impersonated a TfL employee. "
            "They accessed TfL systems. "
            "Flowers accessed an online tool.")
        calls = []

        def fake_call(system, user, model, response_model=AttackGraph):
            calls.append(response_model)
            if response_model in _STAGE_B_MODELS:
                return json.dumps({"assignments": [
                    {"id": "e1", "technique": None, "mitigations": []},
                    {"id": "e2", "technique": None, "mitigations": []},
                ]})
            return json.dumps({
                "title": "TfL core",
                "preconditions": [
                    {"id": "p_access", "label": "TfL identity impersonated",
                     "code": "CA", "parents": ["e1"]},
                    {"id": "p_tool", "label": "Online tool available",
                     "code": "RS", "parents": []},
                ],
                "events": [
                    {
                        "id": "e1", "label": "Impersonate TfL employee",
                        "tactic": "CA", "parents": [], "join": "OR",
                        "actor": "adversary",
                        "source_evidence":
                            "The attackers impersonated a TfL employee.",
                        "action_evidence": "impersonated",
                        "evidence_status": "reported",
                        "evidence_confidence": 90,
                    },
                    {
                        "id": "e2", "label": "Access TfL systems",
                        "tactic": "IA", "parents": ["p_access"],
                        "join": "AND", "actor": "adversary",
                        "source_evidence": "They accessed TfL systems.",
                        "action_evidence": "accessed",
                        "evidence_status": "reported",
                        "evidence_confidence": 90,
                    },
                    {
                        "id": "E6", "label": "Access online tool",
                        "tactic": "RS", "parents": ["p_tool"],
                        "join": "OR", "actor": "adversary",
                        "source_evidence":
                            "Flowers accessed an online tool.",
                        "action_evidence": "accessed",
                        "evidence_status": "reported",
                        "evidence_confidence": 90,
                    },
                ],
            })

        graph = _extract_hierarchical(
            report, fake_call, "none", "student-v1.1")
        self.assertEqual(["e1", "e2"], [event.id for event in graph.events])
        self.assertEqual("AND", graph.events[0].join)
        self.assertEqual([], graph.events[0].parents)
        self.assertFalse(any(
            "e2" in precondition.parents
            for precondition in graph.preconditions))
        self.assertEqual(
            [StudentEvidenceGraphWire, EvidenceTechniqueAssignments], calls)

    def test_v15_accepts_claude_double_encoded_assignment_array(self):
        payload = {
            "assignments": json.dumps([{
                "id": "ev_exfil",
                "technique": None,
                "mitigations": [],
            }])
        }
        result = EvidenceTechniqueAssignments.model_validate(payload)
        self.assertEqual("ev_exfil", result.assignments[0].id)
        self.assertIsNone(result.assignments[0].technique)

    def test_v14_accepts_claude_double_encoded_assignment_array(self):
        payload = {
            "assignments": json.dumps([{
                "id": "ev_access",
                "technique": "T1190",
                "mitigations": ["M1051"],
            }])
        }
        result = TechniqueAssignments.model_validate(payload)
        self.assertEqual("T1190", result.assignments[0].technique)

    def test_v14_stage_a_schema_rejects_an_empty_event_list(self):
        with self.assertRaises(ValidationError):
            AttackGraphSkeleton.model_validate({
                "title": "Empty graph",
                "preconditions": [],
                "events": [],
            })

    def test_v14_pipeline_repairs_an_empty_first_stage_a_answer(self):
        calls = []

        def fake_call(system, user, model, response_model=AttackGraph):
            calls.append(response_model)
            stage_a_calls = sum(
                item is AttackGraphSkeleton for item in calls)
            if response_model is AttackGraphSkeleton:
                if stage_a_calls == 1:
                    return '{"title":"Empty","preconditions":[],"events":[]}'
                return (
                    '{"title":"Recovered","preconditions":['
                    '{"id":"p1","label":"Remote account exposed",'
                    '"code":"R","parents":[]},'
                    '{"id":"p2","label":"Credential obtained",'
                    '"code":"R","parents":["e1"]}],"events":['
                    '{"id":"e1","label":"Guess remote account password",'
                    '"tactic":"CA","likelihood":5,"parents":["p1"],'
                    '"join":"AND"}]}')
            return ('{"assignments":[{"id":"e1","technique":"T1110",'
                    '"mitigations":[]}]}')

        graph = _extract_hierarchical(
            "The attacker repeatedly guessed the remote account password.",
            fake_call, "none", "v1.4")
        self.assertEqual("T1110", graph.events[0].technique)
        self.assertEqual(3, len(calls))

    def test_v14_stage_a_stops_after_one_repair_attempt(self):
        calls = []

        def fake_call(system, user, model, response_model=AttackGraph):
            calls.append(response_model)
            return '{"title":"Empty","preconditions":[],"events":[]}'

        with self.assertRaisesRegex(RuntimeError, "stage A failed"):
            _extract_hierarchical(
                "The attacker guessed a remote account password.",
                fake_call, "none", "v1.4")

        self.assertEqual(
            [AttackGraphSkeleton, AttackGraphSkeleton], calls,
            "Stage A must leave the third API call available for Stage B")

    def test_v14_pipeline_repairs_cross_tactic_stage_b_answer(self):
        calls = []

        def fake_call(system, user, model, response_model=AttackGraph):
            calls.append(response_model)
            if response_model is AttackGraphSkeleton:
                return (
                    '{"title":"Scoped repair","preconditions":['
                    '{"id":"p1","label":"Remote account exposed",'
                    '"code":"R","parents":[]},'
                    '{"id":"p2","label":"Credential obtained",'
                    '"code":"R","parents":["e1"]}],"events":['
                    '{"id":"e1","label":"Guess remote account password",'
                    '"tactic":"CA","likelihood":5,"parents":["p1"],'
                    '"join":"AND"}]}')
            stage_b_number = len(calls) - 1
            technique = "T1589.001" if stage_b_number == 1 else "T1110"
            return json.dumps({"assignments": [{
                "id": "e1", "technique": technique, "mitigations": [],
            }]})

        graph = _extract_hierarchical(
            "The attacker repeatedly guessed the remote account password.",
            fake_call, "none", "v1.4")
        self.assertEqual("T1110", graph.events[0].technique)
        self.assertEqual(3, len(calls))

    def test_v14_reconciles_a_repeated_unambiguous_tactic_conflict(self):
        calls = []

        def fake_call(system, user, model, response_model=AttackGraph):
            calls.append(response_model)
            if response_model is AttackGraphSkeleton:
                return json.dumps({
                    "title": "Impact tactic repair",
                    "preconditions": [
                        {"id": "p1", "label": "Services are running",
                         "code": "R", "parents": []},
                        {"id": "p2", "label": "Services stopped",
                         "code": "R", "parents": ["e1"]},
                        {"id": "p3", "label": "Recovery inhibited",
                         "code": "R", "parents": ["e2"]},
                    ],
                    "events": [
                        {"id": "e1", "label": "Stop services",
                         "tactic": "DE", "likelihood": 7,
                         "parents": ["p1"], "join": "AND"},
                        {"id": "e2", "label": "Delete shadow copies",
                         "tactic": "DE", "likelihood": 7,
                         "parents": ["p2"], "join": "AND"},
                    ],
                })
            return json.dumps({"assignments": [
                {"id": "e1", "technique": "T1489", "mitigations": []},
                {"id": "e2", "technique": "T1490", "mitigations": []},
            ]})

        graph = _extract_hierarchical(
            "The malware stopped services and deleted shadow copies.",
            fake_call, "none", "v1.4")

        self.assertEqual(["IM", "IM"], [event.tactic for event in graph.events])
        self.assertEqual(["T1489", "T1490"],
                         [event.technique for event in graph.events])
        self.assertEqual(3, len(calls))

    def test_v14_reconciles_a_changed_unambiguous_tactic_conflict(self):
        # The Stage B correction prompt asks the model to change its answer, so
        # the second attempt usually returns a different technique and a
        # different mismatch. Reconciliation must not depend on the model
        # repeating its first mistake exactly.
        calls = []

        def fake_call(system, user, model, response_model=AttackGraph):
            calls.append(response_model)
            if response_model is AttackGraphSkeleton:
                return json.dumps({
                    "title": "Discovery mislabelled as collection",
                    "preconditions": [
                        {"id": "p1", "label": "Broad network access held",
                         "code": "R", "parents": []},
                        {"id": "p2", "label": "Sensitive files located",
                         "code": "R", "parents": ["e1"]},
                    ],
                    "events": [
                        {"id": "e1", "label": "Search network for files",
                         "tactic": "CL", "likelihood": 7,
                         "parents": ["p1"], "join": "AND"},
                    ],
                })
            # Both are Discovery-only techniques, but they are not the same
            # technique, so the two mismatches differ.
            technique = "T1083" if len(calls) == 2 else "T1082"
            return json.dumps({"assignments": [
                {"id": "e1", "technique": technique, "mitigations": []},
            ]})

        graph = _extract_hierarchical(
            "The attackers searched the network for sensitive files.",
            fake_call, "none", "v1.4")

        self.assertEqual(["DS"], [event.tactic for event in graph.events])
        self.assertEqual(["T1082"], [event.technique for event in graph.events])
        self.assertEqual(3, len(calls))

    def test_v14_derives_mitigations_from_the_official_relationship(self):
        # Rule 2 and Rule 5 ask for mitigations that specifically counter the
        # event's technique. MITRE already records that as a "mitigates"
        # relationship, so the catalogue decides, not the model.
        def fake_call(system, user, model, response_model=AttackGraph):
            if response_model is AttackGraphSkeleton:
                return json.dumps({
                    "title": "Mitigation provenance",
                    "preconditions": [
                        {"id": "p1", "label": "Backups reachable", "code": "R",
                         "parents": []},
                        {"id": "p2", "label": "Data encrypted", "code": "R",
                         "parents": ["e1"]},
                    ],
                    "events": [
                        {"id": "e1", "label": "Encrypt data", "tactic": "IM",
                         "likelihood": 8, "parents": ["p1"], "join": "AND"},
                    ],
                })
            # A real but unrelated mitigation, of the kind the model returned
            # on the British Library incident review.
            return json.dumps({"assignments": [
                {"id": "e1", "technique": "T1486", "mitigations": ["M1017"]},
            ]})

        graph = _extract_hierarchical(
            "The attackers encrypted data across the estate.",
            fake_call, "none", "v1.4")

        official = set(_TECHNIQUE_MITIGATIONS.get("T1486", ()))
        self.assertEqual(official, set(graph.events[0].mitigations))
        self.assertNotIn("M1017", graph.events[0].mitigations)

    def test_v14_leaves_mitigations_empty_when_mitre_lists_none(self):
        # T1083 has no official mitigation. An empty badge is the correct
        # outcome; the model previously invented two.
        def fake_call(system, user, model, response_model=AttackGraph):
            if response_model is AttackGraphSkeleton:
                return json.dumps({
                    "title": "No official mitigation",
                    "preconditions": [
                        {"id": "p1", "label": "Network access held",
                         "code": "R", "parents": []},
                        {"id": "p2", "label": "Files located", "code": "R",
                         "parents": ["e1"]},
                    ],
                    "events": [
                        {"id": "e1", "label": "Discover files", "tactic": "DS",
                         "likelihood": 7, "parents": ["p1"], "join": "AND"},
                    ],
                })
            return json.dumps({"assignments": [
                {"id": "e1", "technique": "T1083",
                 "mitigations": ["M1022", "M1028"]},
            ]})

        graph = _extract_hierarchical(
            "The attackers scanned the network for sensitive files.",
            fake_call, "none", "v1.4")

        self.assertEqual((), tuple(_TECHNIQUE_MITIGATIONS.get("T1083", ())))
        self.assertEqual([], graph.events[0].mitigations)

    def test_v14_settles_each_tactic_conflict_on_its_own(self):
        # The Stolen Pencil run failed with three conflicts at once: two whose
        # technique names exactly one tactic, and one whose technique spans
        # four. Reconciliation used to require every conflict to be
        # unambiguous, so the single ambiguous one discarded a whole graph the
        # catalogue could otherwise have repaired.
        calls = []

        def fake_call(system, user, model, response_model=AttackGraph):
            calls.append(response_model)
            if response_model is AttackGraphSkeleton:
                return json.dumps({
                    "title": "Mixed tactic conflicts",
                    "preconditions": [
                        {"id": "p1", "label": "Lure delivered", "code": "R",
                         "parents": []},
                        {"id": "p2", "label": "File opened", "code": "R",
                         "parents": ["e1"]},
                        {"id": "p3", "label": "Tooling present", "code": "R",
                         "parents": ["e2"]},
                        {"id": "p4", "label": "Access retained", "code": "R",
                         "parents": ["e3"]},
                    ],
                    "events": [
                        {"id": "e1", "label": "Victim opens malicious file",
                         "tactic": "IA", "likelihood": 7, "parents": ["p1"],
                         "join": "AND"},
                        {"id": "e2", "label": "Transfer tooling to host",
                         "tactic": "EX", "likelihood": 7, "parents": ["p2"],
                         "join": "AND"},
                        {"id": "e3", "label": "Keep access via backdoor account",
                         "tactic": "IM", "likelihood": 7, "parents": ["p3"],
                         "join": "AND"},
                    ],
                })
            return json.dumps({"assignments": [
                {"id": "e1", "technique": "T1204.002", "mitigations": []},
                {"id": "e2", "technique": "T1105", "mitigations": []},
                {"id": "e3", "technique": "T1078", "mitigations": []},
            ]})

        graph = _extract_hierarchical(
            "A campaign report.", fake_call, "none", "v1.4")
        events = {event.id: event for event in graph.events}

        # Unambiguous conflicts: the catalogue names one tactic, so adopt it.
        self.assertEqual("EX", events["e1"].tactic)
        self.assertEqual("T1204.002", events["e1"].technique)
        self.assertEqual("C2", events["e2"].tactic)
        self.assertEqual("T1105", events["e2"].technique)

        # Ambiguous conflict: T1078 spans several tactics and none is the one
        # Stage A chose, so the badge is withheld and the event survives.
        self.assertIsNone(events["e3"].technique)
        self.assertEqual([], events["e3"].mitigations)
        self.assertEqual("IM", events["e3"].tactic)
        self.assertEqual(3, len(graph.events))
        self.assertEqual(3, len(calls))

    def test_hierarchical_rules_do_not_repeat_full_catalogue(self):
        full = load_ruleset("v1.4")
        scoped = load_ruleset("v1.4", include_full_catalogue=False)
        self.assertLess(len(scoped), len(full) // 2)
        self.assertIn("tactic-scoped Stage B candidates", scoped)

    def test_double_encoded_assignments_still_reject_invalid_json(self):
        with self.assertRaises(ValidationError):
            EvidenceTechniqueAssignments.model_validate({
                "assignments": "not JSON",
            })

    def test_v15_pipeline_accepts_double_encoded_stage_b_array(self):
        report = "The attacker exfiltrated data."

        def fake_call(system, user, model, response_model=AttackGraph):
            if response_model in _STAGE_B_MODELS:
                inner = json.dumps([{
                    "id": "ev_exfil",
                    "technique": None,
                    "mitigations": [],
                }])
                return json.dumps({"assignments": inner})
            return (
                '{"title":"Evidence test","preconditions":['
                '{"id":"p_access","label":"Data access obtained",'
                '"code":"R","parents":[]},'
                '{"id":"p_done","label":"Data exfiltrated",'
                '"code":"R","parents":["ev_exfil"]}],"events":['
                '{"id":"ev_exfil","label":"Exfiltrate data",'
                '"tactic":"EF","likelihood":5,"parents":["p_access"],'
                '"join":"AND","source_evidence":'
                '"The attacker exfiltrated data.",'
                '"evidence_status":"reported","evidence_confidence":85}]}')

        graph = _extract_hierarchical(report, fake_call, "none", "v1.5")
        self.assertEqual(1, len(graph.events))
        self.assertIsNone(graph.events[0].technique)

    def test_v15_pipeline_preserves_event_when_stage_b_abstains(self):
        report = "The attacker exfiltrated data."

        def fake_call(system, user, model, response_model=AttackGraph):
            if response_model in _STAGE_B_MODELS:
                return ('{"assignments":[{"id":"ev_exfil",'
                        '"technique":null,"mitigations":[]}]}')
            return (
                '{"title":"Evidence test","preconditions":['
                '{"id":"p_access","label":"Data access obtained",'
                '"code":"R","parents":[]},'
                '{"id":"p_done","label":"Data exfiltrated",'
                '"code":"R","parents":["ev_exfil"]}],"events":['
                '{"id":"ev_exfil","label":"Exfiltrate data",'
                '"tactic":"EF","likelihood":5,"parents":["p_access"],'
                '"join":"AND","source_evidence":'
                '"The attacker exfiltrated data.",'
                '"evidence_status":"reported","evidence_confidence":85}]}')

        graph = _extract_hierarchical(report, fake_call, "none", "v1.5")
        self.assertEqual(1, len(graph.events))
        self.assertIsNone(graph.events[0].technique)
        self.assertEqual([], graph.events[0].mitigations)

    def test_v15_does_not_buy_a_third_call_after_validation_failure(self):
        report = "The attacker exfiltrated data."
        calls = []

        def fake_call(system, user, model, response_model=AttackGraph):
            calls.append(response_model)
            if response_model in _STAGE_B_MODELS:
                # T1110 belongs to Credential Access, not Exfiltration.
                return ('{"assignments":[{"id":"ev_exfil",'
                        '"technique":"T1110","mitigations":[]}]}')
            return (
                '{"title":"Evidence test","preconditions":['
                '{"id":"p_access","label":"Data access obtained",'
                '"code":"R","parents":[]},'
                '{"id":"p_done","label":"Data exfiltrated",'
                '"code":"R","parents":["ev_exfil"]}],"events":['
                '{"id":"ev_exfil","label":"Exfiltrate data",'
                '"tactic":"EF","likelihood":5,"parents":["p_access"],'
                '"join":"AND","source_evidence":'
                '"The attacker exfiltrated data.",'
                '"evidence_status":"reported","evidence_confidence":85}]}')

        with self.assertRaisesRegex(RuntimeError, "stage B failed"):
            _extract_hierarchical(report, fake_call, "none", "v1.5")
        self.assertEqual(2, len(calls))

    def test_v15_null_technique_rejects_mitigation(self):
        with self.assertRaises(ValidationError):
            EvidenceTechniqueAssignments.model_validate({
                "assignments": [{
                    "id": "ev_exfil",
                    "technique": None,
                    "mitigations": ["M1057"],
                }]
            })

    def test_v14_still_requires_a_technique(self):
        with self.assertRaises(ValidationError):
            TechniqueAssignments.model_validate({
                "assignments": [{
                    "id": "ev_exfil",
                    "technique": None,
                    "mitigations": [],
                }]
            })

    def test_student_structure_retains_largest_connected_core(self):
        graph = AttackGraph.model_validate({
            "preconditions": [
                {"id": "p1", "label": "First condition", "code": "R"},
                {"id": "r1", "label": "First result", "code": "IA",
                 "parents": ["e1"]},
                {"id": "r2", "label": "Second result", "code": "IM",
                 "parents": ["e2"]},
                {"id": "p2", "label": "Second condition", "code": "R"},
                {"id": "r3", "label": "Peripheral result", "code": "IM",
                 "parents": ["e3"]},
            ],
            "events": [
                {"id": "e1", "label": "Perform first action", "tactic": "IA",
                 "parents": ["p1"]},
                {"id": "e2", "label": "Perform second action", "tactic": "IM",
                 "parents": ["r1"]},
                {"id": "e3", "label": "Perform peripheral action",
                 "tactic": "IM", "parents": ["p2"]},
            ],
        })
        normalised = _normalise_student_structure(graph)
        self.assertEqual(["e1", "e2"], [e.id for e in normalised.events])
        self.assertEqual(
            {"p1", "r1", "r2"}, {p.id for p in normalised.preconditions})
        self.assertEqual([], _student_structure_problems(normalised))

    def test_student_structure_normalises_single_parent_or(self):
        graph = AttackGraph.model_validate({
            "preconditions": [
                {"id": "p1", "label": "Required condition", "code": "R"},
                {"id": "r1", "label": "Action completed", "code": "IA",
                 "parents": ["e1"]},
            ],
            "events": [{
                "id": "e1", "label": "Perform action", "tactic": "IA",
                "parents": ["p1"], "join": "OR",
            }],
        })
        normalised = _normalise_student_structure(graph)
        self.assertEqual("AND", normalised.events[0].join)
        self.assertEqual([], _student_structure_problems(normalised))

    def test_student_structure_allows_root_and_terminal_events(self):
        graph = AttackGraph.model_validate({
            "preconditions": [
                {"id": "p_access", "label": "TfL access obtained", "code": "IA",
                 "parents": ["e_impersonate"]},
                {"id": "p_data", "label": "Oyster records accessible", "code": "C",
                 "parents": ["e_access"]},
            ],
            "events": [
                {"id": "e_impersonate", "label": "Impersonate TfL employee",
                 "tactic": "CA", "parents": [], "join": "OR"},
                {"id": "e_access", "label": "Access TfL systems",
                 "tactic": "IA", "parents": ["p_access"]},
                {"id": "e_search", "label": "Search Oyster customer records",
                 "tactic": "DS", "parents": ["p_data"]},
            ],
        })
        normalised = _normalise_student_structure(graph)
        self.assertEqual("AND", normalised.events[0].join)
        self.assertEqual([], normalised.events[0].parents)
        self.assertFalse(any(
            "e_search" in precondition.parents
            for precondition in normalised.preconditions))
        self.assertEqual([], _student_structure_problems(normalised))

    def test_cost_guard_blocks_a_call_whose_worst_case_exceeds_limit(self):
        budget = _AnthropicCostBudget(max_usd=0.45, max_calls=3)
        with self.assertRaises(RuntimeError):
            budget.preflight(
                "claude-sonnet-5", input_tokens=100_000,
                max_output_tokens=20_000)

    def test_cost_guard_tracks_actual_tokens_conservatively(self):
        budget = _AnthropicCostBudget(max_usd=0.45, max_calls=3)
        budget.preflight(
            "claude-sonnet-5", input_tokens=10_000,
            max_output_tokens=2_000)
        budget.commit(
            "claude-sonnet-5", input_tokens=10_000,
            output_tokens=1_000)
        self.assertEqual(1, budget.summary()["calls"])
        self.assertAlmostEqual(0.045, budget.summary()["estimated_cost_usd"])

    def test_anthropic_provider_submits_exactly_one_request_per_call(self):
        state = {
            "parses": 0,
            "creates": 0,
            "client_kwargs": None,
            "parse_kwargs": None,
            "count_kwargs": None,
        }

        class FakeMessages:
            def count_tokens(self, **kwargs):
                state["count_kwargs"] = kwargs
                return SimpleNamespace(input_tokens=100)

            def parse(self, **kwargs):
                state["parses"] += 1
                state["parse_kwargs"] = kwargs
                parsed = AttackGraph(
                    title="test", preconditions=[], events=[])
                return SimpleNamespace(
                    parsed_output=parsed,
                    content=[SimpleNamespace(type="text")],
                    stop_reason="end_turn",
                    usage=SimpleNamespace(input_tokens=100, output_tokens=20))

            def create(self, **kwargs):
                state["creates"] += 1
                raise AssertionError("unvalidated messages.create was used")

        class FakeClient:
            def __init__(self, **kwargs):
                state["client_kwargs"] = kwargs
                self.messages = FakeMessages()

        fake_anthropic = SimpleNamespace(Anthropic=FakeClient)
        budget = _AnthropicCostBudget()
        with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
            result = _call_anthropic(
                "system", "user", "claude-sonnet-5", AttackGraph, budget)
        self.assertIn('"events":[]', result)
        self.assertEqual(1, state["parses"])
        self.assertEqual(0, state["creates"])
        self.assertIs(
            AttackGraph, state["parse_kwargs"]["output_format"])
        self.assertIs(
            AttackGraph, state["count_kwargs"]["output_format"])
        self.assertEqual(0, state["client_kwargs"]["max_retries"])
        self.assertEqual(1, budget.summary()["calls"])

    def test_anthropic_api_error_is_not_silently_retried(self):
        state = {"parses": 0}

        class FakeMessages:
            def count_tokens(self, **kwargs):
                return SimpleNamespace(input_tokens=100)

            def parse(self, **kwargs):
                state["parses"] += 1
                raise RuntimeError("simulated API failure")

        class FakeClient:
            def __init__(self, **kwargs):
                self.messages = FakeMessages()

        with patch.dict(sys.modules, {
                "anthropic": SimpleNamespace(Anthropic=FakeClient)}):
            with self.assertRaisesRegex(RuntimeError, "simulated API failure"):
                _call_anthropic(
                    "system", "user", "claude-sonnet-5", AttackGraph,
                    _AnthropicCostBudget())
        self.assertEqual(1, state["parses"])

    def test_anthropic_empty_structured_output_is_rejected(self):
        state = {"parses": 0}

        class FakeMessages:
            def count_tokens(self, **kwargs):
                return SimpleNamespace(input_tokens=100)

            def parse(self, **kwargs):
                state["parses"] += 1
                return SimpleNamespace(
                    parsed_output=None,
                    content=[SimpleNamespace(type="text", text="{}")],
                    stop_reason="end_turn",
                    usage=SimpleNamespace(input_tokens=100, output_tokens=2),
                )

        class FakeClient:
            def __init__(self, **kwargs):
                self.messages = FakeMessages()

        with patch.dict(sys.modules, {
                "anthropic": SimpleNamespace(Anthropic=FakeClient)}):
            with self.assertRaisesRegex(
                    RuntimeError, "no validated structured result"):
                _call_anthropic(
                    "system", "user", "claude-sonnet-5",
                    IncidentSemanticDraft, _AnthropicCostBudget())
        self.assertEqual(1, state["parses"])


if __name__ == "__main__":
    unittest.main()
