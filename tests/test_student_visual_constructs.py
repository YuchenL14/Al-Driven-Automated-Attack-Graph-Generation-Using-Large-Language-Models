"""Student v1.4 visual-construct regression tests (no API calls)."""

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from extract import (
    STAGE_A_STUDENT_V14_USER,
    StudentConstructEvidenceGraphWire,
    StudentEvidenceGraph,
    _normalise_student_structure,
    _normalise_student_constructs,
    _normalise_student_context_annotations,
    _normalise_student_non_adversary_events,
    _student_structure_problems,
    is_construct_ruleset,
    load_ruleset,
)


class StudentVisualConstructTests(unittest.TestCase):

    def test_professional_construct_routing_remains_isolated(self):
        self.assertTrue(is_construct_ruleset("v1.6"))
        self.assertFalse(is_construct_ruleset("student-v1.4"))

    def test_student_v14_prompt_is_evidence_triggered_not_a_quota(self):
        rules = load_ruleset("student-v1.4", include_full_catalogue=False)
        self.assertIn("Visual-construct coverage check", rules)
        self.assertIn("Zero annotations", rules)
        self.assertIn("never be invented", STAGE_A_STUDENT_V14_USER)

    def test_provider_schema_exposes_roles_and_outline_styles(self):
        schema = StudentConstructEvidenceGraphWire.model_json_schema()
        rendered = str(schema)
        self.assertIn("external_resource", rendered)
        self.assertIn("annotation", rendered)
        self.assertIn("dotted", rendered)
        self.assertIn("dashed", rendered)

    def test_uncertainty_and_annotation_are_normalised_without_new_nodes(self):
        raw = {
            "title": "Teaching construct test",
            "preconditions": [
                {"id": "r1", "label": "Exploit available", "code": "RS",
                 "role": "external_resource", "style": "solid",
                 "parents": ["e1"]},
                {"id": "s1", "label": "Possible access obtained", "code": "R",
                 "role": "precondition", "style": "solid",
                 "parents": ["e1"]},
                {"id": "a1", "label": "Monitor authentication attempts",
                 "code": "A", "role": "annotation", "style": "solid",
                 "parents": ["e1"]},
            ],
            "events": [
                {"id": "e1", "label": "Exploit service", "tactic": "IA",
                 "likelihood": 4.0, "parents": ["r1", "a1"], "join": "AND",
                 "source_evidence": "The attacker possibly exploited the service.",
                 "action_evidence": "exploited", "actor": "adversary",
                 "evidence_status": "possible", "evidence_confidence": 55,
                 "stated_technique": "", "stated_mitigations": [],
                 "style": "solid"},
            ],
        }

        normalised = _normalise_student_constructs(raw)
        self.assertEqual(3, len(normalised["preconditions"]))
        self.assertEqual(1, len(normalised["events"]))
        by_id = {node["id"]: node for node in normalised["preconditions"]}
        self.assertEqual([], by_id["r1"]["parents"])
        self.assertEqual("dashed", by_id["a1"]["style"])
        self.assertEqual("dotted", by_id["s1"]["style"])
        self.assertEqual("dotted", normalised["events"][0]["style"])
        self.assertNotIn("a1", normalised["events"][0]["parents"])

        # The same canonical contract consumed by the renderer accepts the
        # result; annotations remain present but outside the causal graph.
        graph = StudentEvidenceGraph.model_validate(normalised)
        self.assertEqual(["a1"], [node.id for node in graph.annotations])

    def test_v14_does_not_prune_a_detached_numbered_action_before_review(self):
        raw = {
            "title": "Detached identifier branch",
            "preconditions": [
                {"id": "p1", "label": "Primary result", "code": "R",
                 "parents": ["e1"]},
                {"id": "p2", "label": "Attachment delivered", "code": "D",
                 "parents": ["e2"]},
            ],
            "events": [
                {"id": "e1", "label": "Access system", "tactic": "IA",
                 "likelihood": 6.0, "parents": [], "join": "AND",
                 "source_evidence": "The attacker accessed the system.",
                 "action_evidence": "accessed", "actor": "adversary",
                 "evidence_status": "confirmed", "evidence_confidence": 90,
                 "stated_technique": "", "stated_mitigations": []},
                {"id": "e2", "label": "Send spearphishing attachment",
                 "tactic": "IA", "likelihood": 6.0, "parents": [],
                 "join": "AND", "source_evidence":
                 "The attacker sent a spearphishing email carrying a malicious "
                 "attachment to finance staff (T1566.001, M1017, M1053).",
                 "action_evidence": "sent", "actor": "adversary",
                 "evidence_status": "confirmed", "evidence_confidence": 95,
                 "stated_technique": "T1566.001",
                 "stated_mitigations": ["M1017", "M1053"]},
            ],
        }

        graph = StudentEvidenceGraph.model_validate(raw)
        kept = _normalise_student_structure(
            graph, StudentEvidenceGraph, prune_disconnected=False)
        self.assertEqual(["e1", "e2"], [event.id for event in kept.events])
        self.assertEqual("T1566.001", kept.events[1].stated_technique)
        self.assertEqual(["M1017", "M1053"],
                         kept.events[1].stated_mitigations)

    def test_v14_collapses_victim_action_and_omits_isolated_recovery(self):
        raw = {
            "title": "Non-adversary normalisation",
            "preconditions": [
                {"id": "p_mail", "label": "Attachment delivered", "code": "D",
                 "parents": ["e_send"]},
                {"id": "p_rat", "label": "Remote access tool installed",
                 "code": "R", "parents": ["e_open"]},
                {"id": "p_creds", "label": "Staff credentials obtained",
                 "code": "R", "parents": ["e_creds"]},
                {"id": "p_backup", "label": "Backup snapshots untouched",
                 "code": "R", "parents": []},
                {"id": "p_restored", "label": "Service restored", "code": "R",
                 "parents": ["e_restore"]},
            ],
            "events": [
                {"id": "e_send", "label": "Send spearphishing attachment",
                 "actor": "adversary", "parents": [], "tactic": "IA",
                 "likelihood": 8.0, "join": "AND",
                 "source_evidence": "The attacker sent an attachment.",
                 "action_evidence": "sent", "evidence_status": "confirmed",
                 "evidence_confidence": 95,
                 "stated_technique": "T1566.001",
                 "stated_mitigations": ["M1017", "M1053"]},
                {"id": "e_open", "label": "Employee opens attachment",
                 "actor": "victim", "parents": ["p_mail"], "tactic": "EX",
                 "likelihood": 8.0, "join": "AND",
                 "source_evidence": "An employee opened the attachment.",
                 "action_evidence": "opened", "evidence_status": "confirmed",
                 "evidence_confidence": 95,
                 "stated_technique": "", "stated_mitigations": []},
                {"id": "e_creds", "label": "Obtain staff credentials",
                 "actor": "adversary", "parents": ["p_rat"], "tactic": "CA",
                 "likelihood": 7.0, "join": "AND",
                 "source_evidence": "The attacker obtained staff credentials.",
                 "action_evidence": "obtained",
                 "evidence_status": "confirmed", "evidence_confidence": 95,
                 "stated_technique": "", "stated_mitigations": []},
                {"id": "e_restore", "label": "Restore from backup snapshots",
                 "actor": "defender", "parents": ["p_backup"], "tactic": "IM",
                 "likelihood": 7.0, "join": "AND",
                 "source_evidence": "Backups were used to restore service.",
                 "action_evidence": "used", "evidence_status": "confirmed",
                 "evidence_confidence": 95,
                 "stated_technique": "", "stated_mitigations": []},
            ],
        }

        normalised = _normalise_student_non_adversary_events(raw)
        event_ids = [event["id"] for event in normalised["events"]]
        self.assertEqual(["e_send", "e_creds"], event_ids)
        states = {node["id"]: node for node in normalised["preconditions"]}
        self.assertEqual(["e_send"], states["p_rat"]["parents"])
        self.assertEqual(["p_rat"], normalised["events"][1]["parents"])
        self.assertNotIn("p_backup", states)
        self.assertNotIn("p_restored", states)
        graph = StudentEvidenceGraph.model_validate(normalised)
        self.assertEqual([], _student_structure_problems(graph))

    def test_v14_does_not_silently_drop_numbered_non_adversary_event(self):
        raw = {
            "preconditions": [
                {"id": "p1", "label": "Attachment delivered", "code": "D",
                 "parents": []},
            ],
            "events": [
                {"id": "e1", "label": "Employee opens attachment",
                 "actor": "victim", "parents": ["p1"],
                 "stated_technique": "T1204.002",
                 "stated_mitigations": ["M1017"]},
            ],
        }
        normalised = _normalise_student_non_adversary_events(raw)
        self.assertEqual(["e1"], [event["id"] for event in normalised["events"]])

    def test_v14_reclassifies_explicit_backup_recovery_context(self):
        report = (
            "The attacker uploaded 40GB of records to an external account. "
            "Backup snapshots on a separate network were untouched and were "
            "later used to restore service. The attacker published the records."
        )
        raw = {
            "title": "Recovery-context annotation",
            "preconditions": [
                {"id": "p_exfil", "label": "Finance records uploaded",
                 "code": "EF", "role": "precondition", "style": "solid",
                 "parents": ["e_exfil"]},
                {"id": "p_backup", "label": "Backup snapshots untouched",
                 "code": "R", "role": "precondition", "style": "solid",
                 "parents": ["e_exfil"]},
                {"id": "p_publish", "label": "Records published", "code": "R",
                 "role": "precondition", "style": "solid",
                 "parents": ["e_publish"]},
            ],
            "events": [
                {"id": "e_exfil", "label": "Upload finance records",
                 "actor": "adversary", "parents": [], "tactic": "EF",
                 "likelihood": 7.0, "join": "AND", "source_evidence":
                 "The attacker uploaded 40GB of records to an external account.",
                 "action_evidence": "uploaded", "evidence_status": "confirmed",
                 "evidence_confidence": 95, "stated_technique": "",
                 "stated_mitigations": [], "style": "solid"},
                {"id": "e_publish", "label": "Publish the records",
                 "actor": "adversary", "parents": ["p_exfil", "p_backup"],
                 "tactic": "IM", "likelihood": 7.0, "join": "AND",
                 "source_evidence": "The attacker published the records.",
                 "action_evidence": "published", "evidence_status": "confirmed",
                 "evidence_confidence": 95, "stated_technique": "",
                 "stated_mitigations": [], "style": "solid"},
            ],
        }

        normalised = _normalise_student_context_annotations(raw, report)
        states = {node["id"]: node for node in normalised["preconditions"]}
        self.assertEqual("annotation", states["p_backup"]["role"])
        self.assertEqual("dashed", states["p_backup"]["style"])
        self.assertEqual(["e_exfil"], states["p_backup"]["parents"])
        publish = next(event for event in normalised["events"]
                       if event["id"] == "e_publish")
        self.assertEqual(["p_exfil"], publish["parents"])
        graph = StudentEvidenceGraph.model_validate(normalised)
        self.assertEqual(["p_backup"], [node.id for node in graph.annotations])

    def test_v14_keeps_attacker_harmed_backups_in_causal_graph(self):
        report = "The attacker destroyed backup snapshots to inhibit recovery."
        raw = {
            "preconditions": [
                {"id": "p1", "label": "Backup snapshots destroyed",
                 "code": "IM", "role": "precondition", "style": "solid",
                 "parents": ["e1"]},
            ],
            "events": [
                {"id": "e1", "label": "Destroy backup snapshots",
                 "actor": "adversary", "parents": [], "tactic": "IM",
                 "likelihood": 8.0, "join": "AND", "source_evidence": report,
                 "action_evidence": "destroyed", "evidence_status": "confirmed",
                 "evidence_confidence": 95, "stated_technique": "T1490",
                 "stated_mitigations": [], "style": "solid"},
            ],
        }
        normalised = _normalise_student_context_annotations(raw, report)
        self.assertEqual("precondition",
                         normalised["preconditions"][0]["role"])
        self.assertEqual("solid", normalised["preconditions"][0]["style"])


if __name__ == "__main__":
    unittest.main()
