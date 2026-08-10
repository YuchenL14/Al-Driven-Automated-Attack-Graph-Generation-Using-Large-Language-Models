"""The student does the ATT&CK mapping; the tool draws it and says what is missing.

The supervisor described the teaching workflow in the eighth project meeting: a
student consolidates several sources, reasons about the incident, adds their own
M and T numbers, and pastes the resulting description in, and the tool generates
the graph with those numbers intact. Garbage in, garbage out is the intended
contract, because noticing that a technique is wrong is the exercise.

The student version did the opposite of that. Stage B chose a technique from a
candidate list without ever being shown what the student had written, and the
v1.2 evidence gate could blank a technique for insufficient evidence even though
the narrative was the student's own curated evidence. A student who researched
T1566.002 and typed it in was handed whatever the model preferred.

The catalogue therefore changes role rather than disappearing. It answers two
questions that are not matters of judgement -- does this identifier exist, and
does MITRE connect this mitigation to this technique -- and it answers neither
of them by rewriting the student's work. Whether T1566.002 is the right
technique for a step remains the student's call. Whether "T9999" is an
identifier at all is a typo, and the legend cannot render it.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (AttackGraph, _extract_hierarchical,
                     get_last_student_notes)
from student_identifiers import (RETIRED_TECHNIQUES, classify_identifiers,
                                 identifier_coverage_problems,
                                 identifier_source_clauses, summarise)

MITIGATES = {"T1566.002": ["M1017", "M1021"], "T1003.001": ["M1043"]}


def _event(event_id, label, technique=None, mitigations=()):
    return {"id": event_id, "label": label, "stated_technique": technique,
            "stated_mitigations": list(mitigations)}


class ClassificationTests(unittest.TestCase):
    def test_a_valid_identifier_is_kept_as_written(self):
        accepted, notes = classify_identifiers(
            [_event("e1", "Send link", "T1566.002", ["M1017"])], MITIGATES)
        self.assertEqual("T1566.002", accepted["e1"].technique)
        self.assertEqual(("M1017",), accepted["e1"].mitigations)
        self.assertEqual([], [n for n in notes if n.kind != "inferred_technique"])

    def test_an_unknown_identifier_is_reported_against_its_step(self):
        accepted, notes = classify_identifiers(
            [_event("e1", "Exploit the service", "T9999")], MITIGATES)
        self.assertIsNone(accepted["e1"].technique)
        self.assertEqual(1, len(notes))
        self.assertEqual("unknown_technique", notes[0].kind)
        self.assertIn("Exploit the service", notes[0].message())

    def test_a_retired_identifier_names_its_replacements_without_substituting(self):
        identifier = next(iter(RETIRED_TECHNIQUES))
        accepted, notes = classify_identifiers(
            [_event("e1", "Disable the tools", identifier)], MITIGATES)
        self.assertIsNone(accepted["e1"].technique)
        self.assertEqual("retired_technique", notes[0].kind)
        self.assertIn("Nothing was substituted", notes[0].detail)

    def test_a_mitigation_mitre_does_not_connect_is_kept_and_flagged(self):
        """Their choice stands; the disagreement is shown, not applied."""
        accepted, notes = classify_identifiers(
            [_event("e1", "Send link", "T1566.002", ["M1017", "M1053"])],
            MITIGATES)
        self.assertEqual(("M1017", "M1053"), accepted["e1"].mitigations)
        flagged = [n for n in notes if n.kind == "unrelated_mitigation"]
        self.assertEqual(1, len(flagged))
        self.assertIn("M1053", flagged[0].detail)
        self.assertIn("kept as you wrote it", flagged[0].detail)

    def test_an_unknown_mitigation_is_dropped_and_reported(self):
        accepted, notes = classify_identifiers(
            [_event("e1", "Send link", "T1566.002", ["M9999"])], MITIGATES)
        self.assertEqual((), accepted["e1"].mitigations)
        self.assertEqual("unknown_mitigation", notes[0].kind)

    def test_a_step_with_no_identifier_is_named_as_inferred(self):
        _, notes = classify_identifiers([_event("e1", "Dump credentials")],
                                        MITIGATES)
        self.assertEqual("inferred_technique", notes[0].kind)
        self.assertIn("Dump credentials", notes[0].message())

    def test_a_students_own_answer_is_the_one_kept(self):
        """This used to test `events_needing_a_technique`, which nothing used.

        Its docstring said the open steps were the only ones Stage B was asked
        about. That is not what happens: Stage B is asked about every step and
        the student's own identifier overrides the answer afterwards, in
        `extract.py`. A helper describing a saving the tool does not make, kept
        alive by the only test that called it, is worse than no helper, so both
        were removed and this checks the rule that is actually implemented.
        """

        accepted, _ = classify_identifiers([
            _event("e1", "Send link", "T1566.002"),
            _event("e2", "Dump credentials"),
        ], MITIGATES)
        self.assertEqual("T1566.002", accepted["e1"].technique)
        self.assertIsNone(accepted["e2"].technique)

    def test_omissions_are_summarised_as_one_point(self):
        _, notes = classify_identifiers([
            _event("e1", "Step one"), _event("e2", "Step two"),
        ], MITIGATES)
        lines = summarise(notes)
        self.assertEqual(1, len(lines))
        self.assertIn("2 step(s)", lines[0])

    def test_an_empty_catalogue_does_not_reject_everything(self):
        """Absence of the lookup file must not make every identifier wrong."""
        import student_identifiers as module
        original = module.KNOWN_TECHNIQUES
        module.KNOWN_TECHNIQUES = set()
        try:
            accepted, _ = classify_identifiers(
                [_event("e1", "Step", "T1566.002")], MITIGATES)
            self.assertEqual("T1566.002", accepted["e1"].technique)
        finally:
            module.KNOWN_TECHNIQUES = original


class InputIdentifierCoverageTests(unittest.TestCase):
    NARRATIVE = (
        "The attackers stole NTDS.dit (T1003.003; mitigations M1026, "
        "M1027, M1041). The attackers deployed ransomware (T1486; "
        "mitigations M1040, M1053).")

    def test_every_identifier_is_accounted_for_when_both_steps_exist(self):
        events = [
            {"id": "e1", "source_evidence":
             "The attackers stole NTDS.dit (T1003.003; mitigations M1026, "
             "M1027, M1041).", "stated_technique": "",
             "stated_mitigations": []},
            {"id": "e2", "source_evidence":
             "The attackers deployed ransomware (T1486; mitigations M1040, "
             "M1053).", "stated_technique": "",
             "stated_mitigations": []},
        ]
        self.assertEqual([], identifier_coverage_problems(
            events, self.NARRATIVE))
        self.assertEqual("T1003.003", events[0]["stated_technique"])
        self.assertEqual("T1486", events[1]["stated_technique"])

    def test_a_whole_omitted_step_names_its_missing_identifiers(self):
        events = [{
            "id": "e1",
            "source_evidence":
                "The attackers stole NTDS.dit (T1003.003; mitigations M1026, "
                "M1027, M1041).",
            "stated_technique": "", "stated_mitigations": [],
        }]
        message = " ".join(identifier_coverage_problems(
            events, self.NARRATIVE))
        self.assertIn("T1486", message)
        self.assertIn("M1040", message)
        self.assertIn("M1053", message)
        self.assertNotIn("T1003.003", message)
        self.assertIn(
            "The attackers deployed ransomware (T1486; mitigations M1040, "
            "M1053).", message)

    def test_identifier_clauses_do_not_split_subtechniques_or_filenames(self):
        clauses = identifier_source_clauses(self.NARRATIVE)
        self.assertEqual(2, len(clauses))
        self.assertIn("NTDS.dit", clauses[0])
        self.assertIn("T1003.003", clauses[0])
        self.assertIn("T1486", clauses[1])

    def test_unknown_identifiers_must_be_attributed_then_reported_later(self):
        narrative = "They exploited the service (T9999; mitigation M9999)."
        message = " ".join(identifier_coverage_problems([], narrative))
        self.assertIn("T9999", message)
        self.assertIn("M9999", message)


NARRATIVE = ("The actor sent a spear-phishing link (T1566.002) to staff. "
             "Credentials were dumped from memory. "
             "They exploited the service (T9999) to gain access.")

SKELETON = {
    "title": "s",
    "preconditions": [
        {"id": "p0", "label": "Server exposed", "code": "IA", "parents": []},
        {"id": "p1", "label": "Foothold", "code": "IA", "parents": ["e1"]},
        {"id": "p2", "label": "Creds held", "code": "CA", "parents": ["e2"]},
        {"id": "p3", "label": "Service compromised", "code": "IA",
         "parents": ["e3"]},
    ],
    "events": [
        {"id": "e1", "label": "Sent spear-phishing link", "tactic": "IA",
         "likelihood": 7.0, "parents": ["p0"], "join": "AND",
         "source_evidence":
             "The actor sent a spear-phishing link (T1566.002) to staff.",
         "action_evidence": "sent", "actor": "adversary",
         "evidence_status": "reported", "evidence_confidence": 80,
         "stated_technique": "T1566.002",
         "stated_mitigations": ["M1017", "M1053"]},
        {"id": "e2", "label": "Dumped credentials from memory", "tactic": "CA",
         "likelihood": 7.0, "parents": ["p1"], "join": "AND",
         "source_evidence": "Credentials were dumped from memory.",
         "action_evidence": "dumped", "actor": "adversary",
         "evidence_status": "reported", "evidence_confidence": 80},
        {"id": "e3", "label": "Exploited the service", "tactic": "IA",
         "likelihood": 6.0, "parents": ["p0"], "join": "AND",
         "source_evidence":
             "They exploited the service (T9999) to gain access.",
         "action_evidence": "exploited", "actor": "adversary",
         "evidence_status": "reported", "evidence_confidence": 70,
         "stated_technique": "T9999"},
    ],
}


class EndToEndTests(unittest.TestCase):
    def _run(self, e2_technique="T1003.001", e2_tactic="CA"):
        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                return json.dumps({"assignments": [
                    {"id": "e1", "technique": "T1190",
                     "mitigations": ["M1051"]},
                    {"id": "e2", "technique": e2_technique,
                     "mitigations": ["M1043"]},
                    {"id": "e3", "technique": "T1190",
                     "mitigations": ["M1051"]}]})
            skeleton = json.loads(json.dumps(SKELETON))
            next(event for event in skeleton["events"]
                 if event["id"] == "e2")["tactic"] = e2_tactic
            return json.dumps(skeleton)

        return _extract_hierarchical(NARRATIVE, call, "model", "student-v1.2")

    def test_the_students_technique_survives_stage_b(self):
        """Stage B answered T1190 for this step. The student said otherwise."""
        graph = self._run()
        event = next(e for e in graph.events if e.id == "e1")
        self.assertEqual("T1566.002", event.technique)

    def test_the_students_mitigations_survive_too(self):
        graph = self._run()
        event = next(e for e in graph.events if e.id == "e1")
        self.assertEqual(["M1017", "M1053"], list(event.mitigations))

    def test_an_open_step_is_answered_by_the_model(self):
        graph = self._run()
        event = next(e for e in graph.events if e.id == "e2")
        self.assertEqual("T1003.001", event.technique)

    def test_a_rejected_identifier_falls_back_to_the_suggestion(self):
        graph = self._run()
        event = next(e for e in graph.events if e.id == "e3")
        self.assertEqual("T1190", event.technique)

    def test_the_student_is_told_all_three_things(self):
        self._run()
        notes = " ".join(get_last_student_notes())
        self.assertIn("M1053", notes)          # kept but not connected
        self.assertIn("T9999", notes)          # not a real identifier
        self.assertIn("Dumped credentials", notes)   # left for the tool

    def test_an_evidence_abstention_does_not_erase_the_candidate(self):
        """A blank badge and a reviewable suggestion are different things."""
        graph = self._run(e2_technique="T1021.001", e2_tactic="LM")
        event = next(e for e in graph.events if e.id == "e2")
        self.assertIsNone(event.technique)
        notes = " ".join(get_last_student_notes())
        self.assertIn("Stage B suggested T1021.001", notes)
        self.assertIn("not a choice confirmed on your behalf", notes)

    def test_the_working_fields_do_not_leak_into_the_saved_graph(self):
        """They are Stage A scaffolding, not part of the attack graph."""
        graph = self._run()
        saved = json.loads(graph.model_dump_json())
        for event in saved["events"]:
            self.assertNotIn("stated_technique", event)
            self.assertNotIn("stated_mitigations", event)

    def test_a_silently_omitted_numbered_step_gets_one_stage_a_repair(self):
        stage_a_prompts = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                return json.dumps({"assignments": [
                    {"id": "e1", "technique": "T1190", "mitigations": []},
                    {"id": "e2", "technique": "T1003.001",
                     "mitigations": ["M1043"]},
                    {"id": "e3", "technique": "T1190", "mitigations": []},
                ]})
            stage_a_prompts.append(user)
            skeleton = json.loads(json.dumps(SKELETON))
            if len(stage_a_prompts) == 1:
                skeleton["events"] = [
                    event for event in skeleton["events"]
                    if event["id"] != "e3"]
                skeleton["preconditions"] = [
                    node for node in skeleton["preconditions"]
                    if node["id"] != "p3"]
            return json.dumps(skeleton)

        graph = _extract_hierarchical(
            NARRATIVE, call, "model", "student-v1.3")
        self.assertEqual(2, len(stage_a_prompts))
        self.assertIn("MANDATORY STUDENT IDENTIFIER CHECKLIST",
                      stage_a_prompts[0])
        self.assertIn(
            "They exploited the service (T9999) to gain access.",
            stage_a_prompts[0])
        self.assertIn("silently omitted", stage_a_prompts[1])
        self.assertIn(
            "They exploited the service (T9999) to gain access.",
            stage_a_prompts[1])
        self.assertTrue(any(event.id == "e3" for event in graph.events))

    def test_the_professional_path_does_not_use_the_student_coverage_gate(self):
        stage_a_calls = 0

        def call(system, user, model, response_model=AttackGraph):
            nonlocal stage_a_calls
            if "Assignment" in response_model.__name__:
                return json.dumps({"assignments": [
                    {"id": "e1", "technique": "T1190", "mitigations": []},
                    {"id": "e2", "technique": "T1003.001",
                     "mitigations": []},
                ]})
            stage_a_calls += 1
            skeleton = json.loads(json.dumps(SKELETON))
            skeleton["events"] = [event for event in skeleton["events"]
                                  if event["id"] != "e3"]
            skeleton["preconditions"] = [
                node for node in skeleton["preconditions"]
                if node["id"] != "p3"]
            return json.dumps(skeleton)

        graph = _extract_hierarchical(NARRATIVE, call, "model", "v1.4")
        self.assertEqual(1, stage_a_calls)
        self.assertEqual(2, len(graph.events))


class PromptContractTests(unittest.TestCase):
    def test_every_stage_a_prompt_still_carries_the_mock_marker(self):
        """The mock decides which stage it is answering by reading the prose.

        Rewording the student Stage A prompt once removed both marker phrases,
        so the mock stopped recognising Stage A and answered with a finished
        graph. The failure surfaced as missing evidence fields, which reads
        like a model fault rather than a prompt edit.
        """
        from extract import (_is_stage_a_prompt, STAGE_A_STUDENT_USER,
                             STAGE_A_STUDENT_EVIDENCE_USER,
                             STAGE_A_STUDENT_V12_USER, STAGE_A_USER,
                             STAGE_A_V16_USER)
        for prompt in (STAGE_A_USER, STAGE_A_V16_USER, STAGE_A_STUDENT_USER,
                       STAGE_A_STUDENT_EVIDENCE_USER,
                       STAGE_A_STUDENT_V12_USER):
            self.assertTrue(
                _is_stage_a_prompt(prompt),
                "a Stage A prompt lost the phrase the mock recognises")

    def test_the_marker_survives_a_line_break(self):
        """v1.6 wraps between "ids" and "yet"; a raw match missed it."""
        from extract import _is_stage_a_prompt
        wrapped = "\n".join(
            ["Do NOT choose technique or mitigation ids",
             "yet; Stage B assigns them."])
        self.assertTrue(_is_stage_a_prompt(wrapped))
        self.assertFalse(_is_stage_a_prompt("Assign techniques to these."))

    def test_the_student_prompt_asks_for_copying_not_choosing(self):
        from extract import STAGE_A_STUDENT_V12_USER
        self.assertIn("COPY OUT, DO NOT CHOOSE", STAGE_A_STUDENT_V12_USER)
        self.assertIn("never supply one of your own here",
                      STAGE_A_STUDENT_V12_USER)


if __name__ == "__main__":
    unittest.main()


class WireContractTests(unittest.TestCase):
    """What the provider is asked for, as opposed to what is accepted.

    The student path sent its strict model straight to the API. Six fields
    carried defaults, so each arrived as an optional property inside an anyOf
    with null: the evidence contract the rules insist on was skippable, and the
    constrained-decoding grammar carried six branches nobody wanted. The first
    real student run failed with "Grammar compilation timed out".

    Whether that message was caused by these branches or was transient is not
    established. The wire model is right either way, for the reason
    `EvidenceEventWire` already records: a field with a default reaches the
    provider as optional, and the model then omits it.
    """

    def test_the_provider_is_sent_the_wire_model(self):
        import extract
        self.assertIs(extract.StudentEvidenceGraphWire,
                      extract.StudentEvidenceGraphWire)
        schema = extract.StudentEvidenceGraphWire.model_json_schema()
        event = schema["$defs"]["StudentEvidenceEventWire"]
        self.assertEqual(
            sorted(["id", "label", "tactic", "likelihood", "source_evidence",
                    "action_evidence", "actor", "evidence_status",
                    "evidence_confidence", "stated_technique",
                    "stated_mitigations"]),
            sorted(event["required"]),
            "the evidence contract must be required, not optional")

    def test_the_stated_identifiers_are_required_too(self):
        """The first real run lost a student's T1213 to exactly this.

        `stated_technique` carried a default, so it was optional to the
        provider and the model omitted it on every event. An empty string for
        a step the student left unnumbered is a value, not an absence, and the
        difference is whether the model was made to look.
        """
        import extract
        event = extract.StudentEvidenceGraphWire.model_json_schema()[
            "$defs"]["StudentEvidenceEventWire"]
        self.assertIn("stated_technique", event["required"])
        self.assertIn("stated_mitigations", event["required"])

    def test_the_wire_schema_has_no_nullable_branches(self):
        import json
        import extract
        schema = json.dumps(
            extract.StudentEvidenceGraphWire.model_json_schema())
        self.assertNotIn('"anyOf"', schema)

    def test_an_unnumbered_step_is_an_empty_string_not_a_null(self):
        """One less branch in the grammar, one less null in the payload."""
        import extract
        event = extract.StudentEvidenceEventWire(
            id="e1", label="Do it", tactic="IA", likelihood=5.0,
            source_evidence="q", action_evidence="did", actor="adversary",
            evidence_status="reported", evidence_confidence=80,
            stated_technique="", stated_mitigations=[])
        self.assertEqual("", event.stated_technique)
        self.assertEqual([], event.stated_mitigations)

    def test_the_strict_model_still_validates_what_comes_back(self):
        import extract
        self.assertTrue(issubclass(extract.StudentEvidenceGraph,
                                   extract.AttackGraph))


class ReadingFromTextTests(unittest.TestCase):
    """Locate the identifiers rather than asking a model to transcribe them.

    Stage A was told to copy them across, and on the first real run it did not:
    it ended each evidence quotation at the action, so the trailing
    "(T1213; mitigations M1047, ...)" fell outside both the quotation and the
    field, and a student's own mapping was reported as missing. The identifiers
    are in the text the student pasted; finding them needs no inference and
    cannot hallucinate.
    """

    NARRATIVE = (
        "Two attackers infiltrated the network in August. The source does not "
        "state how entry was achieved.\n\n"
        "The attackers accessed data held in the refunds system "
        "(T1213; mitigations M1047, M1041).\n\n"
        "Customer refunds were delayed."
    )

    def _events(self):
        from student_identifiers import read_identifiers_from_text
        events = [
            {"id": "e1", "label": "Infiltrate the network",
             "source_evidence": "Two attackers infiltrated the network in August",
             "stated_technique": "", "stated_mitigations": []},
            {"id": "e2", "label": "Access the refunds system",
             "source_evidence":
                 "The attackers accessed data held in the refunds system",
             "stated_technique": "", "stated_mitigations": []},
        ]
        read_identifiers_from_text(events, self.NARRATIVE)
        return {event["id"]: event for event in events}

    def test_an_identifier_after_the_quotation_is_still_found(self):
        events = self._events()
        self.assertEqual("T1213", events["e2"]["stated_technique"])

    def test_the_mitigations_beside_it_come_with_it(self):
        events = self._events()
        self.assertEqual(["M1047", "M1041"], events["e2"]["stated_mitigations"])

    def test_a_step_with_no_identifier_stays_empty(self):
        """Nothing from a neighbouring sentence is borrowed for it."""
        events = self._events()
        self.assertEqual("", events["e1"]["stated_technique"])
        self.assertEqual([], events["e1"]["stated_mitigations"])

    def test_the_text_overrules_what_the_model_supplied(self):
        """This test asserted the opposite, and was wrong about which wins.

        Deferring to the model wherever it had written something lost a real
        student's T1003.003, because the model wrote the parent T1003 and the
        extraction then skipped the step. A transcription that disagrees with
        the source is not evidence about what the student chose.
        """
        from student_identifiers import read_identifiers_from_text
        events = [{"id": "e2", "label": "Access the refunds system",
                   "source_evidence":
                       "The attackers accessed data held in the refunds system",
                   "stated_technique": "T1005", "stated_mitigations": []}]
        read_identifiers_from_text(events, self.NARRATIVE)
        self.assertEqual("T1213", events[0]["stated_technique"])

    def test_a_quotation_absent_from_the_narrative_is_skipped(self):
        from student_identifiers import read_identifiers_from_text
        events = [{"id": "e1", "label": "Something else",
                   "source_evidence": "words that appear nowhere",
                   "stated_technique": "", "stated_mitigations": []}]
        read_identifiers_from_text(events, self.NARRATIVE)
        self.assertEqual("", events[0]["stated_technique"])

    def test_an_empty_narrative_changes_nothing(self):
        from student_identifiers import read_identifiers_from_text
        events = [{"id": "e1", "stated_technique": "", "stated_mitigations": []}]
        read_identifiers_from_text(events, "")
        self.assertEqual("", events[0]["stated_technique"])

    def test_a_word_boundary_is_required(self):
        from student_identifiers import (_MITIGATION_IN_TEXT,
                                         _TECHNIQUE_IN_TEXT)
        self.assertEqual(["T1566.002"], _TECHNIQUE_IN_TEXT.findall(
            "a spear-phishing link (T1566.002) to staff"))
        self.assertEqual([], _TECHNIQUE_IN_TEXT.findall("XT1213Y"))
        self.assertEqual(["M1047"], _MITIGATION_IN_TEXT.findall("use M1047."))


class WrappedNarrativeTests(unittest.TestCase):
    """A pasted description is wrapped, and the quotation is not.

    The first real run lost a student's T1213 because the narrative carried a
    newline between "refunds" and "system" while the model's quotation carried
    a space, so the literal search matched nothing and the whole extraction was
    skipped in silence. This is the third comparison in this project defeated
    by a line break; the other two were the rule-set prompt comparison and the
    mock's stage detection.
    """

    WRAPPED = (
        "The attackers accessed data held in Transport for London's Oyster "
        "refunds\nsystem (T1213; mitigations M1047, M1041).\n\n"
        "Customer refunds were delayed."
    )
    QUOTATION = ("The attackers accessed data held in Transport for London's "
                 "Oyster refunds system")

    def _read(self, narrative):
        from student_identifiers import read_identifiers_from_text
        events = [{"id": "e1", "label": "Access the refunds system",
                   "source_evidence": self.QUOTATION,
                   "stated_technique": "", "stated_mitigations": []}]
        read_identifiers_from_text(events, narrative)
        return events[0]

    def test_a_line_break_inside_the_sentence_does_not_hide_it(self):
        self.assertEqual("T1213", self._read(self.WRAPPED)["stated_technique"])

    def test_the_mitigations_survive_the_wrap_too(self):
        self.assertEqual(["M1047", "M1041"],
                         self._read(self.WRAPPED)["stated_mitigations"])

    def test_the_unwrapped_form_still_works(self):
        flat = " ".join(self.WRAPPED.split())
        self.assertEqual("T1213", self._read(flat)["stated_technique"])

    def test_repeated_spaces_and_tabs_are_tolerated(self):
        noisy = self.WRAPPED.replace("Oyster ", "Oyster\t  ")
        self.assertEqual("T1213", self._read(noisy)["stated_technique"])


class TheTextWinsTests(unittest.TestCase):
    """Two ways to lose a sub-technique, both found on the M&S run.

    A student wrote T1003.003 with the three mitigations MITRE lists beside it.
    The graph came back carrying the parent T1003 and no mitigations at all.

    Two separate faults produced that. The extraction deferred to the model
    wherever the model had already written something, and the model had
    written the parent. And the sentence the identifier sits in was found by
    searching for the next full stop, which lands inside "T1003.003" itself, so
    the span ended mid-identifier at "(T1003" and the pattern matched exactly
    that much.
    """

    NARRATIVE = (
        "The attackers stole the NTDS.dit file from the Windows domain\n"
        "controllers (T1003.003; mitigations M1026, M1027, M1041).\n\n"
        "The attackers deployed DragonForce ransomware."
    )
    QUOTATION = ("The attackers stole the NTDS.dit file from the Windows "
                 "domain controllers")

    def _read(self, supplied_by_model=""):
        from student_identifiers import read_identifiers_from_text
        events = [{"id": "e1", "label": "Steal the NTDS.dit file",
                   "source_evidence": self.QUOTATION,
                   "stated_technique": supplied_by_model,
                   "stated_mitigations": []}]
        read_identifiers_from_text(events, self.NARRATIVE)
        return events[0]

    def test_a_sub_technique_survives_the_full_stop_inside_it(self):
        self.assertEqual("T1003.003", self._read()["stated_technique"])

    def test_a_full_stop_inside_a_filename_does_not_end_the_sentence(self):
        # "NTDS.dit" sits inside the quotation itself.
        self.assertEqual(["M1026", "M1027", "M1041"],
                         self._read()["stated_mitigations"])

    def test_the_text_overrules_the_models_transcription(self):
        """The model wrote the parent. The student wrote the child."""
        self.assertEqual("T1003.003",
                         self._read(supplied_by_model="T1003")["stated_technique"])

    def test_the_model_is_still_used_where_the_text_is_silent(self):
        from student_identifiers import read_identifiers_from_text
        events = [{"id": "e2", "label": "Deploy ransomware",
                   "source_evidence": "The attackers deployed DragonForce ransomware",
                   "stated_technique": "T1486", "stated_mitigations": []}]
        read_identifiers_from_text(events, self.NARRATIVE)
        self.assertEqual("T1486", events[0]["stated_technique"])

    def test_a_sentence_end_is_recognised_at_the_end_of_the_text(self):
        from student_identifiers import read_identifiers_from_text
        events = [{"id": "e1", "label": "Step",
                   "source_evidence": "The attacker acted",
                   "stated_technique": "", "stated_mitigations": []}]
        read_identifiers_from_text(events, "The attacker acted (T1486)")
        self.assertEqual("T1486", events[0]["stated_technique"])


class StudentGatesTests(unittest.TestCase):
    """Two of the v1.6 gates bind every rule set, so the student path runs them.

    Neither changes the visual language a student is taught. Both catch a fault
    that would otherwise surface inside Stage B, where only technique
    identifiers come back and nothing can be relinked, so the whole graph is
    lost after both calls have been paid for.

    The shape review is deliberately not among them: see
    `test_the_shape_review_is_not_ported`.
    """

    @staticmethod
    def _skeleton():
        return {
            "title": "s",
            "preconditions": [
                {"id": "p_nomfa", "label": "Gateway lacked MFA", "code": "IA",
                 "parents": []},
                {"id": "p_a", "label": "Password guessed", "code": "CA",
                 "parents": ["e1"]},
                {"id": "p_b", "label": "Credentials reused", "code": "CA",
                 "parents": ["e2"]},
                {"id": "p_in", "label": "Signed in to gateway", "code": "IA",
                 "parents": ["e3"]},
            ],
            "events": [
                {"id": "e1", "label": "Guessed a weak password", "tactic": "CA",
                 "likelihood": 5.0, "parents": [], "join": "AND",
                 "source_evidence": "The attacker either guessed a weak password",
                 "action_evidence": "guessed", "actor": "adversary",
                 "evidence_status": "possible", "evidence_confidence": 60,
                 "stated_technique": "", "stated_mitigations": []},
                {"id": "e2", "label": "Reused stolen credentials", "tactic": "CA",
                 "likelihood": 5.0, "parents": [], "join": "AND",
                 "source_evidence": "reused stolen credentials",
                 "action_evidence": "reused", "actor": "adversary",
                 "evidence_status": "possible", "evidence_confidence": 60,
                 "stated_technique": "", "stated_mitigations": []},
                {"id": "e3", "label": "Signed in to the gateway", "tactic": "IA",
                 "likelihood": 7.0, "parents": ["p_a", "p_b", "p_nomfa"],
                 "join": "OR",
                 "source_evidence": "The attacker signed in to the gateway",
                 "action_evidence": "signed in", "actor": "adversary",
                 "evidence_status": "confirmed", "evidence_confidence": 85,
                 "stated_technique": "", "stated_mitigations": []},
            ],
        }

    NARRATIVE = ("The gateway lacked multi-factor authentication. "
                 "The attacker either guessed a weak password or reused stolen "
                 "credentials. The attacker signed in to the gateway.")

    def test_a_mixed_join_is_corrected_rather_than_drawn(self):
        """OR over two routes AND an initial condition claims too much."""
        calls = []

        def call(system, user, model, response_model=AttackGraph):
            if "Assignment" in response_model.__name__:
                return json.dumps({"assignments": [
                    {"id": i, "technique": "T1078", "mitigations": []}
                    for i in ("e1", "e2", "e3")]})
            calls.append(user)
            return json.dumps(self._skeleton())

        with self.assertRaises(Exception):
            _extract_hierarchical(self.NARRATIVE, call, "model",
                                  "student-v1.3")
        self.assertGreater(len(calls), 1, "the model must be asked to fix it")
        self.assertIn("one event's join says something you did not mean",
                      calls[1])

    def test_an_annotation_attached_to_a_state_is_caught_here_too(self):
        from extract import _annotation_problems
        skeleton = self._skeleton()
        skeleton["preconditions"].append(
            {"id": "a1", "label": "Detected on day 4", "code": "A1",
             "role": "annotation", "style": "dashed", "parents": ["p_in"]})
        problems = _annotation_problems(skeleton)
        self.assertTrue(problems)
        self.assertIn("comments on a step", problems[0])

    def test_a_clean_student_graph_passes_both(self):
        from extract import _annotation_problems, _mixed_join_problems
        clean = self._skeleton()
        signed_in = clean["events"][2]
        # The shape Rule 3 asks for: one shared state, consumer is AND.
        clean["preconditions"] = [
            node for node in clean["preconditions"]
            if node["id"] not in {"p_a", "p_b"}
        ] + [{"id": "p_creds", "label": "Credentials for the gateway",
              "code": "CA", "parents": ["e1", "e2"]}]
        signed_in["parents"] = ["p_creds", "p_nomfa"]
        signed_in["join"] = "AND"
        self.assertEqual([], _annotation_problems(clean))
        self.assertEqual([], _mixed_join_problems(clean))

    def test_the_shape_review_is_not_ported(self):
        """It is built for graphs an order of magnitude larger than these.

        Its two observations both misfire on a teaching graph. The critical
        path share is 100% for any short sequential attack, which is correct
        and not worth an API call to question. The unused-state count trips on
        a handful of genuine endings, and a student pressed to explain endings
        that need no explanation is being taught to invent consumers for them,
        which is the one thing this project refuses to do.
        """
        from extract import _MIN_EVENTS_FOR_SHAPE_REVIEW, is_construct_ruleset
        self.assertFalse(is_construct_ruleset("student-v1.3"))
        self.assertGreaterEqual(_MIN_EVENTS_FOR_SHAPE_REVIEW, 8)
