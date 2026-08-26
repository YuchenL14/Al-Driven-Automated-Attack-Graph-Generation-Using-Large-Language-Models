from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Literal

from schema import KNOWN_MITIGATIONS, KNOWN_TECHNIQUES

NoteKind = Literal[
    "unknown_technique",
    "retired_technique",
    "unknown_mitigation",
    "unrelated_mitigation",
    "inferred_technique",
    "kept_mitigation_without_technique",
]

# Retirements the rule set already names. Reported as a replacement to consider,
# never substituted: choosing between three successors is the student's call.
RETIRED_TECHNIQUES: dict[str, str] = {
    "T1562": "T1685 (disable or modify tools), T1686 (disable or modify "
             "system firewall) or T1687 (exploitation for defense impairment)",
}


# ATT&CK identifiers as they appear in prose: T1213, T1566.002, M1047.
_TECHNIQUE_IN_TEXT = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_MITIGATION_IN_TEXT = re.compile(r"\bM\d{4}\b")
# A full stop that really ends a sentence: not one inside T1003.003 or
# NTDS.dit, so it must not sit between two digits or before a letter.
_SENTENCE_END = re.compile(r"(?<!\d)\.(?=\s|$)")
_CLAUSE_END = re.compile(r"(?<!\d)[.!?](?=\s|$)")


def identifier_source_clauses(
    narrative: str, identifiers: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """Return exact source clauses containing Student-supplied T/M ids.

    The clauses are a deterministic checklist for Stage A.  Full stops inside
    a sub-technique (``T1003.003``) or filename (``NTDS.dit``) are not sentence
    boundaries, so the model receives the complete source-supported action
    rather than a truncated identifier.
    """

    flat = " ".join((narrative or "").split())
    if not flat:
        return ()
    wanted = set(identifiers or ())
    clauses: list[str] = []
    start = 0
    for match in _CLAUSE_END.finditer(flat):
        clause = flat[start:match.end()].strip()
        start = match.end()
        present = set(_TECHNIQUE_IN_TEXT.findall(clause))
        present.update(_MITIGATION_IN_TEXT.findall(clause))
        if present and (not wanted or present & wanted):
            clauses.append(clause)
    tail = flat[start:].strip()
    if tail:
        present = set(_TECHNIQUE_IN_TEXT.findall(tail))
        present.update(_MITIGATION_IN_TEXT.findall(tail))
        if present and (not wanted or present & wanted):
            clauses.append(tail)
    return tuple(clauses)


def read_identifiers_from_text(events: list[dict], narrative: str) -> None:
    """Fill in what the student wrote, by reading their text rather than asking.

    Stage A was asked to copy the identifiers across. On the first real run it
    did not: it ended each evidence quotation at the action and left the
    parenthetical "(T1213; mitigations M1047, ...)" out of both the quotation
    and the field, so a student's own mapping was reported as missing.

    Asking a model to transcribe something a regular expression can locate
    exactly is the wrong division of labour. The identifiers are literally in
    the text the student pasted; finding them needs no inference and cannot
    hallucinate.

    So the text wins wherever it has an answer. Deferring to the model's
    transcription where it had supplied one lost a student's T1003.003: the
    model wrote the parent T1003 instead, the extraction was skipped because a
    value was already present, and the three mitigations beside the sub-
    technique went with it. A transcription that disagrees with the source is
    not evidence about what the student chose. The model's answer is kept only
    for a step the text says nothing about, where it may have picked up an
    identifier from a sentence the quotation does not cover.

    Attribution is by position: an identifier belongs to the event whose
    evidence quotation shares a sentence with it. An identifier in a sentence
    no event quotes is left alone rather than attached to the nearest event,
    because guessing which step a student meant is exactly the judgement this
    module refuses to make on their behalf.
    """

    if not narrative:
        return
    # Matched on normalised whitespace. A pasted description is wrapped, so a
    # sentence can carry a newline where the quotation carries a space, and a
    # literal search then finds nothing: the first real run lost a student's
    # T1213 to a line break between "refunds" and "system". This is the third
    # comparison in this project to be defeated the same way, so prose is no
    # longer matched on raw text anywhere.
    flat_narrative = " ".join(narrative.split())
    for event in events:
        quotation = " ".join((event.get("source_evidence") or "").split())
        if not quotation:
            continue
        start = flat_narrative.find(quotation)
        if start < 0:
            continue
        # Read exactly the sentence the quotation sits in, so a trailing
        # "(T1213; mitigations M1047)" is included but identifiers from the
        # next sentence can never bleed into this event.  Searching only after
        # the quotation was wrong when the quotation already included its
        # terminal full stop: the next sentence's M-numbers were then silently
        # attributed to the previous action.
        #
        # Not every full stop ends a sentence. "T1003.003" and "NTDS.dit" both
        # contain one, and cutting at the first of them truncated a student's
        # sub-technique to its parent: the span ended mid-identifier at
        # "(T1003" and the pattern matched exactly that.
        tail = _SENTENCE_END.search(flat_narrative, start)
        span = flat_narrative[
            start:tail.end() if tail else len(flat_narrative)]
        found = _TECHNIQUE_IN_TEXT.findall(span)
        if found:
            event["stated_technique"] = found[0]
        mitigations = list(event.get("stated_mitigations") or [])
        for mitigation in _MITIGATION_IN_TEXT.findall(span):
            if mitigation not in mitigations:
                mitigations.append(mitigation)
        event["stated_mitigations"] = mitigations


def identifier_coverage_problems(
    events: list[dict], narrative: str,
) -> list[str]:
    """Name identifiers the Student Stage A skeleton silently omitted.

    Student v1.3 treats identifiers in the submitted narrative as the
    student's work.  It is therefore not enough for the returned skeleton to
    be internally valid: every T/M number in that narrative must be attributed
    to an extracted event, even when the model omitted the number from its
    structured fields.  ``read_identifiers_from_text`` performs the
    deterministic attribution first; this function then checks the whole
    input against the attributed result.

    Unknown and retired identifiers count as covered here.  Their catalogue
    status is handled later by ``classify_identifiers`` and reported to the
    student.  This gate asks only whether anything they wrote disappeared.
    """

    read_identifiers_from_text(events, narrative)
    supplied_techniques = set(_TECHNIQUE_IN_TEXT.findall(narrative or ""))
    supplied_mitigations = set(_MITIGATION_IN_TEXT.findall(narrative or ""))
    attributed_techniques = {
        str(event.get("stated_technique") or "").strip()
        for event in events
        if str(event.get("stated_technique") or "").strip()
    }
    attributed_mitigations = {
        str(identifier).strip()
        for event in events
        for identifier in (event.get("stated_mitigations") or [])
        if str(identifier).strip()
    }

    missing_techniques = sorted(supplied_techniques - attributed_techniques)
    missing_mitigations = sorted(supplied_mitigations - attributed_mitigations)
    if not missing_techniques and not missing_mitigations:
        return []

    parts: list[str] = []
    if missing_techniques:
        parts.append("techniques " + ", ".join(missing_techniques))
    if missing_mitigations:
        parts.append("mitigations " + ", ".join(missing_mitigations))
    missing_identifiers = set(missing_techniques) | set(missing_mitigations)
    clauses = identifier_source_clauses(narrative, missing_identifiers)
    clause_detail = ""
    if clauses:
        clause_detail = ". Missing source clause(s): " + " | ".join(
            f'"{clause}"' for clause in clauses)
    return [
        "student identifier coverage missing from Stage A events: "
        + "; ".join(parts)
        + clause_detail
        + ". Add the source-supported action(s) carrying these identifiers; "
          "do not attach them to an unrelated event"
    ]


@dataclass(frozen=True)
class IdentifierNote:
    """One thing to tell the student about one step."""

    event_id: str
    event_label: str
    kind: NoteKind
    detail: str

    def message(self) -> str:
        return f"{self.event_label}: {self.detail}"


@dataclass(frozen=True)
class AcceptedIdentifiers:
    """What survived checking, per event."""

    technique: str | None
    mitigations: tuple[str, ...]


def _known_technique(identifier: str) -> bool:
    # An empty catalogue means the lookup file is absent; refusing everything
    # then would be worse than accepting, so absence disables the check.
    return not KNOWN_TECHNIQUES or identifier in KNOWN_TECHNIQUES


def _known_mitigation(identifier: str) -> bool:
    return not KNOWN_MITIGATIONS or identifier in KNOWN_MITIGATIONS


def classify_identifiers(
    events: Iterable[dict],
    technique_mitigations: dict[str, list[str]],
) -> tuple[dict[str, AcceptedIdentifiers], list[IdentifierNote]]:
    """Check what the student wrote; report what they wrote wrongly or not at all.

    ``technique_mitigations`` is MITRE's own "mitigates" relationship. It is
    read to annotate, never to replace: a mitigation the student chose that
    MITRE does not connect to their technique is still drawn, with a note.
    """

    accepted: dict[str, AcceptedIdentifiers] = {}
    notes: list[IdentifierNote] = []

    for event in events:
        event_id = event.get("id") or ""
        label = event.get("label") or event_id
        stated = (event.get("stated_technique") or "").strip() or None
        technique: str | None = None

        if stated:
            if _known_technique(stated):
                technique = stated
            elif stated in RETIRED_TECHNIQUES:
                notes.append(IdentifierNote(
                    event_id, label, "retired_technique",
                    f"{stated} was retired in this ATT&CK release. Consider "
                    f"{RETIRED_TECHNIQUES[stated]}. Nothing was substituted "
                    "for you."))
            else:
                notes.append(IdentifierNote(
                    event_id, label, "unknown_technique",
                    f"{stated} is not an identifier in the ATT&CK catalogue "
                    "this tool carries. Check the number, or leave it out and "
                    "the tool will suggest one."))
        else:
            notes.append(IdentifierNote(
                event_id, label, "inferred_technique",
                "you did not give a technique for this step, so one was "
                "suggested. Decide whether you agree with it."))

        kept: list[str] = []
        official = set(technique_mitigations.get(technique, ())) if technique \
            else set()
        for mitigation in event.get("stated_mitigations") or []:
            mitigation = str(mitigation).strip()
            if not mitigation:
                continue
            if not _known_mitigation(mitigation):
                notes.append(IdentifierNote(
                    event_id, label, "unknown_mitigation",
                    f"{mitigation} is not a mitigation identifier in the "
                    "ATT&CK catalogue this tool carries."))
                continue
            if mitigation not in kept:
                kept.append(mitigation)
            if technique and official and mitigation not in official:
                notes.append(IdentifierNote(
                    event_id, label, "unrelated_mitigation",
                    f"MITRE does not list {mitigation} as countering "
                    f"{technique}. It has been kept as you wrote it."))

        if kept and stated and technique is None:
            # A step where the technique was rejected but the mitigations were
            # not. Without this line the student reads the retirement note for
            # their technique and has no way to tell whether the mitigations
            # they wrote beside it survived.
            notes.append(IdentifierNote(
                event_id, label, "kept_mitigation_without_technique",
                f"your technique for this step was not usable, so a technique "
                f"was suggested instead, but {', '.join(kept)} stayed as you "
                "wrote it."))

        accepted[event_id] = AcceptedIdentifiers(
            technique=technique, mitigations=tuple(kept))
    return accepted, notes


def summarise(notes: list[IdentifierNote]) -> tuple[str, ...]:
    """One line per note, grouped so the omissions read as a single point."""

    inferred = [n for n in notes if n.kind == "inferred_technique"]
    problems = [n for n in notes if n.kind != "inferred_technique"]
    lines = [n.message() for n in problems]
    if inferred:
        named = ", ".join(sorted(n.event_label for n in inferred))
        lines.append(
            f"{len(inferred)} step(s) had no technique of yours, so one was "
            f"suggested for each: {named}. Decide whether you agree.")
    return tuple(lines)
