from __future__ import annotations

import re
from typing import Iterable

from schema import ATTACK_TACTICS

_NOISE = frozenset({
    "the", "and", "for", "with", "from", "into", "that", "this", "was", "were",
    "used", "using", "via", "over", "then", "their", "attacker",
    "attackers", "adversary", "system", "systems", "data", "access", "obtain",
    "obtained", "gain", "gained", "run", "ran",
})
_WORD = re.compile(r"[a-z][a-z0-9.]{3,}")

MAX_SHORTLIST = 6


def _significant_words(text: str) -> set[str]:
    return {word for word in _WORD.findall((text or "").lower())
            if word not in _NOISE}


def technique_shortlist(
    label: str,
    evidence: str,
    tactic: str,
    candidate_lines: str,
    suggested: str | None = None,
) -> tuple[str, ...]:
    """Candidates worth looking at for one unmapped step, and why.

    ``candidate_lines`` is the same tactic-scoped block Stage B is given, so
    the student is shown the list the tool itself chose from rather than a
    second list assembled for display.

    Selection is by shared vocabulary between the student's own wording and the
    technique name. That is a weak signal and is meant to be: it narrows the
    field without ranking, and a student who disagrees can see exactly why each
    line is there.
    """

    words = _significant_words(f"{label} {evidence}")
    candidate_by_id: dict[str, str] = {}
    scored: list[tuple[int, str]] = []
    for line in (candidate_lines or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = re.match(
            r"^(T\d{4}(?:\.\d{3})?)\s*(?:=|:)\s*(.+)$", line)
        identifier = parsed.group(1) if parsed else ""
        if parsed:
            candidate_by_id[identifier] = (
                f"{identifier}: {parsed.group(2).strip()}")
        overlap = len(words & _significant_words(line))
        if overlap:
            scored.append((overlap, line))
    scored.sort(key=lambda item: (-item[0], item[1]))

    lines: list[str] = []
    tactic_name = ATTACK_TACTICS.get(tactic, tactic)
    if suggested:
        named_suggestion = candidate_by_id.get(suggested, suggested)
        lines.append(
            f"Stage B suggested {named_suggestion}. This is a candidate for "
            "you to review, not a choice confirmed on your behalf.")
    if scored:
        heading = "Other candidates" if suggested else "Candidates"
        lines.append(
            f"{heading} under {tactic} ({tactic_name}) whose names "
            "share a word with what you wrote:")
        alternatives = [line for _, line in scored
                        if not line.startswith(f"{suggested} ")]
        lines.extend(f"  {line}" for line in alternatives[:MAX_SHORTLIST])
        if not alternatives:
            lines[-1] = (
                f"no candidate besides the Stage B suggestion under {tactic} "
                f"({tactic_name}) shares a meaningful word with what you "
                "wrote.")
    else:
        total = len([ln for ln in (candidate_lines or "").splitlines()
                     if ln.strip()])
        lines.append(
            f"no candidate under {tactic} ({tactic_name}) shares a meaningful "
            "word with "
            f"what you wrote, out of {total}. Either the wording or the tactic "
            "may be worth revisiting.")
    return tuple(lines)


def _phrase(labels: Iterable[str], joiner: str) -> str:
    labels = list(labels)
    if not labels:
        return ""
    if len(labels) == 1:
        return f'"{labels[0]}"'
    quoted = [f'"{label}"' for label in labels]
    return ", ".join(quoted[:-1]) + f" {joiner} {quoted[-1]}"


def restate_graph(model) -> tuple[str, ...]:
    """Say what the drawn graph claims, in ordinary sentences.

    A restatement, not an interpretation: every clause comes from an edge or a
    join value, and nothing is added about what the incident meant. Its use is
    that a student can compare it with what they intended to say, which is the
    same check the evaluation route asks of the tool -- does the output match
    the definitions -- applied by the person who wrote the input.
    """

    labels = {node.id: node.label for node in model.preconditions}
    labels.update({event.id: event.label for event in model.events})
    produced: dict[str, list[str]] = {}
    for precondition in model.preconditions:
        if precondition.role == "annotation":
            continue
        for parent in precondition.parents:
            produced.setdefault(parent, []).append(precondition.label)

    sentences: list[str] = []
    for event in model.events:
        needs = [labels.get(parent, parent) for parent in event.parents]
        results = produced.get(event.id, [])
        if needs:
            joiner = "or" if event.join == "OR" else "and"
            clause = (f'{_phrase(needs, joiner)} made "{event.label}" possible'
                      if len(needs) == 1
                      else f'{_phrase(needs, joiner)} together made '
                           f'"{event.label}" possible')
            if event.join == "OR" and len(needs) > 1:
                clause = (f'either of {_phrase(needs, "or")} was enough for '
                          f'"{event.label}"')
        else:
            clause = (f'"{event.label}" needed nothing already in the graph')
        if results:
            clause += f", and it produced {_phrase(results, 'and')}"
        sentences.append(clause + ".")

    annotations = [node.label for node in model.preconditions
                   if node.role == "annotation"]
    if annotations:
        sentences.append(
            f"Beside the attack, not part of it: {_phrase(annotations, 'and')}.")
    return tuple(sentences)
