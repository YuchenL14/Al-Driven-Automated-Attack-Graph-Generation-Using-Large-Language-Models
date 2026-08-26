from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from schema import AttackGraph


CoverageKind = Literal["event", "state", "context", "unrepresented"]


@dataclass(frozen=True)
class CoverageItem:
    """How one source statement is represented in the generated graph."""

    source: str
    kind: CoverageKind
    graph_labels: tuple[str, ...] = ()
    needs_action_review: bool = False


@dataclass(frozen=True)
class SourceCoverageAudit:
    """Student-facing, non-blocking comparison of prose and graph."""

    items: tuple[CoverageItem, ...]

    @property
    def warnings(self) -> tuple[CoverageItem, ...]:
        return tuple(
            item for item in self.items
            if item.kind == "unrepresented" or item.needs_action_review
        )

    def count(self, kind: CoverageKind) -> int:
        return sum(item.kind == kind for item in self.items)


_SENTENCE_BREAK = re.compile(
    r"(?<=[.!?])\s+(?=(?:[\"'\u2018\u2019\u201c\u201d]?)[A-Z0-9])"
)
_ACTOR_LED = re.compile(
    r"^(?:the\s+)?(?:attackers?|adversar(?:y|ies)|threat\s+actors?)\b|^they\b",
    re.IGNORECASE,
)
_CONTEXT_PATTERNS = (
    re.compile(r"\b(?:report|article|source|account)\s+(?:does|did)\s+not\s+(?:state|say|specify|identify|describe)\b", re.I),
    re.compile(r"\b(?:not|never)\s+(?:reported|stated|specified|identified|described)\b", re.I),
    re.compile(r"\b(?:method|technique|mechanism|route|vector|means)\s+(?:is|was|remains?)\s+(?:unknown|unclear|unreported|unspecified)\b", re.I),
    re.compile(r"\bno\s+(?:attack\s+)?technique\s+(?:is|was)\s+(?:given|stated|reported|specified)\b", re.I),
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP_WORDS = {
    "a", "an", "and", "as", "at", "by", "for", "from", "in", "into",
    "is", "it", "of", "on", "or", "the", "their", "to", "was", "were",
    "with", "all", "around", "company", "first", "that", "this", "its",
}
_CANONICAL = {
    "accessed": "access", "accessing": "access", "achieved": "achieve",
    "applications": "application", "attackers": "attacker",
    "contained": "contain", "containing": "contain",
    "controllers": "controller", "databases": "database",
    "deployed": "deploy", "deploying": "deploy",
    "disrupted": "disrupt", "encrypted": "encrypt",
    "gained": "gain", "given": "give", "hashes": "hash",
    "hosts": "host", "impacted": "impact", "initially": "initial",
    "operations": "operation", "passwords": "password",
    "paused": "pause", "payments": "payment", "possessed": "possess",
    "possession": "possess", "running": "run", "servers": "server",
    "shifts": "shift", "shopping": "shop", "stole": "steal",
    "stolen": "steal", "suspended": "suspend", "systems": "system",
    "told": "tell", "virtual": "vm", "machines": "vm",
    "vms": "vm", "wiped": "wipe", "approximately": "approximate",
    "approx": "approximate",
}


def _source_units(text: str) -> list[str]:
    """Split prose without breaking ATT&CK sub-techniques or filenames."""

    flattened = re.sub(r"\s+", " ", text).strip()
    if not flattened:
        return []
    return [part.strip() for part in _SENTENCE_BREAK.split(flattened)
            if part.strip()]


def _normalise_text(text: str) -> str:
    """Fold the spelling differences that hide a genuine match.

    Expansions run before case is discarded, because case is the only thing
    that distinguishes some of them. "AD" written as an initialism is Active
    Directory; the ordinary English word "ad" is not, and expanding both turned
    "a malicious ad network" into "a malicious active directory network".
    Malvertising is a real intrusion route and one of this project's own sample
    reports carries a malicious advert, so that substitution was not harmless.

    An expansion for one named organisation used to sit here and could never
    fire, because the ampersand it matched on had already been replaced on the
    line above. It has been removed rather than repaired: hard-coding a single
    company into a general teaching tool is not something a dead line earns
    back, and the pair it was meant to join still shares enough other words to
    match without it.
    """

    value = re.sub(r"\bAD\b", " Active Directory ", text)
    value = value.casefold().replace("&", " and ")
    value = re.sub(r"\b(\d+)m\b", r"\1 million", value)
    value = value.replace("/", " ")
    return " ".join(value.split())


def _tokens(text: str) -> set[str]:
    words = _TOKEN_RE.findall(_normalise_text(text))
    result = set()
    for word in words:
        canonical = _CANONICAL.get(word, word)
        if canonical not in _STOP_WORDS and len(canonical) > 1:
            result.add(canonical)
    return result


def _is_context(statement: str) -> bool:
    return any(pattern.search(statement) for pattern in _CONTEXT_PATTERNS)


def _event_matches(statement: str, graph: AttackGraph) -> tuple[str, ...]:
    normalised_statement = _normalise_text(statement)
    matches = []
    for event in graph.events:
        evidence = event.source_evidence
        if evidence and _normalise_text(evidence) in normalised_statement:
            matches.append(event.label)
    return tuple(matches)


def _best_state_matches(statement: str, graph: AttackGraph) -> tuple[str, ...]:
    statement_tokens = _tokens(statement)
    scored: list[tuple[float, int, str]] = []
    for state in graph.preconditions:
        if state.role == "annotation":
            continue
        label_tokens = _tokens(state.label)
        if not label_tokens:
            continue
        shared = len(statement_tokens & label_tokens)
        coverage = shared / len(label_tokens)
        if shared >= 2 and coverage >= 0.55:
            scored.append((coverage, shared, state.label))
    if not scored:
        return ()
    best = max(score for score, _, _ in scored)
    return tuple(label for score, _, label in scored if score == best)


def audit_source_coverage(narrative: str,
                          graph: AttackGraph) -> SourceCoverageAudit:
    """Compare Student prose with a graph without changing either object.

    Exact event evidence takes precedence.  Remaining statements are matched
    conservatively to state labels.  Report limitations are classified as
    context.  An actor-led action represented only as a state is highlighted
    for human review, but never blocks or rewrites the generated graph.
    """

    items = []
    for statement in _source_units(narrative):
        event_labels = _event_matches(statement, graph)
        if event_labels:
            items.append(CoverageItem(statement, "event", event_labels))
            continue
        if _is_context(statement):
            items.append(CoverageItem(statement, "context"))
            continue
        state_labels = _best_state_matches(statement, graph)
        if state_labels:
            items.append(CoverageItem(
                statement,
                "state",
                state_labels,
                needs_action_review=bool(_ACTOR_LED.search(statement)),
            ))
            continue
        items.append(CoverageItem(
            statement,
            "unrepresented",
            needs_action_review=bool(_ACTOR_LED.search(statement)),
        ))
    return SourceCoverageAudit(tuple(items))


__all__ = [
    "CoverageItem", "SourceCoverageAudit", "audit_source_coverage",
]
