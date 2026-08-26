from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from schema import ATTACK_TACTICS, AttackGraph

# How many members make a fan too wide to draw.
#
# This was the pagination event budget plus one, which was a count with no
# measured meaning. Measured against the page-width budget in `layout_renderer`
# -- the width past which a node label prints below 8pt -- a page holds three
# drawn columns at 1194px and four at 1492px against a 1240px budget. So a fan
# of four is already one column too wide, and folding starts there.
MAX_DRAWN_COLUMNS = 3
DEFAULT_MIN_AGGREGATE = MAX_DRAWN_COLUMNS + 1


@dataclass(frozen=True)
class AggregatedOutcomes:
    """One drawn state standing for several results of a single step.

    Bounding the width of an event rank left this case unreached: one action
    can establish any number of results, and each is drawn beside the last.
    A real teaching graph put six outcomes under one ransomware deployment and
    came out at an aspect ratio of 0.17, worse than the fan that prompted the
    width work in the first place. Pagination cannot help either, because an
    action and the state it establishes are one indivisible visual block.

    The rule is the one already used for events: fold only what a page could
    not have held, only where nothing else depends on the members, and put
    every folded label in the legend.
    """

    visual_id: str
    label: str
    event_id: str
    state_ids: tuple[str, ...]
    state_labels: tuple[str, ...]


@dataclass(frozen=True)
class AggregatedGroup:
    """One drawn node standing for several extracted events."""

    visual_id: str
    label: str
    tactic: str
    event_ids: tuple[str, ...]
    event_labels: tuple[str, ...]
    techniques: tuple[str, ...]
    folded_state_ids: tuple[str, ...]
    folded_state_labels: tuple[str, ...]


def _shared_results(model: AttackGraph) -> dict[str, tuple[str, ...]]:
    """event id -> the states it produces jointly with at least one other."""

    producers: dict[str, list[str]] = {}
    for precondition in model.preconditions:
        for parent in precondition.parents:
            producers.setdefault(parent, []).append(precondition.id)
    joint = {
        precondition.id
        for precondition in model.preconditions
        if len(precondition.parents) > 1
    }
    return {
        event_id: tuple(sorted(p for p in produced if p in joint))
        for event_id, produced in producers.items()
    }


def find_aggregatable_groups(
    model: AttackGraph,
    *,
    min_size: int = DEFAULT_MIN_AGGREGATE,
) -> list[tuple[str, ...]]:
    """Sets of events a reader would have to scan sideways to compare.

    Membership is decided mechanically, not editorially: identical parents,
    identical tactic, and at least one result state produced jointly by the
    whole set. Two actions that differ in any of those are telling different
    parts of the story and stay apart -- which is why the keylogger, whose
    tactic and parents differ, is not swept in with the password dumpers.
    """

    if min_size < 2:
        raise ValueError("min_size must be at least 2")

    shared = _shared_results(model)
    buckets: dict[tuple, list[str]] = defaultdict(list)
    for event in model.events:
        key = (frozenset(event.parents), event.tactic, shared.get(event.id, ()))
        if not key[2]:
            continue
        buckets[key].append(event.id)
    return [
        tuple(members) for members in buckets.values()
        if len(members) >= min_size
    ]


def _private_dead_end_states(
    model: AttackGraph,
    event_ids: frozenset[str],
) -> list:
    """States this group alone produced and nothing at all consumes."""

    consumed = {
        parent for event in model.events for parent in event.parents
    }
    return [
        precondition for precondition in model.preconditions
        if precondition.parents
        and set(precondition.parents) <= event_ids
        and precondition.id not in consumed
    ]


def aggregate_for_drawing(
    model: AttackGraph,
    *,
    min_size: int = DEFAULT_MIN_AGGREGATE,
) -> tuple[AttackGraph, tuple[AggregatedGroup, ...]]:
    """Return a graph to draw and a record of what it stands for.

    The returned graph is for rendering only. Nothing else in the pipeline
    should read it: measurements, evidence and the saved JSON all describe the
    graph that came out of extraction.
    """

    # Not an early return on "no event groups": a graph with one action and
    # six results has nothing to group at the event level and is still too wide
    # to read. The outcome pass below is what reaches that case.
    groups = find_aggregatable_groups(model, min_size=min_size)

    by_event = {event.id: event for event in model.events}
    absorbed_events: set[str] = set()
    absorbed_states: set[str] = set()
    records: list[AggregatedGroup] = []
    new_events: list[dict] = []

    for members in groups:
        first = by_event[members[0]]
        folded = _private_dead_end_states(model, frozenset(members))
        techniques: list[str] = []
        mitigations: list[str] = []
        for member_id in members:
            for technique in by_event[member_id].techniques:
                if technique not in techniques:
                    techniques.append(technique)
            for mitigation in by_event[member_id].mitigations:
                if mitigation not in mitigations:
                    mitigations.append(mitigation)

        tactic_name = ATTACK_TACTICS.get(first.tactic, first.tactic)
        visual_id = f"agg_{first.tactic.lower()}_{members[0]}"
        records.append(AggregatedGroup(
            visual_id=visual_id,
            label=f"{len(members)} grouped {tactic_name} actions",
            tactic=first.tactic,
            event_ids=tuple(members),
            event_labels=tuple(by_event[m].label for m in members),
            techniques=tuple(techniques),
            folded_state_ids=tuple(p.id for p in folded),
            folded_state_labels=tuple(p.label for p in folded),
        ))
        absorbed_events.update(members)
        absorbed_states.update(p.id for p in folded)

        merged = first.model_dump()
        merged.update({
            "id": visual_id,
            "label": records[-1].label,
            "techniques": techniques,
            "mitigations": mitigations,
            "likelihood": max(
                by_event[m].likelihood for m in members
            ) if first.likelihood is not None else None,
            "parents": sorted(first.parents),
        })
        new_events.append(merged)

    events = [
        event.model_dump() for event in model.events
        if event.id not in absorbed_events
    ] + new_events

    rewritten = {member: record.visual_id
                 for record in records for member in record.event_ids}
    preconditions = []
    for precondition in model.preconditions:
        if precondition.id in absorbed_states:
            continue
        node = precondition.model_dump()
        parents: list[str] = []
        for parent in node.get("parents") or []:
            replacement = rewritten.get(parent, parent)
            if replacement not in parents:
                parents.append(replacement)
        node["parents"] = parents
        preconditions.append(node)

    outcome_records = _fold_wide_outcomes(events, preconditions, min_size)

    drawn = AttackGraph.model_validate({
        **model.model_dump(),
        "events": events,
        "preconditions": preconditions,
    })
    return drawn, tuple(records) + tuple(outcome_records)


def _fold_wide_outcomes(
    events: list[dict],
    preconditions: list[dict],
    min_size: int,
) -> list[AggregatedOutcomes]:
    """Collapse a step's own results when there are more than a page holds.

    Only results with a single producer and no consumer qualify. A state
    something else depends on is load-bearing, and folding it would cut the
    dependency; a state with two producers belongs to both and is not this
    step's to fold.
    """

    consumed = {
        parent for event in events for parent in (event.get("parents") or [])
    }
    by_event: dict[str, list[dict]] = {}
    for node in preconditions:
        parents = node.get("parents") or []
        if len(parents) != 1 or node.get("role") == "annotation":
            continue
        if node.get("id") in consumed:
            continue
        by_event.setdefault(parents[0], []).append(node)

    records: list[AggregatedOutcomes] = []
    for event_id, members in by_event.items():
        if len(members) < min_size:
            continue
        visual_id = f"agg_out_{event_id}"
        records.append(AggregatedOutcomes(
            visual_id=visual_id,
            label=f"{len(members)} recorded outcomes",
            event_id=event_id,
            state_ids=tuple(node["id"] for node in members),
            state_labels=tuple(node["label"] for node in members),
        ))
        folded = {node["id"] for node in members}
        keep = [node for node in preconditions if node["id"] not in folded]
        keep.append({**members[0], "id": visual_id,
                     "label": records[-1].label})
        preconditions[:] = keep
    return records


def aggregation_legend_lines(
    groups: tuple[AggregatedGroup, ...],
) -> tuple[str, ...]:
    """What the aggregate stands for, verbatim, for the page legend."""

    lines: list[str] = []
    for group in groups:
        lines.append(f"{group.label}:")
        if isinstance(group, AggregatedOutcomes):
            for label in group.state_labels:
                lines.append(f"  = {label}")
            continue
        for label in group.event_labels:
            lines.append(f"  - {label}")
        for label in group.folded_state_labels:
            lines.append(f"  = {label}")
    return tuple(lines)
