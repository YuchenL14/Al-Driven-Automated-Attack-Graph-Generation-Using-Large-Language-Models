# AGVS-SP Phase 4.1: short-path routing and automatic pagination

Status: implemented and offline-validated after British Library live-output
review

## Trigger

The Phase 4 British Library live output was `1248x2419` and contained several
long rectangular connector loops. Two independent issues were present:

1. the professional UI allowed causal pagination to be bypassed, so the run
   produced one full-height PNG instead of `_part1`, `_part2`, and so on;
2. every edge that skipped a rank was sent to an outer lane whenever any node
   existed between its endpoints, even when a direct route was clear.

The second behaviour created long vertical rails that could be mistaken for
shared AND buses. It was a presentation defect, not a new logical relationship.

## Scope and frozen semantics

Phase 4.1 changes the PNG connector router and professional rendering entry
point only. It does not change:

- extracted events or preconditions;
- node labels, node IDs or causal parent IDs;
- AND/OR values stored in the validated graph;
- ATT&CK tactic, Technique or Mitigation assignments;
- likelihood scores;
- report ingestion, prompts, API calls or v1.4 validation.

## Routing algorithm

For each parent-to-target port, the renderer now generates deterministic
orthogonal candidates:

- a direct vertical route where the endpoints align;
- short routes using the upper, middle or lower inter-rank track;
- local left/right lanes around actual blocking node footprints;
- outer lanes only as fallback candidates.

Each candidate is checked against the visible obstacle footprint, including the
purple tactic and cyan score badges. The former fixed 64-pixel right-hand
sticker allowance was removed because Technique and Mitigation stickers are
right-aligned inside the node box.

Clear candidates are ranked by:

```text
Manhattan length
+ 10 * number of turns
+ 180 * proper connector crossings
+ overlap penalty
```

The overlap penalty is stronger for OR inputs so independent alternatives do
not reuse one long track and accidentally look like the supervisor's connected
AND notation. Routes already selected earlier on the page are carried forward
as occupied segments.

AND targets still use exactly one shared horizontal bus and one output arrow.
OR targets retain separate input paths and separate arrowheads.

## Automatic causal pagination

The professional endpoint now always calls the causal pagination renderer.
For a small graph, the planner returns one unchanged image. For a long graph,
it automatically creates lossless state-boundary pages. The previous optional
checkbox has been replaced by:

```text
Long-graph pagination: automatic
```

This prevents accidental reproduction of the `1248x2419` single-page strip.
Student extraction and student application behaviour are unchanged.

## Quantitative verification

Phase 4.1 adds the following regression contracts:

| Failure mode | Acceptance condition | Result |
|---|---|---|
| false detour | an aligned clear skip-rank edge is a two-point vertical path | pass |
| obstacle collision | skip-rank route intersects zero unrelated node boxes | pass |
| excessive stretch | routed length is at most 1.8 times Manhattan distance in the obstacle oracle | pass |
| OR track ambiguity | two long OR inputs share zero collinear pixels | pass |
| pagination bypass | professional long graph creates at least two `_partN` images without form input | pass |
| semantic mutation | graph model is byte-equivalent before and after rendering | pass |

The complete offline suite passes:

```text
Ran 112 tests in 3.149s
OK
```

The Phase 3 report-derived structural oracles retain their page dimensions:

- British Library: `1248x1019`, `1248x1019`;
- WannaCry: `1248x1019`, `1248x1299`;
- M&S: `1248x706`, `1248x1299`, `1248x739`.

The maximum page height/width ratio remains `1.041`, below the project limit of
`1.2`.

## Remaining limitation and live check

The professional app does not persist the validated graph JSON, so the exact
semantic graph used to make the reported `_6.png` cannot be rerouted without
calling the model again. The final live check therefore requires one new
British Library generation. It should now produce numbered parts
automatically, even when no split control is supplied.

A legitimate prerequisite used again several ranks later can still require a
long line. Phase 4.1 makes that line locally shortest and obstacle-aware; it
does not delete or reassign the causal edge.

