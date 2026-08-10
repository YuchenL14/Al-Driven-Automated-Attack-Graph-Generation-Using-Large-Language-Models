# AGVS-SP 1.0 Phase 3 implementation record

Status: completed; live-output repair verified  
Scope: lossless causal-boundary pagination  
Extraction baseline: professional ruleset v1.4

## Problem replaced

The former `render_split` implementation:

- always produced exactly two files;
- assigned events to an early or late half using ATT&CK tactic codes;
- used a fixed event-count trigger;
- filtered parent references independently in each half.

That approach could split one causal phase merely because its ATT&CK tactics
differed, could not make three or more readable pages, and did not prove that
the page union reconstructed the canonical graph.

## Implemented algorithm

`src/causal_split.py` now plans pagination from the validated bipartite DAG.
ATT&CK tactics are preserved as metadata but are not used as cut positions.

1. Validate that the canonical graph is acyclic.
2. Form atomic event/result-state blocks.
   - An event and every state it directly establishes remain together.
   - Alternative events that establish the same state remain together with
     that state.
3. Separate unrelated weak causal components before paginating a long
   component.
4. Collapse atomic blocks into a block DAG and compute longest-path levels.
5. Use dynamic programming to choose contiguous causal layer ranges.
   The lexicographic objective is:
   - minimum number of pages;
   - minimum crossed bridge states;
   - minimum unused page capacity.
6. Materialise each page:
   - every event occurs on exactly one page;
   - all input states required by an event are included;
   - all immediate result states produced by an event are included;
   - a cross-page state is repeated as a bridge;
   - bridge copies retain the same global ID, label and code.
7. Before rendering, reconstruct the union of page node/edge sets and require
   exact equality with the canonical graph.

The public `render_split(...)` signature remains compatible. `threshold` now
means the desired maximum events per page, and the planner may return any
number of parts. The default rank budget was initially 12. A real British
Library API result showed that an 11-rank page still rendered as a narrow
1248 x 1720 pixel strip. The production default is therefore now **9 ranks per
page**. The event budget remains 12, and either budget may trigger pagination.

Every rendered page now also displays:

- `Part N of M` above the graph;
- `continued from part N` inside an incoming repeated bridge state;
- `continues in part N` inside an outgoing repeated bridge state.

These are renderer overlays. They are not added to `AttackGraph`, and the
canonical bridge ID, label, code and parent relationships remain unchanged.

## Report-derived structural oracles

The tests use compact structural oracles, not new LLM extractions and not
report-specific rules.

### British Library

- phishing and brute force are alternative producers of the same credential
  state and are therefore one indivisible OR block;
- the credential state, initial foothold and later data/impact branches can be
  separated only through state bridges;
- Technique, Mitigation, tactic and score fields are copied byte-for-byte.

### WannaCry

- initial exploitation, host execution, discovery, propagation and encryption
  form a long causal path;
- persistence and TOR C2 are branches from the established execution state;
- pagination uses execution, discovery and propagation result states as
  bridges rather than tactic changes.

### M&S / Scattered Spider

- an unrelated actor-capability context component is kept separate from the
  incident-specific identity, ESXi and impact component;
- the main incident component is paginated through AD/credential, ESXi and
  encrypted-system states;
- the layout layer does not promote general actor TTPs into incident facts.

## Quantitative verification

With deliberately strict stress parameters (3 events and 7 ranks per page):

| Structural oracle | Parts | Maximum page ranks | Result |
|---|---:|---:|---|
| British Library | 3 | 5 | lossless |
| WannaCry | 4 | 5 | lossless |
| M&S / Scattered Spider | 4 | 7 | lossless; context component isolated |

For every oracle:

- canonical node preservation: 100%;
- canonical edge preservation: 100%;
- event duplication across parts: 0;
- event metadata changes: 0;
- state label/code changes: 0;
- event/result-state atomic-block splits: 0;
- tested pages exceeding the 7-rank stress budget: 0.

Verification performed:

- 10 Phase 3 causal-pagination tests passed;
- 6 Phase 2 geometry/logic tests passed;
- 7 Phase 1 visual-contract tests passed;
- 13 Phase 0 Stolen Pencil gold tests passed;
- 103 complete offline project tests passed;
- representative PNG pages were rendered and visually inspected.

The revised default rendered the offline WannaCry structural oracle as:

| Part | Pixel size | Height/width |
|---|---:|---:|
| 1 | 1248 x 1019 | 0.82 |
| 2 | 1248 x 1299 | 1.04 |

Both pages display their part number and explicit bridge-state continuation.
The previous live British Library files remain historical artefacts; they are
not silently overwritten and must be regenerated through the application to
use the repaired pagination.

## Files

- `src/causal_split.py`: causal partition plan, materialisation and lossless
  reconstruction validation.
- `src/attack_graph.py`: delegates split rendering to the causal planner.
- `app.py`: changes the checkbox wording from a fixed two-part split to
  long-graph pagination.
- `examples/generate_from_report.py`: documents causal split behaviour.
- `tests/test_phase3_causal_split.py`: three report-derived structural tests.
- `tests/test_project_integrity.py`: N-part output and numbering regression
  tests.

## Frozen professional behaviour

Phase 3 does not edit:

- `rules/ruleset_v1.4.md`;
- `src/schema.py`;
- `src/extract.py`;
- `data/attack_lookup.json`.

It changes neither PDF ingestion nor the LLM prompts, event/precondition
classification, ATT&CK tactic/Technique assignment, Mitigation assignment,
scores, evidence validation, or API usage.

## Delivered in Phase 4

- branch-aware lane assignment within each page;
- centring merge/post-dominator nodes beneath their contributing branches;
- node-aware outer-lane routing for skip-rank connectors, including clearance
  for Technique and Mitigation badge overhang.

## Deferred beyond Phase 4

- fully general edge-to-edge collision elimination for arbitrarily dense
  graphs;
- uncertainty styling for evidence fields already present in the canonical
  graph;
- adaptive legend columns and overview/navigation pages.

The M&S report also demonstrates a content-evaluation limitation: a layout
algorithm can preserve or isolate nodes already present in the validated graph,
but it cannot decide that an extracted generic actor capability was unsupported
without changing the frozen extraction methodology.
