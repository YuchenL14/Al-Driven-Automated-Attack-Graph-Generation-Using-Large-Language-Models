# AGVS-SP Phase 4: branch-aware macro layout

Status: implemented and offline-validated; skip-rank routing refined in
Phase 4.1

## Scope

Phase 4 changes only the placement and routing of an already validated attack
graph. It does not alter:

- report ingestion or LLM prompts;
- event/precondition classification;
- canonical nodes or causal edges;
- ATT&CK tactics, Technique IDs or Mitigation IDs;
- likelihood scores or evidence validation;
- the professional v1.4 rules.

The layout receives an `AttackGraph` and produces presentation coordinates.
The input graph is treated as immutable.

## Visual authority

The algorithm follows the project standard fixed in Phase 0:

1. Lallie, Debattista and Bal (2020) justify using an explicit, consistent
   top-down visual syntax and perceptibly different shapes for actions and
   states. The review does not define one universal attack-graph layout.
2. The supervisor-provided Stolen Pencil graph defines this project's concrete
   visual convention: downward causal flow, horizontally separated preparation
   branches, centred convergence, action rectangles, state ellipses, orthogonal
   connectors and the existing metadata badges.

The LLM still produces and classifies semantics only. It does not choose page
coordinates or freely design the diagram.

## Implemented algorithm

### 1. Fixed topological ranks

The existing causal graph determines vertical rank. Every causal successor is
placed below its predecessor. Phase 4 never moves a node to a rank that changes
the direction or meaning of an edge.

### 2. Branch-aware rank ordering

Nodes within each rank are ordered by deterministic downward and upward
barycentric sweeps:

- a downward sweep places a node near the median position of its parents;
- an upward sweep places a node near the median position of its children;
- stable node IDs break ties, making repeated renders reproducible.

This keeps independent preparation branches in coherent left-to-right lanes
and reduces crossings before coordinates are calculated.

### 3. Horizontal coordinate fitting

Initial equal-width slots are refined using parent/child medians. An isotonic
projection then enforces minimum separation between neighbouring nodes while
preserving their branch order. Final downward passes centre shared successors
under the branches that converge on them.

This produces the Stolen Pencil macro pattern where the graph supports it:
several upper branches, visible convergence and narrower downstream paths.
The algorithm does not invent branches in a graph that is genuinely linear.

### 4. Orthogonal skip-rank routing

Adjacent-rank edges use the normal top-to-bottom orthogonal connector. An edge
that skips one or more ranks is routed through an outer whitespace lane chosen
from the available left or right margin. The route reserves clearance for:

- action/condition node boundaries;
- Technique and Mitigation badge overhang;
- the separate legend area.

Long OR inputs receive separate lane offsets. AND inputs retain the Phase 2
shared-bus convention.

### 5. Pagination compatibility

Phase 4 runs inside each causal page produced by Phase 3. Bridge states remain
the only repeated semantic objects, so pages can still be losslessly
reconstructed into the original canonical graph. Phase 4 changes neither the
cut points nor the bridge identity.

## Quantitative acceptance metrics

The following checks are automated in
`tests/test_phase4_branch_layout.py`:

| Metric | Acceptance condition | Result |
|---|---|---|
| same-rank node overlap | zero overlapping node boxes | pass |
| branch lane stability | parallel branches retain a consistent left-to-right order | pass |
| merge centring | merge centre is within 35 px of the median parent centre | pass |
| adjacent-rank crossings | zero crossings in the four-branch structural oracle | pass |
| skip-rank node collision | long connector outer lane intersects zero unrelated node boxes | pass |
| semantic immutability | render leaves the canonical `AttackGraph` unchanged | pass |
| downward causal flow | every tested causal edge ends at a lower rank | covered by Phase 1 and full regression |
| page aspect ratio | offline report-derived pages remain at or below 1.2 height/width | pass |

The report-derived structural oracles rendered as:

- British Library: `1248x1019`, `1248x1019`;
- WannaCry: `1248x1019`, `1248x1299`;
- M&S: `1248x706`, `1248x1299`, `1248x739`.

The maximum height/width ratio is therefore `1299 / 1248 = 1.041`, below the
project limit of 1.2.

## Verification

The full offline suite passes:

```text
Ran 109 tests in 3.029s
OK
```

The frozen professional files retained their Phase 3 SHA-256 values:

- `rules/ruleset_v1.4.md`:
  `13D357E40A95516CBB63B1D4CCD0D93018E9BB2EC5D5D3D20F30F4DCF785CC2A`
- `src/schema.py`:
  `B9FF2697A54EA96085E7FC077E761C2D3DC6A52A04CC639F38EE6B1598D3487D`
- `src/extract.py`:
  `72E3D3AD6DF7F83D6697FA7503B390221C4D4C283FCD48578C506BDFB3978559`
- `data/attack_lookup.json`:
  `DA15522CCE11C057487762E06E9E64B67E97914A198053CA246B25A1C480DDC9`

## Remaining risks

- A nearly linear causal graph will still be vertically oriented because the
  renderer must not invent parallel branches.
- A very dense rank can require a wider canvas. Pagination controls height, not
  an arbitrarily large number of simultaneous branches.
- Phase 4.1 replaces the original unconditional outer-lane detour with
  shortest-clear-path candidate scoring and page-level route occupancy.
- The exact Phase 4 layout is implemented by the custom PNG renderer. SVG/PDF
  continue to use the Graphviz fallback and are not pixel-identical.
- Layout cannot repair unsupported events, placeholder labels, incorrect T/M
  assignments or missing causal edges produced by extraction.
- The final live API check remains intentionally separate because another API
  generation can produce different semantic content. Use the British Library
  report, professional v1.4, Compact and long-graph split enabled, then inspect
  all generated parts.
