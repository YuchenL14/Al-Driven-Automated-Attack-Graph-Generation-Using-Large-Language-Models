# AGVS-SP 1.0 Phase 2 implementation record

Status: completed  
Scope: causal direction and AND/OR connector syntax  
Extraction baseline: professional ruleset v1.4

## Implemented

- Replaced the fixed four/five-node row packer with topological ranks.
- Every causal target is placed strictly below every source node.
- Kept horizontal segments only inside orthogonal routing, buses and branches;
  no parent/child causal pair shares the same row.
- Replaced text/diamond logic gates:
  - AND parents connect to one shared horizontal bus and use one output arrow;
  - OR parents use separate tracks and distinct target ports;
  - multiple events producing one state remain separate OR alternatives under
    the current canonical schema.
- Applied equivalent unlabelled logic semantics to the Graphviz SVG/PDF
  fallback.

## Quantitative checks

- causal parent bottom `<` target top for 100% of tested edges;
- same-rank causal parent/child pairs: 0;
- AND shared buses: 100% for multi-parent AND events;
- AND output arrows: exactly 1 per AND group;
- OR shared buses: 0;
- OR arrows and distinct target ports: 1 per input;
- textual AND/OR labels and diamond gates: 0.

## Verification

- 6 Phase 2 geometry/logic tests passed.
- 7 Phase 1 visual-semantics tests passed.
- 13 Phase 0 Stolen Pencil tests passed.
- 92 complete offline project tests passed.
- Python byte-code compilation passed.
- Manual PNG checks passed for:
  - a realistic alternating ransomware mock graph;
  - a synthetic graph containing AND, OR, state convergence and final AND.

## Frozen professional behaviour

Phase 2 does not edit:

- `rules/ruleset_v1.4.md`;
- `src/schema.py`;
- `src/extract.py`;
- `data/attack_lookup.json`.

It therefore changes neither report extraction nor T/M selection.

## Deferred risks

- A long causal chain is now intentionally tall. Causal-boundary pagination is
  required before using strict top-down layout on large reports.
- The phase does not yet perform general edge/node collision detection for
  long edges that skip ranks.
- The current schema has no logic field on a state. Multiple producing events
  are consequently displayed as independent OR alternatives; changing that
  meaning would require a later, explicit schema decision.
- Branch-aware macro-layout, annotations, dotted candidate paths and overview
  pages remain later work.
