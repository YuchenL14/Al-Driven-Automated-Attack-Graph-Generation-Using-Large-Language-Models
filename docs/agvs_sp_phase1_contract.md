# AGVS-SP 1.0 Phase 1 implementation record

Status: completed  
Scope: visual semantics only  
Extraction baseline: professional ruleset v1.4

## Implemented contract

- Event/exploit/action nodes project to rectangles.
- Precondition/postcondition/state nodes project to ellipses.
- Event tactic badges use the `attack_tactic` namespace.
- Precondition codes use a separate `state_phase` namespace.
- `IA` is not displayed on a prerequisite ellipse. The canonical input value is
  retained for auditability; the presentation projection does not mutate it.
- Event Technique IDs, Mitigation IDs and likelihood values are copied exactly
  into the presentation model.
- The profile records top-down flow, a shared bus for AND, and separate inputs
  for OR. Layout and connector implementation are intentionally deferred to
  later phases.

## Files

- `src/visual_syntax.py`: immutable `AGVS-SP-1.0` profile and pure projection.
- `src/reference_renderer.py`: consumes the versioned projection for PNG.
- `src/attack_graph.py`: applies the same state-badge rule to SVG/PDF fallback.
- `tests/test_visual_syntax_contract.py`: seven offline contract tests.

## Frozen professional behaviour

Phase 1 does not edit:

- `rules/ruleset_v1.4.md`;
- `src/schema.py`;
- `src/extract.py`;
- `data/attack_lookup.json`.

Consequently it does not change report ingestion, event/precondition
extraction, ATT&CK tactic selection, Technique selection, Mitigation selection,
evidence validation or API prompting.

## Verification

- 7 Phase 1 visual-contract tests passed.
- 13 Phase 0 Stolen Pencil gold tests passed.
- 86 complete offline project tests passed.
- Python byte-code compilation passed.
- A real PNG smoke test using `examples/mock_extraction.json` confirmed:
  - action rectangles retain IA/LM/IM badges;
  - the prerequisite `pc_foothold`, whose source code is `IA`, remains an
    ellipse and does not render an IA badge;
  - event T/M/score metadata remains visible.

## Deferred risks

Phase 1 does not yet fix:

- the current row-packing/snake macro-layout;
- shared-bus AND and separate-edge OR rendering;
- collision-aware edge routing;
- causal-boundary multi-image splitting;
- Stolen Pencil annotations, dotted alternatives, or metadata on ellipses.

Those are separate changes so that a layout regression can be isolated and
rolled back without affecting the semantic contract.
