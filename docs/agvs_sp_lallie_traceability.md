# AGVS-SP traceability to Stolen Pencil and Lallie et al. (2020)

Status: reviewed through Phase 4.1 branch-aware layout and routing

## Correct interpretation of the sources

The supplied review is:

> H. S. Lallie, K. Debattista and J. Bal, “A review of attack graph
> and attack tree visual syntax in cyber security,” *Computer Science
> Review*, vol. 35, 2020, 100219.

It is evidence about published custom, practice and visual-design problems. It
does **not** prescribe one globally accepted attack-graph notation. The paper
reports more than 75 attack-graph configurations and concludes that the field
lacks standardisation and prescriptive methods (pp. 30–31).

The project therefore uses two distinct authorities:

1. **Lallie et al.** supplies the research justification for an explicit,
   consistent, cognitively considered notation.
2. **The supervisor-provided Stolen Pencil graph** supplies this project's
   concrete gold-standard convention for node appearance, badges, metadata
   stickers, connector organisation and overall visual character.

Claims that the review itself mandates the Stolen Pencil colours or labels
would be inaccurate.

## Stage-by-stage traceability

| Project decision | Literature evidence | Project-specific decision | Status |
|---|---|---|---|
| causal flow reads from top to bottom | The review reports 102/118 attack-graph configurations (86.4%) as top-down (p. 7), describes an attack graph as beginning at the top and ending with the goal at the bottom (p. 13), and finds top-down to be the primary attack-graph flow (pp. 18–19). | Stolen Pencil also uses downward causal flow. | implemented and geometry-tested |
| actions/exploits and states must be perceptibly different | Shape is described as a primary variable for object recognition (p. 13). Fig. 6 uses rectangles for exploits and ellipses for pre/postconditions; its text explains the state→exploit→state semantics (pp. 7–8). The review also warns that published practice is diverse. | AGVS-SP fixes actions as rectangles and states as ellipses so one construct does not change symbol between figures. | implemented and contract-tested |
| directed causal arrows | Fig. 6 and its explanation use directed arrows to express event flow and successful state transition (pp. 7–8). | Stolen Pencil fixes the practical arrow and orthogonal-line style. | implemented |
| connected prerequisites vs separate alternatives | The review records several precondition-logic practices and notes that most publications do not represent the logic consistently (p. 23). It does not impose the project's exact line rule. | The supervisor's explicit convention and Stolen Pencil define connected inputs as AND and separate inputs as OR, without text/diamond gates. | implemented and connector-tested |
| limited colour used consistently | The review warns about ambiguous or inconsistent visual syntax and reports no dominant colour standard (pp. 23, 30). | Stolen Pencil supplies the pale purple, cyan, pink and orange metadata colours; white nodes and black lines remain dominant. | implemented |
| causal-boundary pagination | The review stresses event-flow readability and warns that poor layout can distort meaning (pp. 13, 30), but does not prescribe a page-splitting algorithm. | AGVS-SP cuts only at stable state boundaries, repeats state bridges, and requires lossless node/edge reconstruction. | implemented; repaired after live testing |
| branch-aware macro layout | The review identifies top-down flow as the dominant attack-graph direction and stresses perceptual consistency, but does not prescribe a coordinate algorithm. | AGVS-SP uses deterministic barycentric branch ordering, centred convergence and outer-lane routing to approach the Stolen Pencil organisation without changing graph semantics. | implemented and geometry-tested |

## Validation of Stages 0–2 against the live figures

- Actions remain rectangles and conditions/results remain ellipses.
- The `IA` event-tactic badge is suppressed on prerequisite ellipses without
  altering the canonical stored code.
- All tested causal edges point to a lower rank; same-rank causal edges are
  prohibited.
- Multi-parent AND inputs share one bus and one output arrow.
- OR alternatives remain on separate tracks and have no shared bus.
- Tactic, Technique, Mitigation and score metadata are presentation copies of
  the validated professional graph.

The live British Library pages exposed no regression in these contracts. They
exposed a **pagination/readability** problem: 11 ranks still produced a tall
strip and repeated bridge states lacked visible page context. Phase 3 repairs
those two problems without modifying extraction.

## Boundaries and remaining risk

- Lallie et al. does not prove that AGVS-SP is the only or universally best
  syntax.
- Matching Stolen Pencil is a project design choice supported by consistency
  and traceability, not a claim of an international standard.
- Phase 4 centres converging branches, retains coherent branch lanes and routes
  skip-rank edges through the shortest clear orthogonal path. Phase 4.1 also
  penalises route overlap and automatically paginates long professional
  graphs. Very dense ranks can still require a wider canvas.
- A semantically questionable event, T/M mapping or causal edge produced by
  professional v1.4 remains visible but unchanged. Layout testing must not be
  reported as extraction-accuracy testing.
