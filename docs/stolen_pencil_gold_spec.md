# Stolen Pencil gold-standard visual specification

Status: Phase 0 transcription baseline  
Reference: `C:\Users\RicardoLiu\Desktop\Warwick\project\StolenPencil.png`  
Reference SHA-256: `03ccb30b7d67325dc5810928bf48bc1fa5399a30a87dc6cb6274b53398b3e8e6`

## Purpose and scope

This document freezes what can be observed in the supervisor-provided Stolen
Pencil image before production code is changed. The machine-readable companion
is `tests/fixtures/stolen_pencil_gold.json`.

The reference is a **visual-syntax gold standard**, not a content template:

- its node labels, ATT&CK mappings and malware names must never be copied into
  graphs for unrelated incidents;
- professional v1.4 extraction remains frozen during this phase;
- Student extraction and its teaching workflow remain unchanged during this
  phase;
- no API call is required to validate this specification.

## Observed syntax

### Nodes

1. Actions are white rectangles with a thin dark border.
2. Conditions, resources and results are white ellipses.
3. Supplementary controls or tools are white rectangles with dashed borders.
4. Candidate or indirect paths use dotted borders and dotted edges.
5. A visual phase badge sits outside the upper-left corner.
6. A numeric score badge sits outside the lower-left corner when the reference
   supplies a score.
7. Technique IDs appear at the upper-right or as an adjacent pink stack.
8. Mitigation IDs appear at the lower-right or as an adjacent orange stack.
9. T/M metadata can occur on a non-action ellipse. The stolen-certificate
   ellipse is the important example. A future renderer therefore cannot assume
   that T/M belongs only to rectangles.
10. A node may show multiple Technique IDs. A future visual model therefore
    cannot be limited to one Technique ID per displayed node.

### Codes

The reference mixes two namespaces:

- `RE` and `RS` are ATT&CK-style tactic abbreviations.
- `W`, `R`, `D`, `E`, `I`, `C` and `A` are recorded as a separate
  `supervisor_visual_phase` namespace.

These codes are display metadata. They must not be inferred to be ATT&CK
tactics merely because they occupy the same circular badge. In particular, an
ATT&CK code such as `IA` must not be put on an ellipse just because that ellipse
is near an Initial Access action. The supervisor's rule is that the action
badge sits on the square action box.

### Edges and logic

1. Sequential causal flow proceeds downwards.
2. Horizontal lines are allowed for a common parent bus, a convergence bus, or
   a contextual relationship. They are not used to make a causal sequence run
   sideways.
3. According to the supervisor's stated syntax, visibly connected inputs mean
   `AND`; separate alternative inputs mean `OR`.
4. Annotation edges are dashed and do not form a new attack step.
5. The graph can contain several upper branches and two long central branches,
   but they converge on one final objective.

The fixture explicitly records five logic groups:

- three connected `AND` buses on the Font Manager branch;
- one dotted `OR` convergence into `GREASE installed`;
- one final `AND` convergence into `Exfiltrate data`.

The connected PDF-opened/website-accessed bus is recorded as `AND` because that
is what the supplied drawing visibly encodes. Its operational interpretation
could be debated, so it is also listed as a transcription uncertainty rather
than silently “corrected”.

## Macro-layout contract

The reference is portrait because it contains two substantial attack branches,
but its causal direction is consistently top-to-bottom. The important target is
therefore not a fixed 16:9 canvas. The target is:

- independent preparations at the top;
- action-to-result vertical pairs;
- explicit common buses for connected prerequisites;
- long attack branches placed beside each other where space permits;
- convergence towards the final objective;
- a legend in otherwise unused whitespace;
- splitting at a genuine graph boundary when one readable page cannot hold the
  full graph.

This prevents a later implementation from recreating the current four-column
snake merely to force a landscape aspect ratio.

## What the fixture deliberately does not decide

The reference is a raster image and some items are ambiguous. The fixture does
not pretend otherwise:

- the reference prints `T1566.02`; the fixture normalises it to `T1566.002` and
  records the display difference;
- the mitigation stack beside `MECHANICAL malware executed` appears to repeat
  `M1043`; the fixture stores unique legible IDs;
- the meaning of the supervisor visual codes is kept separate from ATT&CK
  tactics pending an explicit glossary;
- wording and capitalisation are transcribed, not editorially improved.

These uncertainties must not be used as automatic training labels until the
supervisor confirms them.

## Phase 0 acceptance checks

The offline fixture test must verify:

- the source identity and dimensions are frozen;
- all node and logic-group IDs are unique;
- every edge endpoint exists;
- action/event nodes are rectangles;
- state/precondition/postcondition nodes are ellipses;
- annotation nodes and edges are dashed;
- no ellipse carries `IA`;
- all T/M identifiers are syntactically valid and represented in the fixture
  legends;
- every logic group and its edges agree;
- at least two independent branches converge on `sp_exfiltrate`;
- the reference includes multiple techniques, T/M on an ellipse, dotted
  uncertainty, and dashed annotations.

Passing these checks proves only that the reference transcription is internally
consistent. It does **not** prove that the current renderer matches the image.
Renderer similarity, collision checks, downward-flow checks and split-graph
checks belong to later phases.

## Production files intentionally unchanged in Phase 0

At the time the baseline was captured:

- `rules/ruleset_v1.4.md`:
  `13d357e40a95516cbb63b1d4ccd0d93018e9bb2ec5d5d3d20f30f4dcf785cc2a`
- `src/schema.py`:
  `b9ff2697a54ea96085e7fc077e761c2d3dc6a52a04cc639f38ee6b1598d3487d`
- `src/reference_renderer.py`:
  `bbc4dc6d3a0efcdf21b7797f504dc0de325079caea35707196be64425be481a2`

Later phases may intentionally change the schema or renderer, but the
professional v1.4 ruleset hash remains the frozen extraction baseline.
