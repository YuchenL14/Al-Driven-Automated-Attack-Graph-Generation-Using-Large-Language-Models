# Handover: attack-graph tool, current state and next steps

Written so a fresh session can continue without re-deriving anything. Read
this first, then `README.md`.

Project root: `C:\Users\RicardoLiu\Desktop\Warwick\project\python project`
Interpreter: `C:\Users\RicardoLiu\anaconda3\envs\python_project\python.exe`
(bare `python` is blocked in this PowerShell; always use the full path)

---

## 1. What the project is

An MSc dissertation prototype (WMG, supervisor H. S. Lallie) that turns a
cyber-incident report into a MITRE ATT&CK-aligned attack graph drawn in the
supervisor's visual syntax. Two applications share one schema, one ATT&CK
catalogue and one renderer:

- `app.py` (port 5000) - report upload, professional rule sets
- `student_app.py` (port 5001) - typed narrative, student rule sets

Pipeline: `ingest -> extract (Stage A skeleton, Stage B ATT&CK) -> causal
pagination -> AGVS-SP layout -> PNG/SVG`.

## 2. Rule-set versions are research conditions, not replacements

| Version | Role | Do not |
| --- | --- | --- |
| v1.4 | Frozen professional baseline. Dissertation chapters 3-5 describe it. | change its semantics |
| v1.5 | Evidence-first comparison: verbatim quotations, technique abstention | confuse with the "Semantic draft pipeline" checkbox, which is a different code path |
| v1.6 | Visual completeness: external resources, annotations, dotted branches. v1.4 copied verbatim plus Rule 6. | assume it changed any v1.4 rule; a test asserts it did not |
| student-v1 .. v1.2 | Teaching, isolated in `student_app.py` | apply professional gates to them |

`app.py` has a rule-set selector. v1.4 is the default; only versions present in
`rules/` are accepted; the version is recorded in every output file name.

## 3. The visual model, established from the supervisor's own fixture

`tests/fixtures/stolen_pencil_gold.json` is the supervisor's hand-drawn graph
of the NETSCOUT STOLEN PENCIL report. Measured from it, three dimensions are
**orthogonal**:

```
role  (construct) : precondition / postcondition / event / goal /
                    external_resource / annotation
shape             : ellipse / rectangle / annotation      <- follows role
style  (outline)  : solid / dotted / dashed               <- independent
```

Counts in the fixture:

```
annotation         style=dashed   shape=annotation  x2
event              style=dotted   shape=rectangle   x2
event              style=solid    shape=rectangle   x11
precondition       style=dotted   shape=ellipse     x2
postcondition      style=solid    shape=ellipse     x12
external_resource  style=solid    shape=ellipse     x2
goal               style=solid    shape=rectangle   x1
```

Read the fixture, and print **all** of its keys before concluding anything.
An earlier draft of this file claimed it had no edges. It has:

```
schema_version purpose source title visual_contract normalisations
code_namespaces technique_legend mitigation_legend nodes
logic_groups edges transcription_uncertainties
```

`list(keys)[:10]` truncates exactly before `edges`, which is how that claim was
made and then written down as fact.

Two further things to read rather than recall:

1. **`techniques` is a list, not a single id**, and 13 nodes carry one. Two of
   them carry SEVEN. An `external_resource` carries three, and the `goal`
   carries some too.
2. **`score` appears on events only** (13 of them), never on a state node.

Structure, computed from the 32 real edges (relation `causal` only):

```
nodes 32   edges 32   logic_groups 5
roots 10   terminals 5   ranks 10   widest 10
width per rank: 10, 6, 3, 3, 2, 2, 2, 2, 1, 1
```

A funnel: ten independent starting points collapsing to one goal.

**Badge namespace, the largest divergence from this tool.** `code_namespaces`
in the fixture is authoritative:

```
supervisor_visual_phase : R W D E I C A     26 of 32 nodes
attack_tactic           : RE RS              2 of 32 nodes
none                    :                    4 of 32 nodes
```

`R W D E I C A` is the Lockheed Martin Cyber Kill Chain (Reconnaissance,
Weaponization, Delivery, Exploitation, Installation, Command and Control,
Actions on Objectives). The supervisor badges the kill-chain phase; this tool
forces an ATT&CK tactic from a 14-value enum onto every event and renders that.
The two notations disagreed on 26 of 32 nodes. Closed since: `badge_source` on
`VisualSyntaxProfile`, profile `AGVS_SP_V1_KILL_CHAIN`, and `active_profile()`
reading `AGVS_BADGE_SOURCE`. The phase is derived from the tactic through
`TACTIC_TO_KILL_CHAIN`, never stored, so a graph cannot carry a phase that
contradicts its tactic. Default is unchanged, so v1.4 output is identical.

Edge relations, from the fixture's own `edges` array: 28 `causal`, 2 `context`
(`external_resource -> event`), 2 `annotation` (`event -> annotation`).
Styles: 24 solid, 6 dotted, 2 dashed.

Note the six-versus-two: **relation alone does not determine style.** Four
dotted edges are ordinary causal edges leaving a step on the uncertain branch.
The rule that reproduces all 32 is: dashed if the relation is `annotation`;
dotted if the relation is `context` **or the source node is dotted**; solid
otherwise. Uncertainty propagates forward along causation. Implemented as
`edge_relation()` and `edge_style()` in `visual_syntax.py`, both derived from
the endpoints rather than stored, and both checked edge by edge against the
fixture in `test_edge_relations.py`.

**dotted means "alternative or uncertain branch", not "annotation".** Lallie,
Debattista and Bal (2020) §6.4.2 record that 11.9% of surveyed attack graphs
use outline texture but that no shared meaning exists for it, and §6.4 finds
texture a weak visual variable. So this is a documented project convention,
not a standard, and the dissertation must say so.

## 4. Literature basis (all local under `参考文献/`)

- Lallie, Debattista & Bal (2020), *Computer Science Review* 35:100219.
  Attack graphs: top-down event flow 106/120 = 88.3% (beta 4.26, z 5.19,
  p 0.00). Semiotic clarity, perceptual discriminability: "a difference in
  shape or the colour that fills the shape creates a perceptible visual
  distance. However, an alteration in edge colour or texture does not."
  Attack goals are represented in only 21.5% of surveyed graphs.
- Pirca & Lallie (2023), *Computers & Security* 130:103254. Fig. 1 reproduces
  the "winning" configuration from Lallie et al. (2018), n=212: ellipses are
  preconditions, rectangles are exploits, arcs express AND.
- Empirical baseline for the ATT&CK mapping task: best LLM micro-F1 0.22 on
  multi-label technique classification over complex CTI.

## 5. Measured results so far

Shape, all four rows measured the same way: longest-path ranks over the causal
dependency graph.

```
                                nodes ranks widest roots terminals
Stolen Pencil (supervisor)         32    10     10    10         5
Stolen Pencil (tool, v1.4)         29    23      4     4         2
British Library review             32    29      2     2         1
Scattered Spider / M&S             36    33      2     1         1
```

Gold-standard comparison on the same source (Stolen Pencil):
technique precision 0.33, recall 0.25, F1 0.29. Note that T1176 vs T1176.001
is a parent/child pair, so a scoring rule for parent/child matches must be
defined in the methods chapter or the score is systematically understated.

Fabrication analysis of the British Library v1.4 run: of 15 events, 9 have a
plausible verbatim quotation in the report and 6 do not (notably T1505.003
Web Shell and T1071.001 C2, neither of which the report mentions). This is the
strongest evidence for v1.5's abstention design.

## 6. What was completed in the last session

Four layers of the two missing constructs:

| Layer | File | Change |
| --- | --- | --- |
| schema | `src/schema.py` | `Precondition.role` and `Precondition.style`; `Event.style`; external resources cannot have parents; events are never dashed; annotations must be dashed; `causal_preconditions` and `annotations` properties |
| causal graph | `src/attack_graph.py` | `build_digraph` excludes annotations so they never create a rank or influence pagination |
| projection | `src/visual_syntax.py` | role decides shape, style passes through independently |
| rendering | `src/layout_renderer.py`, `src/layout_svg.py` | dashed/dotted outlines (manual dash tracing for Pillow, `stroke-dasharray` for SVG) |

Verified by rendering a page containing all four cases: solid external
resource, dotted precondition, dotted event **with** T/M/score, dashed
annotation excluded from the causal graph.

Also in that session: root events re-permitted (a previous fix had required
every event to consume a precondition, which made the sample's four root
events impossible and flattened the fan); likelihood made a required field in
both wire models; per-event tactic reconciliation.

v1.6 was then completed on the extraction side:

| Piece | Where |
| --- | --- |
| `rules/ruleset_v1.6.md` | v1.4 copied verbatim plus Rule 6 (the three constructs) and a "width at the top" paragraph in Rule 4. A test asserts v1.4's Rules 1, 2, 3 and 5 appear in v1.6 unchanged, so the two stay comparable. |
| `ConstructAttackGraphSkeleton` etc. | `src/extract.py`. Plain wire models: `role` and `style` are enum properties the provider enforces, and `dashed` is simply absent from the event enum rather than rejected by a validator. |
| `_normalise_constructs` | `src/extract.py`. Role is authoritative; a disagreeing style is repaired locally rather than costing a paid retry. Also strips annotations out of event parent lists. |
| `STAGE_A_V16_USER` | `src/extract.py`. Defines each construct with a determination test, and states that a parentless event is correct and expected at the top. |
| Structural gate | annotations are stripped before `_skeleton_graph_problems` runs, since an annotation is consumed by nothing and the causal checks would read that as a dangling state. |

Verified end to end without API cost by validating and rendering a v1.6-shaped
graph: wide top (one external resource plus three root events on rank 1), a
dotted two-route branch joined with OR, a dashed annotation excluded from the
causal graph, converging on one objective. 277 tests pass.

## 7. What remains, in order

1. **Run v1.6 against Stolen Pencil** and measure roots/ranks/width against
   both the v1.4 run and the supervisor's fixture. Everything above makes the
   sample's shape *expressible*; whether the model actually produces it is an
   empirical question and has not yet been tested with a paid call.
2. **Edge relations** - the fixture draws `external_resource -> event` dotted
   and `event -> annotation` dashed. The pipeline has no edge-relation concept
   and draws every connector solid. Needs a per-input style on
   `RoutedConnector` and support in both renderers.
3. **Badge collision** - two adjacent dotted events overlap: the right node's
   tactic badge sits on the left node's technique tag, truncating it
   (`T1204.002` renders as `T1204.0`). Reproduced in the v1.6 check render.
4. **Annotation placement** - annotations currently sit in the flow as
   ordinary siblings; the sample hangs them beside their anchor step.
5. **`goal` construct** - the sample distinguishes a final goal rectangle from
   an ordinary event; the schema does not.
6. **External resources carrying ATT&CK metadata** - the fixture attaches
   three techniques to `sp_stolen_certificates`. The schema reserves ATT&CK
   metadata for events, so v1.6 asks for an acquisition event feeding the
   resource instead. A deliberate divergence; report it as one.
7. **Badge namespace** - see section 3. The tool cannot emit a kill-chain badge
   at all, because `tactic` is a 14-value ATT&CK enum and the badge is rendered
   from it. Closing this means a `phase` field alongside `tactic`, a
   `badge_source` on the visual profile, and a tactic-to-kill-chain map. This
   is the single largest remaining difference from the reference and it affects
   26 of its 32 nodes.
8. **Multiple techniques per node** - `technique` is singular in the schema;
   the fixture's field is a list and two nodes carry seven. Any gold-standard
   score computed against the fixture must state how it handles the
   one-versus-many mismatch, or it is not measuring what it claims.

## 7a. Full-codebase audit (2026-08-01)

Fixed:

- **Pipeline routing.** `extract_attack_graph` dispatched on an allowlist of
  hierarchical rule sets; v1.6 was not on it and fell into the single-stage
  path, which sends the whole ATT&CK catalogue in one prompt. It did not fail,
  it timed out. Now `is_single_stage_ruleset()` names the frozen legacy set
  `{v1, v1.1, v1.2, v1.3}` by exact equality and everything else is
  hierarchical. `test_pipeline_routing.py` walks `rules/` and asserts agreement.
- **Output token budget.** Same allowlist shape: graph models were enumerated
  and given 8192, everything else 4096. `ConstructAttackGraphSkeleton` was not
  listed, so the largest graph the tool produces would have had the smallest
  budget. Inverted: the small table now names the Stage B assignment models.
- **Request timeout** 180s -> 600s. A full 8192-token Stage A response can
  legitimately exceed three minutes, and the old ceiling turned a slow success
  into an APITimeoutError.
- **Legacy PNG backend silently falsified v1.6 graphs.** It predates `role`
  and `style` and reads neither, so it does not fail on them: verified by
  rendering, every outline came out solid and the dashed annotation came out
  as a plain rectangle indistinguishable from an attack step.
  `_refuse_unsupported_constructs` now stops it. See `test_legacy_backend_guard`.

Deleted as unreferenced: `_extract_json_text` (extract.py, superseded by
`_sanitize`), `MacroLayout.module_for_block`, `AttackGraph.from_dict`.

Fixed since (each verified by the full suite plus a render):

1. **Edge relations.** `EdgeRelation` and `edge_relation()` in
   `visual_syntax.py`, derived from the roles at each end rather than stored:
   into an annotation is `annotation` (dashed), out of an external resource is
   `context` (dotted), else `causal` (solid). Both backends texture the
   individual approach paths; the shared AND bus stays solid because no single
   relation owns it. `VisualNodeSemantics` gained `role`, since `kind`
   collapses external resources into "state".
2. **`technique` is now `techniques: List[str]`.** `technique` survives as a
   property returning the first, and a `mode="before"` validator folds the
   singular input key, so all 31 readers and every saved v1.4 run are
   unaffected. Both backends stack the tags; the mitigation stack now starts
   below the technique stack instead of printing over it.
3. **Badge namespace.** `KILL_CHAIN_PHASES` and `TACTIC_TO_KILL_CHAIN` in
   `schema.py`, `badge_source` on `VisualSyntaxProfile`, and a second profile
   `AGVS_SP_V1_KILL_CHAIN`. `active_profile()` reads `AGVS_BADGE_SOURCE` and
   defaults to `attack_tactic`, so v1.4 output is byte-identical. The phase is
   derived from the tactic, never stored, so the two cannot disagree.

4. **Strict quality gate reachable.** `quality_mode()` reads
   `AGVS_QUALITY_MODE`, default `warn`. In `strict`, `measure_page_quality`
   calls `validate_layout_quality`, which runs before anything is drawn, so a
   refusal costs no image. Note recorded by test: causal pagination already
   breaks up the page shapes that trip the limits, so strict mode rarely fires
   on a real run.
5. **Correction routing.** The last four inline substring tests became named
   predicates beside their markers: `is_empty_graph_fault`,
   `is_verbatim_evidence_fault`, `is_grounded_action_fault`, joining
   `is_structural_stage_a_fault`. `test_correction_predicates.py` checks every
   raise-site wording plus Pydantic's own `too_short`, and guards that no
   `in str(ex)` returns to `extract.py`.
6. **Graphviz confined.** The AGVS-SP backend now refuses any format other
   than png and svg with a message pointing at svg. Graphviz stays reachable
   under `AGVS_PNG_RENDERER=legacy` only, the same treatment as the legacy PNG
   renderer.
7. **Semantic/v1.6 conflict explicit.** `extract_attack_graph_semantic` takes
   no ruleset, so ticking the checkbox discarded the selection silently.
   `is_construct_ruleset()` now gates the combination in `app.py`; v1.4 and
   v1.5 keep the documented experimental override.

Still unfixed:

8. **External resources cannot carry ATT&CK metadata.** The fixture attaches
   three techniques to `sp_stolen_certificates`. `techniques` lives on `Event`,
   so v1.6 asks for an acquisition event feeding the resource instead. A
   deliberate divergence; report it as one.
5. **Three correction selectors still match raw substrings** of error text
   (extract.py, "no events"/"too_short", "not a verbatim extract", "label does
   not contain the grounded action"). Same shape as the defect that already
   cost a session; a miss degrades to a generic retry rather than a crash, so
   severity is lower, but they belong behind named predicates with
   full-coverage tests like `is_structural_stage_a_fault`.
6. **The Graphviz path** (`_render_graphviz`) draws a different notation
   entirely. No entry point reaches it today: both apps render PNG and
   `export_figure.py` allows only svg/png. It is a trap rather than a bug.
7. **The semantic pipeline** (`semantic_draft`, `semantic_layout`,
   `semantic_layout_renderer`, ~1800 lines) does not know the v1.6 constructs
   and bypasses the rule set entirely when its checkbox is ticked.
8. **The legacy renderer itself** (`reference_renderer.py`, 1011 lines, plus
   `test_phase2_flow_logic` and `test_phase4_branch_layout`) is now guarded but
   remains unable to draw the current schema. Candidate for removal.

## 8. Standing engineering lesson

Nine defects in this codebase shared one cause: **a rule expressed in prose is
not a constraint**. Anything the JSON Schema does not carry, the model is free
to ignore, and anything only a Pydantic validator enforces is raised by the
SDK *inside* the paid call, before any local diagnostic can run.

Consequences now built into the code and its tests:

- API-visible models are separate "wire" models with Literal enums, `minItems`
  and required fields; strict validation happens locally afterwards
  (`AttackGraphSkeleton`, `EvidenceGraphWire`, `TechniqueAssignmentsWire`,
  `EvidenceTechniqueAssignmentsWire`)
- `tests/support_seam.py` reproduces the provider's validation seam; any test
  claiming to exercise recovery must use it
- `tests/test_defensive_wiring.py` has an AST guard that fails if a
  safety-critical callable stops being referenced from `src`
- `tests/test_correction_routing.py` enumerates every real error message from
  both producers and asserts each routes to the correct correction

## 9. Commands

```powershell
# tests (262 at time of writing) and compile check
& "C:\Users\RicardoLiu\anaconda3\envs\python_project\python.exe" -m unittest discover -s tests
& "C:\Users\RicardoLiu\anaconda3\envs\python_project\python.exe" -m compileall -q app.py student_app.py src scripts

# check a report is readable before spending anything
& "C:\Users\RicardoLiu\anaconda3\envs\python_project\python.exe" src\ingest.py "reports\<file>"

# re-render any saved run as a vector figure for LaTeX, free
& "C:\Users\RicardoLiu\anaconda3\envs\python_project\python.exe" scripts\export_figure.py outputs\<run>.json
```

Cost guard: `ATTACK_GRAPH_MAX_COST_USD` (default 0.90, invalid values fall back
to the default, it cannot be disabled). Cost tracks **graph size**, not report
length: the 12k-character STOLEN PENCIL report yields a 47-node graph, and
Stage B carries a tactic-scoped candidate list per event. That run hit a worst
case of $0.496 under the old 0.45 default. Budget by expected node count, not
by characters.

Backups: `backups/*.zip`, newest is the current state.

## 10. Open methodological points

- Runs are n=1. LLM output is stochastic and this project has demonstrated it
  on one document. Report variance, or run each report three times.
- British Library has been run repeatedly with code changes between runs, so
  it is no longer a clean development case in the methodological sense.
- All current metrics are structural. Only Stolen Pencil has a ground truth.
- v1.4's mitigation derivation was changed mid-evaluation (it now comes from
  the official `mitigates` relationship rather than from the model). This
  brought the implementation into line with the frozen rules, which Rule 5
  already required, but it changes comparability with earlier runs and must be
  disclosed.
