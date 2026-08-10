# Project state — read this first

MSc dissertation project **HSL.1, AI-Driven Automated Attack Graph Generation
Using Large Language Models**. Supervisor **H. S. Lallie**, WMG, University of
Warwick. Route: **Cyber Security Management** (not Engineering — the write-up
must carry management, consulting or leadership insight, not only technical
depth).

Written so that someone arriving cold can act without reconstructing the
history. It records what exists, why each non-obvious decision was made, what
has been measured, and what is left. Where a claim here can be checked, the
command to check it is given.

**Status at time of writing: 607 tests passing, `compileall` clean.** The code
phase is essentially complete. The remaining work is the dissertation.

---

## 0. Running it

Interpreter: `.venv\Scripts\python.exe` in the project root.

It was a conda env, `C:\Users\RicardoLiu\anaconda3\envs\python_project`. On
8 August that interpreter stopped working: the `python.exe` Store alias returns
"Access is denied" and the user site-packages directory it installed into no
longer exists. The project venv was created from
`%LOCALAPPDATA%\Microsoft\WindowsApps\python3.12.exe`, which still runs, and
`requirements.txt` reinstalled into it. Recreate it the same way if it is lost:

    %LOCALAPPDATA%\Microsoft\WindowsApps\python3.12.exe -m venv .venv
    .venv\Scripts\python.exe -m pip install -r requirements.txt

Dependencies are in `requirements.txt`. From the project root:

    # the whole suite; must stay green before and after any change
    python -m unittest discover -s tests -q
    python -m compileall -q src scripts tests app.py student_app.py

    # the two applications
    python app.py            # professional, http://127.0.0.1:5000
    python student_app.py    # teaching,     http://127.0.0.1:5001

    # measurement, which is also the evaluation method (see section 5)
    python scripts/measure_runs.py outputs/*rules-v1.6*.json --markdown
    python scripts/measure_runs.py outputs/student_*.json --student

The Anthropic SDK reads `ANTHROPIC_API_KEY` from the environment; the client is
constructed with no explicit key. The `mock` provider needs no key and is what
the tests use.

Four environment variables override tuned defaults, each documented where it is
read: `ATTACK_GRAPH_MAX_COST_USD`, `ATTACK_GRAPH_MAX_OUTPUT_TOKENS`,
`AGVS_PNG_RENDERER=legacy` (rolls the drawing back to the pre-AGVS-SP backend)
and `AGVS_QUALITY_MODE=strict` (turns layout warnings into refusals).

Every generation writes to `outputs/`: the PNG, one per page; the same pages as
SVG, for a document that will be printed; the JSON audit; and
`*.layout-quality.json`. **The JSON is the record.** Measurements, evidence and
any audit read it, never the drawn graph.

Working practice here: **back up before editing, under
`backups/<reason>_<timestamp>/`**, and run the suite after each change rather
than at the end. Several edits to `extract.py` had to be restored from those
backups.

---

## 1. What the tool does

One incident report in, one attack graph out, drawn in the supervisor's visual
syntax and mapped to MITRE ATT&CK.

    report (PDF/TXT/MD)
        -> Stage A   skeleton: states, actions, tactics, causal links
        -> Stage B   ATT&CK technique per action, from a tactic-scoped list
        -> aggregation (draw time)   fold a fan wider than a page
        -> pagination                cut at stable causal state boundaries
        -> layout IR -> planner -> router -> renderer   PNG / SVG
        -> JSON audit + layout-quality report

Two applications share that pipeline:

| | `app.py` (professional) | `student_app.py` (teaching) |
|---|---|---|
| port | 5000 | 5001 |
| input | uploaded report file | text pasted into a box |
| rule set | selectable; `PROFESSIONAL_RULESET = "v1.4"` is the default, **v1.6 is the current research version** | fixed `student-v1.3` |
| ATT&CK mapping | the tool decides | **the student decides**, the tool checks |
| visual syntax | AGVS-SP | **identical AGVS-SP** |

---

## 2. The two versions, and why they differ the way they do

### The professional version answers; the teaching version checks

This is the single most important design fact, and it comes from the eighth
supervision meeting:

> a student would consolidate several sources of attack information, reason
> with them, add their M and T numbers, and then once they have their own
> technical description of the attack, copy paste it into the box and then it
> generates the attack graph with all the M Numbers/T Numbers intact

So in the teaching version the ATT&CK catalogue stops being the thing that
answers and becomes two smaller things:

- **a dictionary** — does `T1566.002` exist, and what is it called for the
  legend;
- **an annotator** — MITRE does not list `M1053` as countering `T1566.002`.

Whether `T1566.002` is the right technique for a step is the student's
judgement and is never overruled. Whether `T9999` is an identifier at all is
not judgement, it is a typo, and the legend cannot render it. "Garbage in,
garbage out" applies to the first and not to the second.

Implemented in `src/student_identifiers.py`. Behaviour:

| the student wrote | the tool does |
|---|---|
| a valid identifier | draws it as written |
| an identifier not in the catalogue | reports it against that step, does not use it |
| a retired identifier (`T1562`) | names the replacements, **substitutes nothing** |
| a mitigation MITRE does not connect to their technique | **draws it**, with a note |
| nothing for a step | suggests one, and **names that step back to them** |

Nothing is silently corrected. Everything the tool did differently appears
beside the figure.

### Why the visual syntax is NOT simplified for students

The obvious move is to make the teaching graph visually simpler. **The
supervisor's own group tested that and it did not work.**

Sherzhanov, Atlam, Azad and Lallie (2024) built a graph with brighter hues,
denser line structures and varied shapes, and evaluated it with 83 participants
split into 37 experts and 46 non-experts. The visual enhancements did not
significantly improve comprehension for non-experts. Their recommendation is to
move to structural clarity and conceptual scaffolding rather than aesthetics.

So both versions share one syntax, and they are differentiated by
**scaffolding** instead: the teaching version names the steps the student left
unmapped and the identifiers it could not use. A student who learns this
notation can read a professional attack graph; a simplified dialect would teach
something unusable.

That paper is also the answer to "should we run a comprehension experiment".
The supervisor's meeting notes offer three evaluation routes; route 3 (experts,
requiring ethical approval) is what that paper already did. **Route 1 was
chosen** — define how a precondition, an exploit and a logical element are
determined, then test that the algorithm decides according to those
definitions. `scripts/measure_runs.py` is that test.

### What the teaching version deliberately does not have

| capability | v1.6 | student-v1.3 | why |
|---|---|---|---|
| external resource / annotation / dotted constructs | yes | no | fewer constructs to teach; keeps a research/teaching contrast worth writing about |
| several techniques on one action | yes | no | same |
| annotation gate | yes | **yes** | pure validation, changes nothing a student sees |
| mixed-join gate | yes | **yes** | same; students get AND/OR wrong most often |
| shape review | yes | **no** | see below |
| aggregation, pagination, layout quality | yes | **yes** | render-time, version independent |

The shape review is not ported and that is deliberate. Both of its observations
misfire on a teaching graph. Critical-path share is 100% for any short
sequential attack, which is correct and not worth an API call to question. The
unused-state count trips on a handful of genuine endings, and a student pressed
to explain endings that need no explanation is being taught to invent consumers
for them — the one thing this project refuses to do. Pinned by
`test_the_shape_review_is_not_ported`.

---

## 3. The rule sets

Versioned, never edited in place, because the supervisor asked for iteration to
be visible ("give me version 1.1 of your rule set, keep going around").

    rules/ruleset_v1.md … v1.6.md          professional
    rules/ruleset_student-v1.md … v1.3.md  teaching

**v1.4 is frozen** as the comparison baseline. Its Stage A prompt still
contains wording v1.6 has since corrected; that is intentional and is pinned by
a test, because rewording it would break the comparison the two-version design
exists to make.

**v1.6** is v1.4 plus three constructs (external resource, annotation, dotted
alternative) plus eight text corrections. Every correction removed a statement
that contradicted another rule in the same document. The changelog sits inside
an HTML comment and `load_ruleset` strips comments, so **the model never sees
it**.

Each rule carries a **determination test**, which is what makes route-1
evaluation possible:

- Rule 1 precondition, Rule 2 event/exploit, Rule 3 logical element,
  Rule 6 the three added constructs.

Two rules are worth knowing before editing anything:

**Rule 2, granularity.** One action is one event, and the report decides what
counts as one action. One tool run producing several effects is one event
carrying several techniques, not several events. This is why the GREASE tool,
which the report describes as adding an admin account *and* enabling RDP, is
one rectangle.

**Rule 3, where an OR lives.** An alternative is a **shared result**, not a
join on the consumer. Two substitutable actions produce the *same* state; the
step that follows consumes that one state with `join: AND`. This follows
MulVAL (Ou et al. 2005): conjunction on the action, disjunction on the state.
The schema has one join per event, so an event needing both is unrepresentable
any other way — see §6.

---

## 4. Code map

| file | lines | what it owns |
|---|---:|---|
| `src/extract.py` | 3628 | prompts, both stages, every gate, retry routing, cost budget, shape review |
| `src/schema.py` | 367 | `AttackGraph`, `Event`, `Precondition`, ATT&CK validation |
| `src/student_identifiers.py` | 282 | read, check and annotate the identifiers a student wrote |
| `src/student_feedback.py` | 147 | the two teaching scaffolds: candidate shortlist, plain-English restatement |
| `src/student_coverage.py` | 166 | which of the student's own sentences reached the graph |
| `src/visual_aggregation.py` | 264 | fold a fan wider than a page, at draw time only |
| `src/causal_split.py` | 859 | lossless pagination at stable causal boundaries, now width-aware |
| `src/visual_syntax.py` | 211 | the AGVS-SP profile: shapes, badges, edge styles |
| `src/layout_ir.py` → `layout_planner.py` → `layout_router.py` → `layout_renderer.py` | 477 / 877 / 501 / 720 | the drawing pipeline |
| `src/layout_svg.py` | 277 | the same pages as vector, from the same geometry |
| `src/layout_quality.py` | 190 | page measurements and acceptance warnings |
| `scripts/measure_runs.py` | 411 | the evaluation harness (see §5) |

`extract.py` is five times the 800-line limit the project's own standards set.
Splitting it is agreed as the **last** task, after the write-up, because it
carries no dissertation value and every edit to it during this project that
went wrong went wrong there.

### Tuned constants, and what tuned them

Nothing here is a guess. Each was measured.

| constant | value | evidence |
|---|---|---|
| `_MAX_GENERATION_COST_USD` | 0.90 | a 47-node graph plus one Stage B retry |
| `_MAX_GENERATION_CALLS` | 5 | 2 Stage A + 1 shape review + 2 Stage B |
| `_MAX_CRITICAL_PATH_SHARE` | 0.70 | chain run 100%, healthy run 41%, v1.4 baseline 92% |
| `_MAX_UNUSED_STATES` | 3 | supervisor fixture 0, good run 1, WannaCry 3 (all genuine), bad run 9 |
| `_MIN_EVENTS_FOR_SHAPE_REVIEW` | 8 | below this a sequential attack is legitimately 100% |
| `DEFAULT_MAX_PARALLEL_EVENTS` | 4 | swept 2–6 against rendered aspect; see §7. Now the *start* of the search, not the answer |
| `DEFAULT_MAX_EVENTS_PER_PART` | 12 | |
| `DEFAULT_MAX_RANKS` | 9 | |
| `MAX_PAGE_WIDTH_PX` | 1240 | `NODE_FONT_PX`(14) × 250 mm in points ÷ an 8 pt figure-text floor. A page wider than this prints labels below 8 pt |
| `LEGEND_TEXT_WIDTH` | 240 | was 386, set to fit the longest technique name on one line; that was 40% of the width budget spent on text that wraps fine, and worth one whole drawn column |
| `DEFAULT_MIN_AGGREGATE` | 4 | three drawn columns measure 1194 px and four measure 1492 px against the 1240 px budget, so a fan of four is already one column too wide |

---

## 5. How the work is evaluated

    python scripts/measure_runs.py outputs/*rules-v1.6*.json --markdown
    python scripts/measure_runs.py outputs/student_*.json --student
    python scripts/measure_runs.py outputs/netscout*.json --gold

This **is** the methodology, not a side tool: meeting 6 offered three routes and
route 1 was chosen, so "test that the algorithm decides according to the
definitions" is the evaluation, and this script is how it is run. Meeting 8 asked
for "a good rigorous test plan… quantitative metrics"; this is that.

It calls the product's own functions and defines no metric of its own, so the
script and the tool cannot disagree. That rule exists because an earlier ad-hoc
script measured a badge stack with the wrong line pitch, reported an overflow
that did not exist, and code was written for it.

Three blocks: **structure** (actions, states, unused states, longest-path share,
convergence), **visual syntax** (11 mechanical checks against the supervisor's
reference specification), **layout** (pages, worst aspect, warnings, bends).

`--student` drops `every action has a technique`, which is a v1.6 contract the
teaching rule sets answer with abstention instead, and reports the abstention
count as a metric.

`--gold` compares technique sets against the transcribed reference figure under
two scoring rules and **prints both disagreement lists**. Current result:

    strict   P=0.30 R=0.38 F1=0.33
    parent   P=0.33 R=0.38 F1=0.35

The previously recorded **F1 0.29 is void**: it was computed on v1.4 output
under single-technique semantics, and the current version assigns several. When
quoting the new number, the caveat the script prints must travel with it: the
reference omits the credential toolkit entirely, so every technique read from
that branch lowers precision without being wrong. **This measures agreement
with one expert's abstraction, not accuracy.**

---

## 6. Conformance and known divergences

The checks are: actions are rectangles, states are ellipses, annotations are
dashed and take no part in the causal path, no ATT&CK tactic appears on an
ellipse, 100% of edges run downward, AND is a shared bus, OR is separate edges,
no connector crosses a node, pagination is lossless, every action carries a
technique.

Across the 13 saved v1.6 runs, **one check fails on one older run** and
everything else passes:

| run | failing check | why it is kept |
|---|---|---|
| Stolen Pencil 4 | every action has a technique | predates the rule that the field is never blank |

Runs 1 and 5 were listed here for "no connector crosses a node" until 8 August
and are not any more. Same saved graphs, same check: the planner now separates
same-rank blocks by the width they are actually drawn at rather than by an
estimate of it, and the routes that had to squeeze past a drifted block no
longer exist. The entry was removed rather than left in place, because this
table's only value is that an entry means something.

The rest is listed in `test_measure_runs.KNOWN_HISTORICAL` rather than deleted,
because it is the evidence that the rules changed something, and a second test
asserts it still fails what it is recorded as failing — a stale allowance would
hide a fixed problem.

AND/OR use **convergence lines, not gate symbols**, matching the reference. The
meeting notes record this as unconfirmed; the code has done it all along.

Three divergences from the reference figure, all deliberate:

1. **Badge namespace.** The tool badges the ATT&CK tactic; the reference uses
   an undefined `W/R/D/E/I/C/A` namespace which the gold specification itself
   says is "kept separate from ATT&CK tactics pending an explicit glossary".
   Decided: keep ATT&CK. `AGVS_SP_V1_KILL_CHAIN` exists if that changes.
2. **Convergence target.** The reference converges on `Exfiltrate data`. The
   STOLEN PENCIL report says twice that there is **no evidence of data theft**
   and states the goal was "gaining access… and holding on to it". The tool
   converges on persistence. **On this point the tool is more faithful to the
   report than the reference.**
3. **Abstraction level.** The reference omits the credential toolkit entirely.
   Omission is an editorial judgement with no report-grounded test, so the tool
   includes it.

The supervisor raised "the visual syntax layout is different to my layout" in
**two consecutive meetings**. The mechanical conformance is complete; what
differs is the three items above. That needs an email, not a code change.

### The one open correctness issue

`join` is per event, not per parent. Rule 3's shared-state construction covers
the common case and a gate now rejects the rest (`_mixed_join_problems`: an OR
event consuming an initial condition is mixing "either route" with "and this
had to hold"). A shape needing genuinely mixed logic within one event still
cannot be expressed. Changing that touches the schema and therefore v1.4
comparability.

---

## 7. Measured results

Six of the thirteen v1.6 runs, chosen to show two repeats of one report and
before/after pairs for two rule changes. `measure_runs.py` prints all thirteen.

**"Convergence" here means the share of actions that can reach the
single terminal state reached by the most of them.** An earlier note in this
project used a different measure — reachability of one *named* objective — and
the two are not comparable: Stolen Pencil run 8 is 78% by the first and 35% by
the second. Only one definition may appear in the write-up, and it is this one.

| report | actions | unused states | longest path | convergence | pages | worst aspect |
|---|---:|---:|---:|---:|---:|---:|
| WannaCry run 1 | 14 | 3 | 79% | 86% | 3 | 0.55 |
| WannaCry run 2 | 14 | 3 | 79% | 86% | 3 | 0.64 |
| Stolen Pencil run 8 | 23 | 14 | 35% | 78% | 4 | 0.16 |
| Stolen Pencil run 9 | 24 | 7 | 46% | 75% | 4 | 0.34 |
| British Library run 1 | 13 | 7 | 46% | 69% | 2 | 0.42 |
| British Library run 2 | 13 | 7 | 62% | 92% | 2 | 0.91 |

Three findings worth writing up:

**Reproducibility.** WannaCry run twice gives an identical structural
signature: 14 actions, 3 unused states, 3 terminals, 79% longest path, 86%
convergence.

**Shape follows the report, not a template.** A worm is a chain (79%); a
toolkit incident is a funnel (46%); the only report with genuine uncertainty
about the entry vector is the only one that produced dotted alternative
branches (4 nodes, British Library).

**The rule iterations moved the numbers.** Giving the shape review its own call
took Stolen Pencil from **14 unused states to 7**: the credential results that
nothing consumed acquired the consumer the report says they had. Convergence
was 78% before and 75% after, so that change is about loose ends and not about
convergence, and claiming otherwise would be reading two different measures as
one. Fixing Rule 3's OR construction took British Library from **1 mixed-join
fault to 0** and convergence from **69% to 92%**.

---

## 8. Recurring defect classes

These cost the most time. Check for them before adding anything.

1. **A rule written in prose is not a constraint.** Rules the schema or a gate
   does not carry are requests. Several rules were "enforced" only in the
   prompt and were quietly ignored for weeks.
2. **A gate at a stage that cannot repair the fault.** Stage B returns only
   technique identifiers, so anything it rejects about structure loses the
   whole graph after both calls are paid for. Every structural check belongs in
   Stage A.
3. **Prose matched on raw text.** Three separate bugs came from a hard line
   break falling inside a phrase being searched for: the rule-set comparison,
   the mock's stage detection (which meant **v1.6 Stage A was never recognised
   by the mock**), and reading a student's `T1213`. Nothing in this project
   matches prose without normalising whitespace first.
4. **A field with a default is optional to the provider.** It then never comes
   back. This is why the wire models exist and why `stated_technique` is
   required with an empty string rather than defaulted.
5. **Telling the model a target shape instead of a test.** "Make it wider"
   produced a chain; "make it a chain" produced a fan. The counterfactual
   dependency test produced neither.
6. **A test that pins a bug.** Two happened here: one asserted the exact
   `required` list that omitted `stated_technique`, one asserted the model's
   transcription should beat the source text.
7. **A budget in the wrong unit.** Page width was capped by counting actions
   for months. The two quantities are not the same, and the widest page the
   tool ever produced — 3731 px, labels printing at 1.7 pt — satisfied every
   budget in force. If a limit exists to protect something, measure the thing
   it protects.
8. **A constant restated instead of imported.** The legend reserve was written
   as a literal `420` in a planner test; when the key column was narrowed the
   test went on measuring a canvas the renderer had stopped drawing.
9. **A correction nobody is told about.** Suppressing an ATT&CK tactic badge on
   an ellipse is right, and a student who labelled all nine of their states
   that way got a figure with nine bare ellipses and no explanation. Silent
   correction keeps reappearing here in new forms; every one found so far is
   now a note rather than a silence.

---

## 9. What is left

**Dissertation, in priority order.** Draft of the whole project was due to the
supervisor by **17 August**.

1. **Testing chapter** (ten sections required). `measure_runs.py` supplies
   sections 5, 6 and 7 directly.
2. **Results chapter.** The table in §7 plus the conformance matrix in §6.
3. **Project-brief reconciliation.** The brief asks for "LLM inference to
   suggest mitigations"; v1.6 **derives** them from MITRE's `mitigates`
   relationship instead, because asked-for mitigations came back valid in
   isolation and unrelated to the chosen technique. Write this as an
   evidence-backed design decision, not a gap. Note the teaching version keeps
   the model's mitigations, so the two versions are a ready-made contrast.
4. **Literature review rewrite.** Supervisor: "at the moment it is presented as
   a serial group of papers" — critique and synthesise.
5. **Cite Sherzhanov et al. (2024).** Same supervisor, same topic, and it is
   the evidence for the shared-syntax decision in §2.
6. **Management dimension.** WMG requires it for this route. The likelihood
   score and mitigation mapping are prioritisation inputs; automated attack
   graphs bear on analyst workload, risk communication and decision support.

**Figure usability — done, with a measured remainder.**

Nothing measured whether a figure could be *printed* until 8 August. Three
changes, all in §4's files:

- every page carries a key that states the visual syntax it uses, listing only
  the symbols that page draws;
- pagination measures its pages in drawn pixels and tightens the action budget
  while a page is over `MAX_PAGE_WIDTH_PX`, preferring a plan that also routes
  cleanly: a connector through a node is a wrong drawing, a page too wide is a
  correct one that cannot be used, and extra pages are a cost with no defect;
- both applications write SVG beside the PNG, from the same geometry;
- pagination will not buy legibility at any price: `PAGE_COUNT_CEILING = 2`
  caps how far a graph may be divided to meet the width budget, after a real
  run divided a six-way fan into seven pages of one action each. A judgement,
  labelled as one, and exposed as `page_count_ceiling`. It costs legibility —
  professional runs inside the 8 pt floor fall from 8/15 to 5/15 — but the
  widest page falls from 2240 px to 1738 px and no figure is fragmented;
- the attack's objective gets the last row to itself and is named in the key.
  It is computed **once from the whole graph** and handed to every page: the
  page-local answer is a different node on every page of a split, and briefly
  shipped as one, so part 1 announced "Privileged terminal server credentials
  obtained" as the attack's objective and part 4 announced "Log files deleted".
  Only the page that draws the graph's objective may name it.
  Rule 5 always had the model name it as a result state, but the figure never
  showed it: the British Library page ended in nine terminal states and the
  objective was distinguishable only by counting arrows. `attack_objective`
  defines it once — the causal terminal state the most actions reach, `None` on
  a tie — and `page_objective` answers the same question for a drawn page
  through the same function. A page ending on a bridge to the next page claims
  no objective. No arrow changes; only the row does.

The semantic draft pipeline's checkbox was removed from the professional page.
The code and its tests are kept and it still runs when the field is posted, but
a figure it produces takes no rule set, refuses v1.6, is not read by
`measure_runs.py`, and is drawn by its own renderer without the key, the width
budget or the vector output — so it cannot be compared with anything the
write-up reports. Worth a paragraph in the design-exploration section.

Measured by re-planning every saved graph through `render_split`'s own settings
against the pre-change source tree and the current one: professional v1.6 runs
meeting the 8 pt floor went from **1 of 14 to 8 of 14**, student runs from **5 of
17 to 17 of 17**, the widest student page from 1950 px to 1194 px. The
remainder is reported, not hidden: the five
professional runs still over budget (5.5, 5.9, 6.6, 7.0 and 4.4 pt) are wide
because of a *rank of states*, which no action budget narrows. `layout_quality`
warns on each page that misses the budget and `measure_runs.py` prints the width
and the printed point size per run. Full record in
`docs/figure_quality_20260808.md`.

**Code, after the write-up.**

- split `extract.py`;
- narrow a page whose width comes from states rather than actions — the one
  remaining figure-usability gap;
- `join` per parent, if the schema change is judged worth the loss of v1.4
  comparability.

**Do not** simplify the teaching version's visual syntax. See §2.

---

## 10. References

| work | why it matters here |
|---|---|
| Lallie, Debattista & Bal (2020), *A review of attack graph and attack tree visual syntax in cyber security*, Computer Science Review 35:100219 | the visual syntax baseline; 180 graphs surveyed; an attack goal appears in only 21.5% of them, so drawing one explicitly is this project's decision and not a field norm |
| Sherzhanov, Atlam, Azad & Lallie (2024), *Improving Attack Graph Visual Syntax Configurations*, Electronics 13(15):3052 | n=83, 37 experts and 46 non-experts; visual enhancement alone did not improve non-expert comprehension. The evidence for one shared syntax plus scaffolding |
| Pirca & Lallie (2023), Computers & Security 130:103254 | the reference configuration |
| Ou, Govindavajhala & Appel (2005), MulVAL | conjunction on the action, disjunction on the state; the fix for Rule 3 |
| Noel & Jajodia (2004), VizSEC/DMSEC | hierarchical aggregation; the basis for folding a fan rather than paginating it |
| Homer et al. (2008), VizSec | data reduction and attack grouping |
| MITRE ATT&CK v19 | the local catalogue; `mitigates` supplies every derived mitigation |

Project artefacts: `docs/stolen_pencil_gold_spec.md` (what the reference figure
does and does not decide), `tests/fixtures/stolen_pencil_gold.json` (the
transcription), `docs/contradiction_fixes_v1.6.md` (every rule contradiction
found and how it was resolved), `docs/HANDOVER.md` (earlier notes; §7 here
supersedes its F1 figure).
