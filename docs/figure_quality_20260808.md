# Figure usability, close-out and dead-code audit — 8 August 2026

Backup: `backups/figure_quality_20260808_143131/`
Suite: 673 tests, 1 skipped, `compileall` clean, before and after.

---

## 1. Figure usability

### The problem, measured

A figure in a dissertation is placed at some physical width, and every pixel
scales with it. The printed size of a node label is therefore decided by the
ratio of the font to the whole canvas, not by the DPI stamped in the file. At
`NODE_FONT_PX = 14`, a page `W` pixels wide placed across a landscape A4 text
area (250 mm = 708.7 pt) prints its labels at `14 / W × 708.7` pt.

The widest page this tool had produced was **3731 px**. Its labels print at
**1.7 pt**. Nothing in the pipeline measured this, because the width budget
counted actions and a rank of four actions can establish a dozen states beside
them.

### What changed

**A key on every page.** `_syntax_key_lines` in `layout_renderer.py` states the
visual syntax on the figure: which shape is an action, which is a state, what a
dashed or dotted outline means, which way the arrows read, what the shared bus
and the separate arrows mean, and what each badge and tag is. Only the symbols
that page actually draws are listed. Lallie, Debattista and Bal (2020) surveyed
180 published attack graphs and found the notation inconsistent between them and
usually unexplained on the figure; that is the failure this closes in our own
output.

**A width budget in the unit that matters.** `MAX_PAGE_WIDTH_PX = 1240`, derived
in code from the font size, the placement width and an 8 pt figure-text floor.
`plan_causal_split` now measures its plan in the geometry that will be drawn and
tightens the action budget while a page is over. Three quantities are traded and
they are not equal, so the order is explicit: a connector drawn through a node is
a **wrong** drawing, a page too wide to read is a **correct** drawing that cannot
be used, and extra pages are a cost with no defect. The planner takes the first
plan that is both clean and within budget, falls back to the first clean one, and
only then to the plan it started with.

**The key stopped competing with the graph.** The key column was 386 px, set to
fit the longest ATT&CK technique name on one line — 40 % of the entire width
budget, and the difference between two and three drawn columns per page. It now
wraps at `LEGEND_TEXT_WIDTH = 240`.

**Aggregation retuned against the same criterion.** `DEFAULT_MIN_AGGREGATE` was
the pagination event budget plus one, a count with no measured meaning. Three
drawn columns measure 1194 px and four measure 1492 px against a 1240 px budget,
so folding starts at four.

**Vector output.** Both applications now write SVG beside the PNG, from the same
geometry, and `render_layout_plan_svg` finally receives `extra_legend_lines` —
without it the vector figure, the one that goes in the document, showed a box
labelled "6 grouped actions" with nothing saying which six.

### The objective, shown rather than only named

Rule 5 has the model name the adversary's objective as a result state, and it
does. Nothing showed it. The British Library page ended in **nine** terminal
states with the objective among them, and the only way to tell which was to
count arrows: three actions converge on `p_objective`, one on each of the rest.
Lallie, Debattista and Bal (2020) found a goal represented in 21.5% of the 180
published attack graphs they surveyed; a goal named in the JSON and buried in a
row of siblings is on the wrong side of that number.

Two changes, no new symbol:

- **`causal_split.attack_objective`** — among the causal terminal states
  (annotations excluded, since an annotation is commentary and not an ending),
  the one the most actions can reach. A tie returns `None`: two endings reached
  by equally much is a graph that does not converge, and picking a winner would
  assert something the graph does not say. `layout_planner.page_objective`
  answers the same question for the page being drawn **through the same
  function**, so the two cannot drift.
- **`_close_on_the_objective`** gives that node the last row to itself, so the
  hourglass closes on it, and the key names it: *"The attack's objective, at
  the foot of the figure: …"*.

Rank carries dependency only through arrows — the key on every page says so —
and no arrow is added, removed or reversed. A test asserts that every edge
still runs from a lower `bottom` to a higher `y` after the move.

A page whose objective is a **bridge** claims nothing. Part 1 of the British
Library split ends on "Wide access across network achieved", which continues
into part 2; the renderer already prints "continues in part 2" under it, so
`objective_label_for_page` returns `None` there. Part 1 gets no objective line,
part 2 does.

### Ink drawn twice, and ink drawn nowhere

The routing check asked only whether a connector crossed a **node**. It never
asked what connectors did to each other. Over 122 drawn pages there were **18
zero-length segments, 35 polylines emitted twice and 35 segments stroked
twice**. A doubled stroke is a heavier, darker line in one place and reads as a
different kind of edge, when it is the same pixel drawn again.

Two fixes: the router normalises every path it emits (the AND drops were not
simplified, so a drop whose input already sat on the bus line came out
zero-length), and both renderers refuse to stroke a segment already stroked on
that page, keyed by style so a dashed run over a solid one still shows. An
arrowhead is never suppressed — it states an edge's direction, and two edges
sharing a column still arrive separately.

All three counts are now **zero across the same 122 pages**, pinned by tests.

What this does **not** fix is a long route detouring into a side column and
back, rank after rank. The router already prices overlap and crossings
(`OVERLAP_PENALTY`, `CROSSING_PENALTY`); those detours are where it cannot do
better without a channel-assignment pass, which is a larger change than this
work.

Two more defects came out of a sweep over all 40 saved graphs, checking the
drawn output rather than the fixtures:

- **A state produced from two parts is drawn in both** — documented bridge
  behaviour, not a duplicate — and one run announced the objective on parts 4
  **and** 5 of five. It is now named on the last page that draws it, where its
  producers have all been seen and it is an ending rather than a partial
  result.
- **An annotation sat lower than the objective.** "No evidence of data
  exfiltration observed" is commentary, off the causal path, and its row
  carries no causal meaning; it was nonetheless at the foot while the key said
  the objective was. The named objective now goes below everything, annotations
  included. A page whose objective is only the page's own convergence is still
  left alone unless it already ends there — nothing names it, so nothing is
  contradicted.

**The page-local fallback was a defect and is gone.** It shipped briefly, and a
split graph exposed it twice over. On one run, part 1 announced "Privileged
terminal server credentials obtained" as the attack's objective and part 4
announced "Log files deleted to hinder forensics" — each page answering with
its own convergence. On another, three endings tie at thirteen of fourteen
actions each, `attack_objective` correctly returned `None`, and the fallback
answered anyway on two pages with two different nodes. A fallback cannot tell
"nobody told me" from "there is no objective", so there is none: a page told
nothing says nothing, and a graph that does not converge names no objective on
any page.

Measured after: no width change, no connector crossings, tests green.

### The page-count ceiling, and what it costs

A later British Library run showed the width budget's own failure mode. That
graph fans **six** actions off one state, each with its own results, and the
only pagination meeting the budget put one action on each of **seven** pages:
every page legible, no page showing any structure. The measured ladder was

| action budget | pages | widest | printed label |
|---|---|---|---|
| 4 | 2 | 1994 px | 5.0 pt |
| 3 | 2 | 1650 px | 6.0 pt |
| 2 | 3 | 1878 px | 5.3 pt |
| 1 | 7 | 1054 px | **9.4 pt** |

— nothing between unreadable and fragmented. Relaxing the "no two pieces of one
causal level share a page" rule was tried a second time, now with the
routing-aware selector in place to catch the damage: it still produced a
1994 px page **and** put a connector back through a node on another run.
Reverted again, with both attempts recorded in the code.

So the selector gained `PAGE_COUNT_CEILING = 2`: a narrower plan is worth
having until it costs more than double the pages the graph started with. This
is **a judgement, not a measurement**, and it is labelled as one where it is
defined. It is exposed as `page_count_ceiling` so the trade can be moved
without editing the planner.

A second run then showed the ceiling was not enough on its own. That graph's
natural plan was **three pages at 1260 px** against a 1240 px budget — labels at
7.9 pt against an 8.0 pt floor — and the planner bought **two extra pages to
close a gap of twenty pixels**. The floor is a convention, not a threshold in
anyone's eye, so `WIDTH_BUDGET_TOLERANCE = 0.05` stops pages being spent on a
near miss. `layout_quality` still reports against the strict budget: the
tolerance changes what is bought, never what is claimed.

The cost is real and is the author's choice, not a measurement: professional
runs within the 8 pt floor fall from 8/15 to **5/15**, while the widest page
drops from 2240 px to **1738 px** (4.4 pt → 5.7 pt). Student runs are
unaffected at 17/17. Two readable pages that show the attack were preferred
over seven legible fragments that do not.

### Three real defects found on the way

- **The planner refused its own plans.** Narrower pagination puts more bridge
  states on a page, and same-rank blocks were spaced by an estimate (slots ×
  node width) that page-local roots could drift outside of, producing
  `same-rank blocks overlap`. `_separate_blocks_by_drawn_extent` now gives the
  last word to the geometry: each block is measured where its nodes actually
  are, the row is fitted with the same order-preserving solver used elsewhere,
  and each block's nodes move together by one offset.
- **That fix removed two recorded conformance failures.** Stolen Pencil runs 1
  and 5 were listed as failing "no connector crosses a node". Same graphs, same
  check, now passing: the routes that had to squeeze past a drifted block no
  longer exist. `KNOWN_HISTORICAL` is down to one entry.
- **The retuned fold threshold never reached a figure.** `render_split` derived
  it as `max_parallel_events + 1`, so `DEFAULT_MIN_AGGREGATE = 4` was
  overridden by 5 in the only path that draws anything. Found by a real
  teaching run — four outcomes, unfolded, 1580 px, labels at 6.3 pt — not by
  the tests, which called the function directly and saw the default. Fixed with
  a named `min_aggregate` parameter and pinned by three tests, one of which
  greps the source for the old expression.

### One change tried and reverted

Letting two pieces of one causal level share a page when the merged rank fits
the width budget — to stop four independent one-action blocks becoming four
pages of one box. It made **five** saved v1.6 runs fail "no connector crosses a
node". The rule was not only about width: two unrelated blocks in one rank put
their result states side by side and the edges reaching across them have nowhere
to go. Reverted, with the reason recorded in the code.

### Result

Measured by re-planning every saved graph through **`render_split`'s own
settings** against the pre-change source tree in
`backups/figure_quality_20260808_143131/src` and against the current one.

The first version of this table was measured by calling `aggregate_for_drawing`
with its default threshold, which is **not** what the applications did:
`render_split` passed `min_size=max_parallel_events + 1`, so the retuned fold
threshold never reached a drawn figure. Corrected below, after that wiring was
fixed. Both columns are now the production path on the same inputs:

| | before | after |
|---|---|---|
| student runs meeting the 8 pt floor | 5 of 17 | **17 of 17** |
| professional v1.6 runs meeting it | 1 of 14 | **8 of 14** |
| widest student page | 1950 px | **1194 px** |
| widest professional page | 2382 px | 2240 px |
| saved runs failing a syntax check | 3 | **1** |

The five professional runs still over budget (5.5, 5.9, 6.6, 7.0 and 4.4 pt) are
wide because of a **rank of states**, which no action budget narrows.
`layout_quality` warns on each, and `measure_runs.py` prints `widest page px` and
the printed point size per run. This is reported, not hidden, and it is the one
remaining figure-usability gap.

---

## 2. Close-out

- **README**: `student-v1.2` → `student-v1.3`, `US$0.45` → `US$0.90` over five
  calls, and the teaching version's two scaffolds described.
- **`Aggarwal et al. 2025`** replaced with `Ou et al. 2005` in `ruleset_v1.6.md`.
  The frozen v1.1–v1.4 rule sets keep it deliberately: editing a frozen baseline
  would change what the recorded comparisons were run against. Say so in the
  write-up rather than silently amending them.
- **ATT&CK snapshot**: `data/attack_lookup.provenance.md` records the source, the
  file date, the SHA-256, and 697 techniques / 44 mitigations. The release
  **cannot** be recovered — the source URL points at a branch and the generator
  recorded only the address, so labelling it from a download made today would be
  a guess presented as a record. What can be said is a bound: the tactic phases
  `stealth` and `defense-impairment` appear in v19, so the snapshot is v19 or
  later. `update_attack_lookup.py` now reads `x_mitre_version` out of the
  bundle's own collection object and writes it with the retrieval date, so every
  future snapshot identifies itself.
- **Student state codes**: suppressing an ATT&CK tactic badge on an ellipse is
  correct and stays, but the student was never told. One submission labelled all
  nine of its states with tactic abbreviations and got nine bare ellipses.
  `_suppressed_state_code_note` now says how many, which codes, why they are not
  drawn, that they are still in the saved graph, and what to use instead.

---

## 3. Dead-code audit

Two static passes over `src/`, `scripts/`, `tests/`, `app.py`, `student_app.py`:
unused imports, definitions nothing references, statements after
`return`/`raise`, byte-order marks, and `src/` names referenced only from tests.
Both passes now return empty.

| removed | why |
|---|---|
| `AGVS_SP_V1` import in `layout_ir.py` | unused |
| `import extract` in two test modules | unused; the only `extract.` text was a file path |
| `events_needing_a_technique` (`student_identifiers.py`) and its test | referenced by nothing but that test, and its docstring described a saving the tool does not make — Stage B is asked about every step and the student's own identifier overrides the answer afterwards, in `extract.py`. The test was rewritten to check the rule that is actually implemented |
| BOM in `tests/test_v15_contract.py` | invalid non-printable character to `ast.parse` |

Corrected rather than removed:

- `attack_graph.py` said "No entry point reaches this today — both applications
  render PNG"; both now render PNG and SVG.
- `test_layout_stage_b_planner.py` restated the legend reserve as a literal
  `420`; when the key column narrowed it went on measuring a canvas the renderer
  had stopped drawing. It imports `LEGEND_RESERVE_WIDTH` now.
- `causal_split.py` and `layout_quality.py` comments describing the width budget
  and the key column.

`widest_page_width_px` would have been left test-only, so `measure_runs.py` now
reports page width and printed point size — the harness that produces the
dissertation's numbers should carry the criterion the figures are judged by.
