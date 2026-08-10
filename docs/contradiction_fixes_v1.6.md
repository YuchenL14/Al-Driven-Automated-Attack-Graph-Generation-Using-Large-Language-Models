# v1.6 contradiction fixes — working record

Baseline before this work: 464 tests passing.
Backup of every touched file: `backups/contradictions_20260802_*/`.

Each item is fixed on its own, audited on its own, and pinned by a test before
the next one starts.

---

## Item 1 — repair prompts demanded a single path

**Status: done. 470 tests passing.**

### What was claimed

An external review pointed at `src/extract.py:231`, `"The two node types
alternate and must be chained into one connected path."`, as the cause of the
chain-shaped output.

### What was actually true

The quote is real but sits in `STAGE_A_USER`, which **v1.6 does not use**. v1.6
runs `STAGE_A_V16_USER`, and that prompt never contained the phrase. v1.4 is
also the frozen comparison baseline, so rewording its prompt would break the
comparison the two-version design exists to make. It was left alone, and a test
now records that this is deliberate.

The live defect was in three **repair** prompts:

| Site | Fires when | Also demanded |
|---|---|---|
| `_stage_a_problems`, parentless events | an event lists no precondition | "consecutive steps must chain" |
| `_stage_a_problems`, flat fan | every event consumes an initial condition | "Chain the steps…" |
| `_extract_hierarchical`, structural fault | any of 13 markers | "giving one connected path from the initial conditions to the final impact" |

The third is the serious one. `_STRUCTURAL_FAULT_MARKERS` holds thirteen
markers; eleven are referential or label problems — a duplicate id, a parent
naming no node, a precondition label too long for its ellipse, a blank field.
A graph rejected because one label would not fit an ellipse was told to
restring the whole attack into a line.

Two defects in one string: a gate repairing one thing while demanding another,
and an instruction naming a target shape rather than a test.

### What changed

All three now state the invariant the checks actually enforce.

- Parentless events: ask for the state each event consumed. No chain clause.
- Flat fan: "Where the report says one step made a later one possible, let that
  later event consume the state the earlier one establishes. Steps the report
  describes as independent stay independent."
- Structural fault: "The graph must hold together as one connected structure…
  Branches are expected… Join a stray node by giving it the precondition it
  actually consumes, not by putting it in a line behind an unrelated step."

The anti-evasion sentence (`Do not delete a node`) was left intact; narrowing it
is item 2.

### Audit

- Only surviving `connected path` is line 231, the frozen v1.4 prompt.
- `STAGE_A_USER` is byte-identical to the backup.
- Fault routing is unchanged; only the text of the correction changed.
- `tests/test_repair_prompts_do_not_reshape.py` pins all of the above.

---

## Item 2 — "Do not delete a node" blocks merging

**Status: done. 472 tests passing.**

### The tension

`Keep every node you already found. Do not delete a node…` exists for a real
reason: the model had been dropping nodes to make a validation error go away.
The external review proposed deleting the sentence. That would reinstate the
evasion.

But the same sentence also forbade the merge that Rule 2's granularity rule
now asks for. A model that split one GREASE run into two events could not put
it back together on the repair path — the repair prompt said keep everything.
Two rules of the pipeline contradicted each other, and the prompt won, because
a prompt is what the model actually reads.

### What changed

The absolute prohibition became a specific one. Dropping a node to make an
error disappear is still refused, in stronger words ("an attack step that
vanishes is not a repair"). A merge is now permitted under exactly the
condition Rule 2 states, and the prompt spells out what the merged event
inherits:

> You may merge two events into one where the report describes them as a single
> action, such as one tool run or one command; the merged event then consumes
> what both consumed, produces one state, and carries both sets of techniques.
> Every other node you already found stays.

### Audit

- `Do not delete a node` still present.
- `Keep every node you already found` gone.
- Prompt and Rule 2 name the same condition; a test compares them on
  normalised whitespace, since the rule set is hard-wrapped and a literal
  comparison silently failed on a line break.

### Note for item 4

While auditing this, the v1.6 changelog turned out to sit inside an HTML
comment, and `load_ruleset` strips comments before the model sees the text. The
claimed contradiction between the changelog and line 99 therefore needs
re-checking: only one of the two statements may actually reach the model.

## Item 3 — annotation test contradicts Rule 6.2

**Status: done. 478 tests passing. The sharpest contradiction found so far.**

The two documents the model reads together classified the *same phrase* two
opposite ways.

| | Rule 6.2 | Stage A prompt |
|---|---|---|
| order | causal test first, defensive question second | defensive question only |
| "no egress filtering" | precondition of exfiltration succeeding | listed as an annotation example |
| "MFA not enabled" | precondition of a login succeeding | caught by "could have done" |

The prompt wins in practice: it is the instruction, the rule set is reference
material. So absent controls were being pushed out of the causal graph into
commentary — and an annotation takes no part in the dependency structure, so
each misclassification silently deletes a reason the attack worked.

The prompt now states Rule 6.2's test in Rule 6.2's order, ends with "The
subject being defensive does not settle it", and its annotation examples are
remarks only ("detected by SOC on day 4", "no evidence of data theft was
found").

---

## Item 4 — ruleset changelog contradicts itself

**Status: done. 495 tests passing. Documentation-only, plus one false citation
found while fixing it.**

The claimed contradiction is real in the file: line 13 says Rules 2–5 each
carry corrections that removed a contradictory statement, line 99 says
"Nothing in v1.4 is removed or reworded".

It does not reach the model. The comment block spans lines 3–157, and
`load_ruleset` strips comments, so **both** statements are removed before the
text is sent. An earlier claim in this session that the model sees both was
wrong.

It still matters for describing version iteration accurately, so it was fixed
last. The paragraph now withdraws the claim explicitly and states the narrower
thing that is actually true: the *mechanism* is unchanged, every correction
removed a statement that contradicted another rule in the same document, and
the v1.4 rule file and prompt are frozen and untouched.

### A false citation found while fixing it

The Rule 4 changelog entry justified relaxing "every path converges toward it"
by saying the supervisor's reference graph "ends in five distinct terminal
states". Measured against the fixture, it has **three** terminal nodes, two of
them annotations — so **one** causal terminal, `Exfiltrate data`. The reference
converges completely. The stated reason was not merely imprecise, it was
backwards.

The relaxation itself stands, on different ground: convergence is a property of
the incident, not of the notation, and the WannaCry report genuinely ends in
three outcomes. Demanding one objective would force a consumer to be invented
for two of them. That reasoning is now what the file records, together with the
fact that the *number* of unconsumed states is what the Stage A review checks.

Two tests in `test_stolen_pencil_gold.py` pin the fixture counts the rule set
now cites, so the citation cannot drift again.

---

## Summary

| item | model-facing | status |
|---|---|---|
| 1 repair prompts demanded a single path | yes | fixed |
| 2 "Do not delete a node" blocked merging | yes | fixed |
| 3 annotation test contradicted Rule 6.2 | yes | fixed |
| 4 changelog contradicted itself | no | fixed |
| 5 shape review had no unused-state gate | yes | fixed |

464 tests before, 495 after. Nothing in v1.4 was modified.

Two claims from the external review did not survive checking, and are recorded
here so they are not re-fixed later:

- `extract.py:231` is in the v1.4 prompt, which v1.6 does not use and which is
  deliberately frozen.
- Neither changelog statement reaches the model; the whole header is inside a
  comment that `load_ruleset` strips.

### Not done, deliberately

No width gate in the shape review — see item 5.

---

## Run 7 — the re-run, and what it exposed

497 tests passing after the follow-up fixes below.

### The three predictions

| prediction | result |
|---|---|
| GREASE becomes one event | **yes** — `e_grease`, carrying T1136.001 + T1021.001 + T1686 |
| MECHANICAL becomes one event | **no** — still `e_keylog` + `e_cryptojack` |
| the credential dead ends acquire a consumer | **no**, and instructively so |

Run 7 is genuinely better as a drawing: 24 events to 19, four pages to three,
page 3's aspect ratio 0.18 to 0.65, bends 15 to 6, and a top rank of four
independent preparation branches — the reference graph's shape, not a chain.

But the convergence is not real. Asked to connect five abandoned credential
states, the model added a *sixth* state, "Wide array of credentials scavenged",
fed it to the PsExec event, and gave it **no parents**. The five stayed
abandoned and the new node floated as a root. Separately, `p_persistentaccess`
— the report's stated main goal, "holding on to it" — was dropped as
unconnected, so run 7 has no objective node at all.

### Two defects in the review loop itself

The revision was accepted because nothing checked the thing the request
demanded.

1. **Only events were compared.** The request says "Keep every event,
   *precondition*, id, label, tactic, likelihood, role and style exactly as
   they are", but the acceptance test compared event ids alone. A revision
   could invent a state freely. Prose again, not a constraint.
   Fixed by `_same_nodes_apart_from_parents`, which compares every node with
   its parents removed — that *is* "change only parents lists".

2. **Acceptance required `critical_path_share` to fall.** The unused-state gate
   added the day before could therefore fire forever and never take effect: a
   revision that connected loose ends without shortening the longest path was
   discarded in silence. Acceptance is now "better on one measure and worse on
   neither".

Two smaller channel defects surfaced while testing this:

- Stage B **replaced** the notes rather than appending, so Stage A's
  explanation of a discarded revision was destroyed before the user saw it.
- Nothing reset the notes between runs, which appending would have turned into
  cross-run leakage.

### A test fixture that was not testing what it claimed

`test_a_better_revision_is_adopted` fed `_funnel(12)` as a revision of
`_chain(12)`. Those have entirely different ids and labels, so it was never a
revision at all — it simply happened to pass while only events were compared.
It now uses `_relinked(12)`: the chain's own nodes, re-parented.

### Still open

- MECHANICAL is not merged, though the report describes one tool with two
  functions in one sentence and the reference graph has one node for it.
- Run 7 has no objective node. Whether the fixes above are enough to restore
  one is the next thing to measure.

### Next

Re-run Stolen Pencil. The revision loop can now actually adopt a fix for
abandoned states, and can no longer accept an invented node. If the credential
states still do not converge, that is the evidence that Stage A needs the v1.7
abstraction layer rather than another rule.

## Item 5 — shape review gates only on critical path share

**Status: done. 493 tests passing.**

### The hole

`measure_skeleton_shape` already computed `widest`, but only
`critical_path_share` opened a gate. A model could satisfy the review by
splitting one long chain into parallel branches that go nowhere. Run 6 did
exactly that: 42% critical path — comfortably passing — with nine states
established by an event and consumed by nothing, six of them recovered
credentials, while the report says the goal was "gaining access to compromised
accounts and systems **via stolen credentials**".

### Calibration, not a guess

| graph | events | unconsumed states |
|---|---:|---:|
| supervisor fixture | 14 | **0** |
| Stolen Pencil run 5 | 19 | 1 |
| WannaCry blind run | 14 | 3 — all genuine endings |
| Stolen Pencil run 1 | 22 | 5 — 3 endings, 2 abandoned capabilities |
| Stolen Pencil run 6 | 24 | 9 |

`_MAX_UNUSED_STATES = 3` sits above the largest correct reading and below the
incorrect ones. This schema ends on a state rather than an action, so at least
one loose end is structural.

### Why there is still no width gate

A wide rank is what the counterfactual test is *supposed* to produce when
several steps needed nothing but a shared earlier state. Asking for a narrower
graph would contradict the test in the same prompt and re-create the chain the
review exists to catch — the exact oscillation that happened earlier in this
project. Width is a page-size problem and pagination now bounds it. The
docstring records this so it is not "fixed" later by mistake.

### The request permits refusal

The instruction ends: "…leave it as it is — an attack has endings, and
inventing a consumer for one is worse than leaving it unconsumed." Without
that, a correct graph with several genuine outcomes would be pushed into
fabricating consumers, which is the prohibition this project treats as
absolute.

### One existing test changed meaning

`test_it_separates_the_real_runs` asserted `bool(shape_revision_request(...))`,
which meant "the critical-path gate fired" when there was only one gate. With
two gates that assertion became ambiguous, and run 1 correctly trips the new
one. It now asserts the critical-path observation by name, so it still tests
what it was written to test.

---

## Run 8 — the wide page came back, because the previous fix worked

499 tests passing.

### What happened

Run 8's page 3 was nine events in one rank again, despite the width-aware
pagination added earlier. The cause is the fix before it succeeding:
`p_creds_scavenged` finally had **eight real producers** — every credential
event feeding one shared state, which is what the shape review asks for and
what run 7 failed to do.

`_event_blocks` merges events that produce the same state into one atomic
block, on the assumption they are OR alternatives. Eight dumpers became one
block of eight events, and the width split works at block granularity, so it
could not cut inside.

### Fix 1 — a block is divisible

`_event_blocks` merges only events that **cannot reach one another**, so every
multi-event block is internally independent by construction and dividing one
splits no causal chain. Keeping an alternative set whole is a readability
preference, not a correctness constraint. Groups are now chunked to the width
budget as blocks are assigned, which keeps `produced_by_block` and the block
graph consistent for free.

Page 3 width fell 2068 to 1612. Not enough on its own.

### Fix 2 — bound the shape, not the width

The page was still unreadable because it was *short*: three ranks tall, six
events wide. Width and rank budgets were independent, so the planner produced
one page nine ranks tall and two wide (aspect 2.07) beside one three ranks tall
and six wide (0.26).

Width may now grow only with height: a page of L event layers occupies 2L+1
visual ranks and may be `cap * (2L+1) / 3` events wide.

Calibrated against the **rendered** `page_aspect_ratio`, not the planner's own
width and height — the legend column adds page width the planner never sees, so
a plan measuring 0.36 renders at 0.25. The first calibration used the plan and
read about 30% high.

### The cap, measured rather than chosen

| cap | run 8 | run 7 | WannaCry |
|---:|---|---|---|
| 6 (before) | 4 pages / 0.20 | 3 / 0.39 | 3 / 0.55 |
| 5 | 4 / 0.22 | 3 / 0.39 | 3 / 0.55 |
| **4** | **5 / 0.25** | **3 / 0.71** | **3 / 0.55** |
| 3 | 6 / 0.28 | 4 / 0.26 | 3 / 0.55 |
| 2 | 7 / 0.33 | 6 / 0.30 | 4 / 0.41 |

Below 4 the pages multiply and run 7 gets worse, not better. A 2:1 target was
offered and rejected: it divided the eight-way convergence across three pages,
which is the one structure on those pages worth seeing whole.

### A latent defect found while sweeping

`plan_causal_split(max_parallel_events=N)` used N for block chunking but the
global function for the pagination width check, so the two could disagree and
make pagination unsatisfiable. The per-layer rule now scales from the caller's
cap, which makes the two consistent by construction.
`render_split` gained the same parameter; it had no way to pass one.

### Still open

Run 8's two credential pages sit at 0.25. The drawing on them is four events
wide and three ranks tall; most of the remaining page width is the legend
column, which is fixed-width regardless of how little the page carries. That is
a separate problem from pagination and is not addressed here.

---

## Render-time aggregation

517 tests passing. New module `src/visual_aggregation.py`.

### Why pagination could not finish the job

Every setting of the width budget only traded page count against page shape:
widest gave run 8 one page at 0.20, narrowest gave seven pages, and dividing
the credential fan put its convergence on two pages at once. The fan is not a
modelling error — the report names seven password-dumping tools, all reachable
once RDP access exists and none needing any other.

### What the literature does instead

Noel and Jajodia (VizSEC/DMSEC 2004) manage attack-graph complexity by
collapsing non-overlapping subgraphs to single vertices, under rules based on
"common attribute values" or "graph connectedness", so the reader moves from
overview to detail rather than sideways. Homer et al. (VizSec 2008) group
attacks for the same purpose. Segmentation — what `plan_causal_split` already
does — is the complementary technique, not a substitute.

The supervisor's reference graph does this by hand: `GREASE malware executed`
and `MECHANICAL malware executed` are single rectangles carrying several
technique identifiers.

### The rule, and where it runs

A set of events aggregates when it shares, mechanically:

- identical parents,
- identical tactic,
- at least one result state produced jointly by the whole set,

and is larger than a page could hold. That last clause matters: a fan that fits
is drawn exactly as the model returned it.

On run 8 it selects the seven Credential Access dumpers and correctly leaves
`e_keylog` out — different tactic, different parents.

It runs at **draw time only**. The extracted JSON keeps all 23 events with
their evidence, techniques and mitigations, and remains what every measurement
and audit reads. The aggregate carries the union of its members' techniques and
mitigations, its label states the rule that formed it rather than a summary
somebody wrote, and the legend lists all seven member labels plus the seven
folded result states verbatim. Only result states with a single producer inside
the group and no consumer at all are folded in; the shared state the group
exists to produce is left standing.

### Result

| | pages | worst aspect |
|---|---:|---:|
| run 8, pagination only | 5 | 0.25 |
| run 8, with aggregation | **3** | **0.60** |
| run 7 | 3 | 0.71 |
| WannaCry | 3 | 0.55 |

No API re-run was needed: this is a rendering change over the graph already
extracted.

### Why this is preferable to asking the model to abstract

The external review proposed a "causal episode" stage that would have the model
group actions before drawing. That adds a stage, roughly doubles the call
count against a cost guard that has already been hit, and can be got wrong —
run 7 answered a convergence request by inventing a parentless node. Render-time
aggregation is deterministic, auditable against the untouched JSON, and can be
turned off with one flag (`aggregate_wide_fans=False`).
