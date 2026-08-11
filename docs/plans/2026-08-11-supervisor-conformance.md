# Supervisor conformance: badges, state codes, objective, CI

## Goal

The professional output conforms to the supervisor's reference figure and to
the configuration his own study found practitioners prefer, and that
conformance is checked automatically rather than asserted.

## What the evidence already settles

Read before planning, so the steps below do not repeat work already done.

**Shape and flow are already conformant, and now citable.** Lallie, Debattista
and Bal (2018), n=212, ran a choice-based conjoint analysis over 18 attack
graph configurations. The winning configuration for every participant group
was `tre` (u=8.042): event flow top-down, exploits as rectangles,
preconditions as ellipses. That is exactly AGVS-SP. The runner-up `ter`
(u=7.861) has the shapes reversed, and the paper records that the earlier
Lallie et al. study used `ter`, so this project uses the winner where the
supervisor's own prior work used the second choice. Attribute importance:
precondition 38.5%, event flow 32.6%, exploit 28.8%.

**Kill-chain badges are already implemented.** `visual_syntax.py` defines
`AGVS_SP_V1_KILL_CHAIN` and selects it from `AGVS_BADGE_SOURCE`. Verified by
rendering WannaCry run 4 under it: actions badge `D`, `C`, `E`, `A`, `I` and
the per-page legend switches to Delivery, Exploitation, Command and Control.
No renderer change is required.

**State codes are the real gap.** `Precondition.code` is a free-form `str`
with no vocabulary. Across the three final runs the model invented `PRE1`,
`PRE11`, `RESULT2`, `EXT-RES`, `VULN`, `NET`, `COND`, `SVCSTOP`, `ENC-EXEC`,
`XFER`, `LM1`. British Library run 8 happened to produce a consistent
`PRE`/`RES`/`ANN`, which shows the model can do it and also that nothing makes
it. This is the inconsistency Lallie (2020) criticises, on the attribute
practitioners weight most.

## Not in scope

- Changing shapes or flow. They already match the preferred configuration.
- Re-running the three final reports. The change is presentational and the
  canonical JSON is untouched, so existing runs re-render under it.
- The student edition's state codes, which have their own note already.

## Risks

- Deriving a badge the model used to supply changes every figure in the
  dissertation. Mitigated by leaving the canonical `code` in the JSON and
  overriding only in the presentation layer, which is the precedent
  `prohibited_state_badges` already set.
- Switching the badge namespace changes every figure too. Mitigated by making
  it an explicit, recorded choice rather than a default flip.

## Steps

### 1. Pin the badge namespace as a decision, not an environment variable

Files: `src/visual_syntax.py`, `tests/test_visual_syntax_contract.py`

Test first: assert `active_profile().badge_source` equals the value the
project has decided on, with no environment variable set. Fails now because
the default is `attack_tactic` and the decision is unrecorded.

Change: keep `AGVS_BADGE_SOURCE` as the override, and state in the module
docstring which namespace the dissertation's figures use and why. If the
supervisor wants the kill chain, change the default and record the reason
beside it.

Verify: `python -m unittest discover -s tests -p "test_visual_syntax_contract.py"`
Rollback: revert the constant.

### 2. Derive the state badge from the graph instead of asking for it

Files: `src/visual_syntax.py`, `tests/test_state_badge_namespace.py` (new)

Test first: build two graphs whose states carry different invented codes and
assert both render the same four-symbol vocabulary. Fails now.

Change: add `state_badge(role, has_parents) -> str` to `visual_syntax.py`,
returning one of exactly four values:

| condition | badge | meaning |
|---|---|---|
| `role == "annotation"` | `ANN` | commentary beside the attack |
| `role == "external_resource"` | `EXT` | something the adversary already held |
| `parents == []` | `PRE` | a condition that held before the attack |
| otherwise | `RES` | a state an action produced |

Every value is derivable from structure the schema already validates, so no
rule set has to remember it and no two graphs can disagree. The canonical
`Precondition.code` stays in the JSON for auditability, exactly as the
suppressed tactic badge does.

Verify: re-render the three final runs and confirm only `PRE`, `RES`, `EXT`,
`ANN` appear on ellipses.
Rollback: the presentation layer falls back to `node.code`.

### 3. Explain the state vocabulary in the per-page key

Files: `src/layout_renderer.py`, `tests/test_figure_legibility.py`

Test first: assert a page containing a produced state carries a key line
defining `RES`, and that a page with no external resource does not define
`EXT`. Fails now.

Change: extend `_syntax_key_lines` with the four state codes, listing only
those the page draws, matching the existing conditional-key rule.

Verify: `python -m unittest discover -s tests -p "test_figure_legibility.py"`
Rollback: revert the added lines.

### 4. Say why a graph has no named objective

Files: `src/layout_renderer.py`, `tests/test_figure_legibility.py`

Test first: assert that a graph whose terminal states tie carries a key line
saying so. Fails now, because `objective_label_for_page` returning `None`
prints nothing and a reader cannot tell an absent objective from a forgotten
one.

Change: when `attack_objective` returns `None`, add one key line naming the
tied terminal states, for example "No single objective: the attack ends in
three independent outcomes, listed at the foot of the figure." Do not invent
a winner. WannaCry run 4 is the case: plants shut down, C2 maintained and
shadow copies deleted all follow from the same encrypted state.

Verify: re-render WannaCry run 4 and read the key.
Rollback: revert the added line.

### 5. Run the checks on every push

Files: `.github/workflows/checks.yml` (new)

Test first: none. This step adds no behaviour, it runs behaviour that already
has tests.

Change: a workflow on `push` and `pull_request` that installs
`requirements.txt` on Python 3.12, runs `python -m compileall -q app.py
student_app.py src`, runs `python -m unittest discover -s tests`, and runs a
conformance script that re-renders every graph in `outputs/` and fails if any
page uses a state badge outside the four-symbol vocabulary, or if any run
fails a syntax check. No API key is needed: every check reads saved JSON or
uses the offline provider.

Verify: push the branch and read the Actions run.
Rollback: delete the workflow file.

## Order

Steps 1 to 4 are independent of step 5 and can land in any order. Step 3
depends on step 2, because the key cannot define a vocabulary that does not
exist yet.
