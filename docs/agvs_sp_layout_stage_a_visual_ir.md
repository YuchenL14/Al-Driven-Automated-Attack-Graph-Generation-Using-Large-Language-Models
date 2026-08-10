# AGVS-SP new layout — Stage A: reversible Visual IR

Date: 28 July 2026

## Outcome

Stage A introduces a renderer-independent Visual Intermediate Representation
(`src/layout_ir.py`).  It is a presentation layer only.  It does not alter the
professional v1.4 extraction pipeline, the report interpretation, ATT&CK
selection, mitigations, scores, labels, or canonical causal relationships.

The current renderer remains connected to the application during Stage A.
Removing it before a replacement renderer exists would leave both applications
unable to produce figures.  It will be removed only after the new renderer:

1. consumes the Visual IR;
2. passes topology round-trip validation;
3. passes the complete regression suite;
4. passes visual acceptance tests on British Library, WannaCry, M&S and the
   Stolen Pencil gold standard.

This is a controlled replacement, not a permanent second rendering system.

## Recovery point

The pre-Stage-A project was archived at:

`backups/python_project_before_layout_stage_a_20260728_235549.zip`

Archive SHA-256:

`9E3E464B2AA929CF88E681909972C9EED42CCF9B373688C728DA217C4C29DEE3`

The archive contains 121 project entries and was opened and checked for the
application, renderer, visual syntax, frozen v1.4 rules and a report.

## Frozen semantic boundary

The following files still match the pre-Stage-A archive byte for byte:

| File | SHA-256 |
|---|---|
| `rules/ruleset_v1.4.md` | `13D357E40A95516CBB63B1D4CCD0D93018E9BB2EC5D5D3D20F30F4DCF785CC2A` |
| `src/schema.py` | `B9FF2697A54EA96085E7FC077E761C2D3DC6A52A04CC639F38EE6B1598D3487D` |
| `src/extract.py` | `72E3D3AD6DF7F83D6697FA7503B390221C4D4C283FCD48578C506BDFB3978559` |
| `data/attack_lookup.json` | `DA15522CCE11C057487762E06E9E64B67E97914A198053CA246B25A1C480DDC9` |

Therefore Stage A cannot change what attack the model detects or which T/M
identifiers the validated graph contains.

## Visual IR contract

### Canonical topology

The IR stores the ordered canonical node IDs and all alternating causal edges:

- state → event for an event requirement;
- event → state for a result established by an event.

Every displayed edge carries its original source and target canonical IDs.
Collapsing display copies must recover the exact original node and edge tuples.
The builder validates this before returning an IR.

### Atomic event/result blocks

Each event is assigned to exactly one atomic block.  States directly produced
by the event are attached to that block.  When several events are alternative
producers of one state, union-find places all producers and the shared state in
one block.  This prevents a later layout or page cut from separating:

`alternative event(s) → shared result state`

Blocks also record external input states, upstream/downstream blocks and a
causal rank.  These fields will drive the new branch-aware layout.

### Display-only state proxies

A root/global condition may feed several events at very different depths.  A
single drawing of that state forces an undesirable page-spanning wire.

Stage A keeps the first occurrence as the canonical visual node and creates a
local state proxy for each additional consumer.  A proxy:

- is always an ellipse/state;
- has the same label and badge projection as the source state;
- has no new canonical identity;
- maps back through `canonical_id`;
- replaces exactly one display edge rather than adding a causal edge.

A root used only once is anchored to its consumer without being duplicated.
Only root conditions are eligible in Stage A; produced states are not copied.

### Explicit logic convergence

Every target with two or more inputs receives a `LogicGroup`:

- input order is copied exactly from the canonical parents;
- an event keeps its canonical `AND` or `OR`;
- a result state with alternative producer events remains `OR`;
- visual input IDs can refer to local proxies, while canonical parent IDs
  remain unchanged.

The next renderer can therefore draw an AND shared bus or separate OR arrows
without trying to rediscover logic from coordinates.

## Verification

New test module: `tests/test_layout_stage_a_ir.py`

It verifies:

1. exact topology round trip;
2. deterministic, side-effect-free projection;
3. display proxy identity and edge mapping;
4. late single-use root anchoring;
5. alternative producer/result atomicity;
6. AND/OR preservation and input order;
7. T/M/score and state-badge preservation;
8. rejection of a damaged IR with a missing edge.

The maintained `examples/sample_ransomware.json` was also projected:

- 5 canonical nodes;
- 5 visual nodes;
- 4 canonical/display edges;
- 1 multi-input logic group;
- 2 atomic blocks;
- exact topology round trip: true.

Complete automated result after Stage A: **120 tests passed**.

## What is intentionally not done yet

Stage A does not change the PNG currently shown in the web application.  It
prepares a safe and testable input for the replacement renderer.

The next layout stage will calculate branch lanes and ranks from atomic blocks,
then route only local orthogonal connectors.  Only after that renderer passes
semantic and visual acceptance will the legacy coordinate/layout functions be
disconnected and deleted.

