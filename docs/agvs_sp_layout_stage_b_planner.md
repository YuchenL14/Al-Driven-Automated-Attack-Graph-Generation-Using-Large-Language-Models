# AGVS-SP new layout — Stage B: branch-aware geometry planner

Date: 29 July 2026

## Outcome

Stage B adds `src/layout_planner.py`.  It consumes the reversible Visual IR
from Stage A and calculates deterministic layout geometry.  It does not draw a
PNG and is not yet connected to the professional or student web route.

This order keeps the existing application usable while the replacement layout
is tested independently.

## Macro-layout algorithm

### 1. Atomic blocks are the layout units

The planner never starts by positioning individual rectangles and ellipses.
It first positions the Stage-A atomic blocks:

`local/root inputs → event(s) → directly established result state(s)`

Alternative events that establish one shared result remain inside the same
block.  A later coordinate pass therefore cannot separate the alternatives
from their result.

### 2. Top-down causal ranks

The block DAG supplies the causal rank.  Within a block rank, repeated
downward/upward barycentric sweeps order parallel branches.  Variable-width
isotonic fitting gives every block a non-overlapping horizontal interval.

The constraints are:

- all canonical/display edges run from a higher node to a lower node;
- two blocks on the same causal rank do not overlap;
- sibling branches keep a stable left-to-right order;
- a merge block is pulled toward the median of its parent branches.

### 3. Main causal spine

One deterministic longest path is identified in each weakly connected block
component.  Those blocks are marked as the main trunk.  The planner gives the
trunk a light pull toward the page centre while retaining room for parallel
branches.

This is a visual organising device only.  It is not a new attack path and does
not change graph semantics.

### 4. Local block expansion

Each block is expanded into up to three local rows:

1. root/global state occurrences anchored to the event that consumes them;
2. action/event rectangles;
3. result/precondition ellipses.

Produced states remain in their producer block.  Display-only root proxies
remain in their consumer block.  This removes the source of the former
page-spanning root-condition lines.

### 5. Logic geometry

Multi-input logic is planned explicitly:

- AND: inputs meet one horizontal shared bus and one target port;
- OR: every input receives a separate target port and no shared bus.

Stage B records the bus and port coordinates.  The next stage will convert
them into obstacle-aware orthogonal paths.

## Stage-B output

`LayoutPlan` contains:

- page-independent graph width and height;
- block bounding boxes, causal ranks, lane indices and component indices;
- main-trunk membership;
- every node's position, dimensions, visual rank and atomic block;
- AND/OR input points, target ports and optional shared bus.

It remains linked to Stage A through visual and canonical IDs.

## Quantitative validation

New test module: `tests/test_layout_stage_b_planner.py`

The tests assert:

| Measure | Acceptance condition | Result |
|---|---|---|
| determinism | repeated planning produces equal immutable plans | pass |
| semantic mutation | source `AttackGraph` remains byte-equivalent | pass |
| causal direction | every display edge has `source.bottom < target.y` | pass |
| node collision | zero intersecting node rectangles | pass |
| lane separation | parallel same-rank blocks receive distinct lanes | pass |
| block collision | zero same-rank block overlaps | pass |
| merge placement | merge centre lies inside its parent-centre interval | pass |
| global input locality | every root occurrence shares its consumer block | pass |
| atomicity | alternative events and their result share one block | pass |
| AND syntax | one shared bus and one target port | pass |
| OR syntax | no shared bus and one distinct port per input | pass |
| page aspect | height/final-width ≤ 1.2 after the 420px legend area | pass |

## Maintained examples

All maintained JSON examples were accepted:

| Example | Events | Visual nodes | Blocks | Planned main area |
|---|---:|---:|---:|---:|
| `mock_extraction.json` | 3 | 7 | 3 | 828×914 |
| `phishing_extension.json` | 7 | 16 | 7 | 1100×1064 |
| `sample_ransomware.json` | 2 | 5 | 2 | 828×614 |

## Report-derived structural oracles

The existing British Library, WannaCry and M&S structural oracles were first
split using the lossless causal pagination layer and then planned:

| Oracle | Parts | Planned main areas |
|---|---:|---|
| British Library | 2 | 828×1214; 828×1064 |
| WannaCry | 2 | 828×1064; 828×1364 |
| M&S | 3 | 828×464; 828×1364; 828×764 |

With the independent 420px legend area, the maximum final height/width ratio
is `1364/1248 = 1.093`, below the project limit of `1.2`.

Complete automated result after Stage B: **130 tests passed**.

## What remains before replacing the old renderer

Stage C must:

1. convert planned edges and logic ports into local orthogonal routes;
2. reject paths that cross unrelated node or label boxes;
3. draw the new plan with the frozen Stolen Pencil colours, shapes and badges;
4. render the three report oracles and the Stolen Pencil gold structure;
5. compare edge direction, collision count, branch organisation and page
   dimensions against the acceptance thresholds.

The old renderer must remain connected until Stage C produces valid images.
After Stage C passes, the web route can switch to the new renderer, and the
obsolete layout/routing functions can then be deleted in one controlled step.

