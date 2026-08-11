"""Re-render every saved graph and fail if any figure breaks the visual syntax.

Run by CI on every push. It buys nothing that the unit tests do not already
assert about the code; what it adds is the same assertions made against every
graph the project has actually produced, which is where a rule set change or a
renderer change shows up first.

No API key and no network: every graph is read from ``outputs/`` and drawn by
the local renderer.
"""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from causal_split import materialize_split_part, plan_causal_split  # noqa: E402
from layout_ir import build_layout_ir  # noqa: E402
from layout_planner import plan_layout  # noqa: E402
from layout_quality import (LEGEND_RESERVE_WIDTH,  # noqa: E402
                            printed_label_pt_for_width)
from schema import ATTACK_TACTICS, AttackGraph, KILL_CHAIN_PHASES  # noqa: E402
from visual_aggregation import aggregate_for_drawing  # noqa: E402
from visual_syntax import STATE_BADGES, project_visual_nodes  # noqa: E402

from measure_runs import check_syntax, checks_for  # noqa: E402

ACTION_VOCABULARY = frozenset(ATTACK_TACTICS) | frozenset(KILL_CHAIN_PHASES)

# Saved runs already known not to conform, and why. Listed rather than deleted:
# a nonconformant run is a measurement the dissertation reports, and removing
# it to keep a build green would be removing the evidence. Listing it keeps the
# check useful, because anything not on this list is a new regression.
#
# Each entry must name the run and the check it fails, so a run that starts
# failing a *different* check is still caught.
KNOWN_NONCONFORMANT: dict[str, set[str]] = {
    "netscout-stolen-pencil__rules-v1.6__anthropic-claude-sonnet-5_4":
        {"every action has a technique"},
}


def graphs() -> list[tuple[str, AttackGraph]]:
    found = []
    for name in sorted(glob.glob(str(ROOT / "outputs" / "*.json"))):
        if name.endswith((".layout-quality.json", ".semantic.json")):
            continue
        try:
            data = json.loads(Path(name).read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict) or "events" not in data:
            continue
        found.append((Path(name).stem, AttackGraph.model_validate(data)))
    return found


def main() -> int:
    failures: list[str] = []
    known: list[str] = []
    pages_checked = 0
    saved = graphs()
    if not saved:
        print("no saved graphs to check")
        return 0

    for stem, model in saved:
        student = "student" in stem

        result = check_syntax(model)
        allowed = KNOWN_NONCONFORMANT.get(stem, set())
        for name in checks_for(student):
            if result[name]:
                continue
            if name in allowed:
                known.append(f"{stem}: {name}")
                continue
            failures.append(f"{stem}: syntax check failed: {name}")

        # Every ellipse badge must come from the closed state vocabulary, and
        # none may borrow a symbol that means something else on a rectangle.
        for node in project_visual_nodes(model):
            if node.kind not in {"state", "annotation"}:
                continue
            if node.badge_code is None:
                continue
            if node.badge_code not in STATE_BADGES:
                failures.append(
                    f"{stem}: state {node.id} badges {node.badge_code!r}, "
                    f"outside {sorted(STATE_BADGES)}")
            if node.badge_code in ACTION_VOCABULARY:
                failures.append(
                    f"{stem}: state {node.id} badges {node.badge_code!r}, "
                    "which belongs to the action vocabulary")

        # Every page must still plan and route, and its printed size is
        # reported so a regression in width is visible in the log.
        drawn, _ = aggregate_for_drawing(model)
        plan = plan_causal_split(drawn)
        for part in plan.parts:
            page = materialize_split_part(drawn, part, len(plan.parts))
            try:
                laid = plan_layout(build_layout_ir(page))
            except Exception as error:                    # noqa: BLE001
                failures.append(
                    f"{stem} page {part.index}: layout failed: {error}")
                continue
            pages_checked += 1
            width = laid.width + LEGEND_RESERVE_WIDTH
            print(f"  {stem[:52]:52s} page {part.index}/{len(plan.parts)}  "
                  f"{width:>5}px  {printed_label_pt_for_width(width):>5.1f}pt")

    print(f"\n{len(saved)} graphs, {pages_checked} pages checked")
    if known:
        print(f"\n{len(known)} known nonconformant run(s), recorded not hidden:")
        for line in known:
            print(f"  {line}")
    if failures:
        print(f"\n{len(failures)} NEW conformance failure(s):")
        for line in failures:
            print(f"  {line}")
        return 1
    print("no new nonconformance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
