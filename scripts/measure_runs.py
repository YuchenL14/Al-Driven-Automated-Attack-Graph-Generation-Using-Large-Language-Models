from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import networkx as nx

from causal_split import (materialize_split_part, plan_causal_split,
                          validate_lossless_split, widest_page_width_px)
from extract import (_annotation_problems, _mixed_join_problems,
                     measure_skeleton_shape, shape_revision_request)
from layout_ir import build_layout_ir
from layout_planner import plan_layout
from layout_renderer import (FIGURE_PLACEMENT_WIDTH_PT, MIN_PRINTED_LABEL_PT,
                             NODE_FONT_PX)
from layout_router import route_layout, validate_routed_layout
from schema import ATTACK_TACTICS, AttackGraph
from visual_aggregation import aggregate_for_drawing
from visual_syntax import active_profile, project_visual_nodes

GOLD = ROOT / "tests" / "fixtures" / "stolen_pencil_gold.json"


# --------------------------------------------------------------------------
# structure
# --------------------------------------------------------------------------
@dataclass
class Structure:
    events: int
    states: int
    annotations: int
    external_resources: int
    dotted: int
    unused_states: int
    terminals: int
    critical_path_share: float
    ranks: int
    widest: int
    convergence: float
    convergence_label: str
    review_would_fire: bool
    mixed_join: int
    annotation_faults: int
    max_techniques: int


def _causal_graph(data: dict) -> nx.DiGraph:
    """Annotations excluded: they are commentary, not part of the path."""

    nodes = (data.get("events") or []) + [
        node for node in (data.get("preconditions") or [])
        if node.get("role") != "annotation"
    ]
    graph = nx.DiGraph()
    graph.add_nodes_from(node["id"] for node in nodes)
    for node in nodes:
        for parent in node.get("parents") or []:
            if parent in graph:
                graph.add_edge(parent, node["id"])
    return graph


def measure_structure(data: dict) -> Structure:
    shape = measure_skeleton_shape(data)
    graph = _causal_graph(data)
    events = [e["id"] for e in data.get("events") or []]
    terminals = [n for n in graph if graph.out_degree(n) == 0]

    def reached(target: str) -> int:
        return sum(1 for e in events
                   if e in graph and nx.has_path(graph, e, target))

    best, best_count = "", 0
    if terminals and events:
        best = max(terminals, key=reached)
        best_count = reached(best)
    labels = {p["id"]: p["label"] for p in data.get("preconditions") or []}
    labels.update({e["id"]: e["label"] for e in data.get("events") or []})

    roles = [p.get("role") for p in data.get("preconditions") or []]
    styles = [n.get("style") for n in
              (data.get("events") or []) + (data.get("preconditions") or [])]
    return Structure(
        events=len(events),
        states=sum(1 for r in roles if r != "annotation"),
        annotations=sum(1 for r in roles if r == "annotation"),
        external_resources=sum(1 for r in roles if r == "external_resource"),
        dotted=sum(1 for s in styles if s == "dotted"),
        unused_states=shape["unused_states"],
        terminals=len(terminals),
        critical_path_share=shape["critical_path_share"],
        ranks=shape["ranks"],
        widest=shape["widest"],
        convergence=best_count / len(events) if events else 0.0,
        convergence_label=labels.get(best, best),
        review_would_fire=bool(shape_revision_request(shape)),
        mixed_join=len(_mixed_join_problems(data)),
        annotation_faults=len(_annotation_problems(data)),
        # Reported, never failed on. A graph whose every action maps to one
        # technique is not violating anything; Rule 7 decides how many, and
        # the answer depends on the report.
        max_techniques=max((len(e.get("techniques") or [])
                            for e in data.get("events") or []), default=0),
    )


# --------------------------------------------------------------------------
# visual syntax
# --------------------------------------------------------------------------
PROFESSIONAL_ONLY_CHECKS = ("every action has a technique",)

SYNTAX_CHECKS = (
    "actions are rectangles",
    "states are ellipses",
    "annotations are dashed",
    "annotations are not consumed",
    "no ATT&CK tactic on a state",
    "every edge runs downward",
    "AND drawn as a shared bus",
    "OR drawn as separate edges",
    "every action has a technique",
    "pagination loses nothing",
    "no connector crosses a node",
)


def checks_for(student: bool) -> tuple[str, ...]:
    """Which checks apply, named rather than subtracted at the call site."""

    if not student:
        return SYNTAX_CHECKS
    return tuple(check for check in SYNTAX_CHECKS
                 if check not in PROFESSIONAL_ONLY_CHECKS)


def check_syntax(model: AttackGraph) -> dict[str, bool]:
    """The supervisor's reference contract, checked rather than assumed."""

    profile = active_profile()
    semantics = project_visual_nodes(model)
    annotations = {s.id for s in semantics if s.role == "annotation"}
    result = {
        "actions are rectangles": all(
            s.shape == profile.event_shape
            for s in semantics if s.kind == "event"),
        "states are ellipses": all(
            s.shape == profile.state_shape for s in semantics
            if s.kind != "event" and s.role != "annotation"),
        "annotations are dashed": all(
            s.style == "dashed" for s in semantics if s.role == "annotation"),
        "annotations are not consumed": not any(
            set(e.parents) & annotations for e in model.events),
        "no ATT&CK tactic on a state": all(
            s.badge_code not in ATTACK_TACTICS
            for s in semantics if s.kind != "event"),
        "every action has a technique": all(
            len(e.techniques) >= 1 for e in model.events),
    }

    drawn, _ = aggregate_for_drawing(model)
    plan = plan_causal_split(drawn)
    try:
        validate_lossless_split(drawn, plan)
        result["pagination loses nothing"] = True
    except (ValueError, KeyError):
        result["pagination loses nothing"] = False

    downward = clear = shared_bus = separate = True
    for part in plan.parts:
        page = materialize_split_part(drawn, part, len(plan.parts))
        layout_ir = build_layout_ir(page)
        planned = plan_layout(layout_ir)
        routed = route_layout(layout_ir, planned)
        for connector in routed.connectors:
            if (connector.logic == "AND"
                    and len(connector.input_visual_ids) > 1
                    and connector.shared_bus is None):
                shared_bus = False
            if connector.logic == "OR" and connector.shared_bus is not None:
                separate = False
            for path in connector.input_paths:
                for start, end in zip(path, path[1:]):
                    if end[1] < start[1]:
                        downward = False
        if validate_routed_layout(layout_ir, planned, routed):
            clear = False
    result["every edge runs downward"] = downward
    result["AND drawn as a shared bus"] = shared_bus
    result["OR drawn as separate edges"] = separate
    result["no connector crosses a node"] = clear
    return result


# --------------------------------------------------------------------------
# layout
# --------------------------------------------------------------------------
@dataclass
class Layout:
    pages: int | None = None
    worst_aspect: float | None = None
    warnings: int | None = None
    bends: int | None = None
    widest_page_px: int | None = None
    printed_label_pt: float | None = None


def read_layout(path: Path, model: AttackGraph | None = None) -> Layout:

    report = path.with_suffix("").with_suffix(".layout-quality.json")
    if not report.is_file():
        report = path.parent / f"{path.stem}.layout-quality.json"
    width = None
    if model is not None:
        drawn, _ = aggregate_for_drawing(model)
        width = widest_page_width_px(drawn, plan_causal_split(drawn))
    printed = (NODE_FONT_PX * FIGURE_PLACEMENT_WIDTH_PT / width
               if width else None)
    if not report.is_file():
        return Layout(widest_page_px=width, printed_label_pt=printed)
    data = json.loads(report.read_text(encoding="utf-8"))
    pages = data.get("pages") or []
    return Layout(
        pages=data.get("page_count"),
        worst_aspect=min((p["page_aspect_ratio"] for p in pages), default=None),
        warnings=data.get("warning_count"),
        bends=sum(p.get("bend_count", 0) for p in pages),
        widest_page_px=width,
        printed_label_pt=printed,
    )


# --------------------------------------------------------------------------
# gold comparison
# --------------------------------------------------------------------------
@dataclass
class GoldScore:
    rule: str
    precision: float
    recall: float
    f1: float
    only_ours: tuple[str, ...] = field(default_factory=tuple)
    only_gold: tuple[str, ...] = field(default_factory=tuple)


def _parent_technique(identifier: str) -> str:
    return identifier.split(".")[0]


def score_against_gold(model: AttackGraph, gold_path: Path) -> list[GoldScore]:

    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold_ids = {t for node in gold["nodes"] for t in node.get("techniques") or []}
    ours = {t for event in model.events for t in event.techniques}

    scores = []
    for rule in ("strict", "parent"):
        if rule == "strict":
            left, right = set(ours), set(gold_ids)
        else:
            left = {_parent_technique(t) for t in ours}
            right = {_parent_technique(t) for t in gold_ids}
        hit = len(left & right)
        precision = hit / len(left) if left else 0.0
        recall = hit / len(right) if right else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if precision + recall else 0.0)
        scores.append(GoldScore(
            rule=rule, precision=precision, recall=recall, f1=f1,
            only_ours=tuple(sorted(left - right)),
            only_gold=tuple(sorted(right - left)),
        ))
    return scores


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------
def _short_name(path: Path) -> str:
    """Report and run number, which is what distinguishes two runs."""

    stem = path.stem
    report, _, tail = stem.partition("__")
    run = tail.rsplit("_", 1)[-1] if "_" in tail else ""
    return f"{report[:11]}#{run}" if run else report[:14]


def _row(name: str, values: list[str], width: int = 30) -> str:
    return f"{name:{width}}" + "".join(f"{v:>16}" for v in values)


def report(paths: list[Path], markdown: bool, gold: Path | None,
           student: bool = False) -> int:
    graphs = []
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        graphs.append((path, data, AttackGraph.model_validate(data)))
    if not graphs:
        print("no graphs given", file=sys.stderr)
        return 1

    names = [_short_name(p) for p, _, _ in graphs]
    structures = [measure_structure(d) for _, d, _ in graphs]
    syntaxes = [check_syntax(m) for _, _, m in graphs]
    layouts = [read_layout(p, m) for p, _, m in graphs]

    def emit(title: str, rows: list[tuple[str, list[str]]]) -> None:
        if markdown:
            print(f"\n### {title}\n")
            print("| metric | " + " | ".join(names) + " |")
            print("|---|" + "---|" * len(names))
            for label, values in rows:
                print(f"| {label} | " + " | ".join(values) + " |")
        else:
            print(f"\n{title}")
            print(_row("", names))
            for label, values in rows:
                print(_row(label, values))

    emit("Structure", [
        ("actions", [str(s.events) for s in structures]),
        ("states", [str(s.states) for s in structures]),
        ("annotations", [str(s.annotations) for s in structures]),
        ("external resources", [str(s.external_resources) for s in structures]),
        ("dotted nodes", [str(s.dotted) for s in structures]),
        ("states nothing consumes", [str(s.unused_states) for s in structures]),
        ("terminals", [str(s.terminals) for s in structures]),
        ("longest-path share",
         [f"{s.critical_path_share:.0%}" for s in structures]),
        ("reaches one ending", [f"{s.convergence:.0%}" for s in structures]),
        ("ranks", [str(s.ranks) for s in structures]),
        ("widest rank", [str(s.widest) for s in structures]),
        ("shape review would fire",
         ["yes" if s.review_would_fire else "no" for s in structures]),
        ("most techniques on one action",
         [str(s.max_techniques) for s in structures]),
        ("mixed-join faults", [str(s.mixed_join) for s in structures]),
        ("annotation faults", [str(s.annotation_faults) for s in structures]),
    ])

    applicable = checks_for(student)
    emit("Visual syntax", [
        (check, ["OK" if s.get(check) else "FAIL" for s in syntaxes])
        for check in applicable
    ])
    if student:
        abstained = [
            str(sum(1 for e in data.get("events") or []
                    if not (e.get("techniques") or [])))
            for _, data, _ in graphs
        ]
        emit("Teaching contract", [
            ("actions with no technique (abstention)", abstained),
        ])

    emit("Layout", [
        ("pages", [str(x.pages if x.pages is not None else "-")
                   for x in layouts]),
        ("worst page aspect",
         [f"{x.worst_aspect:.2f}" if x.worst_aspect is not None else "-"
          for x in layouts]),
        ("layout warnings", [str(x.warnings if x.warnings is not None else "-")
                             for x in layouts]),
        ("bends", [str(x.bends if x.bends is not None else "-")
                   for x in layouts]),
        # Whether the figure can be used, as opposed to whether it is correct.
        ("widest page px",
         [str(x.widest_page_px) if x.widest_page_px else "-"
          for x in layouts]),
        (f"label pt across {FIGURE_PLACEMENT_WIDTH_PT / 72 * 25.4:.0f}mm "
         f"(floor {MIN_PRINTED_LABEL_PT:.0f})",
         [f"{x.printed_label_pt:.1f}" if x.printed_label_pt else "-"
          for x in layouts]),
    ])

    failed = sum(1 for s in syntaxes for c in applicable
                 if not s.get(c))
    print(f"\n{len(graphs)} graph(s); {failed} syntax check(s) failed.")

    if gold is not None:
        print("\nTechnique agreement with the supervisor's reference figure.")
        print("This is agreement with one expert's abstraction, not accuracy:")
        print("the reference omits whole branches the reports do describe, so")
        print("techniques read from those branches lower precision without")
        print("being wrong. Quote it with that caveat or not at all.")
        for (path, _, model) in graphs:
            print(f"\n  {path.stem}")
            for score in score_against_gold(model, gold):
                print(f"    {score.rule:8} P={score.precision:.2f} "
                      f"R={score.recall:.2f} F1={score.f1:.2f}")
                if score.only_gold:
                    print(f"      in reference only: "
                          f"{', '.join(score.only_gold)}")
                if score.only_ours:
                    print(f"      in this graph only: "
                          f"{', '.join(score.only_ours)}")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    description = (__doc__ or "Measure generated attack-graph runs.")
    parser = argparse.ArgumentParser(description=description.splitlines()[0])
    parser.add_argument("graphs", nargs="+", type=Path)
    parser.add_argument("--student", action="store_true",
                        help="measure against the teaching contract, which "
                             "permits an action to abstain from a technique")
    parser.add_argument("--markdown", action="store_true",
                        help="emit tables ready to paste into the write-up")
    parser.add_argument("--gold", nargs="?", const=GOLD, type=Path,
                        default=None,
                        help="compare techniques with the reference figure")
    args = parser.parse_args(argv)
    sidecar_suffixes = (
        ".layout-quality.json",
        ".reproducibility.json",
        ".semantic.json",
    )
    existing = [
        p for p in args.graphs
        if p.is_file() and not p.name.endswith(sidecar_suffixes)
    ]
    return report(existing, args.markdown, args.gold, args.student)


if __name__ == "__main__":
    raise SystemExit(main())
