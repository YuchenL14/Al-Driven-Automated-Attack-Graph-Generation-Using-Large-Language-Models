from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import render_split  # noqa: E402
from schema import AttackGraph  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Re-render a saved attack graph as a figure.")
    parser.add_argument(
        "graph_json",
        help="a validated graph saved by a previous run, e.g. outputs/x.json")
    parser.add_argument(
        "--format", default="svg", choices=("svg", "png"),
        help="svg keeps the figure vector for LaTeX (default)")
    parser.add_argument(
        "--dpi", type=int, default=300,
        help="raster resolution, used by --format png only")
    parser.add_argument(
        "--out-dir", default=None,
        help="destination directory (default: alongside the source JSON)")
    args = parser.parse_args()

    source = Path(args.graph_json)
    if not source.is_file():
        raise SystemExit(f"[error] no such file: {source}")
    if source.name.endswith((
            ".layout-quality.json",
            ".reproducibility.json",
            ".semantic.json",
    )):
        raise SystemExit(
            "[error] that is a run sidecar, not a graph. "
            "Pass the run's graph JSON instead.")

    graph = AttackGraph.from_json_file(source)
    out_dir = Path(args.out_dir) if args.out_dir else source.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{source.stem}.{args.format}"

    paths = render_split(graph, str(target), fmt=args.format, dpi=args.dpi)
    print(f"[ok] {graph.title}")
    print(f"     {len(graph.preconditions)} preconditions, "
          f"{len(graph.events)} events")
    for path in paths:
        print(f"     wrote {path}")


if __name__ == "__main__":
    main()
