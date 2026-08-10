"""Render the maintained phishing-extension example through the real contract.

Run from the project root:
    python examples/sample_attack_graph.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import render  # noqa: E402
from schema import AttackGraph  # noqa: E402


def build() -> AttackGraph:
    return AttackGraph.from_json_file(HERE / "phishing_extension.json")


if __name__ == "__main__":
    graph = build()
    output = HERE / "output" / "sample_attack_graph.png"
    print(f"[ok] wrote {render(graph, str(output))}")
