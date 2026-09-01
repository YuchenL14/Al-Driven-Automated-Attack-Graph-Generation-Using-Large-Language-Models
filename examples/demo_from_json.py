"""
demo_from_json.py -- Route 1 of Approach C in action.

Loads a canonical JSON file, validates it against the schema, and renders the
attack graph. This is the exact same code path an LLM-produced JSON will use
later; only the *source* of the JSON changes.

Run from the project root:
    python examples/demo_from_json.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from schema import AttackGraph          # noqa: E402
from attack_graph import render         # noqa: E402

HERE = Path(__file__).resolve().parent


def main() -> None:
    model = AttackGraph.from_json_file(HERE / "sample_ransomware.json")
    out = render(model, str(HERE / "demo_from_json.png"))
    print(f"[ok] {model.title}: {len(model.preconditions)} preconditions, "
          f"{len(model.events)} events -> {out}")


if __name__ == "__main__":
    main()
