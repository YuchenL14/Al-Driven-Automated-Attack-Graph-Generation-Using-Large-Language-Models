"""Build a PNG from a dictionary using the canonical AttackGraph contract.

Run from the project root:
    python examples/build_from_json.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import render  # noqa: E402
from schema import AttackGraph  # noqa: E402


def render_from_model(model: AttackGraph, out_path: str | Path) -> str:
    return render(model, str(out_path))


def render_from_json(data: dict, out_path: str | Path) -> str:
    return render_from_model(AttackGraph.model_validate(data), out_path)


if __name__ == "__main__":
    demo = {
        "title": "demo_from_json",
        "preconditions": [
            {"id": "p_vpn", "label": "Unpatched internet-facing VPN",
             "code": "RS", "parents": []},
            {"id": "p_access", "label": "Initial VPN access obtained",
             "code": "IA", "parents": ["e_access"]},
        ],
        "events": [
            {"id": "e_access", "label": "Exploit VPN for initial access",
             "tactic": "IA", "technique": "T1190",
             "mitigations": ["M1051"], "likelihood": 6.0,
             "parents": ["p_vpn"], "join": "AND"},
            {"id": "e_encrypt", "label": "Encrypt systems for impact",
             "tactic": "IM", "technique": "T1486",
             "mitigations": ["M1040"], "likelihood": 5.0,
             "parents": ["p_access"], "join": "AND"},
        ],
    }
    output = ROOT / "examples" / "output" / "build_from_json.png"
    written = render_from_json(demo, output)
    print(f"[ok] wrote {written}")
