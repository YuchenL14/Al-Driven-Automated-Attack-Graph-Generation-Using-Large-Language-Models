from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from schema import ATTACK_TACTICS, AttackGraph

_DATA = Path(__file__).resolve().parent.parent / "data" / "attack_lookup.json"


class AttackResolver:
    def __init__(self, data_path: Path = _DATA):
        raw = json.loads(Path(data_path).read_text(encoding="utf-8"))
        self._techniques: Dict[str, str] = raw.get("techniques", {})
        self._mitigations: Dict[str, str] = raw.get("mitigations", {})

    def resolve_technique(self, tid: str) -> str:
        return self._techniques.get(tid, "Unknown technique")

    def resolve_mitigation(self, mid: str) -> str:
        return self._mitigations.get(mid, "Unknown mitigation")

    @staticmethod
    def resolve_tactic(abbr: str) -> str:
        return ATTACK_TACTICS.get(abbr, "Unknown tactic")

    # ---- legend ------------------------------------------------------------
    def build_legend(self, graph: AttackGraph) -> Dict[str, Dict[str, str]]:
        """Collect every code used in the graph -> {code: name}, grouped."""
        tactics, techniques, mitigations = {}, {}, {}
        for e in graph.events:
            tactics[e.tactic] = self.resolve_tactic(e.tactic)
            for technique in e.techniques:
                techniques[technique] = self.resolve_technique(technique)
            for m in e.mitigations:
                mitigations[m] = self.resolve_mitigation(m)
        # sort for stable, readable output
        return {
            "Tactics": dict(sorted(tactics.items())),
            "Techniques": dict(sorted(techniques.items())),
            "Mitigations": dict(sorted(mitigations.items())),
        }
