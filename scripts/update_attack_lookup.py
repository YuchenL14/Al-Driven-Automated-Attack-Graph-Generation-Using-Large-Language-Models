import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

# Official MITRE ATT&CK Enterprise STIX 2.1 bundle, most recent release.
STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/"
            "attack-stix-data/master/enterprise-attack/enterprise-attack.json")

OUT = Path(__file__).resolve().parent.parent / "data" / "attack_lookup.json"

PHASE_TO_ABBR = {
    "reconnaissance": "RE",
    "resource-development": "RS",
    "initial-access": "IA",
    "execution": "EX",
    "persistence": "PS",
    "privilege-escalation": "PE",
    "defense-evasion": "DE",
    "stealth": "DE",
    "defense-impairment": "DE",
    "credential-access": "CA",
    "discovery": "DS",
    "lateral-movement": "LM",
    "collection": "CL",
    "command-and-control": "C2",
    "exfiltration": "EF",
    "impact": "IM",
}


def tactics_of(obj: dict) -> list[str]:
    """Return the tactic abbreviations a technique belongs to, from STIX phases."""
    abbrs = []
    for kcp in obj.get("kill_chain_phases", []):
        if kcp.get("kill_chain_name") == "mitre-attack":
            abbr = PHASE_TO_ABBR.get(kcp.get("phase_name"))
            if abbr and abbr not in abbrs:
                abbrs.append(abbr)
    return abbrs


def collection_version(bundle: dict) -> str:

    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            if version:
                return str(version)
    return "unknown"


def attack_id(obj: dict) -> str | None:
    """Return the ATT&CK id (e.g. T1190, M1051) from a STIX object, if any."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def main() -> None:
    print(f"Downloading official ATT&CK STIX from:\n  {STIX_URL}")
    try:
        with urllib.request.urlopen(STIX_URL, timeout=180) as resp:
            bundle = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[error] could not download STIX data: {e}", file=sys.stderr)
        print("Check your internet connection and try again.", file=sys.stderr)
        raise SystemExit(1)

    techniques: dict[str, str] = {}
    technique_tactics: dict[str, list[str]] = {}
    mitigations: dict[str, str] = {}
    technique_stix_ids: dict[str, str] = {}
    mitigation_stix_ids: dict[str, str] = {}

    for obj in bundle.get("objects", []):
        # skip anything MITRE has retired
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        aid = attack_id(obj)
        if not aid:
            continue
        otype = obj.get("type")
        name = obj.get("name", "")
        if otype == "attack-pattern" and aid.startswith("T"):
            techniques[aid] = name
            technique_stix_ids[obj["id"]] = aid
            tac = tactics_of(obj)
            if tac:
                technique_tactics[aid] = tac
        elif otype == "course-of-action" and aid.startswith("M"):
            mitigations[aid] = name
            mitigation_stix_ids[obj["id"]] = aid

    if not techniques or not mitigations:
        print("[error] parsed no techniques or mitigations; aborting without "
              "overwriting the existing file.", file=sys.stderr)
        raise SystemExit(1)

    technique_mitigations: dict[str, list[str]] = {}
    for obj in bundle.get("objects", []):
        if (obj.get("type") != "relationship"
                or obj.get("relationship_type") != "mitigates"
                or obj.get("revoked")
                or obj.get("x_mitre_deprecated")):
            continue
        mid = mitigation_stix_ids.get(obj.get("source_ref", ""))
        tid = technique_stix_ids.get(obj.get("target_ref", ""))
        if mid and tid:
            related = technique_mitigations.setdefault(tid, [])
            if mid not in related:
                related.append(mid)

    out = {
        "_comment": ("Auto-generated from the official MITRE ATT&CK Enterprise "
                     "STIX data. Do not edit by hand; rerun "
                     "scripts/update_attack_lookup.py to refresh."),
        "_source": STIX_URL,
        "_attack_version": collection_version(bundle),
        "_retrieved": date.today().isoformat(),
        "techniques": dict(sorted(techniques.items())),
        # technique -> tactic abbreviations, added for tactic-scoped retrieval.
        "technique_tactics": dict(sorted(technique_tactics.items())),
        # technique -> officially related mitigations, derived from STIX
        # course-of-action --mitigates--> attack-pattern relationships.
        "technique_mitigations": {
            tid: sorted(mids)
            for tid, mids in sorted(technique_mitigations.items())
        },
        "mitigations": dict(sorted(mitigations.items())),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[ok] wrote {OUT}")
    print(f"     {len(techniques)} techniques (including sub-techniques)")
    print(f"     {len(technique_tactics)} with tactic mapping")
    print(f"     {len(technique_mitigations)} with mitigation mapping")
    print(f"     {len(mitigations)} mitigations")


if __name__ == "__main__":
    main()
