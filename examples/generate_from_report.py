"""
generate_from_report.py -- the full pipeline end to end.

    report (PDF or text)
        -> Stage 2  ingest        clean text
        -> Stage 3  extract       validated AttackGraph (via a language model)
        -> Stage 4  render        attack graph PNG

Input reports live in the reports/ folder, generated graphs are written to the
outputs/ folder, and each graph is named after its report (for example
Case-Study_WannaCry.pdf produces outputs/Case-Study_WannaCry.png), so a new run
never overwrites the graph from a different report.

Usage:
    python examples/generate_from_report.py <report> [provider] [model]

    <report> may be a bare file name found in reports/, or a full path.
    provider is one of: mock | ollama | anthropic
    model (optional) overrides the default for that provider.
    add the word "compact" anywhere to produce a shorter graph.
    add the word "split" to paginate a long graph at causal state boundaries.

Examples:
    python examples/generate_from_report.py Case-Study_WannaCry.pdf anthropic claude-sonnet-5
    python examples/generate_from_report.py reports/my_incident.pdf ollama qwen3:8b
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ingest import ingest                     # noqa: E402
from extract import (DEFAULT_RULESET, extract_attack_graph,  # noqa: E402
                     get_last_api_usage, resolve_model)
from attack_graph import render, render_split, tagged_output_path # noqa: E402

REPORTS_DIR = ROOT / "reports"
OUTPUTS_DIR = ROOT / "outputs"


def resolve_report(arg: str) -> Path:
    """Accept a full path or a bare name looked up in reports/."""
    p = Path(arg)
    if p.is_file():
        return p
    candidate = REPORTS_DIR / arg
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(
        f"report not found: '{arg}'. Put the PDF in the reports/ folder, "
        f"or give a full path."
    )


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    args = sys.argv[1:]
    compact = "compact" in args
    split = "split" in args
    # a "rules=vX" token selects the rule set version; default is the built-in one
    ruleset = next((a.split("=", 1)[1] for a in args if a.startswith("rules=")),
                   DEFAULT_RULESET)
    args = [a for a in args
            if a not in ("compact", "split") and not a.startswith("rules=")]
    report = resolve_report(args[0])
    provider = args[1] if len(args) > 1 else "mock"
    model = args[2] if len(args) > 2 else None
    effective_model = resolve_model(provider, model)

    OUTPUTS_DIR.mkdir(exist_ok=True)
    # fold the rule set version into the name so iterations do not overwrite
    stem = f"{report.stem}__rules-{ruleset}"
    filename_model = None if provider == "mock" else effective_model
    out_path = tagged_output_path(
        OUTPUTS_DIR, stem, provider, filename_model)

    print(f"[1/3] ingesting {report.name} ...")
    text = ingest(report)
    print(f"      {len(text)} characters of clean text")

    label = f"{provider} ({effective_model}), rules {ruleset}"
    print(f"[2/3] extracting attack graph with '{label}' ...")
    graph = extract_attack_graph(text, provider=provider, model=effective_model,
                                 ruleset=ruleset)
    print(f"      {len(graph.preconditions)} preconditions, {len(graph.events)} events")

    print("[3/3] rendering ...")
    if split:
        outs = render_split(graph, str(out_path), dpi=170, compact=compact)
        for o in outs:
            print(f"[done] {o}")
    else:
        out = render(graph, str(out_path), dpi=170, compact=compact)
        print(f"[done] {out}")
    if ruleset.startswith("v1.5"):
        audit_path = out_path.with_suffix(".json")
        audit_path.write_text(graph.model_dump_json(indent=2), encoding="utf-8")
        print(f"[audit] {audit_path}")
    usage = get_last_api_usage()
    if usage and usage["calls"]:
        print(
            f"[cost] {usage['calls']} call(s), {usage['input_tokens']} input, "
            f"{usage['output_tokens']} output, conservative US$"
            f"{usage['estimated_cost_usd']:.4f} / US${usage['limit_usd']:.2f}")


if __name__ == "__main__":
    main()
