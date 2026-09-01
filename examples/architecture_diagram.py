"""
Architecture diagram for the attack-graph generation tool (vertical layout).

Five numbered stages, matching the Design chapter exactly:
  1. Input  2. Ingestion  3. Extraction  4. Graph generation  5. Output

Conventions for the thesis figure:
  * concept names only, no library names (implementation detail lives in text)
  * solid border + thicker  = implemented in the current phase
  * dashed border           = designed, next phase
Run:  python examples/architecture_diagram.py
"""
from pathlib import Path
from graphviz import Digraph

ACCENT    = "#33415e"
STAGE     = "#eef2f6"
AISTAGE   = "#e7e0f3"
DATASTORE = "#fff6e6"
OUT       = "#e9f7f2"
TEXT      = "#1a1a2e"

g = Digraph("architecture", format="png")
g.attr(rankdir="TB", splines="spline", nodesep="0.55", ranksep="0.55",
       dpi="200", bgcolor="white", fontname="Helvetica")
g.attr("node", fontname="Helvetica", fontsize="11", color=ACCENT,
       penwidth="1.4", style="filled", fontcolor=TEXT)
g.attr("edge", color=ACCENT, penwidth="1.4", arrowsize="0.9")

g.node("pdf", "1. Input\ncyber attack report (PDF or text)\ne.g. WannaCry, British Library, NI HSE",
       shape="folder", fillcolor=STAGE)

g.node("ingest", "2. Ingestion\ndocument parsing\nPDF to clean text",
       shape="box", style="filled,rounded,dashed", fillcolor=STAGE)

g.node("llm", "3. Extraction\nlanguage model with retrieval grounding\nidentifies preconditions, events,\nATT&CK techniques (T), mitigations (M),\nlikelihood, tactic",
       shape="box", style="filled,rounded,dashed", fillcolor=AISTAGE, penwidth="1.6")
g.node("kb", "ATT&CK and NVD\nknowledge bases (offline)", shape="cylinder", fillcolor=DATASTORE)

g.node("json", "Validated JSON contract\n(single data model,\nshared by all input routes)",
       shape="box", style="filled,rounded", fillcolor=STAGE, penwidth="2.0")
g.node("render", "4. Graph generation\nstructure validated as acyclic,\nrendered in the target visual syntax\nellipse = precondition, rectangle = event",
       shape="box", style="filled,rounded", fillcolor=STAGE, penwidth="2.0")

g.node("out", "5. Output\nattack graph (PNG or PDF)\nwith auto-generated legend",
       shape="note", fillcolor=OUT)
g.node("alt", "Alternative output:\nMITRE attack model", shape="note",
       style="filled,dashed", fillcolor=OUT)

with g.subgraph() as s:
    s.attr(rank="same")
    s.node("kb")
    s.node("llm")

with g.subgraph() as s2:
    s2.attr(rank="same")
    s2.node("out")
    s2.node("alt")

g.edge("pdf", "ingest")
g.edge("ingest", "llm")
g.edge("kb", "llm", style="dashed", label="ground", fontname="Helvetica",
       fontsize="10", constraint="false")
g.edge("llm", "json")
g.edge("json", "render")
g.edge("render", "out")
g.edge("render", "alt", style="dashed")

out_dir = Path(__file__).resolve().parent / "output"
out_dir.mkdir(exist_ok=True)
path = g.render(filename="architecture_diagram", directory=str(out_dir), cleanup=True)
print(f"[ok] wrote {path}")
