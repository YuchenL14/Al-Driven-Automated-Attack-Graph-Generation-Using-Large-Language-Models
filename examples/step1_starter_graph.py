"""
Step 1 (supervisor's first design step):
Generate a connected graph with TWO RECTANGLES connected to TWO ELLIPSES.

This is the minimal "hello world" that proves the graph-rendering
environment works. Run:

    python examples/step1_starter_graph.py

Output: output/step1_starter_graph.png (and .pdf)
"""
from graphviz import Digraph


def build_starter_graph() -> Digraph:
    g = Digraph("starter", format="png")
    g.attr(rankdir="TB", splines="true")
    g.attr("node", fontname="Helvetica", fontsize="11")

    # Two ellipses (in an attack graph these will become "preconditions")
    g.node("E1", "Ellipse 1", shape="ellipse")
    g.node("E2", "Ellipse 2", shape="ellipse")

    # Two rectangles (in an attack graph these will become "events")
    g.node("R1", "Rectangle 1", shape="box")
    g.node("R2", "Rectangle 2", shape="box")

    # Connect the two rectangles to the two ellipses
    g.edge("E1", "R1")
    g.edge("E2", "R1")
    g.edge("R1", "E2")  # demonstrates a precondition produced by an event
    g.edge("E2", "R2")

    return g


if __name__ == "__main__":
    g = build_starter_graph()
    out = g.render("output/step1_starter_graph", cleanup=True)
    print(f"Wrote {out}")
