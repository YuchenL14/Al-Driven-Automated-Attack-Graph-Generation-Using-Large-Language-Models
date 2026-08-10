"""Phase 4 checks for branch-aware placement and skip-rank edge routing."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import render  # noqa: E402
from reference_renderer import (  # noqa: E402
    _VisualNode,
    _build_nodes,
    _layout,
    _path_segments,
    _plan_connector,
    _segment_interaction,
)
from schema import AttackGraph  # noqa: E402


def _branch_graph() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "Branch-aware layout",
        "preconditions": [
            {"id": f"p_{name}", "label": f"Preparation {name} ready", "code": "R"}
            for name in ("a", "b", "c", "d")
        ] + [
            {
                "id": f"s_{name}",
                "label": f"Branch {name} state",
                "code": "R",
                "parents": [f"e_{name}"],
            }
            for name in ("a", "b", "c", "d")
        ] + [
            {
                "id": "s_left",
                "label": "Left branch complete",
                "code": "R",
                "parents": ["e_left"],
            },
            {
                "id": "s_right",
                "label": "Right branch complete",
                "code": "R",
                "parents": ["e_right"],
            },
            {
                "id": "s_goal",
                "label": "Final objective achieved",
                "code": "R",
                "parents": ["e_final"],
            },
        ],
        "events": [
            {
                "id": f"e_{name}",
                "label": f"Perform branch {name} action",
                "tactic": "IA",
                "parents": [f"p_{name}"],
            }
            for name in ("a", "b", "c", "d")
        ] + [
            {
                "id": "e_left",
                "label": "Combine left prerequisites",
                "tactic": "EX",
                "parents": ["s_a", "s_b"],
                "join": "AND",
            },
            {
                "id": "e_right",
                "label": "Combine right prerequisites",
                "tactic": "EX",
                "parents": ["s_c", "s_d"],
                "join": "AND",
            },
            {
                "id": "e_final",
                "label": "Complete final objective",
                "tactic": "IM",
                "parents": ["s_left", "s_right"],
                "join": "AND",
            },
        ],
    })


def _skip_rank_graph() -> AttackGraph:
    return AttackGraph.model_validate({
        "title": "Skip-rank routing",
        "preconditions": [
            {"id": "p_root", "label": "Root condition ready", "code": "R"},
            {
                "id": "s_middle",
                "label": "Middle state established",
                "code": "R",
                "parents": ["e_middle"],
            },
            {
                "id": "s_final",
                "label": "Final state established",
                "code": "R",
                "parents": ["e_final"],
            },
        ],
        "events": [
            {
                "id": "e_middle",
                "label": "Perform middle action",
                "tactic": "IA",
                "parents": ["p_root"],
            },
            {
                "id": "e_final",
                "label": "Perform final action",
                "tactic": "IM",
                "parents": ["p_root", "s_middle"],
                "join": "AND",
            },
        ],
    })


def _positioned(graph: AttackGraph):
    image = Image.new("RGB", (8, 8), "white")
    draw = ImageDraw.Draw(image)
    return _layout(
        draw,
        _build_nodes(graph),
        ImageFont.load_default(),
        compact=True,
    )


def _segment_crosses_node(start, end, node) -> bool:
    x1, y1 = start
    x2, y2 = end
    left, right = node.x, node.x + node.width
    top, bottom = node.y, node.bottom
    if x1 == x2:
        return (
            left < x1 < right
            and max(min(y1, y2), top) < min(max(y1, y2), bottom)
        )
    if y1 == y2:
        return (
            top < y1 < bottom
            and max(min(x1, x2), left) < min(max(x1, x2), right)
        )
    return False


class Phase4BranchLayoutTests(unittest.TestCase):
    def test_rank_nodes_never_overlap(self):
        nodes = _positioned(_branch_graph())
        by_level = {}
        for node in nodes.values():
            by_level.setdefault(node.level, []).append(node)
        for rank in by_level.values():
            rank.sort(key=lambda node: node.x)
            for left, right in zip(rank, rank[1:]):
                self.assertLess(left.x + left.width, right.x)

    def test_parallel_branches_keep_left_to_right_lanes(self):
        nodes = _positioned(_branch_graph())
        for prefix in ("p", "e", "s"):
            centres = [nodes[f"{prefix}_{name}"].cx for name in "abcd"]
            self.assertEqual(centres, sorted(centres))
        self.assertLess(nodes["e_left"].cx, nodes["e_right"].cx)
        self.assertLess(nodes["s_left"].cx, nodes["s_right"].cx)

    def test_merge_nodes_are_centred_beneath_their_inputs(self):
        nodes = _positioned(_branch_graph())
        for target_id in ("e_left", "e_right", "e_final"):
            target = nodes[target_id]
            parent_centres = [nodes[parent].cx for parent in target.parents]
            midpoint = (min(parent_centres) + max(parent_centres)) / 2
            self.assertLessEqual(abs(target.cx - midpoint), 35)

    def test_adjacent_rank_edges_do_not_cross(self):
        nodes = _positioned(_branch_graph())
        edges = [
            (nodes[parent], target)
            for target in nodes.values()
            for parent in target.parents
            if target.level - nodes[parent].level == 1
        ]
        for index, (left_parent, left_target) in enumerate(edges):
            for right_parent, right_target in edges[index + 1:]:
                if (
                    left_parent.level != right_parent.level
                    or left_target.level != right_target.level
                    or left_parent.id == right_parent.id
                    or left_target.id == right_target.id
                ):
                    continue
                parent_order = left_parent.cx - right_parent.cx
                target_order = left_target.cx - right_target.cx
                self.assertGreaterEqual(parent_order * target_order, 0)

    def test_skip_rank_parent_uses_an_obstacle_free_outer_lane(self):
        nodes = _positioned(_skip_rank_graph())
        target = nodes["e_final"]
        parents = [nodes[parent] for parent in target.parents]
        plan = _plan_connector(
            target,
            parents,
            obstacles=nodes.values(),
            route_bounds=(14, 842),
        )
        root_path = plan.paths[plan.parent_ids.index("p_root")]
        intermediate = (nodes["e_middle"], nodes["s_middle"])
        for start, end in zip(root_path, root_path[1:]):
            self.assertTrue(start[0] == end[0] or start[1] == end[1])
            self.assertFalse(any(
                _segment_crosses_node(start, end, node)
                for node in intermediate
            ))
        routed_length = sum(
            abs(end[0] - start[0]) + abs(end[1] - start[1])
            for start, end in zip(root_path, root_path[1:])
        )
        shortest = (
            abs(nodes["p_root"].cx - target.cx)
            + target.y - nodes["p_root"].bottom
        )
        self.assertLessEqual(routed_length, shortest * 1.8)

    def test_clear_skip_rank_edge_uses_the_short_vertical_route(self):
        parent = _VisualNode(
            id="p", kind="precondition", shape="ellipse",
            label="Clear parent", code="R", code_namespace="state",
            technique=None, mitigations=(), likelihood=None, parents=(),
            join="OR", index=0, level=0, x=40, y=40,
        )
        unrelated = _VisualNode(
            id="other", kind="event", shape="rectangle",
            label="Unrelated middle node", code="EX",
            code_namespace="tactic", technique=None, mitigations=(),
            likelihood=None, parents=(), join="OR", index=1, level=1,
            x=300, y=190,
        )
        target = _VisualNode(
            id="target", kind="event", shape="rectangle",
            label="Distant target", code="IM", code_namespace="tactic",
            technique=None, mitigations=(), likelihood=None, parents=("p",),
            join="OR", index=2, level=3, x=40, y=460,
        )
        plan = _plan_connector(
            target,
            [parent],
            obstacles=(parent, unrelated, target),
            route_bounds=(14, 842),
        )
        self.assertEqual(
            ((parent.cx, parent.bottom), (target.cx, target.y)),
            plan.paths[0],
        )

    def test_long_or_inputs_do_not_share_a_connector_track(self):
        common = {
            "code_namespace": "state",
            "technique": None,
            "mitigations": (),
            "likelihood": None,
            "join": "OR",
        }
        left = _VisualNode(
            id="left", kind="precondition", shape="ellipse", label="Left",
            code="R", parents=(), index=0, level=0, x=40, y=40, **common,
        )
        right = _VisualNode(
            id="right", kind="precondition", shape="ellipse", label="Right",
            code="R", parents=(), index=1, level=0, x=460, y=40, **common,
        )
        blocker = _VisualNode(
            id="blocker", kind="event", shape="rectangle", label="Blocker",
            code="EX", parents=(), index=2, level=1, x=250, y=210, **common,
        )
        target = _VisualNode(
            id="target", kind="event", shape="rectangle", label="Target",
            code="IM", parents=("left", "right"), index=3, level=3,
            x=250, y=500, **common,
        )
        plan = _plan_connector(
            target,
            [left, right],
            obstacles=(left, right, blocker, target),
            route_bounds=(14, 842),
        )
        shared_pixels = sum(
            _segment_interaction(first, second)[0]
            for first in _path_segments(plan.paths[0])
            for second in _path_segments(plan.paths[1])
        )
        self.assertEqual(0, shared_pixels)

    def test_rendering_does_not_mutate_the_canonical_graph(self):
        graph = _branch_graph()
        before = graph.model_dump()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "branch.png"
            render(graph, str(output), compact=True)
            self.assertTrue(output.is_file())
        self.assertEqual(before, graph.model_dump())


if __name__ == "__main__":
    unittest.main()
