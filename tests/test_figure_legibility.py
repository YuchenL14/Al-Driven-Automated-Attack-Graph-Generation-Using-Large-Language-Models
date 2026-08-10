"""What a figure needs before it can go in a document someone prints.

Three properties, none of which anything measured before:

  the key      a reader who has not read the specification can still decode
               the drawing, because the page says what its shapes mean;
  the width    a page is narrow enough that its labels are still readable at
               the size a page gives a figure;
  the format   the vector copy is the same drawing as the raster one, key
               included.

Lallie, Debattista and Bal (2020) surveyed 180 published attack graphs and
found the notation inconsistent and usually unexplained. That is the failure
these tests exist to keep out of this tool's own output.
"""

import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import render_split
from causal_split import (attack_objective, plan_causal_split,
                          widest_page_width_px)
from layout_ir import build_layout_ir
from layout_planner import page_objective, plan_layout
from layout_quality import (LEGEND_RESERVE_WIDTH, measure_layout_quality,
                            quality_warnings)
from layout_renderer import (FIGURE_PLACEMENT_WIDTH_PT, LEGEND_MIN_WIDTH,
                             LEGEND_TEXT_WIDTH, MAX_PAGE_WIDTH_PX,
                             MIN_PRINTED_LABEL_PT, NODE_FONT_PX,
                             _syntax_key_lines, legend_geometry,
                             objective_label_for_page)
from layout_router import route_layout
from layout_svg import render_new_layout_svg
from schema import AttackGraph
from visual_aggregation import DEFAULT_MIN_AGGREGATE, aggregate_for_drawing

PLAIN = AttackGraph.model_validate({
    "events": [
        {"id": "e1", "label": "Send a phishing email", "parents": ["p0"],
         "tactic": "IA", "techniques": ["T1566.002"],
         "mitigations": ["M1017"]},
    ],
    "preconditions": [
        {"id": "p0", "label": "Staff read external mail", "code": "P0",
         "parents": []},
        {"id": "p1", "label": "Credentials captured", "code": "P1",
         "parents": ["e1"]},
    ],
})

RICH = AttackGraph.model_validate({
    "events": [
        {"id": "e1", "label": "Sign in to the gateway", "parents": ["p0"],
         "tactic": "IA", "techniques": ["T1133"]},
        {"id": "e2", "label": "Move to the file server",
         "parents": ["p1", "p2"], "join": "AND", "tactic": "LM",
         "techniques": ["T1021.001"]},
    ],
    "preconditions": [
        {"id": "p0", "label": "Gateway lacked MFA", "code": "P0",
         "parents": []},
        {"id": "p1", "label": "Remote access obtained", "code": "P1",
         "parents": ["e1"]},
        {"id": "p2", "label": "Credentials held", "code": "P2", "parents": [],
         "style": "dotted"},
        {"id": "p3", "label": "File server reached", "code": "P3",
         "parents": ["e2"]},
        {"id": "a1", "label": "Detected on day 4", "code": "A1",
         "role": "annotation", "style": "dashed", "parents": ["e2"]},
    ],
})


class SyntaxKeyTests(unittest.TestCase):
    def test_it_names_the_two_shapes_the_syntax_is_built_on(self):
        key = " ".join(_syntax_key_lines(PLAIN))
        self.assertIn("Rectangle", key)
        self.assertIn("Ellipse", key)

    def test_it_says_which_way_to_read_the_arrows(self):
        self.assertTrue(any("downward" in line
                            for line in _syntax_key_lines(PLAIN)))

    def test_it_describes_only_what_the_page_draws(self):
        """A key entry for a symbol that is absent is noise, not help."""

        plain = " ".join(_syntax_key_lines(PLAIN))
        for absent in ("Dashed outline", "Dotted outline", "AND", "OR"):
            self.assertNotIn(absent, plain)

    def test_it_describes_everything_the_page_does_draw(self):
        rich = " ".join(_syntax_key_lines(RICH))
        for present in ("Dashed outline", "Dotted outline", "(AND)"):
            self.assertIn(present, rich)

    def test_an_or_is_named_only_when_one_is_drawn(self):
        self.assertNotIn("(OR)", " ".join(_syntax_key_lines(RICH)))
        data = RICH.model_dump()
        data["events"][1]["join"] = "OR"
        either = " ".join(_syntax_key_lines(
            AttackGraph.model_validate(data)))
        self.assertIn("(OR)", either)
        self.assertNotIn("(AND)", either)

    def test_a_folded_node_is_declared_as_one(self):
        """Otherwise a line of the key is false for one shape on the page."""

        self.assertNotIn("folded together",
                         " ".join(_syntax_key_lines(RICH)))
        self.assertIn("folded together",
                      " ".join(_syntax_key_lines(RICH, has_aggregates=True)))

    def test_the_fold_line_names_no_shape(self):
        """An action fold is a rectangle and an outcome fold is an ellipse.

        The line said "one rectangle", and the first graph it was shown on had
        folded six outcomes into an ellipse.
        """

        folded = [line for line in _syntax_key_lines(RICH, has_aggregates=True)
                  if "folded together" in line][0]
        self.assertNotIn("ectangle", folded)
        self.assertNotIn("llipse", folded)

    def test_the_likelihood_badge_is_keyed_when_it_is_drawn(self):
        """A symbol on the page and nothing saying what it is."""

        self.assertFalse(any("feasible" in line
                             for line in _syntax_key_lines(RICH)))
        data = RICH.model_dump()
        data["events"][0]["likelihood"] = 7.0
        scored = _syntax_key_lines(AttackGraph.model_validate(data))
        self.assertTrue(any("feasible" in line for line in scored))

    def test_the_key_reaches_the_drawn_legend(self):
        lines, _, _ = legend_geometry(RICH)
        self.assertEqual("How to read this figure", lines[0])
        self.assertTrue(any("T1133" in line for line in lines),
                        "the identifier key must still be there too")


class LegendWidthTests(unittest.TestCase):
    def test_the_key_column_is_fixed_rather_than_as_wide_as_its_longest_line(
            self):
        narrow, width_a, _ = legend_geometry(PLAIN)
        _, width_b, _ = legend_geometry(RICH)
        self.assertEqual(width_a, width_b)
        self.assertEqual(LEGEND_MIN_WIDTH, width_a)

    def test_a_long_entry_wraps_instead_of_widening_the_page(self):
        lines, width, _ = legend_geometry(RICH)
        self.assertLessEqual(LEGEND_TEXT_WIDTH + 24, width)
        self.assertTrue(any(line.startswith("   ") for line in lines),
                        "a wrapped continuation is indented")


class PageWidthBudgetTests(unittest.TestCase):
    def test_the_budget_is_the_arithmetic_it_claims_to_be(self):
        """Not a number someone liked: the width where 8pt stops holding."""

        printed = NODE_FONT_PX * FIGURE_PLACEMENT_WIDTH_PT / MAX_PAGE_WIDTH_PX
        self.assertAlmostEqual(MIN_PRINTED_LABEL_PT, printed, places=1)

    def test_a_page_over_budget_is_reported(self):
        quality = self._quality(RICH)
        over = type(quality)(**{
            **quality.__dict__,
            "page_width_px": MAX_PAGE_WIDTH_PX + 200,
        })
        self.assertTrue(any("budget" in warning
                            for warning in quality_warnings(over)))
        self.assertLess(over.printed_label_pt, MIN_PRINTED_LABEL_PT)

    def test_a_page_within_budget_is_not(self):
        quality = self._quality(RICH)
        self.assertLessEqual(quality.page_width_px, MAX_PAGE_WIDTH_PX)
        self.assertFalse([w for w in quality_warnings(quality)
                          if "budget" in w])

    def test_the_measured_width_is_the_width_the_renderer_draws(self):
        """One number, or the budget polices something nobody sees."""

        plan = plan_layout(build_layout_ir(RICH))
        self.assertEqual(plan.width + LEGEND_RESERVE_WIDTH,
                         self._quality(RICH).page_width_px)

    def test_pagination_reads_the_same_number(self):
        split = plan_causal_split(RICH)
        self.assertEqual(self._quality(RICH).page_width_px,
                         widest_page_width_px(RICH, split))

    def _quality(self, model):
        layout_ir = build_layout_ir(model)
        plan = plan_layout(layout_ir)
        return measure_layout_quality(layout_ir, plan,
                                      route_layout(layout_ir, plan))


class AggregationThresholdWiringTests(unittest.TestCase):
    """The fold threshold the renderer uses must be the measured one.

    `render_split` derived it as `max_parallel_events + 1`, which restates the
    pagination event budget as a fold rule. Retuning `DEFAULT_MIN_AGGREGATE`
    against the page-width budget therefore changed nothing in the only path
    that draws anything, and a real teaching graph with four outcomes went out
    at 1580px with labels at 6.3pt.
    """

    def test_render_split_defaults_to_the_measured_threshold(self):
        import inspect

        from attack_graph import render_split
        signature = inspect.signature(render_split)
        self.assertEqual(DEFAULT_MIN_AGGREGATE,
                         signature.parameters["min_aggregate"].default)

    def test_the_threshold_is_not_derived_from_the_pagination_budget(self):
        source = (ROOT / "src" / "attack_graph.py").read_text(encoding="utf-8")
        self.assertNotIn("min_size=max_parallel_events + 1", source)

    def test_four_outcomes_of_one_action_are_folded(self):
        """Four is one column past what a page holds, so it folds."""

        model = AttackGraph.model_validate({
            "events": [{"id": "e1", "label": "Deploy the ransomware",
                        "parents": ["p0"], "tactic": "IM",
                        "techniques": ["T1486"]}],
            "preconditions": [
                {"id": "p0", "label": "Domain admin held", "code": "P0",
                 "parents": []},
            ] + [
                {"id": f"r{index}", "label": f"Outcome {index}",
                 "parents": ["e1"], "code": f"P{index + 1}"}
                for index in range(4)
            ],
        })
        drawn, _ = aggregate_for_drawing(model)
        outcome_states = [node for node in drawn.preconditions
                          if node.parents]
        self.assertEqual(1, len(outcome_states))
        self.assertIn("4", outcome_states[0].label)


TWO_ENDINGS = AttackGraph.model_validate({
    "events": [
        {"id": "e1", "label": "Deploy the ransomware", "parents": ["p0"],
         "tactic": "IM", "techniques": ["T1486"]},
    ],
    "preconditions": [
        {"id": "p0", "label": "Domain admin held", "code": "P0",
         "parents": []},
        {"id": "r1", "label": "Servers encrypted", "code": "P1",
         "parents": ["e1"]},
        {"id": "r2", "label": "Payments disrupted", "code": "P2",
         "parents": ["e1"]},
    ],
})


WIDE = AttackGraph.model_validate({
    "events": [
        {"id": f"e{index}", "label": f"Independent action {index}",
         "parents": ["p0"], "tactic": "CA", "techniques": ["T1003"]}
        for index in range(9)
    ] + [
        {"id": "e_last", "label": "Reach the objective",
         "parents": [f"r{index}" for index in range(9)], "join": "AND",
         "tactic": "IM", "techniques": ["T1486"]},
    ],
    "preconditions": [
        {"id": "p0", "label": "Foothold on host", "code": "P0", "parents": []},
    ] + [
        {"id": f"r{index}", "label": f"Result of action {index}",
         "code": f"P{index + 1}", "parents": [f"e{index}"]}
        for index in range(9)
    ] + [
        {"id": "r_end", "label": "Objective reached", "code": "P99",
         "parents": ["e_last"]},
    ],
})


class ObjectiveTests(unittest.TestCase):
    """Which ending is the attack's, and can a reader see it.

    Rule 5 has the model name the objective as a result state, and it does.
    Nothing showed it: the British Library page ended in nine terminal states
    with the objective among them, distinguishable only by counting arrows.
    Lallie, Debattista and Bal (2020) found a goal represented in 21.5% of the
    180 published graphs they surveyed, and a goal named in the data but not on
    the figure is on the wrong side of that number.
    """

    def test_the_state_the_most_actions_reach_is_the_objective(self):
        self.assertEqual("p3", attack_objective(RICH))

    def test_two_endings_reached_equally_name_no_objective(self):
        """A graph that does not converge must not be given a winner."""

        self.assertIsNone(attack_objective(TWO_ENDINGS))

    def test_a_graph_with_no_actions_names_no_objective(self):
        empty = AttackGraph.model_validate({"events": [], "preconditions": []})
        self.assertIsNone(attack_objective(empty))

    def test_an_annotation_is_never_the_objective(self):
        """It is commentary beside the attack, not an ending of it."""

        objective = attack_objective(RICH)
        annotations = {node.id for node in RICH.preconditions
                       if node.role == "annotation"}
        self.assertTrue(annotations)
        self.assertNotIn(objective, annotations)

    def test_the_planner_and_the_model_agree_on_which_node_it_is(self):
        """One rule. Two implementations of it is the drift already paid for."""

        layout_ir = build_layout_ir(RICH)
        visual = page_objective(layout_ir)
        canonical = next(node.canonical_id for node in layout_ir.nodes
                         if node.visual_id == visual)
        self.assertEqual(attack_objective(RICH), canonical)

    def test_the_objective_is_drawn_below_everything_else(self):
        plan = plan_layout(build_layout_ir(RICH))
        objective = page_objective(build_layout_ir(RICH))
        drawn = {node.visual_id: node for node in plan.nodes}
        bottom = max(node.y for node in plan.nodes)
        self.assertEqual(bottom, drawn[objective].y)
        self.assertEqual(1, sum(1 for node in plan.nodes
                                if node.y == bottom),
                         "the objective has the last row to itself")

    def test_it_goes_below_an_annotation_too(self):
        """One page put commentary lower than the objective.

        "No evidence of data exfiltration observed" is an annotation: off the
        causal path, and its row carries no meaning. It sat at the foot while
        the key said the objective did. The annotation is the one that gives
        way, and only when the objective is the one the caller named.
        """

        data = RICH.model_dump()
        data["preconditions"].append(
            {"id": "a2", "label": "Noted afterwards", "code": "A2",
             "role": "annotation", "style": "dashed", "parents": ["e2"]})
        model = AttackGraph.model_validate(data)
        objective = attack_objective(model)
        plan = plan_layout(build_layout_ir(model), objective)
        drawn = {node.canonical_id: node for node in plan.nodes}
        bottom = max(node.y for node in plan.nodes)
        self.assertEqual(bottom, drawn[objective].y)
        self.assertEqual(1, sum(1 for node in plan.nodes if node.y == bottom))

    def test_a_split_names_it_on_one_page_only(self):  # noqa: D401
        """A state produced from two parts is drawn in both, correctly.

        One saved run announced the objective on parts 4 and 5 of five. It is
        named where its producers have all been seen -- the last page that
        draws it -- because that is where it is an ending rather than a partial
        result.
        """

        with tempfile.TemporaryDirectory() as tmp:
            pages = render_split(WIDE, str(Path(tmp) / "f.svg"), fmt="svg")
            texts = [Path(page).read_text(encoding="utf-8") for page in pages]
        named = [index for index, text in enumerate(texts)
                 if "objective, at the foot" in text]
        self.assertGreater(len(pages), 1, "the fixture must actually split")
        self.assertLessEqual(len(named), 1)

    def test_moving_it_adds_and_removes_no_edge(self):
        """Rank is not a claim; the arrows are. None of them changed."""

        layout_ir = build_layout_ir(RICH)
        plan = plan_layout(layout_ir)
        drawn = {node.visual_id: node for node in plan.nodes}
        for edge in layout_ir.edges:
            self.assertLess(drawn[edge.source_visual_id].bottom,
                            drawn[edge.target_visual_id].y)

    def test_the_key_names_it(self):
        """Whitespace-normalised, because the key column wraps.

        Four separate bugs in this project came from matching prose against
        text a line break had split. A test that reads the drawn key has to
        normalise for the same reason the code does.
        """

        lines, _, _ = legend_geometry(RICH,
                                      objective_label="File server reached")
        joined = " ".join(" ".join(lines).split())
        self.assertIn("objective", joined)
        self.assertIn("File server reached", joined)

    def test_a_page_that_only_continues_claims_no_objective(self):
        """Part 1 of a split ends on a bridge, not on the attack's objective.

        Calling "Wide access across network achieved" the objective because
        part 1 stops there would be false, and the renderer already knows: it
        prints "continues in part 2" under that node.
        """

        layout_ir = build_layout_ir(RICH)
        canonical = attack_objective(RICH)
        self.assertIsNotNone(
            objective_label_for_page(layout_ir, {}, canonical))
        self.assertIsNone(objective_label_for_page(
            layout_ir, {canonical: "continues in part 2"}, canonical))

    def test_a_page_told_nothing_claims_nothing(self):
        """No fallback to the page's own convergence, on purpose.

        Every page converges on something; on a split graph that something is
        a different node per page, and on a graph whose endings tie there is no
        objective at all. Answering from the page produced two different
        "attack's objective" lines on two pages of one real run, both false.
        """

        layout_ir = build_layout_ir(RICH)
        self.assertIsNone(objective_label_for_page(layout_ir, {}))
        self.assertIsNone(objective_label_for_page(layout_ir, {}, None))
        # The page still has a convergence; it is simply not a claim to make.
        self.assertIsNotNone(page_objective(layout_ir))

    def test_a_graph_whose_endings_tie_names_none_anywhere(self):
        layout_ir = build_layout_ir(TWO_ENDINGS)
        self.assertIsNone(attack_objective(TWO_ENDINGS))
        self.assertIsNone(objective_label_for_page(
            layout_ir, {}, attack_objective(TWO_ENDINGS)))


class LineArtefactTests(unittest.TestCase):
    """Ink drawn twice, and ink drawn nowhere.

    The routing check asked only whether a connector crossed a NODE. It never
    asked what connectors did to each other. Across 122 drawn pages there were
    18 zero-length segments, 35 polylines emitted twice and 35 segments stroked
    twice -- a doubled stroke is a heavier, darker line in one place and reads
    as a different kind of edge when it is the same pixel drawn again.
    """

    def _pages(self, model):
        """Per page, because dedup is per page: two pages are two drawings."""

        with tempfile.TemporaryDirectory() as tmp:
            pages = render_split(model, str(Path(tmp) / "f.svg"), fmt="svg")
            texts = [Path(page).read_text(encoding="utf-8") for page in pages]
        return [
            [[tuple(float(value) for value in pair.split(","))
              for pair in polyline.split()]
             for polyline in re.findall(r'<polyline points="([^"]+)"', text)]
            for text in texts
        ]

    def test_no_segment_has_zero_length(self):
        for page in self._pages(WIDE):
            for path in page:
                for start, end in zip(path, path[1:]):
                    self.assertNotEqual(start, end)

    def test_no_polyline_is_emitted_twice_on_a_page(self):
        for page in self._pages(WIDE):
            paths = [tuple(path) for path in page]
            self.assertEqual(len(paths), len(set(paths)))

    def test_an_arrowhead_survives_a_shared_column(self):
        """Dedup must not silence an edge's direction.

        Two edges may share a column and still arrive separately; the head is
        what says so, and dropping it would remove a claim rather than a
        duplicate.
        """

        with tempfile.TemporaryDirectory() as tmp:
            pages = render_split(RICH, str(Path(tmp) / "f.svg"), fmt="svg")
            text = Path(pages[0]).read_text(encoding="utf-8")
        arrows = text.count("marker-end")
        edges = len(build_layout_ir(RICH).edges)
        self.assertGreaterEqual(arrows, edges - 1,
                                "nearly every edge still carries its head")


class VectorOutputTests(unittest.TestCase):
    def test_the_vector_copy_carries_the_same_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = render_new_layout_svg(RICH, str(Path(tmp) / "f.svg"))
            text = Path(path).read_text(encoding="utf-8")
        self.assertIn("How to read this figure", text)
        self.assertIn("Dashed outline", text)

    def test_it_explains_a_folded_node_too(self):
        """The vector file is the one that goes in the document.

        It was written without the aggregation lines, so a box labelled
        "6 grouped actions" arrived in the figure with nothing saying which
        six.
        """

        with tempfile.TemporaryDirectory() as tmp:
            path = render_new_layout_svg(
                RICH, str(Path(tmp) / "f.svg"),
                extra_legend_lines=("agg stands for: one, two, three",))
            text = Path(path).read_text(encoding="utf-8")
        self.assertIn("stands for", text)

    def test_it_is_scalable_rather_than_a_fixed_raster(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = render_new_layout_svg(RICH, str(Path(tmp) / "f.svg"))
            text = Path(path).read_text(encoding="utf-8")
        self.assertTrue(re.search(r'viewBox="0 0 \d+ \d+"', text))
        self.assertNotIn("<image", text)


if __name__ == "__main__":
    unittest.main()
