"""A page was bounded in height but never in width.

Pagination capped events per page and ranks per page. Neither bounds the
drawing sideways: eleven events that all depend on the same foothold sit at one
causal depth, are drawn in one rank, and satisfy both budgets at once. A real
v1.6 run produced exactly that -- a page 3235 units wide with an aspect ratio
of 0.18, unreadable at any print size.

Events at the same causal depth are mutually independent by construction: a
longest-path level admits no path between its members. Dividing that fan across
pages therefore cuts no causal edge, which is why it is safe to do here and not
something the model should be asked to avoid.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from causal_split import (DEFAULT_MAX_EVENTS_PER_PART,
                          DEFAULT_MAX_PARALLEL_EVENTS, DEFAULT_MAX_RANKS,
                          max_parallel_events_for, plan_causal_split,
                          validate_lossless_split, widest_page_width_px)
from layout_renderer import MAX_PAGE_WIDTH_PX
from schema import AttackGraph


def _fan(width: int) -> AttackGraph:
    """One root state feeding `width` independent events, each with a result."""

    events = [
        {
            "id": f"e{i}",
            "label": f"Independent action {i}",
            "parents": ["p_root"],
            "tactic": "CA",
            "techniques": ["T1003"],
        }
        for i in range(width)
    ]
    preconditions = [
        {"id": "p_root", "label": "Foothold on host", "parents": [], "code": "P0"}
    ] + [
        {"id": f"p{i}", "label": f"Result of action {i}", "parents": [f"e{i}"], "code": f"P{i + 1}"}
        for i in range(width)
    ]
    return AttackGraph.model_validate(
        {
            "goal": "Collect credentials",
            "events": events,
            "preconditions": preconditions,
        }
    )


class WidePageSplitTests(unittest.TestCase):
    def test_wide_fan_is_split_even_though_budgets_are_satisfied(self):
        model = _fan(11)
        self.assertLessEqual(len(model.events), DEFAULT_MAX_EVENTS_PER_PART)

        plan = plan_causal_split(model)
        self.assertGreater(
            len(plan.parts),
            1,
            "a fan wider than the page must be divided",
        )
        for part in plan.parts:
            self.assertLessEqual(
                len(part.event_ids),
                DEFAULT_MAX_PARALLEL_EVENTS,
                "no page may exceed the parallel-event width budget",
            )

    def test_dividing_a_fan_loses_nothing(self):
        model = _fan(11)
        plan = plan_causal_split(model)
        validate_lossless_split(model, plan)

    def test_narrow_graph_is_left_on_one_page(self):
        """A fan that fits must not be divided.

        "Fits" is now the drawn width, not the event count. Four events at one
        depth measure 1356px with the key beside them, over the 1240px budget,
        so the fixture that used to stand for "fits" no longer does. It is the
        premise that changed, not the property being tested.
        """

        model = _fan(3)
        plan = plan_causal_split(model)
        self.assertLessEqual(widest_page_width_px(model, plan),
                             MAX_PAGE_WIDTH_PX)
        self.assertEqual(len(plan.parts), 1)

    def test_width_budget_is_validated(self):
        model = _fan(3)
        with self.assertRaises(ValueError):
            plan_causal_split(model, max_parallel_events=0)

    def test_budget_is_configurable(self):
        """The event count on its own, with the pixel budget switched off."""

        model = _fan(8)
        self.assertEqual(
            len(plan_causal_split(model, max_parallel_events=8,
                                  max_page_width_px=0).parts), 1)
        self.assertGreater(
            len(plan_causal_split(model, max_parallel_events=4,
                                  max_page_width_px=0).parts), 1
        )

    def test_the_pixel_budget_divides_a_page_the_count_accepts(self):
        """The gap the count alone left open.

        Four independent actions satisfy every count budget and still draw a
        page whose labels print at 7.4pt. Nothing measured that until the plan
        was measured in the geometry it would be drawn in.
        """

        model = _fan(DEFAULT_MAX_PARALLEL_EVENTS)
        unbounded = plan_causal_split(model, max_page_width_px=0)
        self.assertEqual(1, len(unbounded.parts))
        self.assertGreater(widest_page_width_px(model, unbounded),
                           MAX_PAGE_WIDTH_PX)

        bounded = plan_causal_split(_fan(5))
        self.assertGreater(len(bounded.parts), 1)
        validate_lossless_split(_fan(5), bounded)

    def test_a_division_costing_more_pages_than_the_ceiling_is_declined(self):
        """Legible fragments are a comprehension failure too.

        A six-way fan off one state divided into one action per page: every
        page inside the width budget, no page showing any structure. The
        measured ladder on the real graph was 2 pages at 5.0pt, 2 at 6.0pt, 3
        at 5.3pt and 7 at 9.4pt, so there was nothing between unreadable and
        fragmented. `PAGE_COUNT_CEILING` is where that stops being worth it,
        and it is a judgement rather than a measurement.
        """

        model = _fan(DEFAULT_MAX_PARALLEL_EVENTS)
        plan = plan_causal_split(model)
        self.assertEqual(1, len(plan.parts))
        self.assertGreater(widest_page_width_px(model, plan),
                           MAX_PAGE_WIDTH_PX,
                           "kept over budget on purpose, and warned about")

        generous = plan_causal_split(model, page_count_ceiling=8)
        self.assertGreater(len(generous.parts), len(plan.parts))
        self.assertLessEqual(widest_page_width_px(model, generous),
                             MAX_PAGE_WIDTH_PX)
        validate_lossless_split(model, generous)

    def test_a_page_that_cannot_be_narrowed_is_still_returned(self):
        """Giving up beats looping, and the quality report says so instead.

        One action with several results is one indivisible visual block. There
        is no pagination that makes it narrower, so the planner stops rather
        than dividing something it must not divide.
        """

        model = AttackGraph.model_validate({
            "events": [{"id": "e0", "label": "Deploy the ransomware",
                        "parents": ["p_root"], "tactic": "IM",
                        "techniques": ["T1486"]}],
            "preconditions": [
                {"id": "p_root", "label": "Domain admin held", "parents": [],
                 "code": "P0"},
            ] + [
                {"id": f"r{i}", "label": f"Outcome {i} of the deployment",
                 "parents": ["e0"], "code": f"P{i + 1}"}
                for i in range(8)
            ],
        })
        plan = plan_causal_split(model)
        self.assertEqual(1, len(plan.parts))
        validate_lossless_split(model, plan)

    def test_width_is_allowed_to_grow_with_height(self):
        """Bounding width alone gave one page 3 ranks tall and 6 events wide.

        The rule is a shape, not a width: a page may be wider when it is also
        taller. The absolute cap is the same rule at its narrowest, a page of
        one event layer.
        """
        widths = [max_parallel_events_for(layers) for layers in range(1, 5)]
        self.assertEqual(sorted(widths), widths, "wider pages need more height")
        self.assertEqual(DEFAULT_MAX_PARALLEL_EVENTS,
                         max_parallel_events_for(1))
        self.assertEqual(max_parallel_events_for(0), max_parallel_events_for(1))

    def test_a_shared_result_state_no_longer_welds_a_fan_together(self):
        """Eight events feeding one state were one indivisible block.

        `_event_blocks` merges only events that cannot reach one another, so a
        multi-event block is internally independent by construction and may be
        divided. Before this, a correct eight-way convergence produced a single
        unsplittable rank.
        """
        model = _fan(9)
        model = AttackGraph.model_validate({
            "events": [e.model_dump() for e in model.events] + [{
                "id": "e_use", "label": "Use everything gathered",
                "parents": ["p_all"], "tactic": "LM",
                "techniques": ["T1021"]}],
            "preconditions": [p.model_dump() for p in model.preconditions] + [{
                "id": "p_all", "label": "Everything gathered",
                "code": "PX", "parents": [f"e{i}" for i in range(9)]}],
        })
        plan = plan_causal_split(model)
        validate_lossless_split(model, plan)
        self.assertGreater(len(plan.parts), 1,
                           "a shared result must not weld the fan together")

    def test_rank_and_event_budgets_still_apply(self):
        events = []
        preconditions = [{"id": "p0", "label": "Start", "parents": [], "code": "P0"}]
        for i in range(12):
            events.append(
                {
                    "id": f"e{i}",
                    "label": f"Step {i}",
                    "parents": [f"p{i}"],
                    "tactic": "EX",
                    "techniques": ["T1059"],
                }
            )
            preconditions.append(
                {"id": f"p{i + 1}", "label": f"State {i + 1}", "parents": [f"e{i}"],
                 "code": f"P{i + 1}"}
            )
        model = AttackGraph.model_validate(
            {"goal": "Reach the end", "events": events,
             "preconditions": preconditions}
        )
        plan = plan_causal_split(model)
        self.assertGreater(len(plan.parts), 1)
        validate_lossless_split(model, plan)
        self.assertLessEqual(plan.estimated_ranks // len(plan.parts),
                             DEFAULT_MAX_RANKS)


if __name__ == "__main__":
    unittest.main()
