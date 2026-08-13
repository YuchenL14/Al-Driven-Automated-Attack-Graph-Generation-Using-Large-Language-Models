"""Stage C tests for the independent Pillow layout renderer."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from causal_split import (continuation_labels, materialize_split_part,  # noqa: E402
                          plan_causal_split)
from layout_ir import build_layout_ir  # noqa: E402
from layout_planner import plan_layout  # noqa: E402
from layout_renderer import (LEGEND_LINE_HEIGHT,  # noqa: E402
                             legend_geometry, render_new_layout_png)
from test_phase3_causal_split import (_british_library_shape,  # noqa: E402
                                      _mands_shape,
                                      _wannacry_shape)


class LayoutStageCRendererTests(unittest.TestCase):
    def test_renderer_writes_png_without_mutating_the_graph(self):
        graph = _british_library_shape()
        before = graph.model_dump()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "render.png"
            returned = render_new_layout_png(graph, str(output))
            self.assertEqual(str(output), returned)
            self.assertTrue(output.is_file())
            _, legend_area_width, graph_offset_x = legend_geometry(graph)
            plan = plan_layout(build_layout_ir(graph))
            with Image.open(output) as image:
                self.assertEqual("PNG", image.format)
                # The page is exactly the legend column plus the planned graph
                # and its badge overhang; it is no longer padded out to a
                # fixed landscape width.
                self.assertGreaterEqual(
                    image.width, graph_offset_x + plan.width
                )
                # This assertion used to read 710, a fixed floor that padded a
                # small graph with blank space amounting to much of the figure.
                # The height now follows the content, so what is asserted is
                # that the content fits and that the padding is bounded.
                legend_lines, _, _ = legend_geometry(graph)
                needed = max(plan.height,
                             len(legend_lines) * LEGEND_LINE_HEIGHT + 88)
                self.assertGreaterEqual(image.height, needed)
                self.assertLessEqual(image.height - needed, 32)
        self.assertEqual(before, graph.model_dump())

    def test_renderer_keeps_main_graph_and_legend_separated(self):
        graph = _british_library_shape()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "separated.png"
            render_new_layout_png(graph, str(output))
            _, legend_area_width, _ = legend_geometry(graph)
            with Image.open(output).convert("RGB") as image:
                # The renderer deliberately reserves a 34px white gutter
                # between the left-hand legend and the causal graph.
                gutter = image.crop(
                    (legend_area_width, 60, legend_area_width + 30, image.height)
                )
                self.assertEqual(
                    {(255, 255, 255)},
                    set(gutter.get_flattened_data()),
                )

    def test_sample_palette_is_present(self):
        graph = _british_library_shape()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "palette.png"
            render_new_layout_png(graph, str(output))
            with Image.open(output).convert("RGB") as image:
                colours = set(image.get_flattened_data())
        self.assertIn((184, 181, 234), colours)  # tactic badge
        self.assertIn((49, 168, 196), colours)   # likelihood badge
        self.assertIn((243, 178, 178), colours)  # technique tag
        self.assertIn((231, 190, 155), colours)  # mitigation tag

    def test_all_report_oracle_pages_render_within_aspect_budget(self):
        factories = (
            _british_library_shape,
            _wannacry_shape,
            _mands_shape,
        )
        with tempfile.TemporaryDirectory() as directory:
            for graph_factory in factories:
                graph = graph_factory()
                split = plan_causal_split(graph)
                for part in split.parts:
                    page = materialize_split_part(
                        graph, part, len(split.parts)
                    )
                    output = (
                        Path(directory)
                        / f"{graph_factory.__name__}_{part.index}.png"
                    )
                    render_new_layout_png(
                        page,
                        str(output),
                        page_header=(
                            f"Part {part.index} of {len(split.parts)}"
                        ),
                        continuation_labels=continuation_labels(split, part),
                    )
                    with Image.open(output) as image:
                        # The Stolen Pencil reference page is portrait, at
                        # roughly 1.13 high per unit wide. The budget allows a
                        # chain-structured incident to be a little taller
                        # without padding the page with empty space.
                        self.assertLessEqual(
                            image.height / image.width,
                            1.65,
                        )
                        self.assertEqual("PNG", image.format)


if __name__ == "__main__":
    unittest.main()
