"""Vector backend tests: SVG must be the same drawing as the PNG."""

from __future__ import annotations

import sys
import tempfile
import unittest
import xml.dom.minidom as minidom
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from attack_graph import render  # noqa: E402
from layout_renderer import render_new_layout_png  # noqa: E402
from layout_svg import render_new_layout_svg  # noqa: E402
from test_phase3_causal_split import _british_library_shape  # noqa: E402


class LayoutSvgTests(unittest.TestCase):
    def test_svg_is_well_formed_and_sized_like_the_png(self):
        graph = _british_library_shape()
        with tempfile.TemporaryDirectory() as directory:
            svg_path = Path(directory) / "graph.svg"
            png_path = Path(directory) / "graph.png"
            render_new_layout_svg(graph, str(svg_path))
            render_new_layout_png(graph, str(png_path))

            document = minidom.parse(str(svg_path))
            root = document.documentElement
            self.assertEqual("svg", root.tagName)
            with Image.open(png_path) as image:
                self.assertEqual(str(image.width), root.getAttribute("width"))
                self.assertEqual(str(image.height), root.getAttribute("height"))

    def test_svg_carries_the_agvs_constructs(self):
        graph = _british_library_shape()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "graph.svg"
            render_new_layout_svg(graph, str(output))
            document = minidom.parse(str(output))

        self.assertGreater(len(document.getElementsByTagName("ellipse")), 0)
        self.assertGreater(len(document.getElementsByTagName("rect")), 1)
        self.assertGreater(len(document.getElementsByTagName("polyline")), 0)
        self.assertGreater(len(document.getElementsByTagName("circle")), 0)
        markers = document.getElementsByTagName("marker")
        self.assertEqual(1, len(markers))
        self.assertEqual("agvs-arrow", markers[0].getAttribute("id"))

    def test_render_routes_svg_to_the_vector_backend(self):
        graph = _british_library_shape()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "routed.svg"
            written = render(graph, str(output), fmt="svg")
            self.assertEqual(str(output), written)
            text = Path(written).read_text(encoding="utf-8")
        self.assertNotIn("<!DOCTYPE", text)
        self.assertIn("agvs-arrow", text)

    def test_svg_escapes_label_markup(self):
        graph = _british_library_shape()
        graph.preconditions[0].label = 'A <b>& "risky"</b> label'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "escaped.svg"
            render_new_layout_svg(graph, str(output))
            minidom.parse(str(output))
            text = Path(output).read_text(encoding="utf-8")
        self.assertNotIn("<b>", text)
        self.assertIn("&amp;", text)


if __name__ == "__main__":
    unittest.main()
