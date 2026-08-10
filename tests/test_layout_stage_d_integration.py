"""Stage D tests for the controlled runtime renderer switch."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import app  # noqa: E402
import attack_graph  # noqa: E402
import student_app  # noqa: E402
from schema import AttackGraph  # noqa: E402


def _small_graph() -> AttackGraph:
    return AttackGraph.from_json_file(
        ROOT / "examples" / "sample_ransomware.json"
    )


def _long_graph() -> AttackGraph:
    preconditions = [
        {"id": "p0", "label": "Initial condition", "code": "R"},
    ]
    events = []
    parent = "p0"
    for index in range(6):
        event_id = f"e{index}"
        state_id = f"p{index + 1}"
        events.append({
            "id": event_id,
            "label": f"Perform attack step {index + 1}",
            "tactic": "EX",
            "parents": [parent],
        })
        preconditions.append({
            "id": state_id,
            "label": f"State {index + 1} established",
            "code": "R",
            "parents": [event_id],
        })
        parent = state_id
    return AttackGraph.model_validate({
        "title": "Long integration graph",
        "preconditions": preconditions,
        "events": events,
    })


class RendererBackendSwitchTests(unittest.TestCase):
    def test_new_renderer_is_the_default(self):
        with patch.dict(
            os.environ,
            {attack_graph.PNG_RENDERER_ENV: "new"},
        ):
            self.assertEqual("new", attack_graph.selected_png_renderer())

    def test_invalid_renderer_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid PNG renderer"):
            attack_graph.selected_png_renderer("unvalidated")

    def test_explicit_backend_selects_only_the_requested_renderer(self):
        graph = _small_graph()
        with patch.object(
            attack_graph,
            "render_new_layout_png",
            return_value="new.png",
        ) as new_renderer, patch.object(
            attack_graph,
            "render_reference_png",
            return_value="legacy.png",
        ) as legacy_renderer:
            self.assertEqual(
                "new.png",
                attack_graph.render(graph, "graph.png", renderer="new"),
            )
            new_renderer.assert_called_once()
            legacy_renderer.assert_not_called()

            new_renderer.reset_mock()
            self.assertEqual(
                "legacy.png",
                attack_graph.render(graph, "graph.png", renderer="legacy"),
            )
            legacy_renderer.assert_called_once()
            new_renderer.assert_not_called()

    def test_environment_can_roll_back_without_changing_the_model(self):
        graph = _small_graph()
        before = graph.model_dump()
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {attack_graph.PNG_RENDERER_ENV: "legacy"},
        ):
            output = Path(directory) / "legacy.png"
            attack_graph.render(graph, str(output))
            self.assertTrue(output.is_file())
        self.assertEqual(before, graph.model_dump())


class WebRuntimeIntegrationTests(unittest.TestCase):
    def test_professional_route_uses_new_palette_and_selected_rules(self):
        graph = _small_graph()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            with patch.dict(
                os.environ,
                {attack_graph.PNG_RENDERER_ENV: "new"},
            ), patch.object(
                app, "REPORTS_DIR", reports
            ), patch.object(
                app, "OUTPUTS_DIR", outputs
            ), patch.object(
                app, "extract_attack_graph", return_value=graph
            ) as extraction:
                response = app.app.test_client().post(
                    "/generate",
                    data={
                        "provider": "mock",
                        "ruleset": "v1.5",
                        "report": (
                            io.BytesIO(b"Technical incident report."),
                            "professional.txt",
                        ),
                    },
                    content_type="multipart/form-data",
                )
            self.assertEqual(200, response.status_code)
            extraction.assert_called_once()
            # The chosen rule set reaches the extractor unchanged; v1.4 is the
            # default rather than the only possibility.
            self.assertEqual(
                "v1.5",
                extraction.call_args.kwargs["ruleset"],
            )
            output = next(outputs.glob("*.png"))
            with Image.open(output).convert("RGB") as image:
                self.assertIn(
                    (184, 181, 234),
                    set(image.get_flattened_data()),
                )
            self.assertIn(b"AGVS-SP branch-aware", response.data)

    def test_student_route_uses_new_renderer_and_causal_pagination(self):
        graph = _long_graph()
        scenario = (
            "The attacker exploited an exposed service, executed malware, "
            "moved through the network, collected data, and disrupted systems."
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            with patch.dict(
                os.environ,
                {attack_graph.PNG_RENDERER_ENV: "new"},
            ), patch.object(
                student_app, "REPORTS_DIR", reports
            ), patch.object(
                student_app, "OUTPUTS_DIR", outputs
            ), patch.object(
                student_app,
                "extract_attack_graph",
                return_value=graph,
            ):
                response = student_app.app.test_client().post(
                    "/generate",
                    data={"scenario": scenario},
                )
            self.assertEqual(200, response.status_code)
            parts = sorted(outputs.glob("*_part*.png"))
            self.assertGreaterEqual(len(parts), 2)
            for output in parts:
                with Image.open(output).convert("RGB") as image:
                    self.assertIn(
                        (184, 181, 234),
                        set(image.get_flattened_data()),
                    )
                self.assertIn(output.name.encode(), response.data)
            quality = list(outputs.glob("*.layout-quality.json"))
            audits = [
                path for path in outputs.glob("*.json")
                if path not in quality
            ]
            self.assertEqual(1, len(audits))
            self.assertEqual(1, len(quality))


if __name__ == "__main__":
    unittest.main()
