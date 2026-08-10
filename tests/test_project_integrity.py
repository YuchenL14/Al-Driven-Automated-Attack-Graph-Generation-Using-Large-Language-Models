"""Offline release checks for the complete attack-graph application."""

from __future__ import annotations

import io
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import app  # noqa: E402
import student_app  # noqa: E402
from attack_graph import (build_digraph, render, render_split,  # noqa: E402
                          tagged_output_path)
from extract import load_ruleset, resolve_model  # noqa: E402
from ingest import ingest  # noqa: E402
from schema import AttackGraph  # noqa: E402


class SchemaIntegrityTests(unittest.TestCase):
    def test_all_maintained_json_examples_validate_and_render(self):
        examples = (
            "sample_ransomware.json",
            "phishing_extension.json",
            "mock_extraction.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            for name in examples:
                with self.subTest(name=name):
                    graph = AttackGraph.from_json_file(ROOT / "examples" / name)
                    self.assertTrue(graph.events)
                    self.assertTrue(build_digraph(graph).nodes)
                    output = Path(directory) / f"{Path(name).stem}.png"
                    written = Path(render(graph, str(output)))
                    self.assertTrue(written.is_file())
                    self.assertGreater(written.stat().st_size, 0)

    def test_duplicate_node_ids_are_rejected(self):
        with self.assertRaisesRegex(ValidationError, "globally unique"):
            AttackGraph.model_validate({
                "preconditions": [
                    {"id": "same", "label": "A state", "code": "R"}
                ],
                "events": [{
                    "id": "same", "label": "Perform action", "tactic": "IA"
                }],
            })

    def test_event_to_event_parent_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "must consume preconditions"):
            AttackGraph.model_validate({
                "events": [
                    {"id": "e1", "label": "First action", "tactic": "IA"},
                    {"id": "e2", "label": "Second action", "tactic": "IM",
                     "parents": ["e1"]},
                ]
            })

    def test_null_technique_with_mitigation_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "without a technique"):
            AttackGraph.model_validate({
                "events": [{
                    "id": "e1", "label": "Perform action", "tactic": "IA",
                    "technique": None, "mitigations": ["M1051"]
                }]
            })

    def test_out_of_tactic_technique_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "not tactic"):
            AttackGraph.model_validate({
                "events": [{
                    "id": "e1", "label": "Exfiltrate data", "tactic": "EF",
                    "technique": "T1110", "mitigations": []
                }]
            })


class InputAndNamingTests(unittest.TestCase):
    def test_professional_v14_rule_file_remains_frozen(self):
        digest = hashlib.sha256(
            (ROOT / "rules" / "ruleset_v1.4.md").read_bytes()).hexdigest()
        self.assertEqual(
            "13d357e40a95516cbb63b1d4ccd0d93018e9bb2ec5d5d3d20f30f4dcf785cc2a",
            digest,
        )

    def test_empty_text_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.txt"
            path.write_text("  \n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "contains no text"):
                ingest(path)

    def test_ruleset_path_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid rule set version"):
            load_ruleset("../../secrets")

    def test_default_model_is_explicit(self):
        self.assertEqual("claude-sonnet-5", resolve_model("anthropic"))
        self.assertEqual("qwen3:8b", resolve_model("ollama"))

    def test_numbered_output_paths_do_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            first = tagged_output_path(
                outputs, "report__rules-v1.5", "anthropic", "claude-sonnet-5")
            first.touch()
            second = tagged_output_path(
                outputs, "report__rules-v1.5", "anthropic", "claude-sonnet-5")
            self.assertTrue(first.name.endswith("_1.png"))
            self.assertTrue(second.name.endswith("_2.png"))

    def test_existing_audit_also_reserves_its_run_number(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            first = tagged_output_path(
                outputs, "report__rules-v1.5", "anthropic", "claude-sonnet-5")
            first.with_suffix(".json").touch()
            second = tagged_output_path(
                outputs, "report__rules-v1.5", "anthropic", "claude-sonnet-5")
            self.assertTrue(second.name.endswith("_2.png"))

    def test_split_renderer_writes_valid_causal_pages(self):
        graph = AttackGraph.from_json_file(
            ROOT / "examples" / "mock_extraction.json")
        with tempfile.TemporaryDirectory() as directory:
            paths = render_split(
                graph, str(Path(directory) / "split.png"), threshold=1)
            self.assertGreaterEqual(len(paths), 2)
            self.assertTrue(all(Path(path).is_file() for path in paths))

    def test_third_split_part_also_reserves_the_run_number(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            first = tagged_output_path(
                outputs, "report__rules-v1.4", "mock", None)
            first.with_name(f"{first.stem}_part3.png").touch()
            second = tagged_output_path(
                outputs, "report__rules-v1.4", "mock", None)
            self.assertTrue(first.name.endswith("_1.png"))
            self.assertTrue(second.name.endswith("_2.png"))


class WebApplicationTests(unittest.TestCase):
    def test_professional_route_defaults_to_the_current_ruleset(self):
        # This assertion used to read v1.4, because v1.4 was both the frozen
        # comparison baseline and the version the work used. It is still the
        # baseline, but every graph the dissertation reports now comes from
        # v1.6, so a request that chooses nothing must run under v1.6 and
        # reaching the baseline must be the deliberate act. The constant and
        # this test were changed together rather than leaving a test that
        # asserted behaviour the tool no longer has.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            with patch.object(app, "REPORTS_DIR", reports), patch.object(
                    app, "OUTPUTS_DIR", outputs):
                response = app.app.test_client().post(
                    "/generate",
                    data={
                        "provider": "mock",
                        "report": (io.BytesIO(b"Mock report text."), "mock.txt"),
                    },
                    content_type="multipart/form-data",
                )
            self.assertEqual(200, response.status_code)
            pngs = list(outputs.glob("*.png"))
            quality = list(outputs.glob("*.layout-quality.json"))
            audits = [
                path for path in outputs.glob("*.json") if path not in quality
            ]
            self.assertEqual(1, len(pngs))
            self.assertEqual(1, len(audits))
            self.assertEqual(1, len(quality))
            expected = f"__rules-{app.DEFAULT_RULESET}__"
            self.assertIn(expected, pngs[0].name)
            self.assertIn(expected, audits[0].name)
            preserved = AttackGraph.from_json_file(audits[0])
            self.assertGreaterEqual(len(preserved.events), 1)

    def test_professional_route_automatically_paginates_a_long_graph(self):
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
        long_graph = AttackGraph.model_validate({
            "title": "Long professional graph",
            "preconditions": preconditions,
            "events": events,
        })

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            with patch.object(app, "REPORTS_DIR", reports), patch.object(
                    app, "OUTPUTS_DIR", outputs), patch.object(
                    app, "extract_attack_graph", return_value=long_graph):
                response = app.app.test_client().post(
                    "/generate",
                    data={
                        "provider": "mock",
                        "report": (
                            io.BytesIO(b"Technical incident report."),
                            "long.txt",
                        ),
                    },
                    content_type="multipart/form-data",
                )
            self.assertEqual(200, response.status_code)
            parts = sorted(outputs.glob("*_part*.png"))
            self.assertGreaterEqual(len(parts), 2)
            self.assertNotIn(b"Split long graph", response.data)
            self.assertIn(b"Long-graph pagination: automatic", response.data)

    def test_professional_route_rejects_a_ruleset_not_on_disk(self):
        # The selector offers the rule files that exist. Anything else, whether
        # a traversal attempt or a typo, falls back to the default instead of
        # reaching load_ruleset as a path fragment. What matters here is that
        # the fallback is a rule set on disk, not which one, so the assertion
        # reads the constant rather than naming a version.
        for tampered in ("../../secrets", "v9.9", "student-v1.2", ""):
            with self.subTest(ruleset=tampered):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    reports = root / "reports"
                    outputs = root / "outputs"
                    reports.mkdir()
                    outputs.mkdir()
                    with patch.object(app, "REPORTS_DIR", reports), patch.object(
                            app, "OUTPUTS_DIR", outputs):
                        response = app.app.test_client().post(
                            "/generate",
                            data={
                                "provider": "mock",
                                "ruleset": tampered,
                                "report": (io.BytesIO(b"Mock report text."),
                                           "mock.txt"),
                            },
                            content_type="multipart/form-data",
                        )
                    self.assertEqual(200, response.status_code)
                    pngs = list(outputs.glob("*.png"))
                    self.assertEqual(1, len(pngs))
                    self.assertIn(
                        f"__rules-{app.DEFAULT_RULESET}__", pngs[0].name)

    def test_professional_route_honours_a_rule_set_on_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            with patch.object(app, "REPORTS_DIR", reports), patch.object(
                    app, "OUTPUTS_DIR", outputs):
                response = app.app.test_client().post(
                    "/generate",
                    data={
                        "provider": "mock",
                        "ruleset": "v1.5",
                        "report": (io.BytesIO(b"Mock report text."), "mock.txt"),
                    },
                    content_type="multipart/form-data",
                )
            self.assertEqual(200, response.status_code)
            pngs = list(outputs.glob("*.png"))
            self.assertEqual(1, len(pngs))
            # The rule set is recorded in the file name, so a run made under a
            # non-baseline version can never be mistaken for a baseline run.
            self.assertIn("__rules-v1.5__", pngs[0].name)

    def test_image_only_pdf_is_explained_not_just_refused(self):
        # Printing a web page or scanning a document produces a PDF whose
        # words are pixels. Refusing it is correct; saying only that nothing
        # was extracted leaves the reader unable to tell that from a corrupt
        # file, or to know what to do instead.
        from ingest import _no_text_message

        message = _no_text_message(Path("saved-page.pdf"))
        self.assertIn("saved-page.pdf", message)
        self.assertIn("no readable text", message)
        self.assertIn(".txt", message)
        self.assertIn("select and copy", message)

    def test_non_pdf_empty_input_gets_its_own_message(self):
        from ingest import _no_text_message

        message = _no_text_message(Path("notes.docx"))
        self.assertIn("notes.docx", message)
        self.assertNotIn("pixels", message)

    def test_professional_route_rejects_unsupported_file(self):
        response = app.app.test_client().post(
            "/generate",
            data={
                "provider": "mock",
                "ruleset": "v1.5",
                "report": (io.BytesIO(b"not a report"), "payload.exe"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(400, response.status_code)

    def test_student_get_route_still_works(self):
        self.assertEqual(200, student_app.app.test_client().get("/").status_code)

    def test_student_mock_route_is_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            scenario = (
                "An unpatched service was reachable. The attacker exploited it, "
                "spread to other hosts, and encrypted files for ransom."
            )
            with patch.object(student_app, "REPORTS_DIR", reports), patch.object(
                    student_app, "OUTPUTS_DIR", outputs), patch.object(
                    student_app, "PROVIDER", "mock"), patch.object(
                    student_app, "MODEL", "none"):
                response = student_app.app.test_client().post(
                    "/generate", data={"scenario": scenario})
            self.assertEqual(200, response.status_code)
            pngs = list(outputs.glob("*.png"))
            self.assertEqual(1, len(pngs))
            self.assertIn(f"__rules-{student_app.RULESET}__", pngs[0].name)
            quality = list(outputs.glob("*.layout-quality.json"))
            audits = [
                path for path in outputs.glob("*.json") if path not in quality
            ]
            self.assertEqual(1, len(audits))
            self.assertEqual(1, len(quality))

    def test_student_rejects_probable_mojibake_before_saving(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = Path(directory) / "reports"
            reports.mkdir()
            scenario = (
                "TfL鈥檚 network suffered 拢29 million in losses after the "
                "incident disrupted services.")
            with patch.object(student_app, "REPORTS_DIR", reports), patch.object(
                    student_app, "extract_attack_graph") as extraction:
                response = student_app.app.test_client().post(
                    "/generate", data={"scenario": scenario})
            self.assertEqual(400, response.status_code)
            extraction.assert_not_called()
            self.assertEqual([], list(reports.iterdir()))

    def test_student_unicode_round_trip_preserves_punctuation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            scenario = (
                "TfL’s unpatched service was reachable despite £29 million in "
                "risk. The attacker exploited it, spread to other hosts, and "
                "encrypted files for ransom.")
            with patch.object(student_app, "REPORTS_DIR", reports), patch.object(
                    student_app, "OUTPUTS_DIR", outputs), patch.object(
                    student_app, "PROVIDER", "mock"), patch.object(
                    student_app, "MODEL", "none"):
                student_app.app.test_client().post(
                    "/generate", data={"scenario": scenario})
            saved = (reports / "student_submission_1.txt").read_text(
                encoding="utf-8")
            self.assertEqual(scenario, saved)


if __name__ == "__main__":
    unittest.main()
