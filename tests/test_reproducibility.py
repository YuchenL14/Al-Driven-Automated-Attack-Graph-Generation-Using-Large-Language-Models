"""Offline checks for professional-run reproducibility and independent sampling."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import app  # noqa: E402
from reproducibility import (build_reproducibility_spec, cache_path,  # noqa: E402
                             graph_sha256, load_validated_graph,
                             store_validated_graph, write_run_manifest)
from schema import AttackGraph  # noqa: E402


def _graph(label: str) -> AttackGraph:
    return AttackGraph.model_validate({
        "title": f"{label} graph",
        "preconditions": [
            {"id": "p0", "label": "Initial access available", "code": "R"},
            {
                "id": "p1",
                "label": f"{label} result established",
                "code": "R",
                "parents": ["e0"],
            },
        ],
        "events": [{
            "id": "e0",
            "label": f"Perform {label} action",
            "tactic": "IA",
            "parents": ["p0"],
        }],
    })


class ReproducibilityCacheTests(unittest.TestCase):
    def setUp(self):
        self.spec = build_reproducibility_spec(
            ROOT,
            "Identical report text.",
            "v1.6",
            "anthropic",
            "claude-sonnet-5",
        )

    def test_identity_is_stable_and_covers_semantic_inputs(self):
        same = build_reproducibility_spec(
            ROOT,
            "Identical report text.",
            "v1.6",
            "anthropic",
            "claude-sonnet-5",
        )
        changed_source = build_reproducibility_spec(
            ROOT,
            "Different report text.",
            "v1.6",
            "anthropic",
            "claude-sonnet-5",
        )
        changed_model = build_reproducibility_spec(
            ROOT,
            "Identical report text.",
            "v1.6",
            "anthropic",
            "claude-sonnet-5-next",
        )
        self.assertEqual(self.spec.cache_key, same.cache_key)
        self.assertNotEqual(self.spec.cache_key, changed_source.cache_key)
        self.assertNotEqual(self.spec.cache_key, changed_model.cache_key)
        self.assertEqual(0, self.spec.decoding["temperature"])

    def test_first_validated_graph_is_immutable_replay_reference(self):
        first = _graph("first")
        second = _graph("second")
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory)
            store_validated_graph(cache_dir, self.spec, first)
            store_validated_graph(cache_dir, self.spec, second)
            replay = load_validated_graph(cache_dir, self.spec)
        self.assertEqual(first, replay)
        self.assertNotEqual(second, replay)

    def test_tampered_cache_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory)
            store_validated_graph(cache_dir, self.spec, _graph("first"))
            path = cache_path(cache_dir, self.spec.cache_key)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["graph"]["events"][0]["label"] = "Tampered action"
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertIsNone(load_validated_graph(cache_dir, self.spec))

    def test_manifest_records_run_mode_and_hashes(self):
        graph = _graph("first")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run.png"
            manifest = write_run_manifest(
                output,
                ROOT,
                self.spec,
                graph,
                cache_hit=True,
                independent_sample=False,
                pages=2,
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual("validated_replay", payload["mode"])
        self.assertEqual(self.spec.cache_key, payload["cache_key"])
        self.assertEqual(graph_sha256(graph), payload["graph_sha256"])
        self.assertEqual(2, payload["pages"])


class ProfessionalRouteReproducibilityTests(unittest.TestCase):
    @staticmethod
    def _post(client, *, independent: bool = False):
        data = {
            "provider": "mock",
            "ruleset": "v1.6",
            "report": (io.BytesIO(b"The same technical report."), "same.txt"),
        }
        if independent:
            data["fresh_sample"] = "1"
        return client.post(
            "/generate", data=data, content_type="multipart/form-data")

    def test_default_replay_is_exact_and_independent_sample_does_not_replace_it(self):
        first = _graph("first")
        independent = _graph("independent")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            client = app.app.test_client()
            with patch.object(app, "REPORTS_DIR", reports), patch.object(
                    app, "OUTPUTS_DIR", outputs), patch.object(
                    app, "extract_attack_graph",
                    side_effect=[first, independent]) as extraction:
                generated = self._post(client)
                replayed = self._post(client)
                sampled = self._post(client, independent=True)
                replayed_again = self._post(client)

            self.assertEqual(200, generated.status_code)
            self.assertEqual(200, replayed.status_code)
            self.assertEqual(200, sampled.status_code)
            self.assertEqual(200, replayed_again.status_code)
            self.assertEqual(2, extraction.call_count)
            self.assertIn(b"new frozen reference", generated.data)
            self.assertIn(b"validated replay", replayed.data)
            self.assertIn(b"independent sample", sampled.data)

            audits = sorted(
                path for path in outputs.glob("*.json")
                if not path.name.endswith((
                    ".layout-quality.json",
                    ".reproducibility.json",
                    ".semantic.json",
                ))
            )
            graphs = [AttackGraph.from_json_file(path) for path in audits]
            self.assertEqual([first, first, independent, first], graphs)

            manifests = sorted(outputs.glob("*.reproducibility.json"))
            modes = [
                json.loads(path.read_text(encoding="utf-8"))["mode"]
                for path in manifests
            ]
            self.assertEqual([
                "new_frozen_reference",
                "validated_replay",
                "independent_sample",
                "validated_replay",
            ], modes)

            pngs = sorted(outputs.glob("*.png"))
            digests = [hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in pngs]
            self.assertEqual(digests[0], digests[1])
            self.assertEqual(digests[0], digests[3])


if __name__ == "__main__":
    unittest.main()
