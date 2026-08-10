"""Offline tests for the evidence-first, coordinate-free semantic draft."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from semantic_draft import (  # noqa: E402
    IncidentSemanticDraft,
    IncidentSemanticDraftWire,
    build_semantic_draft_prompt,
    normalise_parallel_rank_groups,
    project_draft_to_skeleton,
    semantic_presentation_sidecar,
    validate_evidence_against_report,
)
from semantic_layout import plan_semantic_layout  # noqa: E402
from semantic_layout_renderer import render_semantic_layout  # noqa: E402
from schema import AttackGraph  # noqa: E402
import extract  # noqa: E402
import app as professional_app  # noqa: E402


GOLD = ROOT / "tests" / "fixtures" / "british_library_two_page_gold.json"


def _draft_from_gold() -> dict:
    gold = json.loads(GOLD.read_text(encoding="utf-8"))
    pages = []
    for page in gold["page_layout"]:
        rank_groups = [
            {
                "id": f"p{page['page']}_parallel_{index}",
                "node_ids": node_ids,
                "rationale": (
                    "parallel_prerequisite_band"
                    if page["page"] == 1
                    else "parallel_consequence_band"
                ),
            }
            for index, node_ids in enumerate(page["same_row_groups"], 1)
        ]
        pages.append({
            "page": page["page"],
            "title": page["title"],
            "entry_nodes": page["entry_nodes"],
            "exit_nodes": page["exit_nodes"],
            "rank_groups": rank_groups,
        })

    nodes = []
    for node in gold["nodes"]:
        item = {
            key: node[key]
            for key in (
                "id", "label", "role", "shape", "evidence_id",
                "evidence_status", "page", "branch", "tactic",
                "canonical_id", "continued_from_page", "continues_on_page",
            )
            if key in node
        }
        nodes.append(item)

    return {
        "title": "British Library cyber attack",
        "evidence": [
            {
                "id": item["id"],
                "quote": item["quote"],
                "status": item["status"],
                "page": item["page"],
            }
            for item in gold["evidence"]
        ],
        "nodes": nodes,
        "edges": gold["edges"],
        "pages": pages,
    }


class IncidentSemanticDraftTests(unittest.TestCase):
    def test_agreed_british_library_gold_validates_as_a_semantic_draft(self):
        draft = IncidentSemanticDraft.model_validate(_draft_from_gold())
        self.assertEqual(2, len(draft.pages))
        self.assertEqual(
            "bl_broad_access",
            next(
                node.canonical_id for node in draft.nodes
                if node.id == "bl_broad_access_continuation"
            ),
        )

    def test_contract_contains_no_coordinates_or_attack_assignments(self):
        schema = IncidentSemanticDraft.model_json_schema()
        property_names = set()

        def collect_properties(value):
            if isinstance(value, dict):
                property_names.update(value.get("properties", {}))
                for nested in value.values():
                    collect_properties(nested)
            elif isinstance(value, list):
                for nested in value:
                    collect_properties(nested)

        collect_properties(schema)
        for forbidden in (
            "coordinate", "center_px", "x_position", "y_position",
            "technique", "mitigations",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, property_names)

    def test_api_schema_enforces_each_node_role_and_shape(self):
        from anthropic.lib._parse._transform import transform_schema

        schema = transform_schema(
            IncidentSemanticDraftWire.model_json_schema())
        definitions = schema["$defs"]
        expected = {
            "SemanticEventNode": ("event", "rectangle"),
            "SemanticStateNode": ("state", "ellipse"),
            "SemanticContinuationNode": (
                "continuation_state", "ellipse"),
            "SemanticAnnotationNode": ("annotation", "annotation"),
        }
        for definition, (role, shape) in expected.items():
            with self.subTest(definition=definition):
                properties = definitions[definition]["properties"]
                self.assertEqual([role], properties["role"]["enum"])
                self.assertEqual([shape], properties["shape"]["enum"])

    def test_api_schema_enforces_each_edge_relation_and_style(self):
        from anthropic.lib._parse._transform import transform_schema

        schema = transform_schema(
            IncidentSemanticDraftWire.model_json_schema())
        definitions = schema["$defs"]
        expected = {
            "SemanticCausalEdge": ("causal", "solid"),
            "SemanticAnnotationEdge": ("annotation", "dashed"),
        }
        for definition, (relation, style) in expected.items():
            with self.subTest(definition=definition):
                properties = definitions[definition]["properties"]
                self.assertEqual(
                    [relation], properties["relation"]["enum"])
                self.assertEqual([style], properties["style"]["enum"])

    def test_api_tm_schema_uses_the_installed_attack_catalogue(self):
        from anthropic.lib._parse._transform import transform_schema

        schema = transform_schema(
            extract.TechniqueAssignmentsWire.model_json_schema())
        properties = schema["$defs"][
            "TechniqueAssignmentWire"]["properties"]
        self.assertEqual(
            set(extract.KNOWN_TECHNIQUES),
            set(properties["technique"]["enum"]),
        )
        self.assertEqual(
            set(extract.KNOWN_MITIGATIONS),
            set(properties["mitigations"]["items"]["enum"]),
        )

    def test_event_requires_tactic_and_rectangle(self):
        data = _draft_from_gold()
        event = next(node for node in data["nodes"]
                     if node["role"] == "event")
        event["shape"] = "ellipse"
        with self.assertRaises(ValidationError):
            IncidentSemanticDraft.model_validate(data)

    def test_state_cannot_carry_a_tactic_badge(self):
        data = _draft_from_gold()
        state = next(node for node in data["nodes"]
                     if node["role"] == "state")
        state["tactic"] = "IA"
        with self.assertRaises(ValidationError):
            IncidentSemanticDraft.model_validate(data)

    def test_annotation_cannot_become_a_causal_step(self):
        data = _draft_from_gold()
        annotation = next(
            node for node in data["nodes"] if node["role"] == "annotation")
        event = next(node for node in data["nodes"]
                     if node["role"] == "event")
        data["edges"].append({
            "source": annotation["id"],
            "target": event["id"],
            "relation": "causal",
            "style": "solid",
            "logic": None,
        })
        with self.assertRaisesRegex(ValidationError, "annotation nodes"):
            IncidentSemanticDraft.model_validate(data)

    def test_causal_edges_must_alternate_event_and_state(self):
        data = _draft_from_gold()
        events = [node for node in data["nodes"]
                  if node["role"] == "event" and node["page"] == 1]
        data["edges"].append({
            "source": events[0]["id"],
            "target": events[1]["id"],
            "relation": "causal",
            "style": "solid",
            "logic": None,
        })
        with self.assertRaisesRegex(ValidationError, "alternation"):
            IncidentSemanticDraft.model_validate(data)

    def test_rank_group_can_mix_semantic_shapes(self):
        draft = IncidentSemanticDraft.model_validate(_draft_from_gold())
        page_one_group = draft.pages[0].rank_groups[0]
        by_id = {node.id: node for node in draft.nodes}
        shapes = {by_id[node_id].shape
                  for node_id in page_one_group.node_ids}
        self.assertEqual({"ellipse", "annotation"}, shapes)

    def test_rank_group_cannot_hide_a_causal_sequence(self):
        data = _draft_from_gold()
        data["pages"][0]["rank_groups"][0]["node_ids"] = [
            "bl_target_info",
            "bl_access_method",
        ]
        with self.assertRaisesRegex(ValidationError, "causally ordered"):
            IncidentSemanticDraft.model_validate(data)

    def test_one_node_cannot_be_forced_into_two_rank_groups(self):
        data = _draft_from_gold()
        data["pages"][0]["rank_groups"].append({
            "id": "overlap",
            "node_ids": ["bl_no_mfa", "bl_remote_server"],
            "rationale": "parallel_prerequisite_band",
        })
        with self.assertRaisesRegex(ValidationError, "more than one rank group"):
            IncidentSemanticDraft.model_validate(data)

    def test_parallel_outcomes_and_related_annotation_are_inferred(self):
        data = _draft_from_gold()
        data["pages"][1]["rank_groups"] = []
        draft = IncidentSemanticDraft.model_validate(data)
        normalised = normalise_parallel_rank_groups(draft)
        inferred = normalised.pages[1].rank_groups[0]
        self.assertEqual("parallel_consequence_band", inferred.rationale)
        self.assertEqual(
            {
                "bl_discover_data",
                "bl_encrypt_data",
                "bl_destroy_servers",
                "bl_continuity_note",
            },
            set(inferred.node_ids),
        )

    def test_alternative_methods_are_inferred_as_parallel(self):
        data = _draft_from_gold()
        data["pages"][0]["rank_groups"] = []
        draft = IncidentSemanticDraft.model_validate(data)
        normalised = normalise_parallel_rank_groups(draft)
        groups = normalised.pages[0].rank_groups
        self.assertTrue(any(
            group.rationale == "parallel_attack_methods"
            and set(group.node_ids) == {"bl_phishing", "bl_bruteforce"}
            for group in groups
        ))

    def test_parallel_normalisation_does_not_change_graph_content(self):
        data = _draft_from_gold()
        data["pages"][1]["rank_groups"] = []
        draft = IncidentSemanticDraft.model_validate(data)
        normalised = normalise_parallel_rank_groups(draft)
        self.assertEqual(draft.nodes, normalised.nodes)
        self.assertEqual(draft.edges, normalised.edges)
        self.assertEqual(
            project_draft_to_skeleton(draft),
            project_draft_to_skeleton(normalised),
        )

    def test_semantic_layout_honours_both_confirmed_same_row_bands(self):
        draft = IncidentSemanticDraft.model_validate(_draft_from_gold())
        plan = plan_semantic_layout(draft)
        self.assertEqual(2, len(plan.pages))
        for semantic_page, planned_page in zip(draft.pages, plan.pages):
            by_id = {node.id: node for node in planned_page.nodes}
            for group in semantic_page.rank_groups:
                self.assertEqual(
                    1, len({by_id[node_id].rank
                            for node_id in group.node_ids}))

    def test_semantic_layout_is_strictly_top_down(self):
        draft = IncidentSemanticDraft.model_validate(_draft_from_gold())
        plan = plan_semantic_layout(draft)
        for page in plan.pages:
            by_id = {node.id: node for node in page.nodes}
            for edge in page.edges:
                if edge.relation == "causal":
                    self.assertLess(
                        by_id[edge.source].rank,
                        by_id[edge.target].rank,
                    )

    def test_semantic_layout_is_deterministic_and_keeps_shapes(self):
        draft = IncidentSemanticDraft.model_validate(_draft_from_gold())
        first = plan_semantic_layout(draft)
        second = plan_semantic_layout(draft)
        self.assertEqual(first, second)
        source_shapes = {node.id: node.shape for node in draft.nodes}
        planned_shapes = {
            node.id: node.shape
            for page in first.pages for node in page.nodes
        }
        self.assertEqual(source_shapes, planned_shapes)

    def test_semantic_layout_has_no_same_row_overlap(self):
        draft = IncidentSemanticDraft.model_validate(_draft_from_gold())
        plan = plan_semantic_layout(draft)
        for page in plan.pages:
            by_rank = {}
            for node in page.nodes:
                by_rank.setdefault(node.rank, []).append(node)
            for nodes in by_rank.values():
                ordered = sorted(nodes, key=lambda item: item.x)
                for left, right in zip(ordered, ordered[1:]):
                    self.assertLessEqual(left.right + 30, right.x)

    def test_semantic_renderer_writes_two_readable_pages(self):
        from PIL import Image

        draft = IncidentSemanticDraft.model_validate(_draft_from_gold())
        skeleton = project_draft_to_skeleton(draft)
        skeleton["events"] = [
            {
                **event,
                "technique": sorted(
                    extract._TACTIC_TECHNIQUES[event["tactic"]]
                )[0],
                "mitigations": [],
            }
            for event in skeleton["events"]
        ]
        graph = AttackGraph.model_validate(skeleton)
        with tempfile.TemporaryDirectory() as temporary:
            paths = render_semantic_layout(
                graph,
                draft,
                str(Path(temporary) / "british-library.png"),
            )
            self.assertEqual(2, len(paths))
            for index, path in enumerate(paths, 1):
                self.assertTrue(Path(path).is_file())
                self.assertIn(f"_part{index}.png", path)
                with Image.open(path) as image:
                    self.assertGreaterEqual(image.width, 1248)
                    self.assertGreaterEqual(image.height, 710)

    def test_continuation_state_must_preserve_canonical_label(self):
        data = _draft_from_gold()
        continuation = next(
            node for node in data["nodes"]
            if node["role"] == "continuation_state"
        )
        continuation["label"] = "Changed boundary wording"
        with self.assertRaisesRegex(ValidationError, "preserve the state label"):
            IncidentSemanticDraft.model_validate(data)

    def test_report_evidence_must_be_a_contiguous_quotation(self):
        data = _draft_from_gold()
        # A compact synthetic report is enough to test deterministic grounding.
        report = "Alpha happened. " + " ".join(
            item["quote"] for item in data["evidence"]
            if item["status"] != "derived"
        )
        draft = IncidentSemanticDraft.model_validate(data)
        self.assertEqual([], validate_evidence_against_report(draft, report))

        data["evidence"][0]["quote"] = "A paraphrase not present in the report"
        broken = IncidentSemanticDraft.model_validate(data)
        self.assertEqual(
            ["ev_recon: evidence quote is not a contiguous report excerpt"],
            validate_evidence_against_report(broken, report),
        )

    def test_direct_cross_page_edge_is_rejected(self):
        data = _draft_from_gold()
        data["edges"].append({
            "source": "bl_broad_access",
            "target": "bl_discover_data",
            "relation": "causal",
            "style": "solid",
            "logic": None,
        })
        with self.assertRaisesRegex(ValidationError, "cross-page causality"):
            IncidentSemanticDraft.model_validate(data)

    def test_prompt_is_report_agnostic_and_separates_semantics_from_tm(self):
        prompt = build_semantic_draft_prompt("A supplied incident narrative.")
        self.assertIn("Do NOT assign ATT&CK Technique", prompt)
        self.assertIn("parallel outcomes", prompt.casefold())
        self.assertIn("continuation_state", prompt)
        self.assertNotIn("British Library", prompt)
        self.assertNotIn("Finance, HR", prompt)

    def test_projection_recomposes_pages_without_annotations_or_tm(self):
        draft = IncidentSemanticDraft.model_validate(_draft_from_gold())
        skeleton = project_draft_to_skeleton(draft)
        event_by_id = {event["id"]: event for event in skeleton["events"]}
        state_by_id = {
            state["id"]: state for state in skeleton["preconditions"]
        }

        self.assertNotIn("bl_broad_access_continuation", state_by_id)
        self.assertIn("bl_broad_access", event_by_id["bl_discover_data"]["parents"])
        self.assertIn("bl_broad_access", event_by_id["bl_encrypt_data"]["parents"])
        self.assertNotIn("bl_segmentation_note", state_by_id)
        self.assertNotIn("bl_continuity_note", state_by_id)

        serialised = json.dumps(skeleton)
        self.assertNotIn('"technique"', serialised)
        self.assertNotIn('"mitigations"', serialised)

    def test_projection_preserves_or_and_exact_event_evidence(self):
        data = _draft_from_gold()
        draft = IncidentSemanticDraft.model_validate(data)
        skeleton = project_draft_to_skeleton(draft)
        event_by_id = {event["id"]: event for event in skeleton["events"]}
        state_by_id = {
            state["id"]: state for state in skeleton["preconditions"]
        }

        self.assertEqual(
            {"bl_phishing", "bl_bruteforce"},
            set(state_by_id["bl_access_method"]["parents"]),
        )
        evidence_by_id = {
            item["id"]: item["quote"] for item in data["evidence"]
        }
        self.assertEqual(
            evidence_by_id["ev_access_method"],
            event_by_id["bl_phishing"]["source_evidence"],
        )
        self.assertEqual(
            "possible", event_by_id["bl_phishing"]["evidence_status"])

    def test_sidecar_retains_annotations_pages_and_rank_groups(self):
        draft = IncidentSemanticDraft.model_validate(_draft_from_gold())
        sidecar = semantic_presentation_sidecar(draft)
        self.assertEqual(
            {"bl_segmentation_note", "bl_continuity_note"},
            {item["id"] for item in sidecar["annotations"]},
        )
        self.assertEqual(2, len(sidecar["pages"]))
        self.assertEqual(
            {
                "bl_target_info",
                "bl_no_mfa",
                "bl_security_gap",
                "bl_flat_topology",
                "bl_segmentation_note",
            },
            set(sidecar["pages"][0]["rank_groups"][0]["node_ids"]),
        )
        self.assertNotIn("coordinate", json.dumps(sidecar).casefold())

    def test_opt_in_extraction_uses_exactly_two_model_calls(self):
        data = _draft_from_gold()
        draft_json = json.dumps(data)
        calls = []

        def fake_call(system, user, model, response_model):
            calls.append(response_model)
            if response_model is IncidentSemanticDraftWire:
                return draft_json
            self.assertIs(response_model, extract.TechniqueAssignmentsWire)
            skeleton = project_draft_to_skeleton(
                IncidentSemanticDraft.model_validate(data))
            assignments = []
            for event in skeleton["events"]:
                technique = sorted(
                    extract._TACTIC_TECHNIQUES[event["tactic"]])[0]
                assignments.append({
                    "id": event["id"],
                    "technique": technique,
                    "mitigations": [],
                })
            return json.dumps({"assignments": assignments})

        report = "\n".join(
            item["quote"] for item in data["evidence"]
            if item["status"] != "derived"
        )
        with patch.dict(extract._PROVIDERS, {"semantic-test": fake_call}), \
                patch.dict(extract._DEFAULT_MODELS,
                           {"semantic-test": "test-model"}):
            result = extract.extract_attack_graph_semantic(
                report, provider="semantic-test")

        self.assertEqual(
            [
                IncidentSemanticDraftWire,
                extract.TechniqueAssignmentsWire,
            ],
            calls,
        )
        self.assertEqual(
            len(project_draft_to_skeleton(
                IncidentSemanticDraft.model_validate(data))["events"]),
            len(result.graph.events),
        )
        self.assertEqual(2, len(result.presentation["pages"]))

    def test_semantic_extraction_repairs_one_graph_wide_error(self):
        valid_data = _draft_from_gold()
        invalid_data = json.loads(json.dumps(valid_data))
        page_one_events = [
            node for node in invalid_data["nodes"]
            if node["role"] == "event" and node["page"] == 1
        ]
        invalid_data["edges"].append({
            "source": page_one_events[0]["id"],
            "target": page_one_events[1]["id"],
            "relation": "causal",
            "style": "solid",
            "logic": None,
        })
        calls = []
        users = []

        def fake_call(system, user, model, response_model):
            calls.append(response_model)
            users.append(user)
            if response_model is IncidentSemanticDraftWire:
                semantic_call = sum(
                    item is IncidentSemanticDraftWire for item in calls)
                payload = invalid_data if semantic_call == 1 else valid_data
                return json.dumps(payload)
            self.assertIs(response_model, extract.TechniqueAssignmentsWire)
            skeleton = project_draft_to_skeleton(
                IncidentSemanticDraft.model_validate(valid_data))
            return json.dumps({"assignments": [{
                "id": event["id"],
                "technique": sorted(
                    extract._TACTIC_TECHNIQUES[event["tactic"]])[0],
                "mitigations": [],
            } for event in skeleton["events"]]})

        report = "\n".join(
            item["quote"] for item in valid_data["evidence"]
            if item["status"] != "derived"
        )
        with patch.dict(extract._PROVIDERS, {"semantic-test": fake_call}), \
                patch.dict(extract._DEFAULT_MODELS,
                           {"semantic-test": "test-model"}):
            result = extract.extract_attack_graph_semantic(
                report, provider="semantic-test")

        self.assertEqual(
            [
                IncidentSemanticDraftWire,
                IncidentSemanticDraftWire,
                extract.TechniqueAssignmentsWire,
            ],
            calls,
        )
        self.assertIn("LOCAL GRAPH-WIDE VALIDATION ERROR", users[1])
        self.assertTrue(result.graph.events)

    def test_semantic_extraction_stops_before_tm_after_one_failed_repair(self):
        invalid_data = _draft_from_gold()
        page_one_events = [
            node for node in invalid_data["nodes"]
            if node["role"] == "event" and node["page"] == 1
        ]
        invalid_data["edges"].append({
            "source": page_one_events[0]["id"],
            "target": page_one_events[1]["id"],
            "relation": "causal",
            "style": "solid",
            "logic": None,
        })
        calls = []

        def fake_call(system, user, model, response_model):
            calls.append(response_model)
            return json.dumps(invalid_data)

        report = "\n".join(
            item["quote"] for item in invalid_data["evidence"]
            if item["status"] != "derived"
        )
        with patch.dict(extract._PROVIDERS, {"semantic-test": fake_call}), \
                patch.dict(extract._DEFAULT_MODELS,
                           {"semantic-test": "test-model"}):
            with self.assertRaisesRegex(
                    RuntimeError, "after one bounded correction"):
                extract.extract_attack_graph_semantic(
                    report, provider="semantic-test")

        self.assertEqual(
            [IncidentSemanticDraftWire, IncidentSemanticDraftWire], calls)

    def test_semantic_extraction_repairs_one_cross_tactic_assignment(self):
        data = _draft_from_gold()
        skeleton = project_draft_to_skeleton(
            IncidentSemanticDraft.model_validate(data))
        calls = []
        assignment_calls = 0

        def fake_call(system, user, model, response_model):
            nonlocal assignment_calls
            calls.append(response_model)
            if response_model is IncidentSemanticDraftWire:
                return json.dumps(data)
            self.assertIs(response_model, extract.TechniqueAssignmentsWire)
            assignment_calls += 1
            assignments = []
            for index, event in enumerate(skeleton["events"]):
                technique = sorted(
                    extract._TACTIC_TECHNIQUES[event["tactic"]])[0]
                if assignment_calls == 1 and index == 0:
                    technique = "T1486"
                assignments.append({
                    "id": event["id"],
                    "technique": technique,
                    "mitigations": [],
                })
            return json.dumps({"assignments": assignments})

        report = "\n".join(
            item["quote"] for item in data["evidence"]
            if item["status"] != "derived"
        )
        with patch.dict(extract._PROVIDERS, {"semantic-test": fake_call}), \
                patch.dict(extract._DEFAULT_MODELS,
                           {"semantic-test": "test-model"}):
            result = extract.extract_attack_graph_semantic(
                report, provider="semantic-test")

        self.assertEqual(
            [
                IncidentSemanticDraftWire,
                extract.TechniqueAssignmentsWire,
                extract.TechniqueAssignmentsWire,
            ],
            calls,
        )
        self.assertNotEqual("T1486", result.graph.events[0].technique)

    def test_frozen_v14_entry_point_remains_separate(self):
        self.assertIsNot(
            extract.extract_attack_graph,
            extract.extract_attack_graph_semantic,
        )

    def test_semantic_mode_runs_when_posted_but_is_not_offered_in_the_page(
            self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reports = root / "reports"
            outputs = root / "outputs"
            reports.mkdir()
            outputs.mkdir()
            with patch.object(
                professional_app, "REPORTS_DIR", reports
            ), patch.object(
                professional_app, "OUTPUTS_DIR", outputs
            ), patch.object(
                professional_app,
                "extract_attack_graph",
                side_effect=AssertionError(
                    "legacy extraction must not run in semantic mode"),
            ):
                response = professional_app.app.test_client().post(
                    "/generate",
                    data={
                        "provider": "mock",
                        "semantic_mode": "1",
                        # Stated rather than left to the default. The semantic
                        # pipeline refuses v1.6, and v1.6 is now what a request
                        # that chooses nothing gets, so this test used to pass
                        # only because the default happened to be a version the
                        # pipeline accepts.
                        "ruleset": "v1.4",
                        "report": (
                            io.BytesIO(
                                b"The attacker exploited an exposed service."
                            ),
                            "semantic.txt",
                        ),
                    },
                    content_type="multipart/form-data",
                )
            self.assertEqual(200, response.status_code)
            # The pipeline still runs when the field is posted, which is what
            # this test drives. What changed is that the page no longer offers
            # a control for it: a figure from this pipeline takes no rule set,
            # refuses v1.6, is not read by `measure_runs.py`, and is drawn by
            # its own renderer without the visual-syntax key, the page-width
            # budget or the vector output every other figure now carries, so it
            # cannot be compared with anything the write-up reports.
            self.assertNotIn(b'name="semantic_mode"', response.data)
            self.assertEqual(1, len(list(outputs.glob("*.png"))))
            audits = list(outputs.glob("*.semantic.json"))
            self.assertEqual(1, len(audits))
            audit = json.loads(audits[0].read_text(encoding="utf-8"))
            self.assertIn("graph", audit)
            self.assertIn("draft", audit)
            self.assertIn("presentation", audit)


if __name__ == "__main__":
    unittest.main()
