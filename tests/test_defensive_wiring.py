"""Defensive code must be reachable from a production path, not only tests.

Several safety mechanisms in this project were written, documented and covered
by unit tests, yet no production module ever called them, so they could not
protect a real run. A passing suite therefore said nothing about whether the
defence was connected.

Two guards are applied here:

* a static check that every safety-critical callable is referenced from inside
  ``src`` and not only from the test suite;
* dynamic checks that drive the real entry points and assert the gate fired.
"""

from __future__ import annotations

import ast
import inspect
import sys
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT / "tests"))

import attack_graph  # noqa: E402
import extract  # noqa: E402
from schema import AttackGraph  # noqa: E402


# Callables whose whole purpose is to reject or report a bad result during a
# real run. If one of these stops being referenced from src, the defence has
# been disconnected.
#
# ``validate_layout_quality`` is deliberately absent. It is the strict variant
# that raises, and it exists to hold the frozen fixtures to the acceptance
# limits inside the suite. Its production counterpart is ``quality_warnings``,
# which reports without withholding the drawing, and which is guarded below.
SAFETY_CRITICAL = (
    "validate_layout_ir",
    "validate_layout_plan",
    "validate_macro_layout",
    "validate_lossless_split",
    "quality_warnings",
    "measure_page_quality",
    "write_quality_report",
    "_skeleton_graph_problems",
    "_structure_problems",
    "_technique_tactic_mismatches",
    # _repair_alternation was here. It is deliberately gone: it inserted a
    # bridging EVENT wherever one precondition parented another, labelled
    # "Transition from the previous state", and Stage B then assigned it a real
    # ATT&CK technique. A run produced exactly that -- T1059.003 on a step the
    # report never mentions. Repairing a graph by adding to it makes the figure
    # assert something that did not happen, which no amount of correctness
    # elsewhere makes acceptable. The same two faults are now reported by
    # _skeleton_graph_problems and corrected by the model.
    "selected_png_renderer",
)


def _src_trees() -> dict[str, ast.AST]:
    return {
        path.name: ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for path in sorted(SRC.glob("*.py"))
    }


def _defined_names(trees: dict[str, ast.AST]) -> set[str]:
    names: set[str] = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(node.name)
    return names


def _referenced_names(trees: dict[str, ast.AST]) -> set[str]:
    """Every name used as a value or attribute anywhere in src.

    A definition is not a reference, so a function that is only defined and
    never used shows up as missing.
    """

    names: set[str] = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    names.add(alias.asname or alias.name)
    return names


class StaticWiringTests(unittest.TestCase):
    def test_safety_critical_callables_still_exist(self):
        defined = _defined_names(_src_trees())
        missing = [name for name in SAFETY_CRITICAL if name not in defined]
        self.assertEqual(
            [], missing,
            f"safety-critical callables no longer defined in src: {missing}. "
            "Update SAFETY_CRITICAL deliberately if a mechanism was retired.",
        )

    def test_no_safety_mechanism_is_reachable_only_from_tests(self):
        trees = _src_trees()
        referenced = _referenced_names(trees)
        orphaned = [name for name in SAFETY_CRITICAL if name not in referenced]
        self.assertEqual(
            [], orphaned,
            "these safety mechanisms are defined but never called from any "
            f"production module, so only the test suite exercises them: "
            f"{orphaned}",
        )


class ApiEnforcedConstraintTests(unittest.TestCase):
    """A rule the model is merely asked to follow is not a constraint.

    Stage A described the required precondition/event alternation in prose and
    the model still returned every event with an empty parents list, because
    the schema sent to the API marked the field optional with no minimum. The
    constraint has to reach the provider to bind.
    """

    def test_likelihood_is_required_in_the_api_schema(self):
        # The reference sample scores 13 of its 14 action nodes. Left optional
        # the field was simply skipped, and a whole run came back with no cyan
        # badge anywhere.
        for model, key in (
            (extract.AttackGraphSkeleton, "SkeletonEvent"),
            (extract.EvidenceGraphWire, "EvidenceEventWire"),
        ):
            with self.subTest(model=model.__name__):
                event = model.model_json_schema()["$defs"][key]
                self.assertIn("likelihood", event.get("required", []))

    def test_a_root_event_is_expressible(self):
        # The reference sample opens with four attacker actions that consume
        # nothing: creating the extension, building the lure PDF, gathering
        # addresses, configuring the website. Those root events are what give
        # it a wide top, so the contract must permit them.
        model = extract.AttackGraphSkeleton.model_validate({
            "title": "Root events",
            "preconditions": [
                {"id": "p1", "label": "Extension available", "code": "R",
                 "parents": ["e1"]},
            ],
            "events": [
                {"id": "e1", "label": "Create the extension", "tactic": "RS",
                 "likelihood": 9, "parents": []},
            ],
        })
        self.assertEqual([], model.events[0].parents)

    def test_projected_contract_still_allows_a_root_event(self):
        # The evidence-first pathway keeps a root event when the source gives
        # no surrounding state, so its local check must stay permissive.
        model = extract.ProjectedAttackGraphSkeleton.model_validate({
            "title": "Root event",
            "preconditions": [
                {"id": "p1", "label": "Outcome", "code": "R",
                 "parents": ["e1"]},
            ],
            "events": [
                {"id": "e1", "label": "Step", "tactic": "IA", "parents": [],
                 "likelihood": 5},
            ],
        })
        self.assertEqual([], model.events[0].parents)


class ApiVisibleModelTests(unittest.TestCase):
    """A model sent as ``output_format`` must not police what a schema cannot.

    The SDK validates the response against the model given as the output
    format, inside the provider call. Any rule that a JSON Schema cannot carry
    therefore fires there, before the local gate can produce a diagnosis the
    model could act on, and the paid run is lost to a message that names
    nothing. This has now happened three times: an out-of-catalogue technique,
    an event with no parents, and a dangling parent reference.
    """

    DANGLING = {
        "title": "Dangling reference",
        "preconditions": [
            {"id": "p1", "label": "Service exposed", "code": "R",
             "parents": []},
            {"id": "p2", "label": "Foothold", "code": "R", "parents": ["e9"]},
        ],
        "events": [
            {"id": "e1", "label": "Gain entry", "tactic": "IA",
             "parents": ["p1"], "likelihood": 7,
             "source_evidence": "The attacker gained entry.",
             "evidence_status": "reported", "evidence_confidence": 80},
        ],
    }

    def test_evidence_stage_a_wire_model_defers_referential_checks(self):
        # Accepted here so the payload returns and the gate can name the
        # missing node; the strict contract still rejects it afterwards.
        extract.EvidenceGraphWire.model_validate(self.DANGLING)
        with self.assertRaises(ValidationError):
            extract.AttackGraph.model_validate(self.DANGLING)

    def test_evidence_stage_a_sends_the_wire_model_not_the_contract(self):
        source = inspect.getsource(extract._extract_hierarchical)
        self.assertIn("stage_a_model = EvidenceGraphWire", source)
        self.assertNotIn("stage_a_model = AttackGraph\n", source)

    def test_gate_names_the_missing_node_for_the_evidence_path(self):
        problems = extract._skeleton_graph_problems(
            self.DANGLING, require_event_parents=False)
        joined = "; ".join(problems)
        self.assertIn("e9", joined)
        self.assertTrue(extract.is_structural_stage_a_fault(joined))


class RuntimeWiringTests(unittest.TestCase):
    def test_stage_a_gate_runs_on_the_professional_path_only(self):
        original = extract._skeleton_graph_problems
        seen = {"professional": False, "student": False}

        def spy(data, **kwargs):
            seen[spy.mode] = True
            return original(data, **kwargs)

        try:
            extract._skeleton_graph_problems = spy
            spy.mode = "student"
            extract.extract_attack_graph(
                "mock student text", provider="mock", ruleset="student-v1")
            spy.mode = "professional"
            extract.extract_attack_graph(
                "mock report", provider="mock", ruleset="v1.4")
        finally:
            extract._skeleton_graph_problems = original

        self.assertTrue(
            seen["professional"],
            "the professional route must apply the Stage A structural gate",
        )
        self.assertFalse(
            seen["student"],
            "the student contract allows root events, so the professional "
            "gate must not be applied to it",
        )

    def test_rendering_records_page_quality(self):
        graph = AttackGraph.model_validate({
            "title": "Wiring fixture",
            "preconditions": [
                {"id": "p1", "label": "Service exposed", "code": "R",
                 "parents": []},
                {"id": "p2", "label": "Foothold obtained", "code": "R",
                 "parents": ["e1"]},
            ],
            "events": [
                {"id": "e1", "label": "Gain entry", "tactic": "IA",
                 "technique": "T1133", "mitigations": [], "likelihood": 7,
                 "parents": ["p1"], "join": "AND"},
            ],
        })
        original = attack_graph.measure_page_quality
        seen = {"called": False}

        def spy(page_model):
            seen["called"] = True
            return original(page_model)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "graph.png"
            try:
                attack_graph.measure_page_quality = spy
                attack_graph.render_split(graph, str(output))
            finally:
                attack_graph.measure_page_quality = original
            report = attack_graph.quality_report_path(str(output))
            self.assertTrue(
                report.is_file(),
                "every rendered run must leave an auditable metrics record",
            )

        self.assertTrue(seen["called"])


if __name__ == "__main__":
    unittest.main()
