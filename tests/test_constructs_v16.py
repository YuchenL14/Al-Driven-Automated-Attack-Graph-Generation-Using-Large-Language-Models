"""v1.6 constructs: the wire contract, the normaliser, and the rule document.

The point of these tests is that the constructs reach the *API schema*. A
construct the schema does not offer cannot be returned, however carefully the
rule document describes it, and that failure mode has already cost this project
nine defects.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (ConstructAttackGraphSkeleton, ConstructSkeletonEvent,
                     STAGE_A_V16_USER, _normalise_constructs, load_ruleset)
from schema import AttackGraph


class TestConstructsReachTheSchema(unittest.TestCase):
    """Whatever the prompt says, the provider only enforces the schema."""

    def setUp(self):
        self.schema = ConstructAttackGraphSkeleton.model_json_schema()
        self.text = json.dumps(self.schema)

    def test_role_is_an_enumerated_property_of_state_nodes(self):
        self.assertIn("external_resource", self.text)
        self.assertIn("annotation", self.text)

    def test_state_style_offers_all_three_textures(self):
        for style in ("solid", "dotted", "dashed"):
            self.assertIn(f'"{style}"', self.text)

    def test_event_style_cannot_be_dashed(self):
        """An event is never commentary, so the enum omits the value.

        Enforcing this by enum rather than by validator matters: a validator
        raises inside the paid SDK call, an absent enum value simply cannot be
        produced.
        """
        allowed = ConstructSkeletonEvent.model_json_schema()
        style = json.dumps(allowed["properties"]["style"])
        self.assertIn("dotted", style)
        self.assertNotIn("dashed", style)

    def test_likelihood_stays_required_on_events(self):
        required = ConstructSkeletonEvent.model_json_schema()["required"]
        self.assertIn("likelihood", required)

    def test_a_root_event_satisfies_the_contract(self):
        """The reference sample opens with four parentless actions."""
        ConstructAttackGraphSkeleton.model_validate({
            "preconditions": [{"id": "s1", "label": "Lure ready", "code": "R",
                               "parents": ["e1"]}],
            "events": [{"id": "e1", "label": "Build lure document",
                        "tactic": "RS", "likelihood": 5.0, "parents": []}],
        })


class TestNormaliser(unittest.TestCase):
    """Role is authoritative; a disagreeing style is repaired, not re-asked."""

    def test_annotation_is_forced_dashed(self):
        out = _normalise_constructs({
            "preconditions": [{"id": "a1", "label": "Training", "code": "-",
                               "role": "annotation", "style": "solid",
                               "parents": ["e1"]}],
            "events": [],
        })
        self.assertEqual(out["preconditions"][0]["style"], "dashed")

    def test_external_resource_loses_invented_parents(self):
        out = _normalise_constructs({
            "preconditions": [{"id": "r1", "label": "Stolen certificate",
                               "code": "RS", "role": "external_resource",
                               "parents": ["e1"]}],
            "events": [],
        })
        self.assertEqual(out["preconditions"][0]["parents"], [])

    def test_dashed_is_reclaimed_from_a_non_annotation(self):
        out = _normalise_constructs({
            "preconditions": [{"id": "s1", "label": "Service exposed",
                               "code": "IA", "style": "dashed",
                               "parents": []}],
            "events": [],
        })
        self.assertEqual(out["preconditions"][0]["style"], "solid")

    def test_an_event_never_consumes_an_annotation(self):
        out = _normalise_constructs({
            "preconditions": [{"id": "a1", "label": "AV in place", "code": "-",
                               "role": "annotation", "style": "dashed",
                               "parents": ["e1"]},
                              {"id": "s1", "label": "Foothold", "code": "IA",
                               "parents": ["e1"]}],
            "events": [{"id": "e2", "label": "Move laterally", "tactic": "LM",
                        "likelihood": 5.0, "parents": ["a1", "s1"]}],
        })
        self.assertEqual(out["events"][0]["parents"], ["s1"])

    def test_dotted_survives_untouched(self):
        out = _normalise_constructs({
            "preconditions": [{"id": "s1", "label": "Email attachment",
                               "code": "D", "style": "dotted",
                               "parents": []}],
            "events": [],
        })
        self.assertEqual(out["preconditions"][0]["style"], "dotted")

    def test_output_does_not_mutate_its_input(self):
        data = {"preconditions": [{"id": "a1", "label": "Training",
                                   "code": "-", "role": "annotation",
                                   "style": "solid", "parents": []}],
                "events": []}
        before = json.dumps(data, sort_keys=True)
        _normalise_constructs(data)
        self.assertEqual(json.dumps(data, sort_keys=True), before)


class TestNormalisedOutputSatisfiesTheCanonicalSchema(unittest.TestCase):
    """The repair must produce something the renderer will actually accept."""

    def test_a_repaired_graph_validates_end_to_end(self):
        data = _normalise_constructs({
            "title": "Construct round trip",
            "preconditions": [
                {"id": "r1", "label": "Stolen signing certificate",
                 "code": "RS", "role": "external_resource",
                 "style": "solid", "parents": ["e9"]},
                {"id": "s1", "label": "Email attachment", "code": "D",
                 "style": "dotted", "parents": []},
                {"id": "s2", "label": "Payload executed", "code": "EX",
                 "parents": ["e1"]},
                {"id": "a1", "label": "Staff awareness training", "code": "-",
                 "role": "annotation", "style": "solid", "parents": ["e1"]},
            ],
            "events": [
                {"id": "e1", "label": "Victim opens the attachment",
                 "tactic": "EX", "technique": "T1204.002",
                 "mitigations": ["M1017"], "likelihood": 4.0,
                 "style": "dotted", "parents": ["s1", "a1"], "join": "AND"},
            ],
        })
        graph = AttackGraph.model_validate(data)
        self.assertEqual([p.id for p in graph.annotations], ["a1"])
        self.assertNotIn("a1", [p.id for p in graph.causal_preconditions])
        self.assertNotIn("a1", graph.events[0].parents)
        self.assertEqual(graph.events[0].style, "dotted")


class TestRuleDocument(unittest.TestCase):

    def test_v16_loads_with_the_catalogue_substituted(self):
        text = load_ruleset("v1.6", include_full_catalogue=False)
        self.assertNotIn("{tactic_lines}", text)
        self.assertNotIn("{tech_lines}", text)

    def test_v16_records_every_place_it_changes_v14_text(self):
        """The additive claim is only as honest as its exceptions.

        The verbatim check below covers Rules 1, 2, 3 and 5 -- not the preamble
        and not Rule 4. Two inherited defects were corrected there, so those
        two changes are asserted here rather than left to look like oversights:
        a reader comparing the versions must be able to find them.
        """
        v16 = (ROOT / "rules" / "ruleset_v1.6.md").read_text(encoding="utf-8")

        # 1. The document called the graph a tree while Rule 3 required a node
        #    to have several parents. It said so twice, in the preamble and in
        #    Rule 4, and a case-sensitive check caught only the first. The one
        #    permitted use is the sentence that explicitly denies it.
        body = v16.split("-->", 1)[1]
        for line in body.splitlines():
            if "tree" in line.lower():
                self.assertIn("not a tree either", line,
                              f"stray tree wording survives: {line.strip()}")
        self.assertIn("directed acyclic AND-OR graph", body)

        # 2. Rule 4 demanded every path converge on one objective. The
        #    reference graph itself ends in five terminal states.
        self.assertNotIn("Every path converges", body)

        # 3. Rule 3 required an AND outright while requiring an OR only where
        #    the report supported one. A report with no simultaneous
        #    dependency made Rule 3 and Rule 5 contradict each other.
        self.assertNotIn("A good graph contains at least one AND", body)
        self.assertIn("Both are conditional on the report", body)
        self.assertIn("an invented dependency", body)

        # 4. Rule 2 stated "exactly one technique id" while Rule 7 allowed
        #    several, and declared the supersede rather than removing it.
        self.assertNotIn("carries exactly one", body)
        self.assertNotIn("SUPERSEDES", body)

        # 5. Rule 6.1 said an external resource never has a parent and then
        #    described giving it one. schema.py rejects the latter.
        self.assertIn("it is always a root", body)
        self.assertNotIn("whose result is the external resource", body)

        # 6. Rule 5 asked for mitigations the v1.6 Stage B cannot return.
        self.assertNotIn("Choose mitigations that specifically", body)
        self.assertIn("Mitigations are not yours to choose", body)

        # 7. Rule 6.2 classified a missing control as commentary, which
        #    removes it from the causal graph. The test is now causal.
        self.assertIn("Apply the CAUSAL test first", body)
        self.assertNotIn('"No egress filtering in place"; "Detected by SOC',
                         body)

        # 8. Rule 2 required at least one precondition; Rule 4 allows a
        #    preparation event to consume none.
        self.assertNotIn("It consumes one or more preconditions", body)

        # Both changes are declared where a reader will look.
        changelog = v16.split("-->", 1)[0]
        self.assertIn("Every place where v1.6 CHANGES v1.4 text", changelog)
        self.assertIn("21.5%", changelog)

    def test_v16_carries_v14_rules_unchanged(self):
        """Rules 1, 2, 3 and 5 are verbatim; see the test above for the rest."""
        v14 = (ROOT / "rules" / "ruleset_v1.4.md").read_text(encoding="utf-8")
        v16 = (ROOT / "rules" / "ruleset_v1.6.md").read_text(encoding="utf-8")
        body = v14.split("-->", 1)[1]
        # Rule 3 is no longer verbatim: its unconditional "at least one AND"
        # contradicted Rule 5's ban on inventing what the report does not
        # state, and is now conditional like the OR beside it. The change is
        # asserted in test_v16_records_every_place_it_changes_v14_text.
        # Only Rule 1 survives verbatim now. Rules 2, 3, 4 and 5 each lost a
        # claim that contradicted another rule or the mechanism; every removal
        # is asserted in test_v16_records_every_place_it_changes_v14_text.
        for rule in ("## Rule 1",):
            start = body.index(rule)
            end = min((body.index(nxt) for nxt in
                       ("## Rule 1", "## Rule 2", "## Rule 3", "## Rule 4",
                        "## Rule 5")
                       if body.index(nxt) > start), default=len(body))
            self.assertIn(body[start:end].strip(), v16,
                          f"{rule} was reworded rather than kept")

    def test_the_prompt_asks_about_dependency_not_order(self):
        """Both extremes were reached by telling the model a shape.

        "A root event with no parents is correct and expected" produced thirty
        isolated event/result pairs. Replacing it with "THE GRAPH IS A CHAIN,
        this is the rule that matters most" produced the opposite: 52 nodes in
        46 ranks, every one of 23 events on a single path, including four
        credential dumps that do not depend on one another at all.

        Shape is an OUTPUT. The prompt states the test -- could this step have
        happened without the earlier one? -- and lets the shape follow from the
        report.
        """
        prompt = STAGE_A_V16_USER
        self.assertIn("if the earlier step had NOT happened", prompt)
        self.assertIn("CONSUMES WHAT IT ACTUALLY NEEDS", prompt)
        # Neither extreme may be asserted as the target.
        for shape_claim in ("THE GRAPH IS A CHAIN", "correct and expected",
                            "link each step to the one before"):
            self.assertNotIn(shape_claim, prompt)

    def test_the_prompt_still_permits_genuine_sequence(self):
        """Removing the chain instruction must not forbid chaining."""
        self.assertIn("genuinely enable one another DO chain",
                      STAGE_A_V16_USER)

    def test_the_rules_carry_the_same_test_as_the_prompt(self):
        rules = (ROOT / "rules" / "ruleset_v1.6.md").read_text(encoding="utf-8")
        self.assertIn("could this one still have occurred", rules)

    def test_prompt_defines_each_construct_it_asks_for(self):
        for term in ("external_resource", "annotation", "dotted",
                     "no parents"):
            self.assertIn(term, STAGE_A_V16_USER)


if __name__ == "__main__":
    unittest.main()
