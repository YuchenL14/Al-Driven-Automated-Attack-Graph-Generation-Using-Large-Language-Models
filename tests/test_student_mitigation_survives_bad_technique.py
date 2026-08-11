"""A rejected technique must not take a valid mitigation down with it.

The student edition's contract is that numbers the student supplies are drawn
as they wrote them. A run broke it: a step written as

    The attacker disabled the endpoint security agent (T1562, M1038).

produced a step with no technique and no mitigation. T1562 is retired, so
rejecting it and reporting the successors is correct. M1038 is a current
mitigation identifier and was rejected with it, because the code applied the
student's mitigations only inside the branch guarded by their technique having
been accepted. The student was shown the retirement note and nothing about the
mitigation, so the loss was silent.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from extract import _TECHNIQUE_MITIGATIONS  # noqa: E402
from student_identifiers import (RETIRED_TECHNIQUES,  # noqa: E402
                                 classify_identifiers, summarise)


def _events(technique: str | None, mitigations: list[str]) -> list[dict]:
    return [{
        "id": "e5",
        "label": "Disable endpoint security agent",
        "stated_technique": technique,
        "stated_mitigations": mitigations,
    }]


class MitigationSurvivalTests(unittest.TestCase):
    def test_a_retired_technique_does_not_discard_a_valid_mitigation(self):
        self.assertIn("T1562", RETIRED_TECHNIQUES)
        accepted, notes = classify_identifiers(
            _events("T1562", ["M1038"]), _TECHNIQUE_MITIGATIONS)

        self.assertIsNone(accepted["e5"].technique)
        self.assertEqual(("M1038",), accepted["e5"].mitigations)

        kinds = {note.kind for note in notes}
        self.assertIn("retired_technique", kinds)
        self.assertIn("kept_mitigation_without_technique", kinds)

    def test_the_student_is_told_the_mitigation_survived(self):
        _, notes = classify_identifiers(
            _events("T1562", ["M1038"]), _TECHNIQUE_MITIGATIONS)
        text = " ".join(summarise(notes))
        self.assertIn("M1038", text)
        self.assertIn("T1562", text)

    def test_an_unknown_technique_behaves_the_same_way(self):
        accepted, notes = classify_identifiers(
            _events("T9999", ["M1038"]), _TECHNIQUE_MITIGATIONS)
        self.assertIsNone(accepted["e5"].technique)
        self.assertEqual(("M1038",), accepted["e5"].mitigations)
        self.assertIn("kept_mitigation_without_technique",
                      {note.kind for note in notes})

    def test_an_unknown_mitigation_is_still_rejected_and_reported(self):
        accepted, notes = classify_identifiers(
            _events("T1562", ["M9999"]), _TECHNIQUE_MITIGATIONS)
        self.assertEqual((), accepted["e5"].mitigations)
        self.assertIn("unknown_mitigation", {note.kind for note in notes})
        # Nothing survived, so there is nothing to say survived.
        self.assertNotIn("kept_mitigation_without_technique",
                         {note.kind for note in notes})

    def test_an_accepted_technique_is_unaffected(self):
        accepted, notes = classify_identifiers(
            _events("T1566.001", ["M1017"]), _TECHNIQUE_MITIGATIONS)
        self.assertEqual("T1566.001", accepted["e5"].technique)
        self.assertEqual(("M1017",), accepted["e5"].mitigations)
        self.assertNotIn("kept_mitigation_without_technique",
                         {note.kind for note in notes})

    def test_a_step_the_student_left_open_is_not_reported_as_kept(self):
        accepted, notes = classify_identifiers(
            _events(None, []), _TECHNIQUE_MITIGATIONS)
        self.assertIsNone(accepted["e5"].technique)
        self.assertEqual((), accepted["e5"].mitigations)
        self.assertIn("inferred_technique", {note.kind for note in notes})
        self.assertNotIn("kept_mitigation_without_technique",
                         {note.kind for note in notes})


if __name__ == "__main__":
    unittest.main()
