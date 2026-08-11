"""A student's state codes were dropped from the drawing without a word.

The suppression itself is right: an ATT&CK tactic classifies adversary
behaviour, so the reference syntax forbids one on a state and the renderer
drops it. One submission labelled all nine of its states with tactic
abbreviations and every ellipse came out bare, with nothing on the page or
beside it saying that anything had been left out.

Silent correction is the defect class this project keeps finding in itself, so
the omission is now reported. The code stays in the saved graph either way.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import _suppressed_state_code_note
from visual_syntax import active_profile, state_badge_code


def _graph(*codes, role=None):
    return {
        "events": [{"id": "e1", "label": "Do a thing", "parents": ["s0"],
                    "tactic": "IA"}],
        "preconditions": [
            {"id": f"s{index}", "label": f"State {index}", "code": code,
             "parents": [], **({"role": role} if role else {})}
            for index, code in enumerate(codes)
        ],
    }


class SuppressedStateCodeNoteTests(unittest.TestCase):
    def test_a_tactic_code_on_a_state_is_reported(self):
        note = _suppressed_state_code_note(_graph("IA"))
        self.assertEqual(1, len(note))
        self.assertIn("IA", note[0])

    def test_an_ordinary_code_is_not(self):
        self.assertEqual((), _suppressed_state_code_note(_graph("P0", "R1")))

    def test_it_counts_states_and_lists_codes_once(self):
        note = _suppressed_state_code_note(_graph("IA", "IA", "CA"))[0]
        self.assertIn("3 of your states", note)
        self.assertEqual(1, note.count("IA"))

    def test_one_state_reads_as_one(self):
        self.assertIn("One of your states",
                      _suppressed_state_code_note(_graph("CA"))[0])

    def test_it_says_the_code_is_kept(self):
        """The point is that nothing was destroyed, only not drawn."""

        note = _suppressed_state_code_note(_graph("IA"))[0]
        self.assertIn("still in the saved graph", note)

    def test_an_annotation_is_not_counted(self):
        """An annotation carries no ATT&CK metadata by construction."""

        self.assertEqual(
            (), _suppressed_state_code_note(_graph("IA", role="annotation")))

    def test_the_note_matches_what_the_renderer_actually_drops(self):
        """The student note must describe what the figure really shows.

        The renderer no longer reads `Precondition.code` at all: the badge is
        derived from role and parentage, so every stored code is dropped from
        the drawing, not only the prohibited ones. The note therefore has to
        fire for a prohibited code, and what it fires about is that the code
        is not drawn.
        """

        for code in sorted(active_profile().prohibited_state_badges)[:5]:
            self.assertNotEqual(code, state_badge_code("precondition", False))
            self.assertTrue(_suppressed_state_code_note(_graph(code)))

    def test_a_graph_with_no_states_produces_nothing(self):
        self.assertEqual((), _suppressed_state_code_note({"events": []}))


if __name__ == "__main__":
    unittest.main()
