"""A cut-off answer is not a wrong answer, and must not be corrected as one.

A v1.6 run returned 24 preconditions referring to events e1..e23 and exactly
one event. The wire schema asks for at least one event, so it parsed; the
structural gate then reported "the events array is missing 22 events" and the
correction told the model to send them all again. With the same output ceiling
it truncates again, so the single permitted retry could never succeed and the
run was billed twice for nothing.

`stop_reason` was already available. It was only read on the path where parsing
FAILED, which is the one path where truncation does not need detecting.
"""

import os
import sys
import unittest
from unittest.mock import patch

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from extract import (_GRAPH_RESPONSE_TOKENS_DEFAULT, _GRAPH_TOKENS_ENV,
                     _SMALL_RESPONSE_TOKENS, _TruncatedResponse,
                     _graph_response_tokens, is_structural_stage_a_fault)


class TestBudget(unittest.TestCase):

    def test_the_default_is_larger_than_the_one_that_truncated(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(_GRAPH_TOKENS_ENV, None)
            self.assertEqual(_graph_response_tokens(),
                             _GRAPH_RESPONSE_TOKENS_DEFAULT)
            self.assertGreater(_graph_response_tokens(), 8192)

    def test_a_graph_response_still_outranks_an_assignment_response(self):
        self.assertGreater(_graph_response_tokens(), _SMALL_RESPONSE_TOKENS)

    def test_it_is_overridable_for_a_larger_report(self):
        with patch.dict(os.environ, {_GRAPH_TOKENS_ENV: "32000"}):
            self.assertEqual(_graph_response_tokens(), 32000)

    def test_a_nonsense_override_falls_back_rather_than_disabling_the_limit(self):
        for value in ("", "abc", "0", "-1"):
            with self.subTest(value=value):
                with patch.dict(os.environ, {_GRAPH_TOKENS_ENV: value}):
                    self.assertEqual(_graph_response_tokens(),
                                     _GRAPH_RESPONSE_TOKENS_DEFAULT)


class TestTruncationIsItsOwnFault(unittest.TestCase):

    def test_it_is_not_read_as_a_repairable_graph_shape(self):
        """Routing it structurally is what caused the futile retry."""
        message = ("the model ran out of output space after 16384 tokens, so "
                   "the answer is incomplete rather than wrong")
        self.assertFalse(is_structural_stage_a_fault(message))

    def test_the_message_names_the_override_that_fixes_it(self):
        try:
            raise _TruncatedResponse(
                f"the model ran out of output space. Raise {_GRAPH_TOKENS_ENV}")
        except _TruncatedResponse as error:
            self.assertIn(_GRAPH_TOKENS_ENV, str(error))

    def test_it_stops_the_run_instead_of_spending_the_retry(self):
        """Behaviour, not source text.

        An earlier version of this test asserted that a handling branch
        existed in the file. It did exist, and it was dead: RuntimeError is
        not in the tuple the Stage A loop catches, so the exception never
        reached it. Checking that the code is present is not the same as
        checking that it runs.
        """
        from extract import _extract_hierarchical

        calls = []

        def call(system, user, model, response_model=None):
            calls.append(response_model)
            raise _TruncatedResponse(
                "the model ran out of output space after 16384 tokens. "
                f"Raise {_GRAPH_TOKENS_ENV}")

        with self.assertRaises(RuntimeError) as caught:
            _extract_hierarchical("report text", call, "model", "v1.6")
        self.assertEqual(1, len(calls), "a retry was paid for regardless")
        message = str(caught.exception)
        self.assertIn("ran out of output space", message)
        self.assertIn(_GRAPH_TOKENS_ENV, message)
        self.assertNotIn("events array is missing", message)


class TestStopReasonIsCheckedOnTheSuccessPath(unittest.TestCase):
    """The bug was that it was only checked when parsing failed."""

    def test_the_check_precedes_reading_the_parsed_output(self):
        source = (ROOT / "src" / "extract.py").read_text(encoding="utf-8")
        check = source.index('== "max_tokens"')
        read = source.index('parsed = getattr(msg, "parsed_output", None)')
        self.assertLess(check, read,
                        "a truncated response would be accepted before the "
                        "stop_reason check could reject it")


class TestWorstCaseStillFitsTheCostGuard(unittest.TestCase):
    """Doubling the output ceiling doubles the guard's worst-case estimate."""

    def test_two_stage_a_calls_and_two_stage_b_calls_fit(self):
        from extract import _configured_max_cost_usd
        stage_a_in, stage_b_in = 8200, 6000
        worst = 2 * (stage_a_in * 3e-6 + _graph_response_tokens() * 15e-6)
        worst += 2 * (stage_b_in * 3e-6 + _SMALL_RESPONSE_TOKENS * 15e-6)
        self.assertLess(
            worst, _configured_max_cost_usd(),
            f"worst case ${worst:.3f} exceeds the guard; raise the ceiling "
            "deliberately or lower the output budget")


if __name__ == "__main__":
    unittest.main()
