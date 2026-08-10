"""A test double that reproduces the provider's real validation seam.

Production ``call`` is :func:`extract._call_anthropic`, which ends with::

    msg = client.messages.parse(**request_kwargs)   # validates here
    ...
    return parsed.model_dump_json()

Two consequences follow, and neither was reproduced by the hand-written
``fake_call`` doubles used elsewhere in this suite:

1. ``call`` never returns a payload that violates ``response_model``. It either
   returns schema-valid JSON or raises.
2. A schema violation is therefore raised *inside* ``call``, not by the caller
   that validates afterwards.

Every recovery loop in :mod:`extract` depends on point 2, because the loop has
to catch the error to be able to correct it. A double that returns an invalid
string instead of raising exercises a code path that cannot occur in
production, which is how a call placed outside its own retry guard survived the
whole suite. Tests that care about recovery must use :func:`seam_accurate_call`.
"""

from __future__ import annotations

from typing import Callable

from pydantic import BaseModel

from schema import AttackGraph


PayloadFn = Callable[[str, str, str, type[BaseModel]], str]


def seam_accurate_call(payload: PayloadFn,
                       record: list[type[BaseModel]] | None = None):
    """Wrap a payload generator so it behaves like the real provider call.

    ``payload`` returns whatever JSON the model is being made to produce. The
    wrapper then applies the provider's own validation, so an answer that
    violates the requested schema raises from inside the call exactly as the
    Anthropic SDK raises it.
    """

    def call(system: str, user: str, model: str,
             response_model: type[BaseModel] = AttackGraph) -> str:
        if record is not None:
            record.append(response_model)
        raw = payload(system, user, model, response_model)
        validated = response_model.model_validate_json(raw)
        return validated.model_dump_json()

    return call


def scripted(*answers: str) -> PayloadFn:
    """Return successive canned answers, repeating the last one when exhausted."""

    state = {"index": 0}

    def payload(system: str, user: str, model: str,
                response_model: type[BaseModel]) -> str:
        index = min(state["index"], len(answers) - 1)
        state["index"] += 1
        return answers[index]

    return payload
