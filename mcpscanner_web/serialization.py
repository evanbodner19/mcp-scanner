"""Serialize ScanOutcome to the same dict shape as the JSON export."""

from __future__ import annotations

from dataclasses import asdict

from mcpscanner_gui.models import ScanOutcome


def outcome_to_dict(outcome: ScanOutcome) -> dict:
    """Return the outcome as a plain dict, identical to ``dataclasses.asdict``.

    This is the single serialization used by both the JSON export
    (``controllers.outcome_to_json``) and the SSE ``result`` event, so saved
    reports and downstream tooling keep parsing unchanged.
    """
    return asdict(outcome)
