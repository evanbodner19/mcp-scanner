import json
from dataclasses import asdict

from mcpscanner_gui.models import FindingView, ScanItem, ScanOutcome
from mcpscanner_gui.controllers import outcome_to_json
from mcpscanner_web.serialization import outcome_to_dict


def _sample():
    return ScanOutcome(
        ok=True,
        items=[
            ScanItem(
                name="bad_tool", status="completed", is_safe=False,
                findings=[FindingView("yara", "HIGH", "danger", "EXEC")],
            )
        ],
    )


def test_outcome_to_dict_matches_asdict():
    out = _sample()
    assert outcome_to_dict(out) == asdict(out)


def test_outcome_to_dict_matches_export_json_shape():
    out = _sample()
    assert outcome_to_dict(out) == json.loads(outcome_to_json(out))
