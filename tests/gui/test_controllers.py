import json

import pytest

from mcpscanner_gui.controllers import (
    ANALYZERS_BY_TYPE,
    build_scan_request,
    outcome_to_json,
    required_providers,
    summary_line,
)
from mcpscanner_gui.models import FindingView, ScanItem, ScanOutcome, ScanType


def test_analyzer_catalog_per_type():
    assert "llm" in ANALYZERS_BY_TYPE[ScanType.REMOTE]
    assert "behavioral" in ANALYZERS_BY_TYPE[ScanType.FILES]


def test_required_providers_dedups_and_maps():
    assert required_providers(["yara", "llm", "behavioral"]) == ["llm"]
    assert required_providers(["yara", "readiness"]) == []
    assert required_providers(["api", "virustotal"]) == ["cisco_api", "virustotal"]


def test_build_request_valid():
    req = build_scan_request(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
    assert req.target == "http://x/mcp"
    assert req.analyzers == ["yara"]


def test_build_request_empty_target_raises():
    with pytest.raises(ValueError, match="target"):
        build_scan_request(ScanType.REMOTE, "  ", ["yara"], {})


def test_build_request_no_analyzers_raises():
    with pytest.raises(ValueError, match="analyzer"):
        build_scan_request(ScanType.REMOTE, "http://x/mcp", [], {})


def test_build_request_missing_required_key_raises():
    with pytest.raises(ValueError, match="llm"):
        build_scan_request(ScanType.REMOTE, "http://x/mcp", ["llm"], {})


def test_build_request_with_required_key_ok():
    req = build_scan_request(ScanType.REMOTE, "http://x/mcp", ["llm"], {"llm": "sk-1"})
    assert req.keys["llm"] == "sk-1"


def test_summary_line_counts_unsafe():
    out = ScanOutcome(
        ok=True,
        items=[
            ScanItem("a", "completed", True, []),
            ScanItem("b", "completed", False, [FindingView("yara", "HIGH", "s", "c")]),
        ],
    )
    assert "1" in summary_line(out)


def test_outcome_to_json_roundtrips():
    out = ScanOutcome(
        ok=True,
        items=[ScanItem("a", "completed", False, [FindingView("yara", "HIGH", "s", "c")])],
    )
    parsed = json.loads(outcome_to_json(out))
    assert parsed["items"][0]["name"] == "a"
    assert parsed["items"][0]["findings"][0]["severity"] == "HIGH"
