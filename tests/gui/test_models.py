from mcpscanner_gui.models import (
    FindingView,
    ScanItem,
    ScanOutcome,
    ScanRequest,
    ScanType,
    highest_severity,
)


def test_highest_severity_picks_worst():
    fs = [
        FindingView("yara", "LOW", "a", "x"),
        FindingView("llm", "HIGH", "b", "y"),
        FindingView("api", "MEDIUM", "c", "z"),
    ]
    assert highest_severity(fs) == "HIGH"


def test_highest_severity_empty_is_safe():
    assert highest_severity([]) == "SAFE"


def test_scan_item_highest_severity_property():
    item = ScanItem("tool", "completed", False, [FindingView("yara", "MEDIUM", "s", "c")])
    assert item.highest_severity == "MEDIUM"


def test_scan_request_defaults():
    req = ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
    assert req.bearer_token is None
    assert req.keys == {}


def test_scan_outcome_error():
    out = ScanOutcome(ok=False, items=[], error="boom")
    assert out.ok is False and out.error == "boom"
