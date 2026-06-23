# tests/web/test_api_scan.py
from fastapi.testclient import TestClient

from mcpscanner_web.server import create_app
from tests.web.test_api_config import FakeStore


class FakeToolResult:
    def __init__(self, name, safe, findings):
        self.tool_name = name
        self.status = "completed"
        self.is_safe = safe
        self.findings = findings


class FakeFinding:
    def __init__(self):
        self.analyzer = "yara"
        self.severity = "HIGH"
        self.summary = "danger"
        self.threat_category = "EXEC"


class FakeScanner:
    def __init__(self, config):
        pass

    async def scan_remote_server_tools(self, *a, **k):
        return [
            FakeToolResult("safe_tool", True, []),
            FakeToolResult("bad_tool", False, [FakeFinding()]),
        ]


def _client():
    store = FakeStore()
    return TestClient(create_app(store=store, scanner_factory=FakeScanner, version="5.0.0"))


def test_scan_validation_error_returns_400():
    c = _client()
    # empty target -> build_scan_request raises ValueError
    r = c.post("/api/scan", json={"scan_type": "remote", "target": "", "analyzers": ["yara"]})
    assert r.status_code == 400
    assert "target" in r.json()["error"].lower()


def test_scan_runs_and_streams_result():
    c = _client()
    r = c.post("/api/scan", json={"scan_type": "remote", "target": "http://x/mcp", "analyzers": ["yara"]})
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    # consume the SSE stream; the background task completes and emits result+done
    with c.stream("GET", f"/api/scan/{job_id}/events") as resp:
        text = "".join(chunk for chunk in resp.iter_text())
    assert "event: result" in text
    assert "bad_tool" in text
    assert "event: done" in text


def test_scan_poll_fallback():
    c = _client()
    r = c.post("/api/scan", json={"scan_type": "remote", "target": "http://x/mcp", "analyzers": ["yara"]})
    job_id = r.json()["job_id"]
    # drive completion via the stream first
    with c.stream("GET", f"/api/scan/{job_id}/events") as resp:
        for _ in resp.iter_text():
            pass
    poll = c.get(f"/api/scan/{job_id}").json()
    assert poll["status"] == "done"
    assert poll["result"]["items"][1]["name"] == "bad_tool"


def test_scan_unknown_job_404():
    c = _client()
    assert c.get("/api/scan/nope").status_code == 404
    assert c.get("/api/scan/nope/events").status_code == 404
