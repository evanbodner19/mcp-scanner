import asyncio

from mcpscanner_gui.models import ScanRequest, ScanType
from mcpscanner_gui import service


class FakeFinding:
    def __init__(self, analyzer, severity, summary, threat_category):
        self.analyzer = analyzer
        self.severity = severity
        self.summary = summary
        self.threat_category = threat_category


class FakeToolResult:
    def __init__(self, tool_name, status, is_safe, findings):
        self.tool_name = tool_name
        self.status = status
        self.is_safe = is_safe
        self.findings = findings


class FakeScanner:
    def __init__(self, config):
        self.config = config

    async def scan_remote_server_tools(self, server_url, auth=None, analyzers=None, http_headers=None):
        return [
            FakeToolResult("safe_tool", "completed", True, []),
            FakeToolResult(
                "bad_tool", "completed", False,
                [FakeFinding("yara", "HIGH", "danger", "EXEC")],
            ),
        ]


def test_remote_scan_normalizes_results():
    req = ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
    out = asyncio.run(service.run_scan(req, scanner_factory=FakeScanner))
    assert out.ok is True
    assert [i.name for i in out.items] == ["safe_tool", "bad_tool"]
    assert out.items[1].findings[0].severity == "HIGH"


def test_remote_scan_handles_exception():
    class BoomScanner:
        def __init__(self, config):
            pass

        async def scan_remote_server_tools(self, *a, **k):
            raise ConnectionError("no route to host")

    req = ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
    out = asyncio.run(service.run_scan(req, scanner_factory=BoomScanner))
    assert out.ok is False
    assert "no route to host" in out.error
