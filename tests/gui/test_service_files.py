import asyncio

from mcpscanner_gui.models import ScanRequest, ScanType
from mcpscanner_gui import service


class FakeFinding:
    def __init__(self, analyzer, severity, summary, threat_category):
        self.analyzer = analyzer
        self.severity = severity
        self.summary = summary
        self.threat_category = threat_category


class FakeBehavioral:
    def __init__(self, config):
        pass

    async def analyze(self, path, context=None):
        return [FakeFinding("behavioral", "MEDIUM", "mismatch", "DECEPTION")]


class FakeVulnPkg:
    def __init__(self, *a, **k):
        pass

    def analyze_path(self, path):
        return [FakeFinding("vulnerable_package", "HIGH", "CVE-1", "MALICIOUS_PACKAGE")]


def test_files_scan_collects_findings_into_one_item(tmp_path):
    target = tmp_path / "server.py"
    target.write_text("x = 1\n")
    req = ScanRequest(ScanType.FILES, str(target), ["behavioral", "vulnerable_package"], {})
    out = asyncio.run(
        service.run_scan(
            req, behavioral_factory=FakeBehavioral, vulnpkg_factory=FakeVulnPkg
        )
    )
    assert out.ok is True
    assert len(out.items) == 1
    assert out.items[0].name == "server.py"
    sevs = {f.severity for f in out.items[0].findings}
    assert sevs == {"MEDIUM", "HIGH"}


def test_files_scan_clean_is_safe(tmp_path):
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n")

    class CleanBehavioral:
        def __init__(self, config):
            pass

        async def analyze(self, path, context=None):
            return []

    req = ScanRequest(ScanType.FILES, str(target), ["behavioral"], {})
    out = asyncio.run(service.run_scan(req, behavioral_factory=CleanBehavioral))
    assert out.ok is True
    assert out.items[0].is_safe is True
