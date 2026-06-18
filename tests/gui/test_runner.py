import time

from mcpscanner_gui.models import ScanOutcome, ScanRequest, ScanType
from mcpscanner_gui.runner import ScanRunner


def _wait_for_outcome(runner, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = runner.poll()
        if out is not None:
            return out
        time.sleep(0.01)
    raise AssertionError("no outcome produced in time")


def test_runner_delivers_outcome_via_queue():
    async def fake_scan(request):
        return ScanOutcome(ok=True, items=[], error=None)

    runner = ScanRunner(scan_fn=fake_scan)
    runner.start(ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {}))
    out = _wait_for_outcome(runner)
    assert out.ok is True


def test_runner_converts_exception_to_failed_outcome():
    async def boom(request):
        raise RuntimeError("kaboom")

    runner = ScanRunner(scan_fn=boom)
    runner.start(ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {}))
    out = _wait_for_outcome(runner)
    assert out.ok is False
    assert "kaboom" in out.error


def test_poll_returns_none_when_idle():
    runner = ScanRunner(scan_fn=None)
    assert runner.poll() is None
