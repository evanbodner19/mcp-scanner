import asyncio
import json

from mcpscanner_gui.models import ScanRequest, ScanType
from mcpscanner_web import jobs


class FakeToolResult:
    def __init__(self, name, safe):
        self.tool_name = name
        self.status = "completed"
        self.is_safe = safe
        self.findings = []


class FakeScanner:
    def __init__(self, config):
        pass

    async def scan_remote_server_tools(self, *a, **k):
        return [FakeToolResult("t1", True)]


def test_sse_format():
    out = jobs.sse_format("result", {"ok": True})
    assert out == 'event: result\ndata: {"ok": true}\n\n'


def test_run_job_fills_queue_and_result():
    async def scenario():
        reg = jobs.JobRegistry()
        job = reg.create()
        assert reg.get(job.id) is job
        req = ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
        await jobs.run_job(job, req, {"scanner_factory": FakeScanner})
        assert job.status == "done"
        assert job.result.ok is True
        events = []
        while not job.queue.empty():
            events.append(await job.queue.get())
        names = [e[0] for e in events]
        assert names == ["progress", "result", "done"]
        result_event = dict(events)["result"]
        assert result_event["items"][0]["name"] == "t1"

    asyncio.run(scenario())


def test_event_stream_replays_done_job():
    async def scenario():
        reg = jobs.JobRegistry()
        job = reg.create()
        req = ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
        await jobs.run_job(job, req, {"scanner_factory": FakeScanner})
        # drain queue so only the replay path can produce events
        while not job.queue.empty():
            await job.queue.get()
        chunks = []
        async for chunk in jobs.event_stream(job):
            chunks.append(chunk)
        joined = "".join(chunks)
        assert "event: result" in joined
        assert "event: done" in joined

    asyncio.run(scenario())
