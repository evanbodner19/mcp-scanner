"""In-process async job registry and SSE event streaming for scans."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import AsyncIterator

from mcpscanner_gui import service
from mcpscanner_gui.models import ScanOutcome, ScanRequest
from mcpscanner_web.serialization import outcome_to_dict

_KEEPALIVE = ": keepalive\n\n"


class Job:
    def __init__(self, job_id: str):
        self.id = job_id
        self.status = "pending"
        self.result: ScanOutcome | None = None
        self.queue: asyncio.Queue = asyncio.Queue()


class JobRegistry:
    def __init__(self):
        self._jobs: dict[str, Job] = {}

    def create(self) -> Job:
        job = Job(uuid.uuid4().hex)
        self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)


async def run_job(job: Job, request: ScanRequest, factories: dict) -> None:
    """Run a scan to completion, pushing progress/result/done onto the queue.

    `factories` is forwarded to `service.run_scan` (scanner_factory,
    behavioral_factory, vulnpkg_factory) so tests can inject fakes. Engine
    failures already come back as ScanOutcome(ok=False); this never raises.
    """
    job.status = "running"
    await job.queue.put(
        ("progress", {"status": "running", "scan_type": request.scan_type.value})
    )
    outcome = await service.run_scan(request, **factories)
    job.result = outcome
    job.status = "done"
    await job.queue.put(("result", outcome_to_dict(outcome)))
    await job.queue.put(("done", {}))


def sse_format(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def event_stream(job: Job) -> AsyncIterator[str]:
    """Yield SSE-formatted strings for a job until a `done` event is seen.

    If the job already finished (queue drained), replay the final result so a
    late or reconnecting client still gets the outcome.
    """
    if job.status == "done" and job.queue.empty():
        yield sse_format("result", outcome_to_dict(job.result))
        yield sse_format("done", {})
        return

    while True:
        try:
            event, data = await asyncio.wait_for(job.queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            yield _KEEPALIVE
            continue
        yield sse_format(event, data)
        if event == "done":
            break
