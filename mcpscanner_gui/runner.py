"""Runs async scans on a worker thread and marshals results to the UI thread."""

from __future__ import annotations

import asyncio
import queue
import threading

from mcpscanner_gui.models import ScanOutcome, ScanRequest


async def _default_scan_fn(request: ScanRequest) -> ScanOutcome:
    from mcpscanner_gui.service import run_scan

    return await run_scan(request)


class ScanRunner:
    def __init__(self, scan_fn=None):
        self._scan_fn = scan_fn or _default_scan_fn
        self.queue: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None

    def start(self, request: ScanRequest) -> None:
        self._thread = threading.Thread(
            target=self._run, args=(request,), daemon=True
        )
        self._thread.start()

    def _run(self, request: ScanRequest) -> None:
        try:
            outcome = asyncio.run(self._scan_fn(request))
        except Exception as exc:  # noqa: BLE001 - reported to the UI
            outcome = ScanOutcome(ok=False, items=[], error=str(exc))
        self.queue.put(outcome)

    def poll(self) -> ScanOutcome | None:
        try:
            return self.queue.get_nowait()
        except queue.Empty:
            return None
