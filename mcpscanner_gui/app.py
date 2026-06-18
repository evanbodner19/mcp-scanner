"""Main application window."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from mcpscanner_gui.runner import ScanRunner
from mcpscanner_gui.store import KeyStore
from mcpscanner_gui.views.results_view import ResultsView
from mcpscanner_gui.views.scan_view import ScanView
from mcpscanner_gui.views.settings_view import SettingsView

POLL_MS = 100


class ScannerApp(tk.Tk):
    def __init__(self, store=None, runner=None):
        super().__init__()
        self.title("MCP Scanner")
        self.geometry("760x640")
        self._store = store or KeyStore()
        self._runner = runner or ScanRunner()

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        self.scan_view = ScanView(self.notebook, self._store, on_scan=self._start_scan)
        self.results_view = ResultsView(self.notebook)
        self.settings_view = SettingsView(self.notebook, self._store)

        self.notebook.add(self.scan_view, text="Scan")
        self.notebook.add(self.results_view, text="Results")
        self.notebook.add(self.settings_view, text="Settings")

    def _start_scan(self, request) -> None:
        self.results_view.set_status("Scanning…")
        self.notebook.select(self.results_view)
        self._runner.start(request)
        self.after(POLL_MS, self._poll)

    def _poll(self) -> None:
        outcome = self._runner.poll()
        if outcome is None:
            self.after(POLL_MS, self._poll)
            return
        self.results_view.show(outcome)


def main() -> None:
    app = ScannerApp()
    app.mainloop()
