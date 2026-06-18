"""Results tab: summary, table, detail, export."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk

from mcpscanner_gui.controllers import outcome_to_json, summary_line
from mcpscanner_gui.models import ScanOutcome


class ResultsView(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=12)
        self._outcome: ScanOutcome | None = None

        self._summary = tk.StringVar(value="No scan run yet.")
        ttk.Label(self, textvariable=self._summary, font=("", 11, "bold")).pack(
            anchor="w", pady=(0, 8)
        )

        self.tree = ttk.Treeview(
            self, columns=("status", "severity"), height=10
        )
        self.tree.heading("#0", text="Item")
        self.tree.heading("status", text="Status")
        self.tree.heading("severity", text="Severity")
        self.tree.column("status", width=100, anchor="center")
        self.tree.column("severity", width=100, anchor="center")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self.detail = tk.Text(self, height=8, wrap="word")
        self.detail.pack(fill="both", expand=True, pady=(8, 0))

        ttk.Button(self, text="Export JSON…", command=self._export_dialog).pack(
            anchor="e", pady=(8, 0)
        )

    def show(self, outcome: ScanOutcome) -> None:
        self._outcome = outcome
        self._summary.set(summary_line(outcome))
        self.tree.delete(*self.tree.get_children())
        self.detail.delete("1.0", tk.END)
        for idx, item in enumerate(outcome.items):
            self.tree.insert(
                "", "end", iid=str(idx), text=item.name,
                values=(item.status, item.highest_severity),
            )

    def _on_select(self, event=None) -> None:
        if not self._outcome:
            return
        sel = self.tree.selection()
        if not sel:
            return
        item = self._outcome.items[int(sel[0])]
        self.detail.delete("1.0", tk.END)
        if item.is_safe:
            self.detail.insert(tk.END, f"{item.name}: no findings.\n")
            return
        self.detail.insert(tk.END, f"{item.name}\n\n")
        for f in item.findings:
            self.detail.insert(
                tk.END,
                f"[{f.severity}] {f.analyzer}: {f.threat_category}\n    {f.summary}\n",
            )

    def export(self, path: str) -> None:
        if self._outcome is None:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(outcome_to_json(self._outcome))

    def _export_dialog(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")]
        )
        if path:
            self.export(path)
