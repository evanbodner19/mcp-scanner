"""Scan tab: choose scan type, target, analyzers, keys; submit."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from mcpscanner_gui.controllers import (
    ANALYZERS_BY_TYPE,
    build_scan_request,
    required_providers,
)
from mcpscanner_gui.models import ScanType

PROVIDER_LABELS = {
    "llm": "LLM key",
    "cisco_api": "Cisco API key",
    "virustotal": "VirusTotal key",
}


class ScanView(ttk.Frame):
    def __init__(self, master, store, on_scan):
        super().__init__(master, padding=12)
        self._store = store
        self._on_scan = on_scan

        self.scan_type_var = tk.StringVar(value=ScanType.REMOTE.value)
        self.target_var = tk.StringVar(value="")
        self.bearer_var = tk.StringVar(value="")
        self._analyzer_vars: dict[str, tk.BooleanVar] = {}
        self._key_vars: dict[str, tk.StringVar] = {}

        type_frame = ttk.Frame(self)
        type_frame.pack(anchor="w")
        ttk.Radiobutton(
            type_frame, text="Remote server URL", value=ScanType.REMOTE.value,
            variable=self.scan_type_var, command=self._rebuild,
        ).pack(side="left")
        ttk.Radiobutton(
            type_frame, text="Source code / files", value=ScanType.FILES.value,
            variable=self.scan_type_var, command=self._rebuild,
        ).pack(side="left", padx=(8, 0))

        self._target_row = ttk.Frame(self)
        self._target_row.pack(fill="x", pady=(8, 0))
        ttk.Label(self._target_row, text="Target:").pack(side="left")
        ttk.Entry(self._target_row, textvariable=self.target_var, width=44).pack(
            side="left", fill="x", expand=True, padx=(8, 0)
        )
        self._browse_btn = ttk.Button(
            self._target_row, text="Browse…", command=self._browse
        )

        self._bearer_row = ttk.Frame(self)
        ttk.Label(self._bearer_row, text="Bearer token (optional):").pack(side="left")
        ttk.Entry(
            self._bearer_row, textvariable=self.bearer_var, width=36, show="*"
        ).pack(side="left", padx=(8, 0))

        self._analyzer_frame = ttk.LabelFrame(self, text="Analyzers", padding=8)
        self._analyzer_frame.pack(fill="x", pady=(8, 0))
        self._key_frame = ttk.LabelFrame(self, text="Required keys", padding=8)
        self._key_frame.pack(fill="x", pady=(8, 0))

        ttk.Button(self, text="Scan", command=self._submit).pack(
            anchor="e", pady=(8, 0)
        )

        self._rebuild()

    # --- state helpers (used by tests) ---
    def set_scan_type(self, scan_type: ScanType) -> None:
        self.scan_type_var.set(scan_type.value)
        self._rebuild()

    def current_scan_type(self) -> ScanType:
        return ScanType(self.scan_type_var.get())

    def set_analyzer(self, analyzer: str, enabled: bool) -> None:
        if analyzer in self._analyzer_vars:
            self._analyzer_vars[analyzer].set(enabled)
            self._refresh_key_fields()

    def selected_analyzers(self) -> list[str]:
        return [a for a, v in self._analyzer_vars.items() if v.get()]

    def collect_keys(self) -> dict[str, str]:
        keys: dict[str, str] = {}
        for provider in required_providers(self.selected_analyzers()):
            inline = self._key_vars.get(provider)
            value = (inline.get().strip() if inline else "") or (
                self._store.get_key(provider) or ""
            )
            if value:
                keys[provider] = value
        return keys

    def build_request(self):
        return build_scan_request(
            self.current_scan_type(),
            self.target_var.get(),
            self.selected_analyzers(),
            self.collect_keys(),
            bearer_token=self.bearer_var.get() or None,
        )

    # --- UI rebuild ---
    def _rebuild(self) -> None:
        is_remote = self.current_scan_type() == ScanType.REMOTE
        if is_remote:
            self._browse_btn.pack_forget()
            self._bearer_row.pack(fill="x", pady=(8, 0), after=self._target_row)
        else:
            self._browse_btn.pack(side="left", padx=(8, 0))
            self._bearer_row.pack_forget()

        for child in self._analyzer_frame.winfo_children():
            child.destroy()
        self._analyzer_vars.clear()
        for analyzer in ANALYZERS_BY_TYPE[self.current_scan_type()]:
            var = tk.BooleanVar(value=False)
            self._analyzer_vars[analyzer] = var
            ttk.Checkbutton(
                self._analyzer_frame, text=analyzer, variable=var,
                command=self._refresh_key_fields,
            ).pack(anchor="w")
        self._refresh_key_fields()

    def _refresh_key_fields(self) -> None:
        for child in self._key_frame.winfo_children():
            child.destroy()
        needed = required_providers(self.selected_analyzers())
        self._key_vars = {}
        for provider in needed:
            saved = self._store.get_key(provider)
            row = ttk.Frame(self._key_frame)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=PROVIDER_LABELS.get(provider, provider) + ":").pack(
                side="left"
            )
            if saved:
                ttk.Label(row, text="(using saved key)", foreground="gray").pack(
                    side="left", padx=(8, 0)
                )
            else:
                var = tk.StringVar(value="")
                self._key_vars[provider] = var
                ttk.Entry(row, textvariable=var, width=32, show="*").pack(
                    side="left", padx=(8, 0)
                )

    def _browse(self) -> None:
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if path:
            self.target_var.set(path)

    def _submit(self) -> None:
        try:
            request = self.build_request()
        except ValueError as exc:
            messagebox.showerror("Invalid scan", str(exc))
            return
        self._on_scan(request)
