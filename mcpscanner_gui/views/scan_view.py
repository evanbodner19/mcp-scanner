"""Scan tab: choose scan type, target, analyzers, keys; submit."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from mcpscanner_gui.controllers import (
    ANALYZERS_BY_TYPE,
    DEFAULT_LLM_PROVIDER,
    LLM_PROVIDERS,
    build_scan_request,
    default_model_for,
    llm_store_key_id,
    required_providers,
)
from mcpscanner_gui.models import ScanType

PROVIDER_LABELS = {
    "cisco_api": "Cisco API key",
    "virustotal": "VirusTotal key",
}

_PROVIDER_DISPLAY = [label for _pid, label, _m in LLM_PROVIDERS]
_ID_BY_LABEL = {label: pid for pid, label, _m in LLM_PROVIDERS}
_LABEL_BY_ID = {pid: label for pid, label, _m in LLM_PROVIDERS}

_TARGET_LABELS = {
    ScanType.REMOTE: "URL:",
    ScanType.FILES: "Path:",
    ScanType.STDIO: "Command:",
}


class ScanView(ttk.Frame):
    def __init__(self, master, store, on_scan):
        super().__init__(master, padding=12)
        self._store = store
        self._on_scan = on_scan

        self.scan_type_var = tk.StringVar(value=ScanType.REMOTE.value)
        self.target_var = tk.StringVar(value="")
        self.bearer_var = tk.StringVar(value="")
        self.stdio_timeout_var = tk.StringVar(value="60")
        self._analyzer_vars: dict[str, tk.BooleanVar] = {}
        self._key_vars: dict[str, tk.StringVar] = {}

        # LLM provider/model selection, restored from prefs if present.
        self.llm_provider_var = tk.StringVar(value=DEFAULT_LLM_PROVIDER)
        self.llm_model_var = tk.StringVar(
            value=default_model_for(DEFAULT_LLM_PROVIDER)
        )
        saved_provider = self._store.get_pref("llm_provider")
        if saved_provider in _LABEL_BY_ID:
            self.llm_provider_var.set(saved_provider)
        saved_model = self._store.get_pref("llm_model")
        if saved_model:
            self.llm_model_var.set(saved_model)
        else:
            self.llm_model_var.set(default_model_for(self.llm_provider_var.get()))

        type_frame = ttk.Frame(self)
        type_frame.pack(anchor="w")
        ttk.Radiobutton(
            type_frame, text="Remote server URL", value=ScanType.REMOTE.value,
            variable=self.scan_type_var, command=self._rebuild,
        ).pack(side="left")
        ttk.Radiobutton(
            type_frame, text="Stdio server", value=ScanType.STDIO.value,
            variable=self.scan_type_var, command=self._rebuild,
        ).pack(side="left", padx=(8, 0))
        ttk.Radiobutton(
            type_frame, text="Source code / files", value=ScanType.FILES.value,
            variable=self.scan_type_var, command=self._rebuild,
        ).pack(side="left", padx=(8, 0))

        self._target_row = ttk.Frame(self)
        self._target_row.pack(fill="x", pady=(8, 0))
        self._target_label = ttk.Label(self._target_row, text="URL:")
        self._target_label.pack(side="left")
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

        self._timeout_row = ttk.Frame(self)
        ttk.Label(self._timeout_row, text="Timeout (sec):").pack(side="left")
        ttk.Entry(
            self._timeout_row, textvariable=self.stdio_timeout_var, width=6
        ).pack(side="left", padx=(8, 0))
        ttk.Label(
            self._timeout_row, text="(how long to wait for the process to start)",
            foreground="gray",
        ).pack(side="left", padx=(4, 0))

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

    def set_llm_provider(self, provider_id: str) -> None:
        self.llm_provider_var.set(provider_id)
        self.llm_model_var.set(default_model_for(provider_id))
        self._refresh_key_fields()

    def collect_keys(self) -> dict[str, str]:
        keys: dict[str, str] = {}
        for provider in required_providers(self.selected_analyzers()):
            inline = self._key_vars.get(provider)
            if provider == "llm":
                store_id = llm_store_key_id(self.llm_provider_var.get())
            else:
                store_id = provider
            value = (inline.get().strip() if inline else "") or (
                self._store.get_key(store_id) or ""
            )
            if value:
                keys[provider] = value
        return keys

    def build_request(self):
        try:
            timeout = int(self.stdio_timeout_var.get())
        except ValueError:
            timeout = 60
        return build_scan_request(
            self.current_scan_type(),
            self.target_var.get(),
            self.selected_analyzers(),
            self.collect_keys(),
            bearer_token=self.bearer_var.get() or None,
            llm_model=self.llm_model_var.get(),
            stdio_timeout=timeout,
        )

    # --- UI rebuild ---
    def _rebuild(self) -> None:
        scan_type = self.current_scan_type()
        self._target_label.config(text=_TARGET_LABELS.get(scan_type, "Target:"))

        if scan_type == ScanType.REMOTE:
            self._browse_btn.pack_forget()
            self._bearer_row.pack(fill="x", pady=(8, 0), after=self._target_row)
            self._timeout_row.pack_forget()
        elif scan_type == ScanType.STDIO:
            self._browse_btn.pack_forget()
            self._bearer_row.pack_forget()
            self._timeout_row.pack(fill="x", pady=(8, 0), after=self._target_row)
        else:  # FILES
            self._browse_btn.pack(side="left", padx=(8, 0))
            self._bearer_row.pack_forget()
            self._timeout_row.pack_forget()

        for child in self._analyzer_frame.winfo_children():
            child.destroy()
        self._analyzer_vars.clear()
        for analyzer in ANALYZERS_BY_TYPE[scan_type]:
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
        self._key_vars = {}
        for provider in required_providers(self.selected_analyzers()):
            if provider == "llm":
                self._render_llm_rows()
            else:
                self._render_simple_key_row(provider)

    def _render_simple_key_row(self, provider: str) -> None:
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

    def _render_llm_rows(self) -> None:
        prow = ttk.Frame(self._key_frame)
        prow.pack(fill="x", pady=2)
        ttk.Label(prow, text="LLM provider:").pack(side="left")
        combo = ttk.Combobox(
            prow, values=_PROVIDER_DISPLAY, state="readonly", width=20
        )
        combo.set(_LABEL_BY_ID.get(self.llm_provider_var.get(), _PROVIDER_DISPLAY[0]))
        combo.pack(side="left", padx=(8, 0))
        combo.bind("<<ComboboxSelected>>", self._on_provider_selected)
        self._provider_combo = combo

        mrow = ttk.Frame(self._key_frame)
        mrow.pack(fill="x", pady=2)
        ttk.Label(mrow, text="Model:").pack(side="left")
        ttk.Entry(mrow, textvariable=self.llm_model_var, width=32).pack(
            side="left", padx=(8, 0)
        )

        store_id = llm_store_key_id(self.llm_provider_var.get())
        saved = self._store.get_key(store_id)
        krow = ttk.Frame(self._key_frame)
        krow.pack(fill="x", pady=2)
        ttk.Label(krow, text="API key:").pack(side="left")
        if saved:
            ttk.Label(krow, text="(using saved key)", foreground="gray").pack(
                side="left", padx=(8, 0)
            )
        else:
            var = tk.StringVar(value="")
            self._key_vars["llm"] = var
            ttk.Entry(krow, textvariable=var, width=32, show="*").pack(
                side="left", padx=(8, 0)
            )

    def _on_provider_selected(self, event=None) -> None:
        label = self._provider_combo.get()
        provider_id = _ID_BY_LABEL.get(label, DEFAULT_LLM_PROVIDER)
        self.set_llm_provider(provider_id)

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
        if "llm" in required_providers(self.selected_analyzers()):
            self._store.set_pref("llm_provider", self.llm_provider_var.get())
            self._store.set_pref("llm_model", self.llm_model_var.get())
        self._on_scan(request)
