"""Settings tab: manage saved API keys."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from mcpscanner_gui.controllers import LLM_PROVIDERS, llm_store_key_id


def _provider_rows() -> list[tuple[str, str]]:
    """Return (store_id, label) rows: one per LLM provider, then Cisco and VT."""
    rows = [
        (llm_store_key_id(pid), f"{label} API key")
        for pid, label, _model in LLM_PROVIDERS
    ]
    rows.append(("cisco_api", "Cisco AI Defense API key"))
    rows.append(("virustotal", "VirusTotal API key"))
    return rows


class SettingsView(ttk.Frame):
    def __init__(self, master, store):
        super().__init__(master, padding=12)
        self._store = store
        self._rows = _provider_rows()
        self._labels = {store_id: label for store_id, label in self._rows}
        self.entries: dict[str, ttk.Entry] = {}
        self._status = tk.StringVar(value="")

        ttk.Label(self, text="Saved API keys", font=("", 12, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 8)
        )

        for i, (store_id, label) in enumerate(self._rows, start=1):
            ttk.Label(self, text=label).grid(
                row=i, column=0, sticky="w", padx=(0, 8), pady=4
            )
            entry = ttk.Entry(self, show="*", width=44)
            entry.grid(row=i, column=1, sticky="we", pady=4)
            existing = self._store.get_key(store_id)
            if existing:
                entry.insert(0, existing)
            self.entries[store_id] = entry

            btns = ttk.Frame(self)
            btns.grid(row=i, column=2, padx=(8, 0))
            ttk.Button(
                btns, text="Save", command=lambda p=store_id: self.save_provider(p)
            ).pack(side="left")
            ttk.Button(
                btns, text="Clear", command=lambda p=store_id: self.clear_provider(p)
            ).pack(side="left", padx=(4, 0))

        ttk.Label(self, textvariable=self._status, foreground="green").grid(
            row=len(self._rows) + 1, column=0, columnspan=3, sticky="w", pady=(8, 0)
        )
        self.columnconfigure(1, weight=1)

    def save_provider(self, provider: str) -> None:
        value = self.entries[provider].get().strip()
        if value:
            self._store.set_key(provider, value)
            self._status.set(f"Saved {self._labels[provider]}.")

    def clear_provider(self, provider: str) -> None:
        self._store.clear_key(provider)
        self.entries[provider].delete(0, tk.END)
        self._status.set(f"Cleared {self._labels[provider]}.")
