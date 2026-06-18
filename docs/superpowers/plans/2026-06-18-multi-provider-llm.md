# Multi-Provider LLM Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the desktop GUI run LLM analyzers against any LiteLLM-supported provider (OpenAI, Anthropic, Google Gemini, or a custom model string) with per-provider saved keys, instead of being hardwired to OpenAI `gpt-4o`.

**Architecture:** All changes live in the `mcpscanner_gui/` subpackage. A provider catalog and validation live in `controllers.py`; `ScanRequest` carries an `llm_model`; `service._build_config` passes it to the upstream `Config` (which routes through LiteLLM by model name); `store.py` gains a plaintext `prefs` table plus a one-time legacy-key migration; the Scan and Settings views gain provider/model UI.

**Tech Stack:** Python 3.12, Tkinter (`ttk`), SQLite, `cryptography` (Fernet), `keyring`, pytest. Upstream `mcpscanner` package unchanged.

## Global Constraints

- Only `mcpscanner_gui/` and `tests/gui/` change. The `mcpscanner` package is untouched.
- No new runtime dependencies. Tkinter only for UI.
- API keys remain encrypted at rest (Fernet) in the existing SQLite store; new provider IDs reuse the existing per-provider mechanism. No plaintext keys on disk.
- An existing saved `llm` key must not be silently lost (migrate to `llm:openai`).
- An empty/None `llm_model` must preserve today's behavior (upstream `Config` defaults to `gpt-4o`).
- Provider catalog (exact values): `openai`/"OpenAI"/`gpt-4o`; `anthropic`/"Anthropic"/`claude-3-5-sonnet-20241022`; `google`/"Google Gemini"/`gemini/gemini-1.5-pro`; `custom`/"Custom (LiteLLM)"/`""`.
- The encrypted-store key ID for a provider's LLM key is `llm:<provider_id>`.
- Tests run with: `py -3.12 -m pytest <path> -v`. View tests must skip on `tk.TclError` ("no display available") exactly as the existing view tests do.

---

### Task 1: Store — prefs table + legacy key migration

**Files:**
- Modify: `mcpscanner_gui/store.py`
- Test: `tests/gui/test_store.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `KeyStore.get_pref(name: str) -> str | None`, `KeyStore.set_pref(name: str, value: str) -> None`. On construction, a legacy `llm` key is copied to `llm:openai` when `llm:openai` is empty.

- [ ] **Step 1: Write the failing tests**

Add to `tests/gui/test_store.py` (the file already defines `FakeKeyring` and a `store` fixture):

```python
def test_pref_roundtrip(store):
    store.set_pref("llm_provider", "anthropic")
    assert store.get_pref("llm_provider") == "anthropic"


def test_pref_missing_returns_none(store):
    assert store.get_pref("llm_model") is None


def test_pref_overwrite(store):
    store.set_pref("llm_model", "gpt-4o")
    store.set_pref("llm_model", "gemini/gemini-1.5-pro")
    assert store.get_pref("llm_model") == "gemini/gemini-1.5-pro"


def test_legacy_llm_key_migrated(tmp_path):
    db = tmp_path / "s.db"
    kr = FakeKeyring()
    s1 = KeyStore(db_path=db, keyring_backend=kr)
    s1.set_key("llm", "old-key")
    s2 = KeyStore(db_path=db, keyring_backend=kr)
    assert s2.get_key("llm:openai") == "old-key"


def test_legacy_migration_does_not_overwrite(tmp_path):
    db = tmp_path / "s.db"
    kr = FakeKeyring()
    s1 = KeyStore(db_path=db, keyring_backend=kr)
    s1.set_key("llm", "old-key")
    s1.set_key("llm:openai", "already-set")
    s2 = KeyStore(db_path=db, keyring_backend=kr)
    assert s2.get_key("llm:openai") == "already-set"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/gui/test_store.py -v`
Expected: FAIL — `AttributeError: 'KeyStore' object has no attribute 'set_pref'` (and migration tests fail).

- [ ] **Step 3: Implement prefs table, accessors, and migration**

In `mcpscanner_gui/store.py`, replace the `_init_db` method with this version (adds the `prefs` table):

```python
    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS keys ("
                "provider TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS prefs ("
                "name TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
```

Then add these three methods to the `KeyStore` class (e.g. after `list_providers`):

```python
    def get_pref(self, name: str) -> str | None:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT value FROM prefs WHERE name=?", (name,)
            ).fetchone()
        return row[0] if row else None

    def set_pref(self, name: str, value: str) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO prefs(name, value) VALUES(?, ?) "
                "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                (name, value),
            )

    def _migrate_legacy_llm_key(self) -> None:
        """Copy a legacy single 'llm' key into the 'llm:openai' slot once."""
        legacy = self.get_key("llm")
        if legacy and self.get_key("llm:openai") is None:
            self.set_key("llm:openai", legacy)
```

Finally, call the migration at the end of `__init__`. Replace the last line of `__init__` (`self._init_db()`) with:

```python
        self._init_db()
        self._migrate_legacy_llm_key()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/gui/test_store.py -v`
Expected: PASS (all existing store tests plus the five new ones).

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/store.py tests/gui/test_store.py
git commit -m "feat(gui): add prefs table and legacy LLM key migration to store"
```

---

### Task 2: Controllers — provider catalog, model field, validation

**Files:**
- Modify: `mcpscanner_gui/models.py`
- Modify: `mcpscanner_gui/controllers.py`
- Test: `tests/gui/test_controllers.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `ScanRequest.llm_model: str | None = None` (new dataclass field).
  - `controllers.LLM_PROVIDERS: list[tuple[str, str, str]]` — `(id, label, default_model)`.
  - `controllers.DEFAULT_LLM_PROVIDER: str = "openai"`.
  - `controllers.default_model_for(provider_id: str) -> str`.
  - `controllers.llm_store_key_id(provider_id: str) -> str` → `f"llm:{provider_id}"`.
  - `controllers.build_scan_request(..., llm_model: str | None = None)` — now requires a non-empty `llm_model` when `"llm"` is a required provider; sets `ScanRequest.llm_model`.

- [ ] **Step 1: Write the failing tests**

Add to the imports at the top of `tests/gui/test_controllers.py`:

```python
from mcpscanner_gui.controllers import (
    DEFAULT_LLM_PROVIDER,
    LLM_PROVIDERS,
    default_model_for,
    llm_store_key_id,
)
```

Add these tests to `tests/gui/test_controllers.py`:

```python
def test_llm_providers_catalog():
    ids = [pid for pid, _label, _model in LLM_PROVIDERS]
    assert ids == ["openai", "anthropic", "google", "custom"]
    assert DEFAULT_LLM_PROVIDER == "openai"
    assert default_model_for("openai") == "gpt-4o"
    assert default_model_for("anthropic") == "claude-3-5-sonnet-20241022"
    assert default_model_for("google") == "gemini/gemini-1.5-pro"
    assert default_model_for("custom") == ""
    assert default_model_for("nope") == ""


def test_llm_store_key_id():
    assert llm_store_key_id("anthropic") == "llm:anthropic"


def test_build_request_requires_model_when_llm_selected():
    with pytest.raises(ValueError, match="model"):
        build_scan_request(ScanType.REMOTE, "http://x/mcp", ["llm"], {"llm": "k"})


def test_build_request_sets_llm_model():
    req = build_scan_request(
        ScanType.REMOTE, "http://x/mcp", ["llm"], {"llm": "k"}, llm_model="gpt-4o"
    )
    assert req.llm_model == "gpt-4o"


def test_build_request_no_llm_leaves_model_none():
    req = build_scan_request(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
    assert req.llm_model is None
```

Also update the existing `test_build_request_with_required_key_ok` to pass a model (selecting `llm` now requires one). Replace that test body with:

```python
def test_build_request_with_required_key_ok():
    req = build_scan_request(
        ScanType.REMOTE, "http://x/mcp", ["llm"], {"llm": "sk-1"}, llm_model="gpt-4o"
    )
    assert req.keys["llm"] == "sk-1"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/gui/test_controllers.py -v`
Expected: FAIL — `ImportError: cannot import name 'LLM_PROVIDERS'`.

- [ ] **Step 3: Add the `llm_model` field to `ScanRequest`**

In `mcpscanner_gui/models.py`, replace the `ScanRequest` dataclass with:

```python
@dataclass
class ScanRequest:
    scan_type: ScanType
    target: str
    analyzers: list[str]
    keys: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    llm_model: str | None = None
```

- [ ] **Step 4: Add the provider catalog and helpers**

In `mcpscanner_gui/controllers.py`, add after the `PROVIDER_BY_ANALYZER` definition:

```python
LLM_PROVIDERS: list[tuple[str, str, str]] = [
    ("openai", "OpenAI", "gpt-4o"),
    ("anthropic", "Anthropic", "claude-3-5-sonnet-20241022"),
    ("google", "Google Gemini", "gemini/gemini-1.5-pro"),
    ("custom", "Custom (LiteLLM)", ""),
]

DEFAULT_LLM_PROVIDER = "openai"


def default_model_for(provider_id: str) -> str:
    """Return the seed model string for a provider id, or '' if unknown."""
    for pid, _label, model in LLM_PROVIDERS:
        if pid == provider_id:
            return model
    return ""


def llm_store_key_id(provider_id: str) -> str:
    """Return the encrypted-store key id for a provider's LLM API key."""
    return f"llm:{provider_id}"
```

- [ ] **Step 5: Extend `build_scan_request`**

In `mcpscanner_gui/controllers.py`, replace the entire `build_scan_request` function with:

```python
def build_scan_request(
    scan_type: ScanType,
    target: str,
    analyzers: list[str],
    keys: dict[str, str],
    bearer_token: str | None = None,
    llm_model: str | None = None,
) -> ScanRequest:
    """Build a ScanRequest with validation.

    Raises ValueError with a user-facing message on invalid input:
    - empty target
    - no analyzers
    - missing required key for any provider
    - LLM analyzer selected with an empty model
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("Please enter a scan target.")
    if not analyzers:
        raise ValueError("Select at least one analyzer.")
    providers = required_providers(analyzers)
    for provider in providers:
        if not (keys.get(provider) or "").strip():
            raise ValueError(f"A key is required for provider '{provider}'.")
    if "llm" in providers and not (llm_model or "").strip():
        raise ValueError("Enter an LLM model name.")
    return ScanRequest(
        scan_type=scan_type,
        target=target,
        analyzers=list(analyzers),
        keys={k: v for k, v in keys.items() if v},
        bearer_token=(bearer_token or None),
        llm_model=((llm_model or "").strip() or None),
    )
```

Note: the key-presence check runs before the model check, so a request with `["llm"]` and no key still raises the `'llm'` key error (keeping `test_build_request_missing_required_key_raises` green).

- [ ] **Step 6: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/gui/test_controllers.py tests/gui/test_models.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add mcpscanner_gui/models.py mcpscanner_gui/controllers.py tests/gui/test_controllers.py
git commit -m "feat(gui): add LLM provider catalog and model validation to controllers"
```

---

### Task 3: Service — thread llm_model into Config

**Files:**
- Modify: `mcpscanner_gui/service.py`
- Test: `tests/gui/test_service_remote.py`

**Interfaces:**
- Consumes: `ScanRequest.llm_model` (Task 2).
- Produces: `service._build_config(keys: dict[str, str], llm_model: str | None = None)` sets `Config.llm_model`; `run_scan` passes `request.llm_model` to the config for both remote and file scans.

- [ ] **Step 1: Write the failing tests**

Add to `tests/gui/test_service_remote.py`:

```python
def test_build_config_sets_llm_model():
    cfg = service._build_config(
        {"llm": "k"}, llm_model="claude-3-5-sonnet-20241022"
    )
    assert cfg.llm_model == "claude-3-5-sonnet-20241022"


def test_build_config_empty_model_defaults_to_gpt4o():
    cfg = service._build_config({}, llm_model=None)
    assert cfg.llm_model == "gpt-4o"


def test_run_scan_passes_model_to_config():
    captured = {}

    class CapturingScanner:
        def __init__(self, config):
            captured["model"] = config.llm_model

        async def scan_remote_server_tools(self, *a, **k):
            return []

    req = ScanRequest(
        ScanType.REMOTE, "http://x/mcp", ["yara"], {},
        llm_model="gemini/gemini-1.5-pro",
    )
    asyncio.run(service.run_scan(req, scanner_factory=CapturingScanner))
    assert captured["model"] == "gemini/gemini-1.5-pro"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/gui/test_service_remote.py -v`
Expected: FAIL — `TypeError: _build_config() got an unexpected keyword argument 'llm_model'`.

- [ ] **Step 3: Implement model pass-through**

In `mcpscanner_gui/service.py`, replace the `_build_config` function with:

```python
def _build_config(keys: dict[str, str], llm_model: str | None = None):
    """Build an upstream Config from the GUI key dict and chosen model.

    When the real mcpscanner package is unavailable (e.g. injected fake scanner
    in tests), returns a plain namespace so the factory can accept it.
    """
    try:
        from mcpscanner import Config  # lazy: upstream may not be installed in test env
        return Config(
            api_key=keys.get("cisco_api"),
            llm_provider_api_key=keys.get("llm"),
            llm_model=llm_model or None,
            virustotal_api_key=keys.get("virustotal"),
        )
    except ImportError:
        import types
        cfg = types.SimpleNamespace(
            api_key=keys.get("cisco_api"),
            llm_provider_api_key=keys.get("llm"),
            llm_model=llm_model or None,
            virustotal_api_key=keys.get("virustotal"),
        )
        return cfg
```

In `_run_remote`, replace `config = _build_config(request.keys)` with:

```python
    config = _build_config(request.keys, request.llm_model)
```

In `_run_files`, replace `config = _build_config(request.keys)` with:

```python
        config = _build_config(request.keys, request.llm_model)
```

(Note: in `_run_files` the call is inside the `if "behavioral" in request.analyzers:` block — keep its existing indentation.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/gui/test_service_remote.py tests/gui/test_service_files.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/service.py tests/gui/test_service_remote.py
git commit -m "feat(gui): pass selected llm_model through service to Config"
```

---

### Task 4: Settings view — per-provider LLM key rows

**Files:**
- Modify: `mcpscanner_gui/views/settings_view.py`
- Test: `tests/gui/test_settings_view.py`

**Interfaces:**
- Consumes: `controllers.LLM_PROVIDERS`, `controllers.llm_store_key_id` (Task 2).
- Produces: `SettingsView.entries` keyed by store-provider-id (`llm:openai`, `llm:anthropic`, `llm:google`, `llm:custom`, `cisco_api`, `virustotal`); `save_provider(store_id)` / `clear_provider(store_id)` operate on those ids.

- [ ] **Step 1: Update the failing tests**

In `tests/gui/test_settings_view.py`, replace `test_settings_view_saves_to_store` with:

```python
def test_settings_view_saves_to_store(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    view = SettingsView(root, store)
    view.entries["llm:openai"].insert(0, "sk-test")
    view.save_provider("llm:openai")
    assert store.get_key("llm:openai") == "sk-test"
```

Add a test that each LLM provider has its own row:

```python
def test_settings_view_has_per_provider_llm_rows(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    view = SettingsView(root, store)
    for store_id in ("llm:openai", "llm:anthropic", "llm:google", "llm:custom"):
        assert store_id in view.entries
    assert "cisco_api" in view.entries
    assert "virustotal" in view.entries
```

(`test_settings_view_clear_removes_key` is unchanged — it uses `virustotal`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/gui/test_settings_view.py -v`
Expected: FAIL — `KeyError: 'llm:openai'` (entries still keyed by `"llm"`).

- [ ] **Step 3: Rewrite the settings view**

Replace the entire contents of `mcpscanner_gui/views/settings_view.py` with:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/gui/test_settings_view.py -v`
Expected: PASS (or `2 skipped` if no display is available).

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/views/settings_view.py tests/gui/test_settings_view.py
git commit -m "feat(gui): per-provider LLM key rows in settings view"
```

---

### Task 5: Scan view — provider dropdown, model field, persistence

**Files:**
- Modify: `mcpscanner_gui/views/scan_view.py`
- Test: `tests/gui/test_scan_view.py`

**Interfaces:**
- Consumes: `controllers.{ANALYZERS_BY_TYPE, DEFAULT_LLM_PROVIDER, LLM_PROVIDERS, build_scan_request, default_model_for, llm_store_key_id, required_providers}` (Tasks 2); `store.get_pref/set_pref` (Task 1); `ScanRequest.llm_model` (Task 2).
- Produces: `ScanView` with `llm_provider_var: tk.StringVar` (holds provider id), `llm_model_var: tk.StringVar`, `set_llm_provider(provider_id: str)`; `collect_keys()` resolves the LLM key from `llm:<provider>`; `build_request()` passes `llm_model`; submit persists last-used provider/model.

- [ ] **Step 1: Update and add the failing tests**

In `tests/gui/test_scan_view.py`, replace `test_build_request_merges_saved_key` with:

```python
def test_build_request_merges_saved_key(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_key("llm:openai", "saved-key")
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("llm", True)
    req = view.build_request()
    assert req.keys["llm"] == "saved-key"
    assert req.llm_model == "gpt-4o"
```

Add these tests:

```python
def test_provider_switch_reseeds_model(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.set_analyzer("llm", True)
    view.set_llm_provider("anthropic")
    assert view.llm_model_var.get() == "claude-3-5-sonnet-20241022"
    view.set_llm_provider("custom")
    assert view.llm_model_var.get() == ""


def test_collect_keys_resolves_selected_provider(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_key("llm:anthropic", "ak")
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("llm", True)
    view.set_llm_provider("anthropic")
    req = view.build_request()
    assert req.keys["llm"] == "ak"
    assert req.llm_model == "claude-3-5-sonnet-20241022"


def test_last_used_provider_restored(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_pref("llm_provider", "google")
    store.set_pref("llm_model", "gemini/gemini-1.5-pro")
    view = ScanView(root, store, on_scan=lambda req: None)
    assert view.llm_provider_var.get() == "google"
    assert view.llm_model_var.get() == "gemini/gemini-1.5-pro"


def test_submit_persists_selection(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_key("llm:openai", "k")
    captured = {}
    view = ScanView(root, store, on_scan=lambda req: captured.setdefault("req", req))
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("llm", True)
    view._submit()
    assert captured["req"].llm_model == "gpt-4o"
    assert store.get_pref("llm_provider") == "openai"
    assert store.get_pref("llm_model") == "gpt-4o"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/gui/test_scan_view.py -v`
Expected: FAIL — `AttributeError: 'ScanView' object has no attribute 'set_llm_provider'` (or `llm_model_var`).

- [ ] **Step 3: Replace the scan view**

Replace the entire contents of `mcpscanner_gui/views/scan_view.py` with:

```python
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
        return build_scan_request(
            self.current_scan_type(),
            self.target_var.get(),
            self.selected_analyzers(),
            self.collect_keys(),
            bearer_token=self.bearer_var.get() or None,
            llm_model=self.llm_model_var.get(),
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/gui/test_scan_view.py -v`
Expected: PASS (or skipped if no display).

- [ ] **Step 5: Run the full GUI test suite**

Run: `py -3.12 -m pytest tests/gui/ -v`
Expected: PASS — all GUI tests green (view tests may show as skipped on a headless machine).

- [ ] **Step 6: Commit**

```bash
git add mcpscanner_gui/views/scan_view.py tests/gui/test_scan_view.py
git commit -m "feat(gui): LLM provider dropdown, model field, and persistence in scan view"
```

---

### Task 6: Update README and design-spec cross-reference

**Files:**
- Modify: `README.md` (Desktop GUI section)

**Interfaces:**
- Consumes: nothing.
- Produces: user-facing docs describing multi-provider selection.

- [ ] **Step 1: Locate the Desktop GUI section**

Run: `py -3.12 -c "import pathlib,sys; t=pathlib.Path('README.md').read_text(encoding='utf-8'); i=t.find('### Desktop GUI'); print(i); print(t[i:i+1200])"`
Expected: prints the offset and the current Desktop GUI section so you can see the exact surrounding text to edit.

- [ ] **Step 2: Add a multi-provider note**

In `README.md`, within the `### Desktop GUI` section, add the following paragraph immediately after the sentence describing the Scan tab (adjust the anchor text to match what Step 1 printed):

```markdown
The LLM analyzers support multiple providers. When you select an LLM-based
analyzer, a **Provider** dropdown (OpenAI, Anthropic, Google Gemini, or
Custom) and an editable **Model** field appear; the model defaults to a
sensible value per provider (e.g. `gpt-4o`, `claude-3-5-sonnet-20241022`,
`gemini/gemini-1.5-pro`) and accepts any LiteLLM-supported model string. Each
provider keeps its own encrypted API key in the Settings tab, and your last
provider/model choice is remembered between launches.
```

- [ ] **Step 3: Verify the section reads correctly**

Run: `py -3.12 -c "import pathlib; t=pathlib.Path('README.md').read_text(encoding='utf-8'); i=t.find('### Desktop GUI'); print(t[i:i+1600])"`
Expected: the Desktop GUI section now includes the multi-provider paragraph, well-formed.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(gui): document multi-provider LLM selection"
```

---

## Self-Review

**Spec coverage:**
- Provider catalog (presets + custom) → Task 2 (`LLM_PROVIDERS`), UI in Task 5.
- Per-provider encrypted keys → Tasks 4 (settings) & 5 (scan), store ids `llm:<id>`.
- Pass model to `Config` → Task 3.
- Remember last-used provider/model → Task 1 (prefs) + Task 5 (restore/persist).
- Legacy `llm` key migration → Task 1.
- Empty model → upstream `gpt-4o` default → Task 3 (`test_build_config_empty_model_defaults_to_gpt4o`).
- Validation (empty model error, missing key error) → Task 2.
- No upstream changes / no new deps → all tasks confined to `mcpscanner_gui/`, `tests/gui/`, `README.md`.
- Docs → Task 6.

**Placeholder scan:** none — every code step contains complete code.

**Type/name consistency:** `llm_model` field, `LLM_PROVIDERS` tuples `(id, label, default_model)`, `default_model_for`, `llm_store_key_id`, `DEFAULT_LLM_PROVIDER`, `llm_provider_var`/`llm_model_var`, `set_llm_provider`, `get_pref`/`set_pref` are used identically across Tasks 1–5. `build_scan_request` signature `(scan_type, target, analyzers, keys, bearer_token=None, llm_model=None)` matches its callers in Task 5. The abstract key id `"llm"` (used in `keys` dict and `_build_config`) is distinct from the store ids `"llm:<provider>"` — Task 5's `collect_keys` maps between them.
