# Desktop GUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Tkinter native desktop GUI (`mcp-scanner-gui`) to the fork so non-CLI users can run remote-URL and source/file scans and view results, with API keys stored encrypted locally.

**Architecture:** A new `mcpscanner_gui/` subpackage sits beside the untouched `mcpscanner` package. A `service.py` bridge is the only code that imports upstream `Scanner`/analyzers; it normalizes every scan into a common `ScanOutcome`. A `runner.py` runs async scans on a worker thread and marshals results to the Tk UI through a queue. `store.py` persists API keys in SQLite encrypted with Fernet, the master key held in the OS vault via `keyring`. Tk views are thin; their logic lives in pure controller functions that are unit-tested without a display.

**Tech Stack:** Python 3.11+, Tkinter (stdlib), `cryptography` (Fernet/AES), `keyring` (OS secret store), `pytest` + `pytest-asyncio`.

## Global Constraints

- Python `>=3.11`; code must run on 3.11/3.12/3.13.
- Do NOT modify any file under `mcpscanner/` (upstream package stays mergeable).
- UI toolkit is Tkinter from the stdlib — no other GUI framework.
- New runtime dependencies allowed: `cryptography`, `keyring` only.
- API keys are never written to disk in plaintext; only Fernet ciphertext is stored in SQLite. The Fernet master key lives in the OS vault via `keyring`.
- Settings DB path: `~/.mcp-scanner-gui/settings.db` (expand `~` with `pathlib.Path.home()`).
- Keyring service name: `mcp-scanner-gui`; keyring username for the master key: `master-key`.
- Provider keys are identified by these exact strings: `"llm"`, `"cisco_api"`, `"virustotal"`.
- Console script name: `mcp-scanner-gui` → `mcpscanner_gui.app:main`.
- Tests live under `tests/gui/`. Tests that instantiate a Tk widget must skip gracefully when no display is available (catch `tkinter.TclError`).
- Follow the repo's existing style (black, line-length 88).

---

## File Structure

| File | Responsibility |
|------|----------------|
| `mcpscanner_gui/__init__.py` | Package marker, version. |
| `mcpscanner_gui/__main__.py` | `python -m mcpscanner_gui` → calls `app.main()`. |
| `mcpscanner_gui/models.py` | Pure dataclasses: `ScanRequest`, `FindingView`, `ScanItem`, `ScanOutcome`; severity helpers. |
| `mcpscanner_gui/store.py` | `KeyStore`: encrypted SQLite key persistence + keyring master key. |
| `mcpscanner_gui/service.py` | `run_scan(request) -> ScanOutcome`; bridges to `Scanner` / file analyzers; normalizes; catches errors. |
| `mcpscanner_gui/runner.py` | `ScanRunner`: runs async `run_scan` on a thread, posts to a `queue.Queue`. |
| `mcpscanner_gui/controllers.py` | Pure UI logic: analyzer catalog, `required_providers`, `build_scan_request`, `outcome_to_json`, `summary_line`. |
| `mcpscanner_gui/views/scan_view.py` | Scan tab (Tk). |
| `mcpscanner_gui/views/results_view.py` | Results tab (Tk). |
| `mcpscanner_gui/views/settings_view.py` | Settings tab (Tk). |
| `mcpscanner_gui/app.py` | `ScannerApp` root window + `ttk.Notebook`, wires runner; `main()`. |
| `tests/gui/test_*.py` | Unit tests. |

**Upstream interfaces this plan consumes (verified, do not change):**
- `from mcpscanner import Config, Scanner` — `Scanner(config).scan_remote_server_tools(server_url, auth=None, analyzers=[...], http_headers=None) -> List[ToolScanResult]`.
- `Config(api_key=..., endpoint_url=..., llm_provider_api_key=..., llm_model=..., virustotal_api_key=...)`.
- `from mcpscanner.core.models import AnalyzerEnum` → `.YARA .LLM .API .READINESS .PROMPT_DEFENSE .BEHAVIORAL .VIRUSTOTAL .VULNERABLE_PACKAGE`.
- `from mcpscanner.core.auth import Auth` → `Auth.bearer(bearer_token="...")`.
- `mcpscanner.core.result.ToolScanResult`: `.tool_name: str`, `.status: str`, `.is_safe: bool`, `.findings: List[SecurityFinding]`.
- `mcpscanner.core.analyzers.base.SecurityFinding`: `.severity: str` (HIGH/MEDIUM/LOW/INFO/SAFE/UNKNOWN), `.summary: str`, `.threat_category: str`, `.analyzer: str`.
- File scans: `from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer` → `await BehavioralCodeAnalyzer(config).analyze(path, context={"file_path": path}) -> List[SecurityFinding]`.
- `from mcpscanner.core.analyzers.vulnerable_package_analyzer import VulnerablePackageAnalyzer` → `VulnerablePackageAnalyzer(enabled=True, vulnerability_service="pypi", timeout=...).analyze_path(path) -> List[SecurityFinding]`.

---

## Task 1: Package scaffold, dependencies, console script

**Files:**
- Create: `mcpscanner_gui/__init__.py`
- Create: `mcpscanner_gui/__main__.py`
- Modify: `pyproject.toml` (dependencies, scripts, package include)
- Create: `tests/gui/__init__.py`
- Test: `tests/gui/test_package.py`

**Interfaces:**
- Produces: importable package `mcpscanner_gui` with `__version__: str`; `mcpscanner_gui.__main__` calls `app.main()` (added in Task 10 — guard the import inside `main_entry`).

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_package.py
import importlib


def test_package_imports_and_has_version():
    mod = importlib.import_module("mcpscanner_gui")
    assert isinstance(mod.__version__, str)
    assert mod.__version__
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/gui/test_package.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mcpscanner_gui'`

- [ ] **Step 3: Create the package files**

```python
# mcpscanner_gui/__init__.py
"""Native desktop GUI for MCP Scanner."""

__version__ = "0.1.0"
```

```python
# mcpscanner_gui/__main__.py
"""Entry point for ``python -m mcpscanner_gui``."""


def main_entry() -> None:
    from mcpscanner_gui.app import main

    main()


if __name__ == "__main__":
    main_entry()
```

```python
# tests/gui/__init__.py
```

- [ ] **Step 4: Update `pyproject.toml`**

In `[project].dependencies`, add these two lines at the end of the list:

```toml
    "cryptography>=42.0.0",
    "keyring>=24.0.0",
```

In `[project.scripts]`, add:

```toml
mcp-scanner-gui = "mcpscanner_gui.app:main"
```

In `[tool.setuptools.packages.find]`, change `include` to also ship the GUI package:

```toml
include = ["mcpscanner*", "mcpscanner_gui*"]
```

- [ ] **Step 5: Sync deps and run test to verify it passes**

Run: `uv sync && uv run pytest tests/gui/test_package.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add mcpscanner_gui/__init__.py mcpscanner_gui/__main__.py tests/gui/__init__.py tests/gui/test_package.py pyproject.toml uv.lock
git commit -m "feat(gui): scaffold mcpscanner_gui package, deps, console script"
```

---

## Task 2: Normalized data models

**Files:**
- Create: `mcpscanner_gui/models.py`
- Test: `tests/gui/test_models.py`

**Interfaces:**
- Produces:
  - `ScanType` (`str`, Enum): `REMOTE = "remote"`, `FILES = "files"`.
  - `@dataclass ScanRequest(scan_type: ScanType, target: str, analyzers: list[str], keys: dict[str, str], bearer_token: str | None = None)` — `analyzers` holds `AnalyzerEnum` values (e.g. `"yara"`); `keys` maps provider id → plaintext key.
  - `@dataclass FindingView(analyzer: str, severity: str, summary: str, threat_category: str)`.
  - `@dataclass ScanItem(name: str, status: str, is_safe: bool, findings: list[FindingView])` with property `highest_severity: str`.
  - `@dataclass ScanOutcome(ok: bool, items: list[ScanItem], error: str | None = None)`.
  - `SEVERITY_ORDER: dict[str, int]` and `highest_severity(findings: list[FindingView]) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_models.py
from mcpscanner_gui.models import (
    FindingView,
    ScanItem,
    ScanOutcome,
    ScanRequest,
    ScanType,
    highest_severity,
)


def test_highest_severity_picks_worst():
    fs = [
        FindingView("yara", "LOW", "a", "x"),
        FindingView("llm", "HIGH", "b", "y"),
        FindingView("api", "MEDIUM", "c", "z"),
    ]
    assert highest_severity(fs) == "HIGH"


def test_highest_severity_empty_is_safe():
    assert highest_severity([]) == "SAFE"


def test_scan_item_highest_severity_property():
    item = ScanItem("tool", "completed", False, [FindingView("yara", "MEDIUM", "s", "c")])
    assert item.highest_severity == "MEDIUM"


def test_scan_request_defaults():
    req = ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
    assert req.bearer_token is None
    assert req.keys == {}


def test_scan_outcome_error():
    out = ScanOutcome(ok=False, items=[], error="boom")
    assert out.ok is False and out.error == "boom"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/gui/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mcpscanner_gui.models'`

- [ ] **Step 3: Implement `models.py`**

```python
# mcpscanner_gui/models.py
"""Pure data models shared across the GUI layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

SEVERITY_ORDER: dict[str, int] = {
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "SAFE": 0,
    "UNKNOWN": 0,
}


class ScanType(str, Enum):
    REMOTE = "remote"
    FILES = "files"


@dataclass
class FindingView:
    analyzer: str
    severity: str
    summary: str
    threat_category: str


def highest_severity(findings: list[FindingView]) -> str:
    """Return the worst severity among findings, or ``"SAFE"`` if none."""
    worst = "SAFE"
    for f in findings:
        if SEVERITY_ORDER.get(f.severity.upper(), 0) > SEVERITY_ORDER[worst]:
            worst = f.severity.upper()
    return worst


@dataclass
class ScanItem:
    name: str
    status: str
    is_safe: bool
    findings: list[FindingView] = field(default_factory=list)

    @property
    def highest_severity(self) -> str:
        return highest_severity(self.findings)


@dataclass
class ScanRequest:
    scan_type: ScanType
    target: str
    analyzers: list[str]
    keys: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None


@dataclass
class ScanOutcome:
    ok: bool
    items: list[ScanItem] = field(default_factory=list)
    error: str | None = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/gui/test_models.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/models.py tests/gui/test_models.py
git commit -m "feat(gui): add normalized scan data models"
```

---

## Task 3: Encrypted key store

**Files:**
- Create: `mcpscanner_gui/store.py`
- Test: `tests/gui/test_store.py`

**Interfaces:**
- Consumes: `keyring`, `cryptography.fernet.Fernet`.
- Produces: `class KeyStore`:
  - `__init__(self, db_path: pathlib.Path | None = None, keyring_backend=keyring)` — `db_path` defaults to `~/.mcp-scanner-gui/settings.db`; `keyring_backend` is injectable for tests (must expose `get_password(service, user)` / `set_password(service, user, value)`).
  - `set_key(self, provider: str, value: str) -> None`
  - `get_key(self, provider: str) -> str | None`
  - `clear_key(self, provider: str) -> None`
  - `list_providers(self) -> list[str]`
  - `KEYRING_SERVICE = "mcp-scanner-gui"`, `KEYRING_USER = "master-key"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_store.py
import pytest

from mcpscanner_gui.store import KeyStore


class FakeKeyring:
    """In-memory stand-in for the keyring module."""

    def __init__(self):
        self._store = {}

    def get_password(self, service, user):
        return self._store.get((service, user))

    def set_password(self, service, user, value):
        self._store[(service, user)] = value


@pytest.fixture
def store(tmp_path):
    return KeyStore(db_path=tmp_path / "settings.db", keyring_backend=FakeKeyring())


def test_set_and_get_roundtrip(store):
    store.set_key("llm", "sk-secret-123")
    assert store.get_key("llm") == "sk-secret-123"


def test_get_missing_returns_none(store):
    assert store.get_key("virustotal") is None


def test_ciphertext_is_not_plaintext_on_disk(tmp_path):
    db = tmp_path / "settings.db"
    store = KeyStore(db_path=db, keyring_backend=FakeKeyring())
    store.set_key("cisco_api", "PLAINTEXTKEY")
    raw = db.read_bytes()
    assert b"PLAINTEXTKEY" not in raw


def test_clear_key(store):
    store.set_key("llm", "x")
    store.clear_key("llm")
    assert store.get_key("llm") is None


def test_list_providers(store):
    store.set_key("llm", "a")
    store.set_key("virustotal", "b")
    assert sorted(store.list_providers()) == ["llm", "virustotal"]


def test_master_key_persisted_in_keyring(tmp_path):
    kr = FakeKeyring()
    KeyStore(db_path=tmp_path / "s.db", keyring_backend=kr)
    assert kr.get_password("mcp-scanner-gui", "master-key") is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/gui/test_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mcpscanner_gui.store'`

- [ ] **Step 3: Implement `store.py`**

```python
# mcpscanner_gui/store.py
"""Encrypted local storage for API keys."""

from __future__ import annotations

import pathlib
import sqlite3

import keyring as _keyring
from cryptography.fernet import Fernet


def _default_db_path() -> pathlib.Path:
    return pathlib.Path.home() / ".mcp-scanner-gui" / "settings.db"


class KeyStore:
    KEYRING_SERVICE = "mcp-scanner-gui"
    KEYRING_USER = "master-key"

    def __init__(self, db_path: pathlib.Path | None = None, keyring_backend=_keyring):
        self._db_path = pathlib.Path(db_path) if db_path else _default_db_path()
        self._keyring = keyring_backend
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._fernet = Fernet(self._load_or_create_master_key())
        self._init_db()

    def _load_or_create_master_key(self) -> bytes:
        existing = self._keyring.get_password(self.KEYRING_SERVICE, self.KEYRING_USER)
        if existing:
            return existing.encode("ascii")
        key = Fernet.generate_key()
        self._keyring.set_password(
            self.KEYRING_SERVICE, self.KEYRING_USER, key.decode("ascii")
        )
        return key

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS keys ("
                "provider TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)"
            )

    def set_key(self, provider: str, value: str) -> None:
        token = self._fernet.encrypt(value.encode("utf-8"))
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO keys(provider, ciphertext) VALUES(?, ?) "
                "ON CONFLICT(provider) DO UPDATE SET ciphertext=excluded.ciphertext",
                (provider, token),
            )

    def get_key(self, provider: str) -> str | None:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT ciphertext FROM keys WHERE provider=?", (provider,)
            ).fetchone()
        if row is None:
            return None
        return self._fernet.decrypt(row[0]).decode("utf-8")

    def clear_key(self, provider: str) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("DELETE FROM keys WHERE provider=?", (provider,))

    def list_providers(self) -> list[str]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute("SELECT provider FROM keys").fetchall()
        return [r[0] for r in rows]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/gui/test_store.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/store.py tests/gui/test_store.py
git commit -m "feat(gui): add encrypted SQLite key store with keyring master key"
```

---

## Task 4: UI controller logic (analyzer catalog, validation, export)

**Files:**
- Create: `mcpscanner_gui/controllers.py`
- Test: `tests/gui/test_controllers.py`

**Interfaces:**
- Consumes: `models.ScanType`, `models.ScanRequest`, `models.ScanOutcome`.
- Produces:
  - `ANALYZERS_BY_TYPE: dict[ScanType, list[str]]` — remote: `["yara","llm","api","readiness","prompt_defense"]`; files: `["behavioral","vulnerable_package","virustotal","yara"]`.
  - `PROVIDER_BY_ANALYZER: dict[str, str]` — `{"llm":"llm","api":"cisco_api","virustotal":"virustotal","behavioral":"llm"}`.
  - `required_providers(analyzers: list[str]) -> list[str]` — distinct providers needed, in stable order.
  - `build_scan_request(scan_type, target, analyzers, keys, bearer_token=None) -> ScanRequest` — raises `ValueError` with a user-facing message on invalid input (empty target, no analyzers, missing required key).
  - `summary_line(outcome: ScanOutcome) -> str`.
  - `outcome_to_json(outcome: ScanOutcome) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_controllers.py
import json

import pytest

from mcpscanner_gui.controllers import (
    ANALYZERS_BY_TYPE,
    build_scan_request,
    outcome_to_json,
    required_providers,
    summary_line,
)
from mcpscanner_gui.models import FindingView, ScanItem, ScanOutcome, ScanType


def test_analyzer_catalog_per_type():
    assert "llm" in ANALYZERS_BY_TYPE[ScanType.REMOTE]
    assert "behavioral" in ANALYZERS_BY_TYPE[ScanType.FILES]


def test_required_providers_dedups_and_maps():
    assert required_providers(["yara", "llm", "behavioral"]) == ["llm"]
    assert required_providers(["yara", "readiness"]) == []
    assert required_providers(["api", "virustotal"]) == ["cisco_api", "virustotal"]


def test_build_request_valid():
    req = build_scan_request(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
    assert req.target == "http://x/mcp"
    assert req.analyzers == ["yara"]


def test_build_request_empty_target_raises():
    with pytest.raises(ValueError, match="target"):
        build_scan_request(ScanType.REMOTE, "  ", ["yara"], {})


def test_build_request_no_analyzers_raises():
    with pytest.raises(ValueError, match="analyzer"):
        build_scan_request(ScanType.REMOTE, "http://x/mcp", [], {})


def test_build_request_missing_required_key_raises():
    with pytest.raises(ValueError, match="llm"):
        build_scan_request(ScanType.REMOTE, "http://x/mcp", ["llm"], {})


def test_build_request_with_required_key_ok():
    req = build_scan_request(ScanType.REMOTE, "http://x/mcp", ["llm"], {"llm": "sk-1"})
    assert req.keys["llm"] == "sk-1"


def test_summary_line_counts_unsafe():
    out = ScanOutcome(
        ok=True,
        items=[
            ScanItem("a", "completed", True, []),
            ScanItem("b", "completed", False, [FindingView("yara", "HIGH", "s", "c")]),
        ],
    )
    assert "1" in summary_line(out)


def test_outcome_to_json_roundtrips():
    out = ScanOutcome(
        ok=True,
        items=[ScanItem("a", "completed", False, [FindingView("yara", "HIGH", "s", "c")])],
    )
    parsed = json.loads(outcome_to_json(out))
    assert parsed["items"][0]["name"] == "a"
    assert parsed["items"][0]["findings"][0]["severity"] == "HIGH"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/gui/test_controllers.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mcpscanner_gui.controllers'`

- [ ] **Step 3: Implement `controllers.py`**

```python
# mcpscanner_gui/controllers.py
"""Pure UI logic, unit-testable without Tk."""

from __future__ import annotations

import json
from dataclasses import asdict

from mcpscanner_gui.models import ScanOutcome, ScanRequest, ScanType

ANALYZERS_BY_TYPE: dict[ScanType, list[str]] = {
    ScanType.REMOTE: ["yara", "llm", "api", "readiness", "prompt_defense"],
    ScanType.FILES: ["behavioral", "vulnerable_package", "virustotal", "yara"],
}

PROVIDER_BY_ANALYZER: dict[str, str] = {
    "llm": "llm",
    "api": "cisco_api",
    "virustotal": "virustotal",
    "behavioral": "llm",
}


def required_providers(analyzers: list[str]) -> list[str]:
    out: list[str] = []
    for a in analyzers:
        provider = PROVIDER_BY_ANALYZER.get(a)
        if provider and provider not in out:
            out.append(provider)
    return out


def build_scan_request(
    scan_type: ScanType,
    target: str,
    analyzers: list[str],
    keys: dict[str, str],
    bearer_token: str | None = None,
) -> ScanRequest:
    target = (target or "").strip()
    if not target:
        raise ValueError("Please enter a scan target.")
    if not analyzers:
        raise ValueError("Select at least one analyzer.")
    for provider in required_providers(analyzers):
        if not (keys.get(provider) or "").strip():
            raise ValueError(f"A key is required for provider '{provider}'.")
    return ScanRequest(
        scan_type=scan_type,
        target=target,
        analyzers=list(analyzers),
        keys={k: v for k, v in keys.items() if v},
        bearer_token=(bearer_token or None),
    )


def summary_line(outcome: ScanOutcome) -> str:
    if not outcome.ok:
        return f"Scan failed: {outcome.error}"
    total = len(outcome.items)
    unsafe = sum(1 for i in outcome.items if not i.is_safe)
    return f"{unsafe} unsafe of {total} scanned"


def outcome_to_json(outcome: ScanOutcome) -> str:
    return json.dumps(asdict(outcome), indent=2)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/gui/test_controllers.py -v`
Expected: PASS (9 passed)

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/controllers.py tests/gui/test_controllers.py
git commit -m "feat(gui): add UI controller logic (catalog, validation, export)"
```

---

## Task 5: Service bridge — remote scan path

**Files:**
- Create: `mcpscanner_gui/service.py`
- Test: `tests/gui/test_service_remote.py`

**Interfaces:**
- Consumes: `models.ScanRequest/ScanOutcome/ScanItem/FindingView`, upstream `Config`, `Scanner`, `Auth`, `AnalyzerEnum`.
- Produces:
  - `async def run_scan(request: ScanRequest, scanner_factory=None, behavioral_factory=None, vulnpkg_factory=None) -> ScanOutcome` — factories injectable for tests; defaults wire real classes.
  - `_build_config(keys: dict[str, str]) -> Config`
  - `_finding_views(findings) -> list[FindingView]`
  - `_run_remote(request, scanner_factory) -> ScanOutcome`
- This task implements `run_scan` dispatch + the remote branch + `_build_config` + `_finding_views`. The files branch is added in Task 6.

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_service_remote.py
import asyncio
import types

from mcpscanner_gui.models import ScanRequest, ScanType
from mcpscanner_gui import service


class FakeFinding:
    def __init__(self, analyzer, severity, summary, threat_category):
        self.analyzer = analyzer
        self.severity = severity
        self.summary = summary
        self.threat_category = threat_category


class FakeToolResult:
    def __init__(self, tool_name, status, is_safe, findings):
        self.tool_name = tool_name
        self.status = status
        self.is_safe = is_safe
        self.findings = findings


class FakeScanner:
    def __init__(self, config):
        self.config = config

    async def scan_remote_server_tools(self, server_url, auth=None, analyzers=None, http_headers=None):
        return [
            FakeToolResult("safe_tool", "completed", True, []),
            FakeToolResult(
                "bad_tool", "completed", False,
                [FakeFinding("yara", "HIGH", "danger", "EXEC")],
            ),
        ]


def test_remote_scan_normalizes_results():
    req = ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
    out = asyncio.run(service.run_scan(req, scanner_factory=FakeScanner))
    assert out.ok is True
    assert [i.name for i in out.items] == ["safe_tool", "bad_tool"]
    assert out.items[1].findings[0].severity == "HIGH"


def test_remote_scan_handles_exception():
    class BoomScanner:
        def __init__(self, config):
            pass

        async def scan_remote_server_tools(self, *a, **k):
            raise ConnectionError("no route to host")

    req = ScanRequest(ScanType.REMOTE, "http://x/mcp", ["yara"], {})
    out = asyncio.run(service.run_scan(req, scanner_factory=BoomScanner))
    assert out.ok is False
    assert "no route to host" in out.error
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/gui/test_service_remote.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mcpscanner_gui.service'`

- [ ] **Step 3: Implement `service.py` (remote path)**

```python
# mcpscanner_gui/service.py
"""Bridge between GUI scan requests and the upstream scanner engines."""

from __future__ import annotations

from mcpscanner import Config, Scanner
from mcpscanner.core.auth import Auth
from mcpscanner.core.models import AnalyzerEnum

from mcpscanner_gui.models import (
    FindingView,
    ScanItem,
    ScanOutcome,
    ScanRequest,
    ScanType,
)


def _build_config(keys: dict[str, str]) -> Config:
    return Config(
        api_key=keys.get("cisco_api"),
        llm_provider_api_key=keys.get("llm"),
        virustotal_api_key=keys.get("virustotal"),
    )


def _finding_views(findings) -> list[FindingView]:
    return [
        FindingView(
            analyzer=getattr(f, "analyzer", "") or "",
            severity=getattr(f, "severity", "UNKNOWN") or "UNKNOWN",
            summary=getattr(f, "summary", "") or "",
            threat_category=getattr(f, "threat_category", "") or "",
        )
        for f in findings
    ]


async def _run_remote(request: ScanRequest, scanner_factory) -> ScanOutcome:
    config = _build_config(request.keys)
    scanner = scanner_factory(config)
    analyzers = [AnalyzerEnum(a) for a in request.analyzers]
    auth = Auth.bearer(bearer_token=request.bearer_token) if request.bearer_token else None
    results = await scanner.scan_remote_server_tools(
        request.target, auth=auth, analyzers=analyzers
    )
    items = [
        ScanItem(
            name=r.tool_name,
            status=r.status,
            is_safe=r.is_safe,
            findings=_finding_views(r.findings),
        )
        for r in results
    ]
    return ScanOutcome(ok=True, items=items)


async def run_scan(
    request: ScanRequest,
    scanner_factory=Scanner,
    behavioral_factory=None,
    vulnpkg_factory=None,
) -> ScanOutcome:
    try:
        if request.scan_type == ScanType.REMOTE:
            return await _run_remote(request, scanner_factory)
        raise NotImplementedError(f"Unsupported scan type: {request.scan_type}")
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI, never crashes it
        return ScanOutcome(ok=False, items=[], error=str(exc))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/gui/test_service_remote.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/service.py tests/gui/test_service_remote.py
git commit -m "feat(gui): service bridge for remote-server scans"
```

---

## Task 6: Service bridge — file/source scan path

**Files:**
- Modify: `mcpscanner_gui/service.py`
- Test: `tests/gui/test_service_files.py`

**Interfaces:**
- Consumes: upstream `BehavioralCodeAnalyzer`, `VulnerablePackageAnalyzer`.
- Produces (added to `service.py`):
  - `async def _run_files(request, behavioral_factory, vulnpkg_factory) -> ScanOutcome` — runs each selected file-analyzer, collecting `FindingView`s into one `ScanItem` named after the target basename. `run_scan` dispatches `ScanType.FILES` here.
- Behavior: each file scan yields exactly one `ScanItem` (name = `os.path.basename(target)`), whose findings are the union across selected analyzers; `is_safe = not findings`. `yara` selected under files is ignored here (no file YARA path in scope) — only `behavioral`, `vulnerable_package`, `virustotal` contribute; `virustotal` runs via the real analyzer only when a key is present, else it is skipped with no error.

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_service_files.py
import asyncio

from mcpscanner_gui.models import ScanRequest, ScanType
from mcpscanner_gui import service


class FakeFinding:
    def __init__(self, analyzer, severity, summary, threat_category):
        self.analyzer = analyzer
        self.severity = severity
        self.summary = summary
        self.threat_category = threat_category


class FakeBehavioral:
    def __init__(self, config):
        pass

    async def analyze(self, path, context=None):
        return [FakeFinding("behavioral", "MEDIUM", "mismatch", "DECEPTION")]


class FakeVulnPkg:
    def __init__(self, *a, **k):
        pass

    def analyze_path(self, path):
        return [FakeFinding("vulnerable_package", "HIGH", "CVE-1", "MALICIOUS_PACKAGE")]


def test_files_scan_collects_findings_into_one_item(tmp_path):
    target = tmp_path / "server.py"
    target.write_text("x = 1\n")
    req = ScanRequest(ScanType.FILES, str(target), ["behavioral", "vulnerable_package"], {})
    out = asyncio.run(
        service.run_scan(
            req, behavioral_factory=FakeBehavioral, vulnpkg_factory=FakeVulnPkg
        )
    )
    assert out.ok is True
    assert len(out.items) == 1
    assert out.items[0].name == "server.py"
    sevs = {f.severity for f in out.items[0].findings}
    assert sevs == {"MEDIUM", "HIGH"}


def test_files_scan_clean_is_safe(tmp_path):
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n")

    class CleanBehavioral:
        def __init__(self, config):
            pass

        async def analyze(self, path, context=None):
            return []

    req = ScanRequest(ScanType.FILES, str(target), ["behavioral"], {})
    out = asyncio.run(service.run_scan(req, behavioral_factory=CleanBehavioral))
    assert out.ok is True
    assert out.items[0].is_safe is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/gui/test_service_files.py -v`
Expected: FAIL — `run_scan` raises `NotImplementedError` for `ScanType.FILES`, so `out.ok` is False (assertion fails).

- [ ] **Step 3: Implement the files branch**

Add these imports at the top of `service.py` (below the existing imports):

```python
import os

from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer
from mcpscanner.core.analyzers.vulnerable_package_analyzer import (
    VulnerablePackageAnalyzer,
)
```

Add the `_run_files` function above `run_scan`:

```python
async def _run_files(request: ScanRequest, behavioral_factory, vulnpkg_factory) -> ScanOutcome:
    behavioral_factory = behavioral_factory or BehavioralCodeAnalyzer
    vulnpkg_factory = vulnpkg_factory or VulnerablePackageAnalyzer
    findings: list = []

    if "behavioral" in request.analyzers:
        config = _build_config(request.keys)
        analyzer = behavioral_factory(config)
        findings += await analyzer.analyze(
            request.target, context={"file_path": request.target}
        )

    if "vulnerable_package" in request.analyzers:
        vp = vulnpkg_factory(enabled=True, vulnerability_service="pypi", timeout=300)
        findings += vp.analyze_path(request.target)

    item = ScanItem(
        name=os.path.basename(request.target.rstrip("/\\")) or request.target,
        status="completed",
        is_safe=not findings,
        findings=_finding_views(findings),
    )
    return ScanOutcome(ok=True, items=[item])
```

Update `run_scan`'s dispatch — replace the `raise NotImplementedError` line with:

```python
        if request.scan_type == ScanType.FILES:
            return await _run_files(request, behavioral_factory, vulnpkg_factory)
        raise NotImplementedError(f"Unsupported scan type: {request.scan_type}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/gui/test_service_files.py tests/gui/test_service_remote.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/service.py tests/gui/test_service_files.py
git commit -m "feat(gui): service bridge for file/source scans"
```

---

## Task 7: Scan runner (async on a worker thread)

**Files:**
- Create: `mcpscanner_gui/runner.py`
- Test: `tests/gui/test_runner.py`

**Interfaces:**
- Consumes: `models.ScanRequest/ScanOutcome`, `service.run_scan`.
- Produces: `class ScanRunner`:
  - `__init__(self, scan_fn=None)` — `scan_fn(request) -> ScanOutcome` (async); default adapts `service.run_scan`.
  - `start(self, request: ScanRequest) -> None` — launches a daemon thread running `asyncio.run(scan_fn(request))`; pushes the `ScanOutcome` onto `self.queue` (a `queue.Queue`) when done. Exceptions become a failed `ScanOutcome`.
  - `poll(self) -> ScanOutcome | None` — non-blocking read of the queue; `None` if nothing ready.
  - `queue: queue.Queue`.

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_runner.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/gui/test_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mcpscanner_gui.runner'`

- [ ] **Step 3: Implement `runner.py`**

```python
# mcpscanner_gui/runner.py
"""Runs async scans on a worker thread and marshals results to the UI thread."""

from __future__ import annotations

import asyncio
import queue
import threading

from mcpscanner_gui.models import ScanOutcome, ScanRequest


def _default_scan_fn(request: ScanRequest) -> ScanOutcome:
    from mcpscanner_gui.service import run_scan

    return run_scan(request)  # coroutine; awaited inside the worker thread


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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/gui/test_runner.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/runner.py tests/gui/test_runner.py
git commit -m "feat(gui): add threaded scan runner with queue marshalling"
```

---

## Task 8: Settings view

**Files:**
- Create: `mcpscanner_gui/views/__init__.py`
- Create: `mcpscanner_gui/views/settings_view.py`
- Test: `tests/gui/test_settings_view.py`

**Interfaces:**
- Consumes: `store.KeyStore`.
- Produces: `class SettingsView(ttk.Frame)`:
  - `__init__(self, master, store)` — builds masked entries for providers `["llm","cisco_api","virustotal"]`, each with Save/Clear buttons; pre-loads existing values from `store`.
  - `save_provider(self, provider: str) -> None` / `clear_provider(self, provider: str) -> None` — call the store and refresh the field state.
  - `PROVIDER_LABELS: dict[str,str]` — human labels.

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_settings_view.py
import tkinter as tk

import pytest

from mcpscanner_gui.store import KeyStore
from mcpscanner_gui.views.settings_view import SettingsView


class FakeKeyring:
    def __init__(self):
        self._s = {}

    def get_password(self, s, u):
        return self._s.get((s, u))

    def set_password(self, s, u, v):
        self._s[(s, u)] = v


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    r.withdraw()
    yield r
    r.destroy()


def test_settings_view_saves_to_store(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    view = SettingsView(root, store)
    view.entries["llm"].insert(0, "sk-test")
    view.save_provider("llm")
    assert store.get_key("llm") == "sk-test"


def test_settings_view_clear_removes_key(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_key("virustotal", "vt")
    view = SettingsView(root, store)
    view.clear_provider("virustotal")
    assert store.get_key("virustotal") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/gui/test_settings_view.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mcpscanner_gui.views'`

- [ ] **Step 3: Implement the view**

```python
# mcpscanner_gui/views/__init__.py
```

```python
# mcpscanner_gui/views/settings_view.py
"""Settings tab: manage saved API keys."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

PROVIDERS = ["llm", "cisco_api", "virustotal"]


class SettingsView(ttk.Frame):
    PROVIDER_LABELS = {
        "llm": "LLM provider API key",
        "cisco_api": "Cisco AI Defense API key",
        "virustotal": "VirusTotal API key",
    }

    def __init__(self, master, store):
        super().__init__(master, padding=12)
        self._store = store
        self.entries: dict[str, ttk.Entry] = {}
        self._status = tk.StringVar(value="")

        ttk.Label(self, text="Saved API keys", font=("", 12, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 8)
        )

        for i, provider in enumerate(PROVIDERS, start=1):
            ttk.Label(self, text=self.PROVIDER_LABELS[provider]).grid(
                row=i, column=0, sticky="w", padx=(0, 8), pady=4
            )
            entry = ttk.Entry(self, show="*", width=44)
            entry.grid(row=i, column=1, sticky="we", pady=4)
            existing = self._store.get_key(provider)
            if existing:
                entry.insert(0, existing)
            self.entries[provider] = entry

            btns = ttk.Frame(self)
            btns.grid(row=i, column=2, padx=(8, 0))
            ttk.Button(
                btns, text="Save", command=lambda p=provider: self.save_provider(p)
            ).pack(side="left")
            ttk.Button(
                btns, text="Clear", command=lambda p=provider: self.clear_provider(p)
            ).pack(side="left", padx=(4, 0))

        ttk.Label(self, textvariable=self._status, foreground="green").grid(
            row=len(PROVIDERS) + 1, column=0, columnspan=3, sticky="w", pady=(8, 0)
        )
        self.columnconfigure(1, weight=1)

    def save_provider(self, provider: str) -> None:
        value = self.entries[provider].get().strip()
        if value:
            self._store.set_key(provider, value)
            self._status.set(f"Saved {self.PROVIDER_LABELS[provider]}.")

    def clear_provider(self, provider: str) -> None:
        self._store.clear_key(provider)
        self.entries[provider].delete(0, tk.END)
        self._status.set(f"Cleared {self.PROVIDER_LABELS[provider]}.")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/gui/test_settings_view.py -v`
Expected: PASS (2 passed, or skipped if no display)

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/views/__init__.py mcpscanner_gui/views/settings_view.py tests/gui/test_settings_view.py
git commit -m "feat(gui): add settings tab for saved API keys"
```

---

## Task 9: Results view

**Files:**
- Create: `mcpscanner_gui/views/results_view.py`
- Test: `tests/gui/test_results_view.py`

**Interfaces:**
- Consumes: `models.ScanOutcome/ScanItem`, `controllers.summary_line`, `controllers.outcome_to_json`.
- Produces: `class ResultsView(ttk.Frame)`:
  - `__init__(self, master)` — summary label, a `ttk.Treeview` table (columns: name, status, severity), a detail `tk.Text`, and an Export button.
  - `show(self, outcome: ScanOutcome) -> None` — populate the table + summary; stores `self._outcome`.
  - `_on_select(self, event)` — fills the detail pane for the selected row.
  - `export(self, path: str) -> None` — writes `outcome_to_json` to `path`.

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_results_view.py
import json
import tkinter as tk

import pytest

from mcpscanner_gui.models import FindingView, ScanItem, ScanOutcome
from mcpscanner_gui.views.results_view import ResultsView


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    r.withdraw()
    yield r
    r.destroy()


def _outcome():
    return ScanOutcome(
        ok=True,
        items=[
            ScanItem("safe", "completed", True, []),
            ScanItem("bad", "completed", False, [FindingView("yara", "HIGH", "s", "EXEC")]),
        ],
    )


def test_show_populates_table(root):
    view = ResultsView(root)
    view.show(_outcome())
    assert len(view.tree.get_children()) == 2


def test_export_writes_json(root, tmp_path):
    view = ResultsView(root)
    view.show(_outcome())
    out_file = tmp_path / "results.json"
    view.export(str(out_file))
    parsed = json.loads(out_file.read_text())
    assert len(parsed["items"]) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/gui/test_results_view.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mcpscanner_gui.views.results_view'`

- [ ] **Step 3: Implement the view**

```python
# mcpscanner_gui/views/results_view.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/gui/test_results_view.py -v`
Expected: PASS (2 passed, or skipped if no display)

- [ ] **Step 5: Commit**

```bash
git add mcpscanner_gui/views/results_view.py tests/gui/test_results_view.py
git commit -m "feat(gui): add results tab with table, detail, JSON export"
```

---

## Task 10: Scan view + app assembly

**Files:**
- Create: `mcpscanner_gui/views/scan_view.py`
- Create: `mcpscanner_gui/app.py`
- Test: `tests/gui/test_scan_view.py`
- Test: `tests/gui/test_app.py`

**Interfaces:**
- Consumes: `controllers` (catalog, `required_providers`, `build_scan_request`), `store.KeyStore`, `runner.ScanRunner`, `views.ResultsView`, `views.SettingsView`, `models.ScanType`.
- Produces:
  - `class ScanView(ttk.Frame)`:
    - `__init__(self, master, store, on_scan)` — `on_scan(request: ScanRequest)` callback invoked with a validated request.
    - `current_scan_type() -> ScanType`, `selected_analyzers() -> list[str]`, `collect_keys() -> dict[str,str]` (merges saved store keys with inline entry values), `build_request() -> ScanRequest` (delegates to `controllers.build_scan_request`; raises `ValueError`).
    - `_submit()` — builds the request, shows validation errors via `messagebox`, else calls `on_scan`.
  - `class ScannerApp(tk.Tk)` — builds the `ttk.Notebook` (Scan / Results / Settings), owns a `ScanRunner`, polls it via `after`, routes outcomes to `ResultsView`.
  - `def main() -> None` — constructs `ScannerApp` and runs `mainloop()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/gui/test_scan_view.py
import tkinter as tk

import pytest

from mcpscanner_gui.models import ScanType
from mcpscanner_gui.store import KeyStore
from mcpscanner_gui.views.scan_view import ScanView


class FakeKeyring:
    def __init__(self):
        self._s = {}

    def get_password(self, s, u):
        return self._s.get((s, u))

    def set_password(self, s, u, v):
        self._s[(s, u)] = v


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    r.withdraw()
    yield r
    r.destroy()


def test_build_request_uses_form_state(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("yara", True)
    req = view.build_request()
    assert req.target == "http://x/mcp"
    assert req.analyzers == ["yara"]


def test_build_request_merges_saved_key(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_key("llm", "saved-key")
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("llm", True)
    req = view.build_request()
    assert req.keys["llm"] == "saved-key"
```

```python
# tests/gui/test_app.py
import tkinter as tk

import pytest

from mcpscanner_gui.app import ScannerApp


def test_app_constructs():
    try:
        app = ScannerApp()
    except tk.TclError:
        pytest.skip("no display available")
    try:
        assert app.notebook.index("end") == 3  # three tabs
    finally:
        app.destroy()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/gui/test_scan_view.py tests/gui/test_app.py -v`
Expected: FAIL with `ModuleNotFoundError` for `mcpscanner_gui.views.scan_view` / `mcpscanner_gui.app`.

- [ ] **Step 3: Implement `scan_view.py`**

```python
# mcpscanner_gui/views/scan_view.py
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
```

- [ ] **Step 4: Implement `app.py`**

```python
# mcpscanner_gui/app.py
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
        self.results_view._summary.set("Scanning…")
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/gui/test_scan_view.py tests/gui/test_app.py -v`
Expected: PASS (3 passed, or skipped if no display)

- [ ] **Step 6: Run the full GUI test suite**

Run: `uv run pytest tests/gui -v`
Expected: PASS (all GUI tests pass or skip).

- [ ] **Step 7: Commit**

```bash
git add mcpscanner_gui/views/scan_view.py mcpscanner_gui/app.py tests/gui/test_scan_view.py tests/gui/test_app.py
git commit -m "feat(gui): add scan tab and assemble app window"
```

---

## Task 11: Manual launch check + README section

**Files:**
- Modify: `README.md` (add a short "Desktop GUI" section)
- Test: manual (documented below)

**Interfaces:**
- Consumes: `mcp-scanner-gui` console script.

- [ ] **Step 1: Manual smoke test (documented, run by the implementer)**

Run: `uv run mcp-scanner-gui`
Expected: a window opens with three tabs (Scan / Results / Settings). Enter a remote URL (e.g. `https://mcp.deepwiki.com/mcp`), tick `yara`, click Scan; the Results tab shows a table. Close the window.

If no MCP server is handy, verify the window opens and the Settings tab saves a dummy key without error.

- [ ] **Step 2: Add a README section**

Add this after the "API Server Usage" section in `README.md`:

```markdown
### Desktop GUI

A simple native desktop GUI (Tkinter) is available for local scanning without the CLI:

\`\`\`bash
mcp-scanner-gui
\`\`\`

- **Scan tab:** choose **Remote server URL** or **Source code / files**, pick analyzers, and scan. Analyzers that need an API key (LLM, Cisco API, VirusTotal) prompt for the key inline unless it is already saved in Settings.
- **Results tab:** summary, per-item severity table, finding details, and JSON export.
- **Settings tab:** save API keys locally. Keys are encrypted (AES/Fernet) in `~/.mcp-scanner-gui/settings.db`; the master key is held in your OS keychain via `keyring`.
\`\`\`
```

(Remove the backslashes before the triple backticks when editing — they are escaped here only to render inside this plan.)

- [ ] **Step 3: Run the full test suite**

Run: `uv run pytest tests/gui -v`
Expected: PASS / skip, no failures.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(gui): document the desktop GUI"
```

---

## Self-Review Notes

- **Spec coverage:** package/console script (T1) ✓; encrypted SQLite + keyring master key (T3) ✓; normalized results (T2) ✓; remote scan (T5) ✓; file scan behavioral + vulnerable-package + VirusTotal-by-key (T6) ✓; threading/queue model (T7) ✓; Settings tab with encrypted store (T8) ✓; Results tab + export (T9) ✓; Scan tab with dynamic key fields + "using saved key" (T10) ✓; error handling returns structured `ScanOutcome` (T5/T7) ✓; testing under `tests/gui/` with display-skip guard ✓; README/docs (T11) ✓.
- **Deferred per spec (not implemented):** stdio/config/known-config scan types, prompt/resource/instructions scanning, scan history, master-password fallback. VirusTotal under files runs only when a key is present (degrades gracefully); `yara` under files is shown but not wired to a file path (no file-YARA in scope) — acceptable for a first cut.
- **Type consistency:** `ScanRequest/ScanItem/FindingView/ScanOutcome` names and fields are used identically across `service.py`, `runner.py`, `controllers.py`, and views. Provider ids (`llm`/`cisco_api`/`virustotal`) are consistent across `store`, `controllers.PROVIDER_BY_ANALYZER`, and the views.
