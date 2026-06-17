# MCP Scanner — Desktop GUI Design

**Date:** 2026-06-17
**Status:** Approved (design phase)
**Branch:** `gui-desktop-app`

## Goal

Add a simple native desktop GUI to a fork of MCP Scanner so non-CLI users can
run scans without memorizing CLI flags. The GUI targets the "easy local
scanning" use case: point at an MCP server URL or a local source tree, pick
analyzers, and view results visually.

## Scope

**In scope at launch:**
- Two scan inputs: **Remote server URL** (SSE/HTTP, optional bearer token) and
  **Source code / files** (folder or file).
- Analyzers exposed per scan type (see UI section).
- Dynamic API-key requirement: selecting a key-requiring analyzer makes its key
  field required (unless a saved key exists).
- A Settings panel that persists API keys locally, encrypted at rest.
- Results view with summary, per-item table, detail pane, and JSON export.

**Out of scope (deferred):**
- Stdio command scanning and config-file/known-configs scanning (can be added
  later as additional scan types).
- Prompt/resource/instructions scanning.
- Scan history/persistence beyond the current session.
- Multi-user / hosted deployment, auth.

## Non-negotiable constraints

- **UI toolkit:** Tkinter (Python stdlib). No GUI framework dependency.
- **Upstream isolation:** the existing `mcpscanner` package is not modified;
  the GUI is a new sibling subpackage so upstream changes remain mergeable.
- **Key storage:** API keys stored in a local SQLite DB, encrypted with AES
  (Fernet). The master encryption key lives in the OS-native secret store via
  `keyring` — never in plaintext on disk.

## Architecture

```
mcp-scanner/                  (fork)
├── mcpscanner/               # untouched upstream package
└── mcpscanner_gui/           # NEW desktop app
    ├── __main__.py           # `python -m mcpscanner_gui`
    ├── app.py                # Tkinter root window + ttk.Notebook tabs
    ├── service.py            # bridge: ScanRequest -> Scanner/analyzers -> normalized result
    ├── runner.py             # runs async scans on a worker thread; queue back to UI
    ├── store.py              # encrypted SQLite settings/keys store
    └── views/
        ├── scan_view.py      # Scan tab
        ├── results_view.py   # Results tab
        └── settings_view.py  # Settings tab
```

New console script in `pyproject.toml`:
`mcp-scanner-gui = "mcpscanner_gui.app:main"` (alongside `mcp-scanner` and
`mcp-scanner-api`).

New dependencies (GUI only): `cryptography` (AES/Fernet), `keyring` (OS vault).
Tkinter is stdlib.

### Isolation boundaries

- **`service.py` is the single integration point with upstream.** The UI never
  imports `Scanner` or analyzer classes. It calls `service.run_scan(request)`
  and receives a normalized result. This hides the difference between:
  - live-server scans — via `Scanner.scan_remote_server_tools(...)` etc., and
  - file scans — via `BehavioralCodeAnalyzer`, `VulnerablePackageAnalyzer`,
    and the VirusTotal analyzer, assembled the way `cli.py` does it.
- **`store.py`** owns all encryption + persistence. Callers see plaintext key
  values in memory only; ciphertext on disk.
- **`runner.py`** owns the async↔Tk threading. Views never touch asyncio.
- **Views** are thin: layout + event wiring only, no business logic.

### Threading model

Scans are `asyncio`-based and slow; Tkinter's mainloop is single-threaded.
`runner.py` runs each scan with `asyncio.run(service.run_scan(...))` on a worker
thread and marshals progress + final result to the UI thread through a
thread-safe `queue.Queue`, drained by a periodic `root.after(...)` poll. A
Cancel sets a flag/cancels the task; the UI re-enables on completion or error.

## UI

One resizable window, `ttk.Notebook` with three tabs.

### Tab 1 — Scan
- Scan-type radio: **Remote server URL** | **Source code / files**.
- Form adapts to type:
  - Remote: URL field, optional bearer-token field.
  - Source/files: path field + "Browse…" (folder or file picker).
- Analyzer checkboxes filtered by scan type:
  - Remote: YARA, LLM judge, Cisco API, Readiness, Prompt Defense.
  - Source/files: Behavioral, Vulnerable-Package, VirusTotal, YARA.
- **Dynamic key fields:** ticking a key-requiring analyzer (LLM, Cisco API,
  VirusTotal) reveals an inline key field, required to start the scan. If a key
  is saved in Settings, the field is pre-filled / shows "using saved key" and is
  not required.
- Scan button (disabled until valid), status/progress line, Cancel.

### Tab 2 — Results
- Auto-selected on scan completion.
- Summary banner (e.g. "3 unsafe of 12 tools").
- Table: item name (tool/file), status, per-analyzer severity, highest
  severity — severity color-coded.
- Row selection → detail pane: threat names, summaries, findings per analyzer.
- Export button → JSON (reuses scanner result data).

### Tab 3 — Settings
- Saved API keys (LLM / Cisco / VirusTotal): masked entry, Save / Clear.
- Backed by the encrypted store below.

## Key storage

- **DB:** SQLite at `~/.mcp-scanner-gui/settings.db`; one row per provider
  (`provider`, `ciphertext`).
- **Cipher:** Fernet (AES) from `cryptography`.
- **Master key:** random 32-byte key generated on first run, stored in the OS
  vault via `keyring` (Windows Credential Manager / macOS Keychain / Linux
  Secret Service). The DB stores only ciphertext; the master key never lands on
  disk in plaintext.
- At scan time `service.py` decrypts the needed key into memory, builds the
  scanner `Config`, and discards the plaintext after the scan.

## Data flow (single scan)

1. Scan tab validates the form → builds a `ScanRequest` (type, target,
   analyzers, keys [saved or inline]).
2. `runner.py` starts a worker thread → `service.run_scan(request)` → dispatches
   to the correct `Scanner` method or file analyzer → normalizes output to a
   common result shape (list of items, each with per-analyzer severities +
   findings + overall safe/unsafe).
3. Worker pushes progress + final result to the queue; UI thread drains via
   `root.after()` and renders Results.

## Error handling

- `service.py` catches connection failures, invalid URLs, missing/invalid keys,
  unreadable paths, and analyzer exceptions, returning a structured error — the
  UI never crashes. The UI surfaces a clear inline message.
- Missing optional analyzer deps (e.g. a tree-sitter language) degrade
  gracefully with a per-analyzer note rather than failing the whole scan.

## Testing

- `store.py`: encrypt/decrypt round-trip, keyring interaction mocked, DB CRUD.
- `service.py`: request → normalized result with `Scanner` and file analyzers
  mocked; error paths return structured errors.
- `runner.py`: thread/queue marshalling with a fake scan function.
- Views: thin, light smoke tests only (logic lives below them).
- Location: `tests/gui/`, following the repo's existing pytest configuration.

## Risks / open considerations

- `keyring` may have no usable backend on some headless Linux setups; acceptable
  for a desktop tool, but `store.py` should raise a clear error if so. (A
  master-password fallback was considered and deferred.)
- Normalizing live-scan results vs file-scan result dicts into one shape is the
  main integration effort; isolated entirely within `service.py`.
- PyInstaller packaging reuses the existing `mcp-scanner.spec` pattern; a GUI
  spec/entry may be added in a later iteration (not required for `pip`/`uv` run).
