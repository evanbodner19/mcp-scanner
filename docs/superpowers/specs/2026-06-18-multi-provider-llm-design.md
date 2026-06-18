# Multi-Provider LLM Support — Design

**Date:** 2026-06-18
**Status:** Approved (design phase)
**Branch:** `gui-desktop-app`

## Goal

Let the desktop GUI run the LLM-based analyzers against any LiteLLM-supported
provider (OpenAI, Anthropic, Google Gemini, or a custom model string) instead
of being hardwired to OpenAI's `gpt-4o`. The user picks a provider and model in
the UI, and each provider keeps its own saved API key.

## Background / root cause

The upstream scanner already routes LLM calls through LiteLLM, which infers the
provider from the model name (`gpt-4o` → OpenAI, `claude-3-5-sonnet-20241022` →
Anthropic, `gemini/gemini-1.5-pro` → Google). `Config` already accepts
`llm_model` and a single `llm_provider_api_key` that works for any non-Bedrock
provider (`mcpscanner/config/config.py`, `mcpscanner/core/analyzers/llm_analyzer.py`).

The GUI's `service._build_config` never passes `llm_model`, so it always falls
back to the upstream default `gpt-4o` (`mcpscanner/config/constants.py:119`). A
non-OpenAI key therefore fails with an OpenAI `AuthenticationError`. This design
closes that gap entirely within the GUI subpackage — **no upstream changes.**

## Scope

**In scope:**
- A provider selector (preset dropdown + editable model field) on the Scan tab,
  shown whenever an LLM-requiring analyzer is selected.
- Presets for OpenAI, Anthropic, Google Gemini, plus a Custom (free-text
  LiteLLM model string) option.
- Per-provider encrypted key storage; Settings tab shows one key row per LLM
  provider plus the existing Cisco and VirusTotal rows.
- Passing the chosen model through to `Config(llm_model=...)`.
- Remembering the last-used provider + model across launches.
- One-time migration of any legacy single `llm` key to the `llm:openai` slot.

**Out of scope (deferred):**
- AWS Bedrock's region/profile/bearer-token credential handling as a
  first-class provider.
- Azure-specific `api_base` / `api_version` wiring as a first-class provider
  (still reachable via a Custom model string + key).
- Per-provider memory of *distinct* model strings (we remember a single
  last-used provider+model pair, not one model per provider).

## Non-negotiable constraints

- **Upstream isolation:** only `mcpscanner_gui/` changes. The `mcpscanner`
  package is untouched.
- **Key storage:** API keys remain encrypted at rest (Fernet) in the existing
  SQLite store with the master key in the OS vault. New provider IDs reuse the
  existing per-provider mechanism — no plaintext keys on disk.
- **Backward compatibility:** an existing saved `llm` key must not be silently
  lost. Empty model selection must preserve today's behavior (defaults to
  `gpt-4o`).
- **UI toolkit:** Tkinter only. No new runtime dependencies.

## Providers

Single source of truth in `controllers.py`:

| ID          | Label              | Default model                  |
|-------------|--------------------|--------------------------------|
| `openai`    | OpenAI             | `gpt-4o`                       |
| `anthropic` | Anthropic          | `claude-3-5-sonnet-20241022`   |
| `google`    | Google Gemini      | `gemini/gemini-1.5-pro`        |
| `custom`    | Custom (LiteLLM)   | _(empty — user enters)_        |

The model field is always editable; presets only seed a sensible default the
user can change (e.g. `gpt-4o-mini`, `gemini/gemini-2.0-flash`). The store key
ID for a provider's API key is `llm:<id>` (e.g. `llm:anthropic`).

## Architecture

The change stays within the established GUI layering:

- **`controllers.py`** (pure logic): provider catalog, default-model lookup,
  store-key-ID helper, and extended `build_scan_request` validation. No Tk.
- **`models.py`**: `ScanRequest` gains `llm_model: str | None = None`.
- **`store.py`**: add a plaintext `prefs` key/value table with
  `get_pref`/`set_pref`, and a one-time legacy-key migration. The encrypted
  keys table is unchanged (already keyed by arbitrary provider string).
- **`service.py`**: `_build_config` accepts and applies `llm_model`; the scan
  paths thread it through from the request.
- **`views/scan_view.py`**: provider dropdown + model entry + provider-aware
  key field; persists last-used selection.
- **`views/settings_view.py`**: per-provider LLM key rows.

### Component responsibilities

- **`controllers.py`** owns *what providers exist* and *what makes a request
  valid*. Views read the catalog from here; they don't hardcode provider lists.
- **`store.py`** owns persistence: encrypted keys (unchanged API) and a new
  plaintext prefs table for non-secret UI state (last provider/model). Model
  names are not secrets, so they live in plaintext prefs rather than the
  encrypted table.
- **`service.py`** remains the only integration point with upstream `Config`.

## UI

### Scan tab

When `required_providers(selected_analyzers)` includes `llm` (i.e. the `llm` or
`behavioral` analyzer is ticked), the "Required keys" area shows, in order:

1. **Provider** — a read-only `ttk.Combobox` listing the four provider labels.
2. **Model** — an editable `ttk.Entry`, seeded with the selected provider's
   default model. For `custom` it starts empty and is required.
3. **Key** — the API-key field for the *selected* provider: a masked entry, or
   the "(using saved key)" label if `store.get_key("llm:<provider>")` exists.

Changing the Provider dropdown reseeds the Model field to that provider's
default and re-points the Key field at that provider's saved-key state. Non-LLM
provider key rows (Cisco, VirusTotal) are unaffected.

### Settings tab

The single "LLM provider API key" row is replaced by four rows — OpenAI,
Anthropic, Google Gemini, Custom — each a masked entry with Save / Clear,
backed by `store` keys `llm:openai` … `llm:custom`. The existing Cisco AI
Defense and VirusTotal rows remain.

## Data flow (single scan)

1. Scan view reads the selected provider `p` and model string `m`.
2. It resolves the LLM key: inline entry if present, else
   `store.get_key("llm:" + p)`, and places it in the request key dict under the
   abstract id `"llm"` (so downstream code stays provider-agnostic).
3. `build_scan_request(..., llm_model=m)` validates and returns a `ScanRequest`
   carrying `llm_model`.
4. `runner` → `service.run_scan(request)` → `_run_remote` / `_run_files` call
   `_build_config(request.keys, request.llm_model)`, which builds
   `Config(llm_provider_api_key=keys.get("llm"), llm_model=(m or None), ...)`.
   An empty/None model defers to the upstream `gpt-4o` default.
5. On a successful submit, the view persists `llm_provider=p` and `llm_model=m`
   via `store.set_pref`. On next launch the view restores them.

## Storage & persistence

- **Keys:** reuse the existing per-provider encrypted store with IDs
  `llm:openai`, `llm:anthropic`, `llm:google`, `llm:custom`. No change to the
  `set_key`/`get_key`/`clear_key`/`list_providers` API.
- **Prefs:** new plaintext table `prefs(name TEXT PRIMARY KEY, value TEXT)` in
  the same SQLite DB, with `get_pref(name) -> str | None` and
  `set_pref(name, value) -> None`. Stores `llm_provider` and `llm_model`.
- **Migration:** on `KeyStore` initialization, if a legacy `llm` key exists and
  `llm:openai` does not, copy the legacy value into `llm:openai` (old default
  provider was OpenAI). Idempotent: runs only when the target slot is empty.

## Validation & error handling

- LLM analyzer selected with an empty model (only reachable via `custom`) →
  `ValueError("Enter an LLM model name.")`, surfaced inline by the Scan tab's
  existing `messagebox.showerror`.
- Missing key for the selected LLM provider → existing
  `"A key is required for provider 'llm'."` path (now resolving against the
  per-provider slot).
- All scan-time exceptions continue to be caught in `service.run_scan` and
  returned as `ScanOutcome(ok=False, error=...)`; the UI never crashes.

## Testing

- **controllers**: provider catalog shape; `default_model_for(id)`;
  `llm_store_key_id(id)`; `build_scan_request` with `llm_model` — valid path,
  missing-model error (custom), missing-key error.
- **store**: prefs get/set round-trip (including missing key → `None`);
  per-provider key round-trip under `llm:*` ids; legacy `llm` → `llm:openai`
  migration (and idempotency when target already set).
- **service**: `_build_config` sets `Config.llm_model` from the argument and
  leaves it `None` when empty; `run_scan` passes `request.llm_model` through to
  the config (fake factory captures `config.llm_model`).
- **views** (skip on no display, as existing tests do): scan view dropdown
  change reseeds model + re-points key resolution; settings view per-provider
  save/clear writes the right `llm:*` slot.

Location: `tests/gui/`, following the repo's existing pytest configuration.

## Risks / open considerations

- LiteLLM model-name conventions vary (`gemini/...` prefix required for Google;
  Anthropic auto-detected by `claude-` prefix). The Custom escape hatch and the
  editable model field mean the user can always supply the exact string LiteLLM
  expects; the presets cover the common cases.
- Default model strings will age as providers release new models. They are
  seeds, not locks — the editable field lets the user update without a code
  change.
