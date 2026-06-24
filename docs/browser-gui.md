# Browser GUI

`mcp-scanner-gui` (entry point → `mcpscanner_web.launcher:main`) starts a
FastAPI server on `127.0.0.1` at an ephemeral port and opens your browser.

## Architecture

- `mcpscanner_web/server.py` — FastAPI app (`/api/*` + static SPA).
- `mcpscanner_web/launcher.py` — server thread, health poll, update gate, browser open.
- `mcpscanner_web/static/` — vendored SPA (no CDN).
- Scans run via the unchanged `mcpscanner_gui.service.run_scan`.

## Auto-update

See `mcpscanner_web/updater.py`. Install modes: frozen (download + SHA-256
verify + atomic swap), pip/uv (package-manager upgrade), git (notice only).
Repo slug: `evanbodner19/mcp-scanner`. Update checks fail open — offline or
rate-limited launches proceed on the current version.
