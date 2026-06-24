# MCP Scanner GUI

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A standalone Windows desktop app for the [Cisco AI Defense MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) — scan MCP (Model Context Protocol) servers for security threats without touching the command line.

## Desktop GUI (browser-based)

Download the standalone build for your OS from
[Releases](https://github.com/evanbodner19/mcp-scanner/releases) — no Python
required. Unzip and run **MCP Scanner**; it opens in your default web browser
at `http://127.0.0.1:<port>/` (local only, never exposed to the network).

From source:

```bash
pip install ".[gui]"
mcp-scanner-gui            # or: python -m mcpscanner_web
```

### Results triage

- Severity summary (HIGH / MEDIUM / LOW / SAFE) with unsafe/total counts.
- "Hide likely noise" (on by default) collapses test files, lockfiles,
  `.git/`, generated code, docs, and CI — nothing is deleted; toggle to show.
- Filter by severity / threat category / analyzer, group by item/severity/
  category, search, and sort. Export **JSON** or **Markdown**.

### Auto-update

On launch the app checks GitHub Releases. In **Settings → Updates**:

- `auto_update`: `prompt` (default), `auto`, or `off`.
- "Check for updates now" and "Skip this version".

Standalone builds download the matching `MCP-Scanner-<os>-<arch>.zip`, verify
its SHA-256 against `checksums.txt`, and swap atomically. `pip`/`uv` installs
upgrade via the package manager; git checkouts only show a notice.

## CLI, SDK, and API docs

This repo adds the desktop GUI only. For the full CLI, REST API server, SDK, and analyzer documentation see the upstream tool:

**[github.com/cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)**

## License

Apache 2.0 — see [LICENSE](LICENSE).
