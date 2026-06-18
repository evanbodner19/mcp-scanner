# MCP Scanner GUI

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A standalone Windows desktop app for the [Cisco AI Defense MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) — scan MCP (Model Context Protocol) servers for security threats without touching the command line.

## Download

**[Latest release →](https://github.com/evanbodner19/mcp-scanner/releases/latest)**

1. Download `mcp-scanner-gui-windows.zip`
2. Unzip anywhere (e.g. `C:\Tools\MCP Scanner\`)
3. Run `MCP Scanner.exe` — no Python installation required

## Features

### Scan tab
Point at a remote MCP server URL or local source files, pick your analyzers, and scan. API keys are prompted inline if not already saved in Settings.

**Multi-provider LLM support:** choose OpenAI, Anthropic, Google Gemini, or any custom [LiteLLM](https://docs.litellm.ai/docs/providers) model string. Each provider keeps its own encrypted key; your last selection is remembered between launches.

### Results tab
Severity summary, per-tool findings table, full finding details, and JSON export.

### Settings tab
Save API keys locally. Keys are encrypted (AES/Fernet) at rest in `~/.mcp-scanner-gui/settings.db`; the master key is stored in Windows Credential Manager via `keyring`.

## Analyzers

| Analyzer | Needs key | What it does |
|---|---|---|
| `yara` | No | YARA rule matching for known attack patterns |
| `api` | Cisco AI Defense | Cisco inspect API |
| `llm` | LLM provider | LLM-as-judge semantic analysis |
| `virustotal` | VirusTotal | Malware hash lookup for binary files |
| `readiness` | No | Production-readiness linter (timeouts, error handling) |
| `prompt_defense` | No | Checks for missing prompt-injection defenses |

## Running from source

```bash
git clone https://github.com/evanbodner19/mcp-scanner
cd mcp-scanner
pip install -e ".[gui]"
mcp-scanner-gui
```

## CLI, SDK, and API docs

This repo adds the desktop GUI only. For the full CLI, REST API server, SDK, and analyzer documentation see the upstream tool:

**[github.com/cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)**

## License

Apache 2.0 — see [LICENSE](LICENSE).
