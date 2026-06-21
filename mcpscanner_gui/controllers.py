"""Pure UI logic, unit-testable without Tk."""

from __future__ import annotations

import json
from dataclasses import asdict

from mcpscanner_gui.models import ScanOutcome, ScanRequest, ScanType

ANALYZERS_BY_TYPE: dict[ScanType, list[str]] = {
    ScanType.REMOTE: ["yara", "llm", "api", "readiness", "prompt_defense"],
    ScanType.FILES: ["behavioral", "vulnerable_package", "virustotal", "yara"],
    ScanType.STDIO: ["yara", "llm", "api", "readiness", "prompt_defense"],
}

PROVIDER_BY_ANALYZER: dict[str, str] = {
    "llm": "llm",
    "api": "cisco_api",
    "virustotal": "virustotal",
    "behavioral": "llm",
}

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


def required_providers(analyzers: list[str]) -> list[str]:
    """Return distinct providers needed for the given analyzers, in stable order."""
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
    llm_model: str | None = None,
    stdio_timeout: int = 60,
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
        stdio_timeout=max(1, int(stdio_timeout)),
    )


def summary_line(outcome: ScanOutcome) -> str:
    """Return a human-readable summary of the scan outcome."""
    if not outcome.ok:
        return f"Scan failed: {outcome.error}"
    total = len(outcome.items)
    unsafe = sum(1 for i in outcome.items if not i.is_safe)
    return f"{unsafe} unsafe of {total} scanned"


def outcome_to_json(outcome: ScanOutcome) -> str:
    """Export a ScanOutcome to JSON using dataclasses.asdict."""
    return json.dumps(asdict(outcome), indent=2)
