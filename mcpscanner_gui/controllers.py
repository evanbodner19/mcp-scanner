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
) -> ScanRequest:
    """Build a ScanRequest with validation.

    Raises ValueError with a user-facing message on invalid input:
    - empty target
    - no analyzers
    - missing required key for any provider
    """
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
    """Return a human-readable summary of the scan outcome."""
    if not outcome.ok:
        return f"Scan failed: {outcome.error}"
    total = len(outcome.items)
    unsafe = sum(1 for i in outcome.items if not i.is_safe)
    return f"{unsafe} unsafe of {total} scanned"


def outcome_to_json(outcome: ScanOutcome) -> str:
    """Export a ScanOutcome to JSON using dataclasses.asdict."""
    return json.dumps(asdict(outcome), indent=2)
