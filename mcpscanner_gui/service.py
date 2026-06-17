"""Bridge between GUI scan requests and the upstream scanner engines."""

from __future__ import annotations

from mcpscanner_gui.models import (
    FindingView,
    ScanItem,
    ScanOutcome,
    ScanRequest,
    ScanType,
)


def _build_config(keys: dict[str, str]):
    """Build an upstream Config from the GUI key dict.

    When the real mcpscanner package is unavailable (e.g. injected fake scanner
    in tests), returns a plain namespace so the factory can accept it.
    """
    try:
        from mcpscanner import Config  # lazy: upstream may not be installed in test env
        return Config(
            api_key=keys.get("cisco_api"),
            llm_provider_api_key=keys.get("llm"),
            virustotal_api_key=keys.get("virustotal"),
        )
    except Exception:
        import types
        cfg = types.SimpleNamespace(
            api_key=keys.get("cisco_api"),
            llm_provider_api_key=keys.get("llm"),
            virustotal_api_key=keys.get("virustotal"),
        )
        return cfg


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


def _to_analyzer_enums(analyzer_strings: list[str]):
    """Convert string analyzer names to AnalyzerEnum values.

    Falls back to passing raw strings if the upstream package is unavailable
    (e.g. in test environments with injected fake scanners).
    """
    try:
        from mcpscanner.core.models import AnalyzerEnum  # lazy import
        return [AnalyzerEnum(a) for a in analyzer_strings]
    except Exception:
        return analyzer_strings or None


def _make_auth(bearer_token: str | None):
    """Build an upstream Auth object, or return None."""
    if not bearer_token:
        return None
    try:
        from mcpscanner.core.auth import Auth  # lazy import
        return Auth.bearer(bearer_token=bearer_token)
    except Exception:
        return None


async def _run_remote(request: ScanRequest, scanner_factory) -> ScanOutcome:
    config = _build_config(request.keys)
    scanner = scanner_factory(config)
    analyzers = _to_analyzer_enums(request.analyzers) if request.analyzers else None
    auth = _make_auth(request.bearer_token)
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
    scanner_factory=None,
    behavioral_factory=None,
    vulnpkg_factory=None,
) -> ScanOutcome:
    """Dispatch a scan request and return a ScanOutcome.

    All exceptions are caught and returned as ScanOutcome(ok=False, error=...)
    so the UI never crashes.
    """
    if scanner_factory is None:
        from mcpscanner import Scanner  # lazy: defer real import to runtime
        scanner_factory = Scanner

    try:
        if request.scan_type == ScanType.REMOTE:
            return await _run_remote(request, scanner_factory)
        raise NotImplementedError(f"Unsupported scan type: {request.scan_type}")
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI, never crashes it
        return ScanOutcome(ok=False, items=[], error=str(exc))
