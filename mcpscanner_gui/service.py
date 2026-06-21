"""Bridge between GUI scan requests and the upstream scanner engines."""

from __future__ import annotations

import os

from mcpscanner_gui.models import (
    FindingView,
    ScanItem,
    ScanOutcome,
    ScanRequest,
    ScanType,
)


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
    except ImportError:
        return analyzer_strings or None


def _make_auth(bearer_token: str | None):
    """Build an upstream Auth object, or return None."""
    if not bearer_token:
        return None
    try:
        from mcpscanner.core.auth import Auth  # lazy import
        return Auth.bearer(bearer_token=bearer_token)
    except ImportError:
        return None


async def _run_remote(request: ScanRequest, scanner_factory) -> ScanOutcome:
    config = _build_config(request.keys, request.llm_model)
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


async def _run_files(request: ScanRequest, behavioral_factory, vulnpkg_factory) -> ScanOutcome:
    from pathlib import Path

    target = request.target
    target_path = Path(target)

    if not target_path.exists():
        return ScanOutcome(ok=False, error=f"Target not found: {target}")

    file_paths = (
        [p for p in target_path.rglob("*") if p.is_file()]
        if target_path.is_dir()
        else [target_path]
    )

    items: list[ScanItem] = []

    # YARA: scan each file's text content individually, one result per file
    if "yara" in request.analyzers:
        from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer  # lazy
        yara_analyzer = YaraAnalyzer()
        for fpath in file_paths:
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            file_findings = await yara_analyzer.analyze(
                content, context={"tool_name": fpath.name, "content_type": "file"}
            )
            rel = str(fpath.relative_to(target_path) if target_path.is_dir() else fpath.name)
            items.append(ScanItem(
                name=rel,
                status="completed",
                is_safe=not file_findings,
                findings=_finding_views(file_findings),
            ))

    # Behavioral: tree-sitter source code analysis against the whole target path
    if "behavioral" in request.analyzers:
        if behavioral_factory is None:
            from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer  # lazy
            behavioral_factory = BehavioralCodeAnalyzer
        config = _build_config(request.keys, request.llm_model)
        analyzer = behavioral_factory(config)
        b_findings = await analyzer.analyze(target, context={"file_path": target})
        items.append(ScanItem(
            name=os.path.basename(target.rstrip("/\\")) or target,
            status="completed",
            is_safe=not b_findings,
            findings=_finding_views(b_findings),
        ))

    # Vulnerable packages: pip-audit against the target path
    if "vulnerable_package" in request.analyzers:
        if vulnpkg_factory is None:
            from mcpscanner.core.analyzers.vulnerable_package_analyzer import VulnerablePackageAnalyzer  # lazy
            vulnpkg_factory = VulnerablePackageAnalyzer
        vp = vulnpkg_factory(enabled=True, vulnerability_service="pypi", timeout=300)
        vp_findings = vp.analyze_path(target)
        items.append(ScanItem(
            name=os.path.basename(target.rstrip("/\\")) or target,
            status="completed",
            is_safe=not vp_findings,
            findings=_finding_views(vp_findings),
        ))

    if not items:
        items.append(ScanItem(
            name=os.path.basename(target.rstrip("/\\")) or target,
            status="completed",
            is_safe=True,
            findings=[],
        ))

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
    try:
        if request.scan_type == ScanType.REMOTE:
            if scanner_factory is None:
                from mcpscanner import Scanner  # lazy: defer real import to runtime
                scanner_factory = Scanner
            return await _run_remote(request, scanner_factory)
        if request.scan_type == ScanType.FILES:
            return await _run_files(request, behavioral_factory, vulnpkg_factory)
        raise NotImplementedError(f"Unsupported scan type: {request.scan_type}")
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI, never crashes it
        return ScanOutcome(ok=False, items=[], error=str(exc))
