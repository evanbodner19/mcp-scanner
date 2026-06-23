"""GitHub-Releases auto-updater: version check, install-mode, checksum, swap.

Fail-open by design: any network error, rate limit, or offline state returns
"no update" rather than raising, so launch is never blocked.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from packaging.version import InvalidVersion, Version

DEFAULT_REPO_SLUG = "evanbodner19/mcp-scanner"
_API = "https://api.github.com/repos/{slug}/releases/latest"


@dataclass
class ReleaseInfo:
    version: str
    tag: str
    notes: str
    assets: dict[str, str] = field(default_factory=dict)


def _strip_v(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def fetch_latest_release(slug, client=None, timeout: float = 5.0) -> ReleaseInfo | None:
    own = client is None
    client = client or httpx.Client(timeout=timeout)
    try:
        resp = client.get(_API.format(slug=slug), headers={"Accept": "application/vnd.github+json"})
        if resp.status_code != 200:
            return None
        data = resp.json()
        tag = data.get("tag_name") or ""
        assets = {
            a["name"]: a["browser_download_url"]
            for a in data.get("assets", [])
            if a.get("name") and a.get("browser_download_url")
        }
        return ReleaseInfo(version=_strip_v(tag), tag=tag, notes=data.get("body") or "", assets=assets)
    except Exception:
        return None
    finally:
        if own:
            client.close()


def is_update_available(current: str, latest: str, skipped_version: str | None = None) -> bool:
    if skipped_version and latest == skipped_version:
        return False
    try:
        return Version(latest) > Version(current)
    except InvalidVersion:
        return False


def detect_install_mode(frozen=None, package_dir=None) -> str:
    is_frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    if is_frozen:
        return "frozen"
    pkg = Path(package_dir) if package_dir else Path(__file__).resolve().parent
    if (pkg.parent / ".git").exists():
        return "git"
    return "pip"
