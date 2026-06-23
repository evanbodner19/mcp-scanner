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


import hashlib
import platform

_OS_MAP = {"windows": "windows", "darwin": "macos", "linux": "linux"}
_ARCH_MAP = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}


def asset_name(system=None, machine=None) -> str:
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    os_part = _OS_MAP.get(system, system)
    arch_part = _ARCH_MAP.get(machine, machine)
    return f"MCP-Scanner-{os_part}-{arch_part}.zip"


def parse_checksums(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            out[parts[-1]] = parts[0]
    return out


def verify_checksum(path: str, expected_sha256: str) -> bool:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower() == (expected_sha256 or "").lower()


def download_asset(url: str, dest: str, client=None, timeout: float = 60.0) -> str:
    own = client is None
    client = client or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        with client.stream("GET", url) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as fh:
                for chunk in resp.iter_bytes():
                    fh.write(chunk)
        return dest
    finally:
        if own:
            client.close()
