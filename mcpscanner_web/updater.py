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


import os
import shutil
import subprocess
import tempfile
import zipfile

CHECKSUMS_FILE = "checksums.txt"


class UpdateError(Exception):
    pass


def prepare_frozen_update(release, dest_dir, *, system=None, machine=None, client=None, downloader=download_asset) -> str:
    """Download the OS/arch asset + checksums, verify SHA-256, return zip path.

    Raises UpdateError if the asset is missing or the checksum does not match.
    """
    name = asset_name(system, machine)
    if name not in release.assets:
        raise UpdateError(f"No release asset for this platform: {name}")
    if CHECKSUMS_FILE not in release.assets:
        raise UpdateError("Release is missing checksums.txt")

    os.makedirs(dest_dir, exist_ok=True)
    zip_path = os.path.join(dest_dir, name)
    sums_path = os.path.join(dest_dir, CHECKSUMS_FILE)
    downloader(release.assets[name], zip_path, client=client)
    downloader(release.assets[CHECKSUMS_FILE], sums_path, client=client)

    with open(sums_path, "r", encoding="utf-8") as fh:
        sums = parse_checksums(fh.read())
    expected = sums.get(name)
    if not expected:
        raise UpdateError(f"checksums.txt has no entry for {name}")
    if not verify_checksum(zip_path, expected):
        raise UpdateError("Checksum mismatch — aborting update")
    return zip_path


def apply_frozen_update(
    release, *, install_dir=None, staging_root=None, system=None, machine=None,
    client=None, downloader=download_asset, spawn=None, replace=None,
) -> bool:
    """Download+verify, extract to staging, and swap the install atomically.

    Side effects are injected for testability:
      - `spawn(cmd)`   : launch the Windows updater helper (default subprocess.Popen).
      - `replace(src, dst)` : atomic dir replace on POSIX (default _atomic_replace_dir).
    Returns True if a relaunch was scheduled. Raises UpdateError on failure;
    callers treat any failure as "keep running the current version".
    """
    install_dir = install_dir or _frozen_install_dir()
    staging_root = staging_root or tempfile.mkdtemp(prefix="mcp-update-")
    zip_path = prepare_frozen_update(
        release, staging_root, system=system, machine=machine, client=client, downloader=downloader
    )
    extract_dir = os.path.join(staging_root, "extracted")
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(extract_dir)
    # the zip contains a top-level "MCP Scanner/" dir; use it if present
    inner = os.path.join(extract_dir, "MCP Scanner")
    new_root = inner if os.path.isdir(inner) else extract_dir

    if (system or platform.system()).lower() == "windows":
        return _windows_swap_and_relaunch(install_dir, new_root, spawn or _spawn)
    (replace or _atomic_replace_dir)(new_root, install_dir)
    _relaunch_posix(install_dir)
    return True


def _frozen_install_dir() -> str:
    # onedir: the executable lives in the install dir
    return os.path.dirname(sys.executable)


def _spawn(cmd):  # pragma: no cover - real process spawn
    return subprocess.Popen(cmd, close_fds=True)


def _atomic_replace_dir(src, dst):
    backup = dst + ".old"
    if os.path.exists(backup):
        shutil.rmtree(backup, ignore_errors=True)
    if os.path.exists(dst):
        os.replace(dst, backup)
    shutil.move(src, dst)
    shutil.rmtree(backup, ignore_errors=True)


def _relaunch_posix(install_dir):  # pragma: no cover - real exec
    exe = os.path.join(install_dir, "MCP Scanner")
    os.execv(exe, [exe])


def _windows_swap_and_relaunch(install_dir, new_root, spawn) -> bool:
    """Write a .bat that waits for this PID, swaps the dir, and relaunches."""
    pid = os.getpid()
    exe = os.path.join(install_dir, "MCP Scanner.exe")
    bat = os.path.join(tempfile.gettempdir(), f"mcp-update-{pid}.bat")
    script = (
        "@echo off\r\n"
        f':wait\r\n'
        f'tasklist /FI "PID eq {pid}" | find "{pid}" >nul\r\n'
        "if not errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait)\r\n"
        f'robocopy "{new_root}" "{install_dir}" /MIR /NFL /NDL /NJH /NJS >nul\r\n'
        f'start "" "{exe}"\r\n'
        f'del "%~f0"\r\n'
    )
    with open(bat, "w", encoding="ascii") as fh:
        fh.write(script)
    spawn(["cmd", "/c", bat])
    return True
