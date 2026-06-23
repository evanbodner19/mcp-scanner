# tests/web/test_updater.py
import httpx
import respx

from mcpscanner_web import updater


def _release_json(tag="v5.1.0", notes="new stuff"):
    return {
        "tag_name": tag,
        "body": notes,
        "assets": [
            {"name": "MCP-Scanner-windows-x86_64.zip", "browser_download_url": "https://x/win.zip"},
            {"name": "checksums.txt", "browser_download_url": "https://x/checksums.txt"},
        ],
    }


@respx.mock
def test_fetch_latest_release_parses():
    respx.get("https://api.github.com/repos/evanbodner19/mcp-scanner/releases/latest").mock(
        return_value=httpx.Response(200, json=_release_json())
    )
    info = updater.fetch_latest_release("evanbodner19/mcp-scanner")
    assert info.version == "5.1.0"
    assert info.tag == "v5.1.0"
    assert info.notes == "new stuff"
    assert info.assets["MCP-Scanner-windows-x86_64.zip"] == "https://x/win.zip"


@respx.mock
def test_fetch_latest_release_fails_open_on_error():
    respx.get("https://api.github.com/repos/evanbodner19/mcp-scanner/releases/latest").mock(
        return_value=httpx.Response(403)  # rate limited
    )
    assert updater.fetch_latest_release("evanbodner19/mcp-scanner") is None


@respx.mock
def test_fetch_latest_release_fails_open_on_network():
    respx.get("https://api.github.com/repos/evanbodner19/mcp-scanner/releases/latest").mock(
        side_effect=httpx.ConnectError("offline")
    )
    assert updater.fetch_latest_release("evanbodner19/mcp-scanner") is None


def test_is_update_available_semver():
    assert updater.is_update_available("5.0.0", "5.1.0") is True
    assert updater.is_update_available("5.0.0", "5.0.0") is False
    assert updater.is_update_available("5.1.0", "5.0.9") is False  # not string compare


def test_is_update_available_honors_skip():
    assert updater.is_update_available("5.0.0", "5.1.0", skipped_version="5.1.0") is False
    assert updater.is_update_available("5.0.0", "5.2.0", skipped_version="5.1.0") is True


def test_detect_install_mode_frozen():
    assert updater.detect_install_mode(frozen=True) == "frozen"


def test_detect_install_mode_git(tmp_path):
    pkg = tmp_path / "repo" / "mcpscanner_web"
    pkg.mkdir(parents=True)
    (tmp_path / "repo" / ".git").mkdir()
    assert updater.detect_install_mode(frozen=False, package_dir=str(pkg)) == "git"


def test_detect_install_mode_pip(tmp_path):
    pkg = tmp_path / "site-packages" / "mcpscanner_web"
    pkg.mkdir(parents=True)
    assert updater.detect_install_mode(frozen=False, package_dir=str(pkg)) == "pip"


import hashlib


def test_asset_name_mapping():
    assert updater.asset_name("Windows", "AMD64") == "MCP-Scanner-windows-x86_64.zip"
    assert updater.asset_name("Darwin", "arm64") == "MCP-Scanner-macos-arm64.zip"
    assert updater.asset_name("Linux", "x86_64") == "MCP-Scanner-linux-x86_64.zip"


def test_parse_checksums():
    text = "abc123  MCP-Scanner-windows-x86_64.zip\ndef456  MCP-Scanner-linux-x86_64.zip\n"
    parsed = updater.parse_checksums(text)
    assert parsed["MCP-Scanner-windows-x86_64.zip"] == "abc123"
    assert parsed["MCP-Scanner-linux-x86_64.zip"] == "def456"


def test_verify_checksum_match_and_mismatch(tmp_path):
    f = tmp_path / "asset.zip"
    f.write_bytes(b"hello world")
    digest = hashlib.sha256(b"hello world").hexdigest()
    assert updater.verify_checksum(str(f), digest) is True
    assert updater.verify_checksum(str(f), digest.upper()) is True
    assert updater.verify_checksum(str(f), "0" * 64) is False


@respx.mock
def test_download_asset_streams_to_disk(tmp_path):
    respx.get("https://x/win.zip").mock(return_value=httpx.Response(200, content=b"ZIPDATA"))
    dest = str(tmp_path / "out.zip")
    out = updater.download_asset("https://x/win.zip", dest)
    assert out == dest
    with open(dest, "rb") as fh:
        assert fh.read() == b"ZIPDATA"


# ---------------------------------------------------------------------------
# Task 17: prepare_frozen_update
# ---------------------------------------------------------------------------
import io
import zipfile

import pytest

from mcpscanner_web.updater import ReleaseInfo, UpdateError


def _zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("MCP Scanner/run.txt", "v2")
    return buf.getvalue()


def test_prepare_frozen_update_verifies_checksum(tmp_path):
    zip_data = _zip_bytes()
    sha = hashlib.sha256(zip_data).hexdigest()
    name = updater.asset_name("Windows", "AMD64")
    release = ReleaseInfo(
        version="5.1.0", tag="v5.1.0", notes="",
        assets={name: "https://x/app.zip", "checksums.txt": "https://x/checksums.txt"},
    )

    def fake_downloader(url, dest, client=None):
        if url == "https://x/app.zip":
            with open(dest, "wb") as fh:
                fh.write(zip_data)
        else:
            with open(dest, "w") as fh:
                fh.write(f"{sha}  {name}\n")
        return dest

    out = updater.prepare_frozen_update(
        release, str(tmp_path), system="Windows", machine="AMD64", downloader=fake_downloader
    )
    assert out.endswith(name)


def test_prepare_frozen_update_aborts_on_mismatch(tmp_path):
    name = updater.asset_name("Linux", "x86_64")
    release = ReleaseInfo(
        version="5.1.0", tag="v5.1.0", notes="",
        assets={name: "https://x/app.zip", "checksums.txt": "https://x/checksums.txt"},
    )

    def fake_downloader(url, dest, client=None):
        with open(dest, "wb") as fh:
            fh.write(b"corrupt" if url.endswith("app.zip") else b"")
        if url.endswith("checksums.txt"):
            with open(dest, "w") as fh:
                fh.write("0" * 64 + f"  {name}\n")
        return dest

    with pytest.raises(UpdateError):
        updater.prepare_frozen_update(
            release, str(tmp_path), system="Linux", machine="x86_64", downloader=fake_downloader
        )


def test_prepare_frozen_update_missing_asset(tmp_path):
    release = ReleaseInfo(version="5.1.0", tag="v5.1.0", notes="", assets={"checksums.txt": "https://x/c.txt"})
    with pytest.raises(UpdateError):
        updater.prepare_frozen_update(release, str(tmp_path), system="Windows", machine="AMD64")
