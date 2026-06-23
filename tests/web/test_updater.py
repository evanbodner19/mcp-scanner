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
