# tests/web/test_api_update.py
from fastapi.testclient import TestClient

from mcpscanner_web import updater
from mcpscanner_web.server import create_app
from tests.web.test_api_config import FakeStore


def _client(release=None, install_mode="frozen", store=None):
    app = create_app(store=store or FakeStore(), version="5.0.0")
    app.state.release_fetcher = lambda slug: release
    app.state.install_mode_detector = lambda: install_mode
    return TestClient(app), app


def test_version_no_update():
    c, _ = _client(release=None)
    body = c.get("/api/version").json()
    assert body["current"] == "5.0.0"
    assert body["update_available"] is False
    assert body["latest"] is None


def test_version_update_available():
    rel = updater.ReleaseInfo(version="5.1.0", tag="v5.1.0", notes="notes", assets={})
    c, _ = _client(release=rel)
    body = c.get("/api/version").json()
    assert body["latest"] == "5.1.0"
    assert body["update_available"] is True
    assert body["install_mode"] == "frozen"
    assert body["release_notes"] == "notes"


def test_version_honors_skipped(monkeypatch):
    store = FakeStore()
    store.set_pref("skipped_version", "5.1.0")
    rel = updater.ReleaseInfo(version="5.1.0", tag="v5.1.0", notes="", assets={})
    c, _ = _client(release=rel, store=store)
    body = c.get("/api/version").json()
    assert body["update_available"] is False
    assert body["skipped"] is True


def test_update_git_mode_is_noop():
    rel = updater.ReleaseInfo(version="5.1.0", tag="v5.1.0", notes="", assets={})
    c, _ = _client(release=rel, install_mode="git")
    body = c.post("/api/update").json()
    assert body["status"] == "git"


def test_update_frozen_invokes_applier():
    rel = updater.ReleaseInfo(version="5.1.0", tag="v5.1.0", notes="", assets={})
    app = create_app(store=FakeStore(), version="5.0.0")
    app.state.release_fetcher = lambda slug: rel
    app.state.install_mode_detector = lambda: "frozen"
    called = {}
    app.state.frozen_applier = lambda release: called.setdefault("frozen", release.version)
    c = TestClient(app)
    body = c.post("/api/update").json()
    assert body["status"] == "started"
    assert called["frozen"] == "5.1.0"
