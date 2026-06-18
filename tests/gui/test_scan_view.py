"""Tests for ScanView."""
import tkinter as tk

import pytest

from mcpscanner_gui.models import ScanType
from mcpscanner_gui.store import KeyStore
from mcpscanner_gui.views.scan_view import ScanView


class FakeKeyring:
    def __init__(self):
        self._s = {}

    def get_password(self, s, u):
        return self._s.get((s, u))

    def set_password(self, s, u, v):
        self._s[(s, u)] = v


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    r.withdraw()
    yield r
    r.destroy()


def test_build_request_uses_form_state(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("yara", True)
    req = view.build_request()
    assert req.target == "http://x/mcp"
    assert req.analyzers == ["yara"]


def test_build_request_merges_saved_key(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_key("llm:openai", "saved-key")
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("llm", True)
    req = view.build_request()
    assert req.keys["llm"] == "saved-key"
    assert req.llm_model == "gpt-4o"


def test_provider_switch_reseeds_model(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.set_analyzer("llm", True)
    view.set_llm_provider("anthropic")
    assert view.llm_model_var.get() == "claude-3-5-sonnet-20241022"
    view.set_llm_provider("custom")
    assert view.llm_model_var.get() == ""


def test_collect_keys_resolves_selected_provider(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_key("llm:anthropic", "ak")
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("llm", True)
    view.set_llm_provider("anthropic")
    req = view.build_request()
    assert req.keys["llm"] == "ak"
    assert req.llm_model == "claude-3-5-sonnet-20241022"


def test_last_used_provider_restored(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_pref("llm_provider", "google")
    store.set_pref("llm_model", "gemini/gemini-1.5-pro")
    view = ScanView(root, store, on_scan=lambda req: None)
    assert view.llm_provider_var.get() == "google"
    assert view.llm_model_var.get() == "gemini/gemini-1.5-pro"


def test_submit_persists_selection(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_key("llm:openai", "k")
    captured = {}
    view = ScanView(root, store, on_scan=lambda req: captured.setdefault("req", req))
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("llm", True)
    view._submit()
    assert captured["req"].llm_model == "gpt-4o"
    assert store.get_pref("llm_provider") == "openai"
    assert store.get_pref("llm_model") == "gpt-4o"
