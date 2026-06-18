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
    store.set_key("llm", "saved-key")
    view = ScanView(root, store, on_scan=lambda req: None)
    view.set_scan_type(ScanType.REMOTE)
    view.target_var.set("http://x/mcp")
    view.set_analyzer("llm", True)
    req = view.build_request()
    assert req.keys["llm"] == "saved-key"
