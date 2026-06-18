# tests/gui/test_settings_view.py
import tkinter as tk

import pytest

from mcpscanner_gui.store import KeyStore
from mcpscanner_gui.views.settings_view import SettingsView


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


def test_settings_view_saves_to_store(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    view = SettingsView(root, store)
    view.entries["llm"].insert(0, "sk-test")
    view.save_provider("llm")
    assert store.get_key("llm") == "sk-test"


def test_settings_view_clear_removes_key(root, tmp_path):
    store = KeyStore(db_path=tmp_path / "s.db", keyring_backend=FakeKeyring())
    store.set_key("virustotal", "vt")
    view = SettingsView(root, store)
    view.clear_provider("virustotal")
    assert store.get_key("virustotal") is None
