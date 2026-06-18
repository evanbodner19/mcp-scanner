"""Tests for ScannerApp."""
import tkinter as tk

import pytest

from mcpscanner_gui.app import ScannerApp


def test_app_constructs():
    try:
        app = ScannerApp()
    except tk.TclError:
        pytest.skip("no display available")
    try:
        assert app.notebook.index("end") == 3  # three tabs
    finally:
        app.destroy()
