# tests/gui/test_results_view.py
import json
import tkinter as tk

import pytest

from mcpscanner_gui.models import FindingView, ScanItem, ScanOutcome
from mcpscanner_gui.views.results_view import ResultsView


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    r.withdraw()
    yield r
    r.destroy()


def _outcome():
    return ScanOutcome(
        ok=True,
        items=[
            ScanItem("safe", "completed", True, []),
            ScanItem("bad", "completed", False, [FindingView("yara", "HIGH", "s", "EXEC")]),
        ],
    )


def test_show_populates_table(root):
    view = ResultsView(root)
    view.show(_outcome())
    assert len(view.tree.get_children()) == 2


def test_export_writes_json(root, tmp_path):
    view = ResultsView(root)
    view.show(_outcome())
    out_file = tmp_path / "results.json"
    view.export(str(out_file))
    parsed = json.loads(out_file.read_text())
    assert len(parsed["items"]) == 2
