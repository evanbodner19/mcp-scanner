import importlib


def test_package_imports_and_has_version():
    mod = importlib.import_module("mcpscanner_gui")
    assert isinstance(mod.__version__, str)
    assert mod.__version__
