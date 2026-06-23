import importlib


def test_mcpscanner_has_version():
    import mcpscanner
    assert isinstance(mcpscanner.__version__, str)
    assert mcpscanner.__version__  # non-empty


def test_web_package_imports():
    mod = importlib.import_module("mcpscanner_web")
    assert mod is not None
