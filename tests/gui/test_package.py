# tests/gui/test_package.py
def test_core_modules_import():
    import mcpscanner_gui.controllers  # noqa: F401
    import mcpscanner_gui.models  # noqa: F401
    import mcpscanner_gui.service  # noqa: F401
    import mcpscanner_gui.store  # noqa: F401
