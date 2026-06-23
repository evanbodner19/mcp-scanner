from mcpscanner_web.schemas import KeyIn, PrefIn, ScanRequestIn


def test_scan_request_defaults():
    s = ScanRequestIn(scan_type="remote", target="http://x/mcp", analyzers=["yara"])
    assert s.stdio_timeout == 60
    assert s.bearer_token is None
    assert s.llm_provider is None


def test_key_and_pref_models():
    assert KeyIn(provider_id="llm:openai", value="k").value == "k"
    assert PrefIn(name="auto_update", value="off").name == "auto_update"
