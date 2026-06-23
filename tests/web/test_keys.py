from mcpscanner_web.keys import assemble_keys


class FakeStore:
    def __init__(self, data):
        self._data = data

    def get_key(self, key_id):
        return self._data.get(key_id)


def test_assemble_pulls_llm_key_by_provider():
    store = FakeStore({"llm:anthropic": "sk-ant"})
    keys = assemble_keys(store, ["llm"], "anthropic")
    assert keys == {"llm": "sk-ant"}


def test_assemble_pulls_simple_providers():
    store = FakeStore({"cisco_api": "cab", "virustotal": "vt"})
    keys = assemble_keys(store, ["api", "virustotal"], None)
    assert keys == {"cisco_api": "cab", "virustotal": "vt"}


def test_assemble_omits_missing_keys():
    store = FakeStore({})
    keys = assemble_keys(store, ["llm", "api"], "openai")
    assert keys == {}
