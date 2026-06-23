from fastapi.testclient import TestClient

from mcpscanner_web.server import create_app


class FakeStore:
    def __init__(self):
        self._keys = {}
        self._prefs = {}

    def list_providers(self):
        return list(self._keys.keys())

    def get_key(self, k):
        return self._keys.get(k)

    def set_key(self, k, v):
        self._keys[k] = v

    def clear_key(self, k):
        self._keys.pop(k, None)

    def get_pref(self, n):
        return self._prefs.get(n)

    def set_pref(self, n, v):
        self._prefs[n] = v


def _client():
    return TestClient(create_app(store=FakeStore(), version="5.0.0"))


def test_healthz():
    r = _client().get("/api/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "version": "5.0.0"}


def test_config_shape():
    r = _client().get("/api/config")
    body = r.json()
    assert body["version"] == "5.0.0"
    assert "remote" in body["analyzers_by_type"]
    assert "files" in body["analyzers_by_type"]
    assert "stdio" in body["analyzers_by_type"]
    assert {"id": "openai", "label": "OpenAI", "default_model": "gpt-4o"} in body["llm_providers"]
    assert body["default_llm_provider"] == "openai"
    assert body["stored_key_ids"] == []
    assert "**/*.md" in body["noise_patterns"]
