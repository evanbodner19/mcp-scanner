from fastapi.testclient import TestClient

from mcpscanner_web.server import create_app
from tests.web.test_api_config import FakeStore


def _client(store):
    return TestClient(create_app(store=store, version="5.0.0"))


def test_set_and_list_keys():
    store = FakeStore()
    c = _client(store)
    assert c.get("/api/keys").json() == {"stored": []}
    r = c.post("/api/keys", json={"provider_id": "llm:openai", "value": "sk-x"})
    assert r.json() == {"stored": ["llm:openai"]}
    # value is stored but never returned
    assert "sk-x" not in r.text
    assert store.get_key("llm:openai") == "sk-x"


def test_clear_key_with_empty_value():
    store = FakeStore()
    c = _client(store)
    c.post("/api/keys", json={"provider_id": "cisco_api", "value": "v"})
    r = c.post("/api/keys", json={"provider_id": "cisco_api", "value": ""})
    assert r.json() == {"stored": []}


def test_prefs_roundtrip():
    store = FakeStore()
    c = _client(store)
    c.post("/api/prefs", json={"name": "llm_provider", "value": "anthropic"})
    body = c.get("/api/prefs").json()
    assert body["prefs"]["llm_provider"] == "anthropic"
