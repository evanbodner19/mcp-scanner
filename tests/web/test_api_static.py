from fastapi.testclient import TestClient

from mcpscanner_web.server import create_app
from tests.web.test_api_config import FakeStore


def _client():
    return TestClient(create_app(store=FakeStore(), version="5.0.0"))


def test_root_serves_html():
    r = _client().get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "MCP Scanner" in r.text


def test_static_app_js_served():
    r = _client().get("/static/app.js")
    assert r.status_code == 200
