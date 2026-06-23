# tests/web/test_launcher.py
import asyncio
import threading
import time

import httpx

from mcpscanner_web import launcher
from mcpscanner_web.server import create_app
from tests.web.test_api_config import FakeStore


def test_build_server_and_health_poll_and_browser_open():
    app = create_app(store=FakeStore(), version="5.0.0")
    server = launcher.build_server(app, port=0)
    assert app.state.server is server

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # wait for uvicorn to bind a socket
    deadline = time.time() + 10
    port = None
    while time.time() < deadline:
        port = launcher.bound_port(server)
        if port:
            break
        time.sleep(0.05)
    assert port

    assert launcher.wait_healthy(port, timeout=10.0) is True

    opened = []
    launcher.open_browser(port, opener=opened.append)
    assert opened == [f"http://127.0.0.1:{port}/"]

    # graceful shutdown
    server.should_exit = True
    thread.join(timeout=10)
    assert not thread.is_alive()


def test_wait_healthy_returns_false_on_dead_port():
    # nothing listening on this port; short timeout
    assert launcher.wait_healthy(1, timeout=0.5, sleep=0.05) is False
