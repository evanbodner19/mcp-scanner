# mcpscanner_web/launcher.py
"""Start the web server in a thread, wait until healthy, open the browser."""

from __future__ import annotations

import threading
import time
import webbrowser

import httpx
import uvicorn

from mcpscanner_web import updater as updater_mod
from mcpscanner_web.server import create_app


def build_server(app, host: str = "127.0.0.1", port: int = 0) -> uvicorn.Server:
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    app.state.server = server
    return server


def bound_port(server: uvicorn.Server) -> int | None:
    """Return the actual port uvicorn bound to, or None if not bound yet."""
    servers = getattr(server, "servers", None)
    if not servers:
        return None
    sockets = getattr(servers[0], "sockets", None)
    if not sockets:
        return None
    try:
        return sockets[0].getsockname()[1]
    except OSError:
        return None


def wait_healthy(port: int, timeout: float = 10.0, sleep: float = 0.1, client=None) -> bool:
    url = f"http://127.0.0.1:{port}/api/healthz"
    own_client = client is None
    client = client or httpx.Client(timeout=1.0)
    try:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = client.get(url)
                if r.status_code == 200 and r.json().get("ok"):
                    return True
            except Exception:
                pass
            time.sleep(sleep)
        return False
    finally:
        if own_client:
            client.close()


def pre_launch_update_gate(
    store, slug, current_version, *,
    fetcher=None, mode_detector=None, frozen_applier=None, pip_applier=None,
) -> bool:
    """Check for updates before opening the browser. Returns True if a blocking
    auto-update was applied (a relaunch is scheduled; don't open the browser).

    Fails open: any error returns False and launch proceeds normally.
    """
    fetcher = fetcher or (lambda s: updater_mod.fetch_latest_release(s))
    mode_detector = mode_detector or updater_mod.detect_install_mode
    frozen_applier = frozen_applier or (lambda rel: updater_mod.apply_frozen_update(rel))
    pip_applier = pip_applier or (lambda s, tag: updater_mod.apply_pip_update(s, tag))

    try:
        auto = store.get_pref("auto_update") or "prompt"
        if auto == "off":
            return False
        release = fetcher(slug)
        if release is None:
            return False
        skipped = store.get_pref("skipped_version")
        if not updater_mod.is_update_available(current_version, release.version, skipped):
            return False
        if auto != "auto":
            return False  # prompt mode: the SPA banner handles it
        mode = mode_detector()
        if mode == "git":
            return False
        if mode == "frozen":
            frozen_applier(release)
            return True
        pip_applier(slug, release.tag)
        return True
    except Exception:
        return False


def open_browser(port: int, opener=webbrowser.open) -> None:
    url = f"http://127.0.0.1:{port}/"
    try:
        opener(url)
    except Exception:
        print(f"Open your browser to: {url}")


def main(open_browser_fn=None, run: bool = True) -> None:
    app = create_app()
    server = build_server(app, port=0)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # wait for a bound socket
    deadline = time.time() + 10
    port = None
    while time.time() < deadline:
        port = bound_port(server)
        if port:
            break
        time.sleep(0.05)

    if not port or not wait_healthy(port):
        print("MCP Scanner server failed to start.")
        return

    import mcpscanner
    from mcpscanner_gui.store import KeyStore

    try:
        applied = pre_launch_update_gate(KeyStore(), "evanbodner19/mcp-scanner", mcpscanner.__version__)
    except Exception:
        applied = False
    if applied:
        return  # update scheduled a relaunch; don't open this (old) instance's browser

    (open_browser_fn or open_browser)(port)

    if run:
        try:
            while not server.should_exit and thread.is_alive():
                time.sleep(0.25)
        except KeyboardInterrupt:
            server.should_exit = True
        thread.join(timeout=10)
