"""FastAPI app factory for the MCP Scanner browser GUI."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from mcpscanner_gui.controllers import (
    ANALYZERS_BY_TYPE,
    DEFAULT_LLM_PROVIDER,
    LLM_PROVIDERS,
    build_scan_request,
)
from mcpscanner_gui.models import ScanType
from mcpscanner_web import jobs as jobs_mod
from mcpscanner_web import updater as updater_mod
from mcpscanner_web.keys import assemble_keys
from mcpscanner_web.schemas import ScanRequestIn
from mcpscanner_web.serialization import outcome_to_dict

DEFAULT_REPO_SLUG = "evanbodner19/mcp-scanner"

# Pref names the API will read back in GET /api/prefs.
KNOWN_PREFS = [
    "llm_provider",
    "llm_model",
    "update_channel",
    "auto_update",
    "skipped_version",
]

_STATIC_DIR = Path(__file__).resolve().parent / "static"


def _config_payload(app: FastAPI) -> dict:
    return {
        "version": app.state.version,
        "scan_types": [t.value for t in ScanType],
        "analyzers_by_type": {
            t.value: analyzers for t, analyzers in ANALYZERS_BY_TYPE.items()
        },
        "llm_providers": [
            {"id": pid, "label": label, "default_model": model}
            for pid, label, model in LLM_PROVIDERS
        ],
        "default_llm_provider": DEFAULT_LLM_PROVIDER,
        "stored_key_ids": list(app.state.store.list_providers()),
        "noise_patterns": list(app.state.noise_patterns),
    }


def create_app(
    store=None,
    scanner_factory=None,
    behavioral_factory=None,
    vulnpkg_factory=None,
    version=None,
    repo_slug=DEFAULT_REPO_SLUG,
) -> FastAPI:
    if store is None:
        from mcpscanner_gui.store import KeyStore

        store = KeyStore()
    if version is None:
        import mcpscanner

        version = mcpscanner.__version__

    app = FastAPI(title="MCP Scanner")
    app.state.store = store
    app.state.version = version
    app.state.repo_slug = repo_slug
    app.state.factories = {
        "scanner_factory": scanner_factory,
        "behavioral_factory": behavioral_factory,
        "vulnpkg_factory": vulnpkg_factory,
    }
    from mcpscanner_web.noise import NOISE_PATTERNS

    app.state.noise_patterns = list(NOISE_PATTERNS)
    app.state.server = None  # set by the launcher for graceful shutdown
    app.state.jobs = jobs_mod.JobRegistry()
    app.state.background_tasks = set()
    app.state.release_fetcher = lambda slug: updater_mod.fetch_latest_release(slug)
    app.state.install_mode_detector = updater_mod.detect_install_mode
    app.state.frozen_applier = lambda release: updater_mod.apply_frozen_update(release)
    app.state.pip_applier = lambda slug, tag: updater_mod.apply_pip_update(slug, tag)

    @app.get("/api/healthz")
    async def healthz():
        return {"ok": True, "version": app.state.version}

    @app.get("/api/config")
    async def config():
        return _config_payload(app)

    @app.get("/api/keys")
    async def list_keys():
        return {"stored": list(app.state.store.list_providers())}

    @app.post("/api/keys")
    async def set_key(request: Request):
        body = await request.json()
        provider_id = body.get("provider_id", "")
        value = body.get("value", "")
        if value:
            app.state.store.set_key(provider_id, value)
        else:
            app.state.store.clear_key(provider_id)
        return {"stored": list(app.state.store.list_providers())}

    @app.get("/api/prefs")
    async def get_prefs():
        prefs = {}
        for name in KNOWN_PREFS:
            val = app.state.store.get_pref(name)
            if val is not None:
                prefs[name] = val
        return {"prefs": prefs}

    @app.post("/api/prefs")
    async def set_pref(request: Request):
        body = await request.json()
        app.state.store.set_pref(body["name"], body["value"])
        prefs = {}
        for name in KNOWN_PREFS:
            val = app.state.store.get_pref(name)
            if val is not None:
                prefs[name] = val
        return {"prefs": prefs}

    @app.post("/api/shutdown")
    async def shutdown():
        if app.state.server is not None:
            app.state.server.should_exit = True
        return {"ok": True}

    @app.post("/api/scan")
    async def start_scan(payload: ScanRequestIn):
        keys = assemble_keys(app.state.store, payload.analyzers, payload.llm_provider)
        try:
            request = build_scan_request(
                ScanType(payload.scan_type),
                payload.target,
                payload.analyzers,
                keys,
                bearer_token=payload.bearer_token,
                llm_model=payload.llm_model,
                stdio_timeout=payload.stdio_timeout,
            )
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        # persist provider/model choice like the old GUI did
        if "llm" in keys or payload.llm_provider:
            if payload.llm_provider:
                app.state.store.set_pref("llm_provider", payload.llm_provider)
            if payload.llm_model:
                app.state.store.set_pref("llm_model", payload.llm_model)

        job = app.state.jobs.create()
        task = asyncio.create_task(jobs_mod.run_job(job, request, app.state.factories))
        app.state.background_tasks.add(task)
        task.add_done_callback(app.state.background_tasks.discard)
        return {"job_id": job.id}

    @app.get("/api/scan/{job_id}")
    async def poll_scan(job_id: str):
        job = app.state.jobs.get(job_id)
        if job is None:
            return JSONResponse({"error": "unknown job"}, status_code=404)
        return {
            "status": job.status,
            "result": outcome_to_dict(job.result) if job.result else None,
        }

    @app.get("/api/scan/{job_id}/events")
    async def scan_events(job_id: str):
        job = app.state.jobs.get(job_id)
        if job is None:
            return JSONResponse({"error": "unknown job"}, status_code=404)
        return StreamingResponse(
            jobs_mod.event_stream(job), media_type="text/event-stream"
        )

    @app.get("/api/version")
    async def version_info():
        current = app.state.version
        release = app.state.release_fetcher(app.state.repo_slug)
        skipped_version = app.state.store.get_pref("skipped_version")
        if release is None:
            return {
                "current": current, "latest": None, "update_available": False,
                "install_mode": app.state.install_mode_detector(),
                "release_notes": "", "skipped": False,
            }
        available = updater_mod.is_update_available(current, release.version, skipped_version)
        return {
            "current": current,
            "latest": release.version,
            "update_available": available,
            "install_mode": app.state.install_mode_detector(),
            "release_notes": release.notes,
            "skipped": bool(skipped_version and skipped_version == release.version),
        }

    @app.post("/api/update")
    async def do_update():
        try:
            release = app.state.release_fetcher(app.state.repo_slug)
            if release is None:
                return {"status": "unavailable"}
            mode = app.state.install_mode_detector()
            if mode == "git":
                return {"status": "git", "message": "Update via git pull (development checkout)."}
            if mode == "frozen":
                app.state.frozen_applier(release)
                return {"status": "started", "message": "Updating and relaunching…"}
            app.state.pip_applier(app.state.repo_slug, release.tag)
            return {"status": "started", "message": "Upgraded via package manager. Restart to apply."}
        except Exception as exc:  # noqa: BLE001 - surfaced to UI, never 500
            return {"status": "error", "error": str(exc)}

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @app.get("/")
    async def index():
        return FileResponse(str(_STATIC_DIR / "index.html"))

    return app
