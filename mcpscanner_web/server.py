"""FastAPI app factory for the MCP Scanner browser GUI."""

from __future__ import annotations

import asyncio

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from mcpscanner_gui.controllers import (
    ANALYZERS_BY_TYPE,
    DEFAULT_LLM_PROVIDER,
    LLM_PROVIDERS,
    build_scan_request,
)
from mcpscanner_gui.models import ScanType
from mcpscanner_web import jobs as jobs_mod
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
    app.state.noise_patterns = []  # replaced in the noise task
    app.state.server = None  # set by the launcher for graceful shutdown
    app.state.jobs = jobs_mod.JobRegistry()
    app.state.background_tasks = set()

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

    return app
