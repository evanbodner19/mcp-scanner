"""Pydantic request/response models for the web API."""

from __future__ import annotations

from pydantic import BaseModel


class ScanRequestIn(BaseModel):
    scan_type: str
    target: str
    analyzers: list[str]
    bearer_token: str | None = None
    llm_provider: str | None = None
    llm_model: str | None = None
    stdio_timeout: int = 60


class KeyIn(BaseModel):
    provider_id: str
    value: str = ""


class PrefIn(BaseModel):
    name: str
    value: str


class JobOut(BaseModel):
    job_id: str
