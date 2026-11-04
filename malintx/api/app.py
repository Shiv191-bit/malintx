"""MALINT-X HTTP API (v1)."""

from __future__ import annotations

import contextlib
import logging
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from malintx import SCHEMA_VERSION, __version__
from malintx.analysis.rules.catalog import RULESET_VERSION
from malintx.api.security import (
    BodyLimitMiddleware,
    SlidingWindowLimiter,
    client_key,
    configured_limit,
    require_auth,
)
from malintx.config import Settings, get_settings
from malintx.errors import (
    InvalidSampleError,
    MalintxError,
    NotFoundError,
    OversizedUploadError,
)
from malintx.ingestion import ingest
from malintx.ingestion.service import read_chunks
from malintx.logging_setup import configure_logging
from malintx.mitre import get_catalog
from malintx.pipeline.orchestrator import JobRunner, Platform
from malintx.risk.engine import ENGINE_VERSION
from malintx.schemas.common import JobStatus
from malintx.schemas.results import AnalysisResult, JobInfo
from malintx.tools.decompilers import find_tools

log = logging.getLogger("malintx.api")


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def create_app(settings: Settings | None = None, platform: Platform | None = None, runner: JobRunner | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.platform = platform or Platform.create(settings)
        app.state.runner = runner or JobRunner(app.state.platform)
        yield
        app.state.runner.shutdown()

    app = FastAPI(title="MALINT-X API", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    app.add_middleware(BodyLimitMiddleware, max_bytes=configured_limit(settings))
    api_limiter = SlidingWindowLimiter(settings.api_rate_limit_per_minute)
    upload_limiter = SlidingWindowLimiter(settings.upload_rate_limit_per_minute)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        rid = uuid.uuid4().hex[:12]
        start = time.perf_counter()
        if not api_limiter.check(client_key(request)):
            return _error(429, "rate_limited", "too many requests")
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001 - boundary: never leak internals
            log.exception("unhandled error rid=%s path=%s", rid, request.url.path)
            return _error(500, "internal_error", f"unexpected server error (request {rid})")
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        log.info("rid=%s %s %s -> %s %.0fms", rid, request.method, request.url.path, response.status_code,
                 (time.perf_counter() - start) * 1000)
        return response

    @app.exception_handler(MalintxError)
    async def malintx_error(_: Request, exc: MalintxError) -> JSONResponse:
        status = 413 if isinstance(exc, OversizedUploadError) else 400 if isinstance(exc, InvalidSampleError) else 404 if isinstance(exc, NotFoundError) else 500
        return _error(status, exc.code, str(exc))

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "http_error", "message": str(exc.detail)}
        return JSONResponse(status_code=exc.status_code, content={"error": detail})

    router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_auth(settings))])

    def plat(request: Request) -> Platform:
        return request.app.state.platform

    @router.get("/health")
    def health(request: Request) -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "schema_version": SCHEMA_VERSION,
                "schema_migration": plat(request).db.schema_version()}

    @router.get("/config")
    def config(request: Request) -> dict[str, Any]:
        p = plat(request)
        tools = find_tools(settings)
        cat = get_catalog(settings)
        return {
            "versions": {"platform": __version__, "schema": SCHEMA_VERSION, "ruleset": RULESET_VERSION,
                         "risk_engine": ENGINE_VERSION, "mitre": cat.source, "mitre_sha256": cat.dataset_sha256},
            "threat_intel": p.intel.provider_status(),
            "ai": {"provider": settings.ai_provider, "configured": settings.integrations().get(settings.ai_provider, False)
                   if settings.ai_provider != "openai" else settings.integrations()["openai_compatible"]},
            "decompilers": {"java": bool(tools.java), "jadx": bool(tools.jadx), "apktool": bool(tools.apktool),
                            "mode": "bytecode+source" if tools.can_decompile else "bytecode-only"},
            "limits": {"max_upload_mb": settings.max_upload_mb, "analysis_timeout_s": settings.analysis_timeout_s,
                       "worker_memory_mb": settings.worker_memory_mb},
            "auth_required": bool(settings.api_token.get_secret_value()),
        }

    @router.get("/overview")
    def overview(request: Request) -> dict[str, Any]:
        return plat(request).repo.overview()

    @router.post("/analyses", status_code=202)
    def submit(request: Request, file: UploadFile = File(...), enrich: bool = Form(False),
                     ai: bool = Form(False), force: bool = Form(False)) -> dict[str, Any]:
        if not upload_limiter.check(client_key(request)):
            raise HTTPException(429, detail={"code": "rate_limited", "message": "too many uploads"})
        sample = ingest(read_chunks(file.file), file.filename, settings)
        job, reused = request.app.state.runner.submit(sample, enrich=enrich, ai=ai, force=force)
        return {"job": job.model_dump(mode="json"), "reused_existing": reused}

    @router.get("/analyses")
    def history(request: Request, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return plat(request).repo.list_jobs(min(max(limit, 1), 200), max(offset, 0))

    @router.get("/analyses/{job_id}", response_model=JobInfo)
    def job_status(request: Request, job_id: str) -> JobInfo:
        return plat(request).repo.get_job(job_id)

    @router.get("/analyses/{job_id}/result")
    def job_result(request: Request, job_id: str):
        p = plat(request)
        job = p.repo.get_job(job_id)
        result = p.repo.get_result(job_id)
        if result is None:
            if job.status.terminal:
                raise NotFoundError("no result was stored for this job")
            return JSONResponse(status_code=202, content={"job": job.model_dump(mode="json"), "result": None})
        return JSONResponse(content=result.model_dump(mode="json"))

    @router.get("/analyses/{job_id}/similar")
    def similar(request: Request, job_id: str, limit: int = 8, min_similarity: float = 0.3) -> dict[str, Any]:
        """Hash-free lineage: other analysed samples with a similar framework-API behavioural fingerprint."""
        from malintx.lineage.search import rank

        p = plat(request)
        result = p.repo.get_result(job_id)
        if result is None:
            raise NotFoundError("no result stored for this job")
        fp = result.static.lineage if result.static else None
        if fp is None:
            return {"job_id": job_id, "available": False, "reason": "no analysable code, so no fingerprint was computed", "matches": []}
        matches = rank(fp, p.repo.all_fingerprints(exclude_job=job_id), min(max(limit, 1), 50), min(max(min_similarity, 0.0), 1.0))
        return {"job_id": job_id, "available": True, "api_count": fp.api_count, "compared_against": len(p.repo.all_fingerprints(exclude_job=job_id)),
                "matches": matches, "method": "MinHash(128) over framework APIs called by app code; estimates Jaccard similarity"}

    @router.get("/infrastructure")
    def infrastructure(request: Request, limit: int = 200) -> dict[str, Any]:
        """Network hosts referenced by analysed samples, with any passive intel the analyst opted into, and which samples share them."""
        from malintx import infra

        items = [(m, r.model_dump(mode="json")) for m, r in plat(request).repo.latest_results(min(max(limit, 1), 500))]
        return infra.build(items)

    @router.get("/diff")
    def diff(request: Request, base: str, other: str) -> dict[str, Any]:
        """Capability delta: what `other` has that `base` lacks (repackaging / version-drift analysis)."""
        from malintx.lineage.diff import diff_results
        from malintx.lineage.search import compare

        p = plat(request)
        a, b = p.repo.get_result(base), p.repo.get_result(other)
        if a is None or b is None or a.static is None or b.static is None:
            raise NotFoundError("both analyses must have stored static results")
        out = diff_results(a.static, b.static)
        if a.static.lineage and b.static.lineage:
            out["similarity"] = compare(a.static.lineage, b.static.lineage)
        return out

    @router.get("/analyses/{job_id}/report")
    def job_report(request: Request, job_id: str):
        rep = plat(request).repo.get_report(job_id)
        if rep is None or not Path(rep["path"]).is_file():
            raise NotFoundError("no report is available for this job")
        return FileResponse(rep["path"], media_type="application/pdf", filename=f"malintx-{job_id}.pdf",
                            headers={"X-Report-SHA256": rep["sha256"]})

    app.include_router(router)
    return app


def main() -> None:  # pragma: no cover
    import uvicorn

    s = get_settings()
    uvicorn.run(create_app(s), host=s.api_host, port=s.api_port, log_config=None)


__all__ = ["AnalysisResult", "JobStatus", "create_app", "main"]

if __name__ == "__main__":  # pragma: no cover
    main()
