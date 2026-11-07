"""Analysis job orchestration: ingest → static → intel → AI → scoring → report.

Each optional stage is fault-isolated: a failing enrichment, AI call or report renderer is recorded on
the job and in the result but never invalidates the deterministic findings.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass

from malintx import SCHEMA_VERSION, __version__
from malintx.ai.service import not_requested, run_ai
from malintx.analysis.runner import run_static_analysis
from malintx.config import Settings
from malintx.errors import MalintxError
from malintx.ingestion import IngestedSample, workspace
from malintx.intel.service import IntelService
from malintx.risk.engine import assess
from malintx.schemas.common import JobStatus, StageState
from malintx.schemas.results import AIResult, AnalysisResult, IntelReport, JobInfo, StageRecord
from malintx.storage.db import Database, utcnow
from malintx.storage.repository import Repository

log = logging.getLogger(__name__)

STAGES = ("ingest", "static_analysis", "threat_intel", "ai_reasoning", "scoring", "reporting")
_STAGE_STATUS = {
    "static_analysis": JobStatus.STATIC_ANALYSIS, "threat_intel": JobStatus.THREAT_INTEL,
    "ai_reasoning": JobStatus.AI_REASONING, "scoring": JobStatus.SCORING, "reporting": JobStatus.REPORTING,
}


@dataclass
class Platform:
    settings: Settings
    db: Database
    repo: Repository
    intel: IntelService

    @classmethod
    def create(cls, settings: Settings, intel: IntelService | None = None) -> Platform:
        settings.ensure_dirs()
        db = Database(settings.db_path)
        repo = Repository(db)
        return cls(settings, db, repo, intel or IntelService(settings, repo))


class JobRunner:
    def __init__(self, platform: Platform, report_fn: Callable[[AnalysisResult, Settings], bytes] | None = None) -> None:
        self.p = platform
        self._pool = ThreadPoolExecutor(max_workers=max(1, platform.settings.worker_threads), thread_name_prefix="job")
        self._futures: dict[str, Future[None]] = {}
        if report_fn is None:
            from malintx.reports.pdf import render_report

            report_fn = render_report
        self._report_fn = report_fn
        interrupted = platform.repo.fail_interrupted_jobs()
        if interrupted:
            log.warning("marked %d interrupted job(s) as failed on startup", interrupted)

    # ---------------------------------------------------------------- submission
    def submit(self, sample: IngestedSample, *, enrich: bool, ai: bool, force: bool = False) -> tuple[JobInfo, bool]:
        """Create a job for an ingested sample. Returns (job, reused_existing)."""
        repo = self.p.repo
        repo.upsert_sample(sha256=sample.sha256, sha1=sample.sha1, md5=sample.md5, size_bytes=sample.size_bytes,
                           display_name=sample.display_name, first_seen=sample.first_seen,
                           stored_path=str(sample.stored_path))
        if not force:
            prior = repo.latest_completed_job(sample.sha256)
            if prior and (prior.enrich_requested or not enrich) and (prior.ai_requested or not ai):
                return prior, True
        now = utcnow()
        job = JobInfo(
            id=uuid.uuid4().hex[:16], sample_sha256=sample.sha256, display_name=sample.display_name,
            status=JobStatus.QUEUED, created_at=now, updated_at=now, enrich_requested=enrich, ai_requested=ai,
            stages=[StageRecord(name=s) for s in STAGES],
            duplicate_of_job=(repo.latest_completed_job(sample.sha256).id if repo.latest_completed_job(sample.sha256) else None),
        )
        job.stages[0] = StageRecord(
            name="ingest", state=StageState.DONE, started_at=now, finished_at=now,
            message=f"validated {sample.size_bytes} bytes, {sample.archive.entry_count} archive entries; sha256 {sample.sha256[:16]}…"
            + (" (sample already stored)" if sample.already_stored else ""),
        )
        repo.create_job(job)
        self._futures[job.id] = self._pool.submit(self._run_safely, job.id, sample)
        return job, False

    def wait(self, job_id: str, timeout: float | None = None) -> None:
        fut = self._futures.get(job_id)
        if fut:
            fut.result(timeout=timeout)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    # ---------------------------------------------------------------- execution
    def _stage(self, job: JobInfo, name: str, state: StageState, message: str = "") -> None:
        for s in job.stages:
            if s.name == name:
                s.state = state
                s.message = message[:300] or s.message
                if state == StageState.RUNNING:
                    s.started_at = utcnow()
                    if name in _STAGE_STATUS:
                        job.status = _STAGE_STATUS[name]
                elif state in (StageState.DONE, StageState.FAILED, StageState.SKIPPED):
                    s.finished_at = utcnow()
        self.p.repo.update_job(job)

    def _run_safely(self, job_id: str, sample: IngestedSample) -> None:
        job = self.p.repo.get_job(job_id)
        try:
            self._run(job, sample)
        except Exception as exc:  # noqa: BLE001 - last-resort boundary: a job must always reach a terminal state
            log.exception("job %s crashed", job_id)
            job.status, job.error_code, job.error_message = JobStatus.FAILED, "internal_error", f"{type(exc).__name__}: {str(exc)[:200]}"
            self.p.repo.update_job(job)

    def _fail(self, job: JobInfo, stage: str, code: str, message: str, static=None) -> None:
        self._stage(job, stage, StageState.FAILED, message)
        job.status, job.error_code, job.error_message = JobStatus.FAILED, code, message[:500]
        risk = assess(static, None, self.p.settings)
        result = AnalysisResult(schema_version=SCHEMA_VERSION, job=job, static=static, risk=risk,
                                intel=None, ai=not_requested(), platform_version=__version__)
        self.p.repo.update_job(job)
        self.p.repo.save_result(result)

    def _run(self, job: JobInfo, sample: IngestedSample) -> None:
        s = self.p.settings
        ingested = {
            "sha256": sample.sha256, "sha1": sample.sha1, "md5": sample.md5, "size_bytes": sample.size_bytes,
            "display_name": sample.display_name, "first_seen": sample.first_seen,
            "archive": sample.archive.model_dump(mode="json"),
        }
        # ---- static analysis (isolated subprocess) ------------------------------------------
        self._stage(job, "static_analysis", StageState.RUNNING, "decoding manifest, scanning bytecode, extracting indicators")
        try:
            with workspace(s.workspaces_dir, f"job-{job.id}-") as ws:
                static = run_static_analysis(sample.stored_path, ingested, s, ws)
        except MalintxError as exc:
            self._fail(job, "static_analysis", exc.code, str(exc))
            return
        self._stage(job, "static_analysis", StageState.DONE,
                    f"{len(static.findings)} findings, {len(static.evidence)} evidence items, {len(static.indicators)} indicators "
                    f"({static.coverage.duration_s}s analysis)")
        self.p.repo.upsert_sample(sha256=sample.sha256, sha1=sample.sha1, md5=sample.md5, size_bytes=sample.size_bytes,
                                  display_name=sample.display_name, first_seen=sample.first_seen,
                                  stored_path=str(sample.stored_path), package_name=static.sample.package_name)

        # ---- threat intelligence --------------------------------------------------------------
        intel: IntelReport | None = None
        if job.enrich_requested:
            self._stage(job, "threat_intel", StageState.RUNNING, "passive provider lookups")
            try:
                intel = self.p.intel.enrich(static, lambda m: self._stage(job, "threat_intel", StageState.RUNNING, f"lookup {m}"))
                states = ", ".join(f"{k}={v.value}" for k, v in intel.providers.items())
                self._stage(job, "threat_intel", StageState.DONE, f"{len(intel.indicators)} indicators enriched ({states})")
            except Exception as exc:  # noqa: BLE001 - enrichment must never invalidate static findings
                log.exception("threat intel stage failed for %s", job.id)
                intel = IntelReport(requested=True, notes=[f"enrichment failed: {type(exc).__name__}"])
                self._stage(job, "threat_intel", StageState.FAILED, f"{type(exc).__name__}: enrichment failed; static results unaffected")
        else:
            self._stage(job, "threat_intel", StageState.SKIPPED, "not requested (no data leaves this host)")

        # ---- AI reasoning ----------------------------------------------------------------------
        ai: AIResult = not_requested()
        if job.ai_requested:
            self._stage(job, "ai_reasoning", StageState.RUNNING, "evidence-grounded interpretation")
            try:
                ai = run_ai(static, intel, s)
            except Exception as exc:  # noqa: BLE001
                log.exception("AI stage failed for %s", job.id)
                ai = AIResult(status="failed", error=f"{type(exc).__name__}")
            state = {"completed": StageState.DONE, "unconfigured": StageState.SKIPPED}.get(ai.status, StageState.FAILED)
            self._stage(job, "ai_reasoning", state, f"AI {ai.status}" + (f": {ai.error}" if ai.error else ""))
        else:
            self._stage(job, "ai_reasoning", StageState.SKIPPED, "not requested (no evidence sent to an AI provider)")

        # ---- deterministic scoring ---------------------------------------------------------------
        self._stage(job, "scoring", StageState.RUNNING, "deterministic risk engine")
        risk = assess(static, intel, s)
        self._stage(job, "scoring", StageState.DONE, f"{risk.classification.value}" + (f" ({risk.score}/100)" if risk.score is not None else ""))

        result = AnalysisResult(schema_version=SCHEMA_VERSION, job=job, static=static, intel=intel, ai=ai, risk=risk,
                                platform_version=__version__)
        self.p.repo.save_result(result)

        # ---- report ------------------------------------------------------------------------------
        self._stage(job, "reporting", StageState.RUNNING, "rendering PDF")
        try:
            pdf = self._report_fn(result, s)
            path = s.reports_dir / f"{job.id}.pdf"
            path.write_bytes(pdf)
            self.p.repo.save_report(job.id, str(path), hashlib.sha256(pdf).hexdigest())
            result.report_available = True
            self._stage(job, "reporting", StageState.DONE, f"{len(pdf) // 1024} KiB")
        except Exception as exc:  # noqa: BLE001
            log.exception("report rendering failed for %s", job.id)
            self._stage(job, "reporting", StageState.FAILED, f"{type(exc).__name__}: report could not be rendered")
        job.status = JobStatus.COMPLETED
        self.p.repo.update_job(job)
        result.job = job
        self.p.repo.save_result(result)

