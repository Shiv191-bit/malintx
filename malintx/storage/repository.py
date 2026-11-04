"""Typed repository over the SQLite database."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from malintx.errors import NotFoundError
from malintx.schemas.analysis import LineageFingerprint
from malintx.schemas.common import JobStatus
from malintx.schemas.results import AnalysisResult, JobInfo, StageRecord
from malintx.storage.db import Database, utcnow


def _job_from_row(row: Any) -> JobInfo:
    return JobInfo(
        id=row["id"], sample_sha256=row["sample_sha256"], display_name=row["display_name"],
        status=JobStatus(row["status"]), created_at=row["created_at"], updated_at=row["updated_at"],
        enrich_requested=bool(row["enrich_requested"]), ai_requested=bool(row["ai_requested"]),
        error_code=row["error_code"], error_message=row["error_message"],
        stages=[StageRecord.model_validate(s) for s in json.loads(row["stages_json"])],
        duplicate_of_job=row["duplicate_of_job"],
    )


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- samples ---------------------------------------------------------------------------
    def upsert_sample(self, *, sha256: str, sha1: str, md5: str, size_bytes: int, display_name: str,
                      first_seen: str, stored_path: str, package_name: str | None = None) -> None:
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO samples(sha256,sha1,md5,size_bytes,display_name,first_seen,stored_path,package_name) "
                "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET "
                "package_name=COALESCE(excluded.package_name, samples.package_name)",
                (sha256, sha1, md5, size_bytes, display_name, first_seen, stored_path, package_name),
            )

    def get_sample(self, sha256: str) -> dict[str, Any] | None:
        with self.db.connect() as c:
            row = c.execute("SELECT * FROM samples WHERE sha256=?", (sha256,)).fetchone()
        return dict(row) if row else None

    def latest_completed_job(self, sha256: str) -> JobInfo | None:
        with self.db.connect() as c:
            row = c.execute(
                "SELECT * FROM jobs WHERE sample_sha256=? AND status='completed' ORDER BY created_at DESC LIMIT 1",
                (sha256,),
            ).fetchone()
        return _job_from_row(row) if row else None

    # ---- jobs ------------------------------------------------------------------------------
    def create_job(self, job: JobInfo) -> None:
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO jobs(id,sample_sha256,display_name,status,created_at,updated_at,enrich_requested,"
                "ai_requested,error_code,error_message,stages_json,duplicate_of_job) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (job.id, job.sample_sha256, job.display_name, job.status.value, job.created_at, job.updated_at,
                 int(job.enrich_requested), int(job.ai_requested), job.error_code, job.error_message,
                 json.dumps([s.model_dump(mode="json") for s in job.stages]), job.duplicate_of_job),
            )

    def update_job(self, job: JobInfo) -> None:
        job.updated_at = utcnow()
        with self.db.tx() as c:
            c.execute(
                "UPDATE jobs SET sample_sha256=?, status=?, updated_at=?, error_code=?, error_message=?, "
                "stages_json=?, duplicate_of_job=? WHERE id=?",
                (job.sample_sha256, job.status.value, job.updated_at, job.error_code, job.error_message,
                 json.dumps([s.model_dump(mode="json") for s in job.stages]), job.duplicate_of_job, job.id),
            )

    def get_job(self, job_id: str) -> JobInfo:
        with self.db.connect() as c:
            row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"job {job_id} not found")
        return _job_from_row(row)

    def list_jobs(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """History rows joined with the headline result fields."""
        with self.db.connect() as c:
            rows = c.execute(
                "SELECT j.*, r.classification, r.score, r.package_name, s.sha256 AS sha, s.size_bytes "
                "FROM jobs j LEFT JOIN results r ON r.job_id=j.id LEFT JOIN samples s ON s.sha256=j.sample_sha256 "
                "ORDER BY j.created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [
            {
                "job_id": r["id"], "display_name": r["display_name"], "status": r["status"],
                "created_at": r["created_at"], "sha256": r["sha"], "size_bytes": r["size_bytes"],
                "classification": r["classification"], "score": r["score"], "package_name": r["package_name"],
                "error_code": r["error_code"], "enrich_requested": bool(r["enrich_requested"]),
                "ai_requested": bool(r["ai_requested"]),
            }
            for r in rows
        ]

    def fail_interrupted_jobs(self) -> int:
        """Called on startup: jobs left in a non-terminal state by a crashed process can never finish."""
        with self.db.tx() as c:
            cur = c.execute(
                "UPDATE jobs SET status='failed', error_code='interrupted', "
                "error_message='Process restarted while this job was running', updated_at=? "
                "WHERE status NOT IN ('completed','failed')",
                (utcnow(),),
            )
            return cur.rowcount

    # ---- results & reports -----------------------------------------------------------------
    def save_result(self, result: AnalysisResult) -> None:
        risk = result.risk
        pkg = result.static.sample.package_name if result.static else None
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO results(job_id,schema_version,json,classification,score,package_name,created_at) "
                "VALUES (?,?,?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET json=excluded.json, "
                "classification=excluded.classification, score=excluded.score, package_name=excluded.package_name",
                (result.job.id, result.schema_version, result.model_dump_json(),
                 risk.classification.value if risk else None, risk.score if risk else None, pkg, utcnow()),
            )
        self._save_fingerprint(result)

    def _save_fingerprint(self, result: AnalysisResult) -> None:
        st = result.static
        if st is None or st.lineage is None:
            return
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO fingerprints(job_id,sample_sha256,package_name,display_name,json,created_at) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET json=excluded.json",
                (result.job.id, st.sample.sha256, st.sample.package_name, result.job.display_name, st.lineage.model_dump_json(), utcnow()),
            )

    def all_fingerprints(self, exclude_job: str | None = None) -> list[tuple[str, dict[str, Any], LineageFingerprint]]:
        """One fingerprint per distinct sample (latest job), for similarity search."""
        with self.db.connect() as c:
            rows = c.execute(
                "SELECT f.* FROM fingerprints f JOIN (SELECT sample_sha256, MAX(created_at) m FROM fingerprints GROUP BY sample_sha256) x "
                "ON x.sample_sha256=f.sample_sha256 AND x.m=f.created_at"
            ).fetchall()
        return [(r["job_id"], {"sha256": r["sample_sha256"], "package": r["package_name"], "name": r["display_name"]},
                 LineageFingerprint.model_validate_json(r["json"])) for r in rows if r["job_id"] != exclude_job]

    def latest_results(self, limit: int = 200) -> list[tuple[dict[str, Any], AnalysisResult]]:
        """Latest completed result per distinct sample (newest first), for cross-sample views such as shared infrastructure."""
        with self.db.connect() as c:
            rows = c.execute(
                "SELECT r.json, j.id AS job_id, j.display_name, r.classification, r.score FROM results r JOIN jobs j ON j.id=r.job_id "
                "JOIN (SELECT j2.sample_sha256 sha, MAX(j2.created_at) m FROM jobs j2 JOIN results r2 ON r2.job_id=j2.id GROUP BY j2.sample_sha256) x "
                "ON x.sha=j.sample_sha256 AND x.m=j.created_at ORDER BY j.created_at DESC LIMIT ?", (limit,),
            ).fetchall()
        return [({"job_id": r["job_id"], "name": r["display_name"], "classification": r["classification"], "score": r["score"]},
                 AnalysisResult.model_validate_json(r["json"])) for r in rows]

    def get_result(self, job_id: str) -> AnalysisResult | None:
        with self.db.connect() as c:
            row = c.execute("SELECT json FROM results WHERE job_id=?", (job_id,)).fetchone()
        return AnalysisResult.model_validate_json(row["json"]) if row else None

    def save_report(self, job_id: str, path: str, sha256: str) -> None:
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO reports(job_id,path,sha256,created_at) VALUES (?,?,?,?) ON CONFLICT(job_id) "
                "DO UPDATE SET path=excluded.path, sha256=excluded.sha256, created_at=excluded.created_at",
                (job_id, path, sha256, utcnow()),
            )

    def get_report(self, job_id: str) -> dict[str, Any] | None:
        with self.db.connect() as c:
            row = c.execute("SELECT * FROM reports WHERE job_id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    # ---- intel cache -----------------------------------------------------------------------
    def cache_get(self, key: str) -> str | None:
        with self.db.connect() as c:
            row = c.execute("SELECT json, expires_at FROM intel_cache WHERE cache_key=?", (key,)).fetchone()
        if row is None or row["expires_at"] < utcnow():
            return None
        return row["json"]

    def cache_put(self, key: str, provider: str, subject: str, payload: str, ttl_s: int) -> None:
        now = datetime.now(timezone.utc)
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO intel_cache VALUES (?,?,?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET "
                "json=excluded.json, retrieved_at=excluded.retrieved_at, expires_at=excluded.expires_at",
                (key, provider, subject, payload, now.isoformat(timespec="seconds"),
                 (now + timedelta(seconds=ttl_s)).isoformat(timespec="seconds")),
            )

    # ---- aggregates for the dashboard -------------------------------------------------------
    def overview(self) -> dict[str, Any]:
        with self.db.connect() as c:
            total = c.execute("SELECT COUNT(*) n FROM jobs").fetchone()["n"]
            by_status = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM jobs GROUP BY status")}
            by_class = {
                r["classification"]: r["n"]
                for r in c.execute("SELECT classification, COUNT(*) n FROM results WHERE classification IS NOT NULL GROUP BY classification")
            }
            samples = c.execute("SELECT COUNT(*) n FROM samples").fetchone()["n"]
        return {"jobs_total": total, "samples_total": samples, "jobs_by_status": by_status, "results_by_classification": by_class}
