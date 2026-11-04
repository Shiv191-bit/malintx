"""End-to-end: HTTP upload → isolated analysis → scoring → PDF, plus failure isolation and API hardening."""

from __future__ import annotations

import io
import json
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient
from scenarios import banking_trojan, benign_bank

from malintx.api.app import create_app
from malintx.config import Settings
from malintx.errors import AnalysisTimeoutError
from malintx.pipeline import orchestrator as orch
from malintx.pipeline.orchestrator import JobRunner, Platform
from malintx.schemas.common import Classification, JobStatus, StageState
from malintx.storage.db import Database
from malintx.storage.repository import Repository


@pytest.fixture()
def env(tmp_path):
    s = Settings(data_dir=tmp_path / "var", _env_file=None)
    plat = Platform.create(s)
    runner = JobRunner(plat)
    app = create_app(s, plat, runner)
    with TestClient(app) as client:
        yield s, plat, runner, client
    runner.shutdown()


def upload(client, data, name="sample.apk", **form):
    return client.post("/api/v1/analyses", files={"file": (name, data, "application/octet-stream")}, data={k: str(v).lower() for k, v in form.items()})


def finish(runner, client, resp):
    job_id = resp.json()["job"]["id"]
    runner.wait(job_id, 180)
    return job_id


def test_full_workflow_trojan(env):
    s, plat, runner, client = env
    r = upload(client, banking_trojan(), name="../../weird name.apk")
    assert r.status_code == 202 and not r.json()["reused_existing"]
    job_id = finish(runner, client, r)

    job = client.get(f"/api/v1/analyses/{job_id}").json()
    assert job["status"] == "completed" and job["display_name"] == "weird name.apk"
    assert [st["state"] for st in job["stages"]] == ["done", "done", "skipped", "skipped", "done", "done"]

    res = client.get(f"/api/v1/analyses/{job_id}/result").json()
    assert res["schema_version"] == "1.1" and res["report_available"] is True
    assert res["risk"]["classification"] in ("high", "critical") and res["risk"]["score"] >= 80
    assert res["static"]["sample"]["package_name"] == "com.fake.update.service"
    assert res["intel"] is None and res["ai"]["status"] == "not_requested"
    assert res["static"]["coverage"]["backend"] == "androguard"

    rep = client.get(f"/api/v1/analyses/{job_id}/report")
    assert rep.status_code == 200 and rep.content.startswith(b"%PDF") and rep.headers["x-report-sha256"]
    import hashlib
    assert hashlib.sha256(rep.content).hexdigest() == rep.headers["x-report-sha256"]

    hist = client.get("/api/v1/analyses").json()
    assert hist[0]["job_id"] == job_id and hist[0]["classification"] in ("high", "critical")
    ov = client.get("/api/v1/overview").json()
    assert ov["jobs_total"] == 1 and ov["samples_total"] == 1


def test_benign_workflow_not_flagged(env):
    _, _, runner, client = env
    r = upload(client, benign_bank())
    job_id = finish(runner, client, r)
    res = client.get(f"/api/v1/analyses/{job_id}/result").json()
    assert res["risk"]["classification"] == "informational" and not [f for f in res["static"]["findings"] if f["kind"] == "malicious_behavior"]


def test_duplicate_upload_reuses_job_unless_forced(env):
    _, _, runner, client = env
    data = banking_trojan()  # identical bytes (each build uses a fresh signing key, so rebuilding would change the hash)
    first = upload(client, data)
    jid = finish(runner, client, first)
    again = upload(client, data, name="renamed.apk")
    assert again.json()["reused_existing"] and again.json()["job"]["id"] == jid
    forced = upload(client, data, force=True)
    assert not forced.json()["reused_existing"] and forced.json()["job"]["id"] != jid
    assert forced.json()["job"]["duplicate_of_job"] == jid
    runner.wait(forced.json()["job"]["id"], 180)


@pytest.mark.parametrize("payload,code,status", [
    (b"just text", "not_an_apk", 400),
    (b"", "invalid_sample", 400),
    (b"PK\x03\x04garbage", "corrupt_archive", 400),
])
def test_invalid_uploads_rejected_cleanly(env, payload, code, status):
    *_, client = env
    r = upload(client, payload)
    assert r.status_code == status and r.json()["error"]["code"] == code


def test_zip_without_manifest_rejected(env):
    *_, client = env
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "hi")
    r = upload(client, buf.getvalue())
    assert r.status_code == 400 and r.json()["error"]["code"] == "not_an_apk"


def test_oversize_rejected_by_declared_length_and_streaming(tmp_path):
    s = Settings(data_dir=tmp_path / "var", _env_file=None, max_upload_mb=1)
    plat = Platform.create(s)
    app = create_app(s, plat, JobRunner(plat))
    with TestClient(app) as client:
        r = upload(client, b"PK\x03\x04" + b"\x00" * (2 * 1024 * 1024))
        assert r.status_code == 413 and r.json()["error"]["code"] == "oversized_upload"

        def gen():  # no Content-Length: must be stopped while streaming
            for _ in range(40):
                yield b"A" * 100_000

        r2 = client.post("/api/v1/analyses", content=gen(), headers={"content-type": "multipart/form-data; boundary=xyz"})
        assert r2.status_code == 413
    assert not list(s.samples_dir.rglob("*.sample"))


def test_bearer_auth_enforced_with_constant_time_compare(tmp_path):
    s = Settings(data_dir=tmp_path / "var", _env_file=None, api_token="s3cret-token")
    plat = Platform.create(s)
    with TestClient(create_app(s, plat, JobRunner(plat))) as c:
        assert c.get("/api/v1/health").status_code == 401
        assert c.get("/api/v1/health", headers={"Authorization": "Bearer nope"}).status_code == 401
        assert c.get("/api/v1/health", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200


def test_rate_limits(tmp_path):
    s = Settings(data_dir=tmp_path / "var", _env_file=None, upload_rate_limit_per_minute=2, api_rate_limit_per_minute=1000)
    plat = Platform.create(s)
    with TestClient(create_app(s, plat, JobRunner(plat))) as c:
        codes = [upload(c, b"junk").status_code for _ in range(4)]
    assert codes[:2] == [400, 400] and codes[2:] == [429, 429]


def test_config_endpoint_never_leaks_secrets(tmp_path):
    s = Settings(data_dir=tmp_path / "var", _env_file=None, vt_api_key="VT-LEAK-CHECK", anthropic_api_key="AN-LEAK-CHECK",
                 ai_provider="anthropic", api_token="TOK-LEAK-CHECK")
    plat = Platform.create(s)
    with TestClient(create_app(s, plat, JobRunner(plat))) as c:
        body = c.get("/api/v1/config", headers={"Authorization": "Bearer TOK-LEAK-CHECK"}).text
    assert "LEAK-CHECK" not in body
    data = json.loads(body)
    assert data["threat_intel"]["virustotal"]["configured"] is True and data["ai"] == {"provider": "anthropic", "configured": True}
    assert data["versions"]["mitre"].startswith("MITRE ATT&CK for Mobile v") and data["auth_required"] is True


def test_unknown_job_is_404_with_error_envelope(env):
    *_, client = env
    r = client.get("/api/v1/analyses/doesnotexist")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"
    assert client.get("/api/v1/analyses/doesnotexist/report").status_code == 404


# ---------------------------------------------------------------------------------------------- failure isolation
def run_job(plat, runner, settings, data, **kw):
    from malintx.ingestion import ingest

    sample = ingest([data], "x.apk", settings)
    job, _ = runner.submit(sample, force=True, **{"enrich": False, "ai": False, **kw})
    runner.wait(job.id, 180)
    return plat.repo.get_job(job.id), plat.repo.get_result(job.id)


def test_static_failure_is_reported_not_hidden(env, monkeypatch):
    s, plat, runner, _ = env
    monkeypatch.setattr(orch, "run_static_analysis", lambda *a, **k: (_ for _ in ()).throw(AnalysisTimeoutError("static analysis exceeded 1s")))
    job, result = run_job(plat, runner, s, banking_trojan())
    assert job.status == JobStatus.FAILED and job.error_code == "analysis_timeout"
    assert result.risk.classification == Classification.ANALYSIS_FAILED and result.risk.score is None
    assert result.static is None and not result.report_available


def test_intel_failure_does_not_invalidate_static_results(env, monkeypatch):
    s, plat, runner, _ = env
    monkeypatch.setattr(plat.intel, "enrich", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("provider exploded")))
    job, result = run_job(plat, runner, s, banking_trojan(), enrich=True)
    assert job.status == JobStatus.COMPLETED
    assert next(st for st in job.stages if st.name == "threat_intel").state == StageState.FAILED
    assert result.risk.classification in (Classification.HIGH, Classification.CRITICAL) and result.static.findings
    assert result.intel.requested and "enrichment failed" in result.intel.notes[0]


def test_ai_failure_does_not_invalidate_deterministic_results(env, monkeypatch):
    s, plat, runner, _ = env
    monkeypatch.setattr(orch, "run_ai", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("llm exploded")))
    job, result = run_job(plat, runner, s, banking_trojan(), ai=True)
    assert job.status == JobStatus.COMPLETED and result.ai.status == "failed"
    assert result.risk.score >= 80


def test_report_failure_keeps_result(tmp_path):
    s = Settings(data_dir=tmp_path / "var", _env_file=None)
    plat = Platform.create(s)
    runner = JobRunner(plat, report_fn=lambda *a: (_ for _ in ()).throw(ValueError("render bug")))
    job, result = run_job(plat, runner, s, banking_trojan())
    runner.shutdown()
    assert job.status == JobStatus.COMPLETED and not result.report_available
    assert next(st for st in job.stages if st.name == "reporting").state == StageState.FAILED


def test_ai_unconfigured_is_skipped_not_failed(env):
    s, plat, runner, _ = env
    job, result = run_job(plat, runner, s, banking_trojan(), ai=True)
    assert next(st for st in job.stages if st.name == "ai_reasoning").state == StageState.SKIPPED and result.ai.status == "unconfigured"


def test_enrichment_with_mocked_providers_changes_score_inputs(tmp_path):
    from malintx.intel.service import IntelService

    s = Settings(data_dir=tmp_path / "var", _env_file=None, vt_api_key="k")
    repo = Repository(Database(s.db_path))

    def h(req):
        if "/files/" in req.url.path:
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 33, "undetected": 20}}}})
        return httpx.Response(404)

    plat = Platform(s, repo.db, repo, IntelService(s, repo, transport=httpx.MockTransport(h), sleep=lambda x: None))
    s.ensure_dirs()
    runner = JobRunner(plat)
    job, result = run_job(plat, runner, s, benign_bank(), enrich=True)
    runner.shutdown()
    assert result.intel.sample_verdict.value == "known_malicious"
    assert result.risk.classification in (Classification.HIGH, Classification.CRITICAL)  # corroboration floor
    assert any("known-malicious" in f or "known-malicious" in c.note or c.source == "intel:sample" for f in result.risk.floors_applied for c in result.risk.contributions)


def test_interrupted_jobs_recovered_on_startup(tmp_path):
    from malintx.schemas.results import JobInfo, StageRecord
    from malintx.storage.db import utcnow

    s = Settings(data_dir=tmp_path / "var", _env_file=None)
    plat = Platform.create(s)
    now = utcnow()
    plat.repo.create_job(JobInfo(id="stuck1", display_name="x", status=JobStatus.STATIC_ANALYSIS, created_at=now, updated_at=now,
                                 stages=[StageRecord(name="static_analysis")]))
    JobRunner(plat).shutdown()
    j = plat.repo.get_job("stuck1")
    assert j.status == JobStatus.FAILED and j.error_code == "interrupted"


def test_migrations_idempotent_and_versioned(tmp_path):
    p = tmp_path / "m.db"
    assert Database(p).schema_version() == 2
    assert Database(p).schema_version() == 2


def test_workspaces_cleaned_after_job(env):
    s, plat, runner, _ = env
    run_job(plat, runner, s, banking_trojan())
    assert not [p for p in s.workspaces_dir.iterdir() if p.is_dir()]


def test_relative_data_dir_is_resolved_for_workers(tmp_path, monkeypatch):
    """Regression: MALINTX_DATA_DIR=./var (from .env) broke the isolated worker, which runs in another cwd."""
    monkeypatch.chdir(tmp_path)
    s = Settings(data_dir="./var", _env_file=None)
    assert s.data_dir.is_absolute() and s.data_dir == (tmp_path / "var").resolve()
    plat = Platform.create(s)
    runner = JobRunner(plat)
    job, result = run_job(plat, runner, s, banking_trojan())
    runner.shutdown()
    assert job.status == JobStatus.COMPLETED and result.risk.classification != Classification.ANALYSIS_FAILED


def test_assets_dir_is_configurable_and_reaches_the_worker(tmp_path):
    """Regression (found in Docker): an installed package must locate the ATT&CK dataset via MALINTX_ASSETS_DIR."""
    import shutil

    from malintx.config import PROJECT_ROOT

    assets = tmp_path / "assets"
    (assets / "mitre").mkdir(parents=True)
    shutil.copy(PROJECT_ROOT / "data" / "mitre" / "mobile-attack-20.0.json", assets / "mitre")
    s = Settings(data_dir=tmp_path / "var", assets_dir=assets, _env_file=None)
    assert s.mitre_dataset == (assets / "mitre" / "mobile-attack-20.0.json").resolve()
    plat = Platform.create(s)
    runner = JobRunner(plat)
    job, result = run_job(plat, runner, s, banking_trojan())
    runner.shutdown()
    assert job.status == JobStatus.COMPLETED and result.static.mitre
