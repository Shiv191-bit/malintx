"""Dashboard renders real backend data (Streamlit AppTest against a live in-process API server)."""

from __future__ import annotations

import socket
import threading
import time

import httpx
import pytest
import uvicorn
from scenarios import banking_trojan, benign_bank, packed_app
from streamlit.testing.v1 import AppTest

from malintx.api.app import create_app
from malintx.config import PROJECT_ROOT, Settings
from malintx.pipeline.orchestrator import JobRunner, Platform

APP = str(PROJECT_ROOT / "malintx" / "dashboard" / "app.py")


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    s = Settings(data_dir=tmp_path_factory.mktemp("dash") / "var", _env_file=None)
    plat = Platform.create(s)
    runner = JobRunner(plat)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(s, plat, runner), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    base = f"http://127.0.0.1:{port}"
    jobs = {}
    with httpx.Client(base_url=base + "/api/v1", timeout=120) as c:
        for name, fn in (("trojan", banking_trojan), ("bank", benign_bank), ("packed", packed_app)):
            jid = c.post("/analyses", files={"file": (f"{name}.apk", fn(), "application/octet-stream")}).json()["job"]["id"]
            runner.wait(jid, 180)
            jobs[name] = jid
    yield base, jobs
    server.should_exit = True
    runner.shutdown()
    t.join(timeout=10)


def run(base, monkeypatch, **state):
    monkeypatch.setenv("MALINTX_API_URL", base)
    at = AppTest.from_file(APP, default_timeout=60)
    for k, v in state.items():
        at.session_state[k] = v
    return at.run()


def texts(at) -> str:
    parts = [m.value for m in at.markdown] + [t.value for t in at.title] + [s.value for s in at.subheader] + [c.value for c in at.caption]
    return "\n".join(parts)


def test_overview_shows_real_counts(live, monkeypatch):
    base, _ = live
    at = run(base, monkeypatch)
    assert not at.exception
    blob = texts(at)
    assert "Overview" in blob and "Recent analyses" in blob
    kpis = " ".join(m.value for m in at.markdown if "mx-kpi-value" in m.value)
    assert ">3<" in kpis  # three analyses submitted through the real API


def test_trojan_analysis_renders_every_tab_without_errors(live, monkeypatch):
    base, jobs = live
    at = run(base, monkeypatch, page="Analysis", job_id=jobs["trojan"])
    assert not at.exception, [e.value for e in at.exception]
    blob = texts(at)
    assert "CRITICAL" in blob and "9 correlated malicious-behaviour pattern" in blob
    assert len(at.tabs) == 9
    assert any("com.fake.update.service" in t.value for t in at.title)


def test_benign_and_inconclusive_labelled_honestly(live, monkeypatch):
    base, jobs = live
    bank = run(base, monkeypatch, page="Analysis", job_id=jobs["bank"])
    assert not bank.exception and "INFORMATIONAL" in texts(bank) and "No correlated malicious-behaviour patterns" in texts(bank)
    packed = run(base, monkeypatch, page="Analysis", job_id=jobs["packed"])
    assert not packed.exception and "INCONCLUSIVE" in texts(packed) and "must not be read as benign" in texts(packed)


def test_unrequested_enrichment_and_ai_are_labelled_unavailable(live, monkeypatch):
    base, jobs = live
    at = run(base, monkeypatch, page="Analysis", job_id=jobs["trojan"])
    html = " ".join(m.value for m in at.markdown)
    assert "Threat intelligence: unavailable." in html and "AI interpretation: unavailable." in html
    assert "UNKNOWN, not safe" in html


def test_history_config_and_upload_pages(live, monkeypatch):
    base, _ = live
    for page in ("History", "Configuration", "Analyze"):
        at = run(base, monkeypatch, page=page)
        assert not at.exception, (page, [e.value for e in at.exception])
    cfg = run(base, monkeypatch, page="Configuration")
    assert any("MITRE ATT&CK for Mobile v20.0" in str(df.value) for df in cfg.dataframe)


def test_backend_down_is_reported_not_crashed(monkeypatch):
    monkeypatch.setenv("MALINTX_API_URL", "http://127.0.0.1:9")
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    assert any("Backend: unavailable." in m.value for m in at.markdown)


def test_md_escape_neutralises_markdown_and_html():
    from malintx.dashboard.theme import md

    out = md("[click](http://evil.example) `x` <img src=x onerror=1> **b** ![i](u)")
    assert "\[click\]" in out and "\<img" in out and "\*\*b\*\*" in out and "\!\[i\]" in out


def test_hostile_certificate_subject_cannot_inject_links(live, monkeypatch):
    """A sample controls its certificate subject; it must render as inert text, not a clickable link."""
    base, jobs = live
    import httpx as _httpx

    res = _httpx.get(f"{base}/api/v1/analyses/{jobs['bank']}/result").json()
    res["static"]["sample"]["certificates"][0]["subject"] = "[Verify your account](http://evil.example/login)"
    monkeypatch.setenv("MALINTX_API_URL", base)

    def script():
        import streamlit as st

        from malintx.dashboard import views_analysis

        res = st.session_state["res"]
        views_analysis._summary(res, res["static"], res["risk"])

    at = AppTest.from_function(script, default_timeout=60)
    at.session_state["res"] = res
    at.run()
    assert not at.exception
    captions = [c.value for c in at.caption if "Certificate" in c.value]
    assert captions and "\[Verify your account\]\(http\://evil\.example/login\)" in captions[0]
    assert "[Verify your account](http://evil.example/login)" not in captions[0]
