from __future__ import annotations

import io
import re

from pypdf import PdfReader

from malintx import SCHEMA_VERSION
from malintx.reports.pdf import render_report
from malintx.risk.engine import assess
from malintx.schemas.common import Confidence, JobStatus
from malintx.schemas.results import AIAssessment, AIClaim, AIResult, AnalysisResult, JobInfo


def job(**kw):
    return JobInfo(id="job-test-1", display_name="x.apk", status=JobStatus.COMPLETED, created_at="2026-11-03T00:00:00+00:00",
                   updated_at="2026-11-03T00:00:05+00:00", **kw)


def text(pdf: bytes) -> str:
    assert pdf.startswith(b"%PDF")
    return "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf)).pages)


def result(static, settings, ai=None, intel=None):
    return AnalysisResult(schema_version=SCHEMA_VERSION, job=job(), static=static, intel=intel, ai=ai or AIResult(status="not_requested"),
                          risk=assess(static, intel, settings), platform_version="0.2.0")


def test_full_report_contains_required_sections(analyzed, settings):
    t = text(render_report(result(analyzed["banking_trojan"], settings)))
    for needle in ("Executive summary", "Sample metadata", "SHA-256", "Signing certificate", "Analysis environment, coverage and limitations",
                   "Manifest findings", "Behavioural findings", "Code and artifact evidence", "Extracted indicators", "Threat intelligence",
                   "MITRE ATT&CK for Mobile mapping", "Security posture", "Risk score and methodology", "Recommendations",
                   "AI-assisted interpretation", "Traceability", "com.fake.update.service", "T1636.004", "job-test-1"):
        assert needle in t, needle
    assert "not a legally validated chain-of-custody record" in t.replace("\n", " ")
    assert "AI interpretation was not requested" in t.replace("\n", " ")
    assert "Unknown is NOT" in t.replace("\n", " ") or "Unknown means" in t.replace("\n", " ") or "UNKNOWN, not safe" in t.replace("\n", " ")


def test_report_traceable_to_inputs_digest(analyzed, settings):
    res = result(analyzed["banking_trojan"], settings)
    assert res.risk.inputs_digest in text(render_report(res)).replace("\n", "")


def test_ai_section_is_labelled_and_separate(analyzed, settings):
    st = analyzed["banking_trojan"]
    ev = st.findings[0].evidence_ids[0]
    ai = AIResult(status="completed", provider="anthropic", model="m", dropped_claims=["'fake': cites no valid evidence id"],
                  assessment=AIAssessment(overall="likely_malicious", summary="Looks like an SMS stealer.", limitations=["x"],
                                          claims=[AIClaim(title="OTP theft", explanation="because", assessment="malicious_intent", confidence=Confidence.HIGH,
                                                          evidence_ids=[ev], mitre_ids=["T1636.004"], uncertainty="unknown reach")]))
    t = text(render_report(result(st, settings, ai=ai))).replace("\n", " ")
    assert "advisory" in t and "did not influence the score" in t and "OTP theft" in t and ev in t
    assert "Discarded by validation" in t


def test_inconclusive_and_failed_reports_do_not_claim_verdicts(analyzed, settings):
    t = text(render_report(result(analyzed["packed_app"], settings))).replace("\n", " ")
    assert "INCONCLUSIVE" in t and "No benign or malicious verdict is asserted" in t
    failed = AnalysisResult(schema_version=SCHEMA_VERSION, job=job(error_code="analysis_timeout", error_message="exceeded 600s"),
                            static=None, risk=assess(None, None, settings), platform_version="0.2.0")
    t2 = text(render_report(failed)).replace("\n", " ")
    assert "ANALYSIS FAILED" in t2 and "analysis_timeout" in t2 and "No benign or malicious verdict is asserted" in t2


def test_low_risk_report_carries_not_safe_disclaimer(analyzed, settings):
    t = text(render_report(result(analyzed["benign_bank"], settings))).replace("\n", " ")
    assert "not a certification that the application is safe" in t


def test_hostile_strings_cannot_break_rendering(analyzed, settings):
    st = analyzed["banking_trojan"].model_copy(deep=True)
    st.evidence[0] = st.evidence[0].model_copy(update={"snippet": "<script>alert(1)</script> & <b>bold</b> \x00\x07" * 50,
                                                       "artifact": "<para>&&&</para>"})
    st.findings[0] = st.findings[0].model_copy(update={"title": "<b>unclosed & <i>tag", "description": "</para><br/>x"})
    pdf = render_report(result(st, settings))
    assert pdf.startswith(b"%PDF")


def test_report_is_deterministic_in_content(analyzed, settings):
    a = text(render_report(result(analyzed["benign_bank"], settings)))
    b = text(render_report(result(analyzed["benign_bank"], settings)))
    strip = lambda s: re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00)?", "<ts>", s)  # noqa: E731
    assert strip(a) == strip(b)
