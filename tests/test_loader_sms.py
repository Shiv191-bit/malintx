from __future__ import annotations

from conftest import run_static
from scenarios import loader_stub, sms_interceptor, tiny_benign

from malintx.risk.engine import assess
from malintx.schemas.common import Classification, FindingKind, Severity


def beh(st):
    return {f.rule_id: f for f in st.findings if f.kind == FindingKind.MALICIOUS_BEHAVIOR}


def test_loader_stub_is_not_called_clean(settings, tmp_path):
    """Regression from real malware: tiny DexClassLoader stubs with archive anomalies scored 'low' (about 10/100)."""
    st, _ = run_static(loader_stub(), tmp_path, settings)
    assert "COMP-LOADER-STUB" in beh(st)
    risk = assess(st, None, settings)
    assert risk.classification in (Classification.MEDIUM, Classification.HIGH, Classification.CRITICAL), risk.classification


def test_small_benign_app_is_not_a_loader_stub(settings, tmp_path):
    st, _ = run_static(tiny_benign(), tmp_path, settings)
    assert "COMP-LOADER-STUB" not in beh(st)
    assert assess(st, None, settings).classification in (Classification.INFORMATIONAL, Classification.LOW)


def test_sms_interception_registration_and_sms_client_context(settings, tmp_path):
    st, _ = run_static(sms_interceptor(), tmp_path, settings)
    f = beh(st)["COMP-SMS-INTERCEPT-REGISTRATION"]
    assert f.severity == Severity.HIGH and not f.suppressed_by
    client, _ = run_static(sms_interceptor(default_handler=True), tmp_path / "c", settings) if (tmp_path / "c").mkdir() is None else (None, None)
    g = beh(client)["COMP-SMS-INTERCEPT-REGISTRATION"]
    assert g.severity == Severity.MEDIUM and g.suppressed_by == ["CTX-SMS-CLIENT"]
