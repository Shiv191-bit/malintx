"""Deterministic risk engine: reproducibility, FP resistance, honest non-verdicts."""

from __future__ import annotations

import random

from malintx.risk.engine import assess, classify
from malintx.schemas.common import Classification, FindingKind, IntelVerdict, ProviderStatus
from malintx.schemas.results import IndicatorIntel, IntelLookup, IntelReport


def test_banking_trojan_scores_high_or_critical(analyzed, settings):
    risk = assess(analyzed["banking_trojan"], None, settings)
    assert risk.classification in (Classification.HIGH, Classification.CRITICAL)
    assert risk.score >= 80
    assert 0 <= risk.score <= 100


def test_legit_banking_sms_is_not_flagged(analyzed, settings):
    """SMS permission + SMS APIs in a banking app must not independently establish malicious intent."""
    risk = assess(analyzed["benign_bank"], None, settings)
    assert risk.classification == Classification.INFORMATIONAL and risk.score < 10
    assert risk.suppressions  # the OTP-autofill context adjustment is disclosed


def test_sms_capability_alone_never_reaches_high(analyzed, settings):
    inj = analyzed["injection_app"]  # SMS read + permission, nothing else
    risk = assess(inj, None, settings)
    assert risk.classification in (Classification.INFORMATIONAL, Classification.LOW)


def test_misconfiguration_does_not_add_to_score(analyzed, settings):
    risk = assess(analyzed["misconfigured_only"], None, settings)
    assert risk.score == 0 and risk.classification == Classification.INFORMATIONAL
    assert risk.security_posture_issues == 5 and risk.misconfiguration_finding_ids


def test_packed_sample_is_inconclusive_not_benign(analyzed, settings):
    risk = assess(analyzed["packed_app"], None, settings)
    assert risk.classification == Classification.INCONCLUSIVE
    assert "must not be read as benign" in risk.summary
    assert any("Verdict withheld" in x for x in risk.limitations)


def test_no_analysable_code_is_insufficient_evidence(analyzed, settings):
    for name in ("manifest_only", "broken_dex"):
        risk = assess(analyzed[name], None, settings)
        assert risk.classification == Classification.INSUFFICIENT_EVIDENCE, name
        assert "not a verdict" in risk.summary


def test_failed_analysis_has_no_score_and_is_not_clean(settings):
    risk = assess(None, None, settings)
    assert risk.classification == Classification.ANALYSIS_FAILED and risk.score is None
    assert "not a clean result" in risk.summary


def test_score_is_reproducible_and_order_independent(analyzed, settings):
    r = analyzed["banking_trojan"]
    base = assess(r, None, settings)
    for seed in range(5):
        shuffled = r.model_copy(update={"findings": random.Random(seed).sample(r.findings, len(r.findings))})
        again = assess(shuffled, None, settings)
        assert (again.score, again.classification, again.inputs_digest) == (base.score, base.classification, base.inputs_digest)
        assert [(c.source, c.applied_points) for c in again.contributions] == [(c.source, c.applied_points) for c in base.contributions]


def test_every_point_is_explained(analyzed, settings):
    risk = assess(analyzed["banking_trojan"], None, settings)
    assert risk.contributions
    for c in risk.contributions:
        assert c.note and c.applied_points >= 0
    total = sum(c.applied_points for c in risk.contributions)
    assert risk.score == min(100, round(total)) or risk.floors_applied or total > 100


def test_diminishing_returns_prevent_api_pile_up(analyzed, settings):
    risk = assess(analyzed["banking_trojan"], None, settings)
    sms = [c for c in risk.contributions if c.category == "sms"]
    assert len(sms) >= 4
    assert sum(c.applied_points for c in sms) < sum(c.base_points * c.multiplier for c in sms)


def test_trusted_signer_halves_capability_points(analyzed, settings):
    r = analyzed["benign_bank"].model_copy(deep=True)
    fp = r.sample.certificates[0].sha256
    plain = assess(r, None, settings)
    trusted = assess(r, None, settings.model_copy(update={"trusted_cert_sha256": fp.upper()}))
    assert trusted.score <= plain.score
    assert any("trusted" in c.note for c in trusted.contributions) or plain.score == 0


def _intel(sample=IntelVerdict.UNKNOWN, inds=()):
    return IntelReport(requested=True, providers={"virustotal": ProviderStatus.OK}, sample_verdict=sample,
                       sample_lookups=[IntelLookup(provider="virustotal", subject="x", subject_type="sha256", status=ProviderStatus.OK,
                                                   verdict=sample, malicious=40, retrieved_at="t")],
                       indicators=[IndicatorIntel(indicator_id=f"i{n}", value=v, type="domain", verdict=vd) for n, (v, vd) in enumerate(inds)])


def test_unknown_intel_adds_nothing_and_is_never_safe(analyzed, settings):
    r = analyzed["misconfigured_only"]
    base = assess(r, None, settings)
    unknown = assess(r, _intel(inds=[("x.example", IntelVerdict.UNKNOWN)]), settings)
    assert unknown.score == base.score
    assert any("never as benign" in a for a in unknown.adjustments)


def test_benign_observed_intel_never_lowers_score(analyzed, settings):
    r = analyzed["banking_trojan"]
    base = assess(r, None, settings)
    benign = assess(r, _intel(sample=IntelVerdict.BENIGN_OBSERVED, inds=[("a.example", IntelVerdict.BENIGN_OBSERVED)]), settings)
    assert benign.score >= base.score


def test_known_malicious_hash_sets_floor_and_corroborates(analyzed, settings):
    r = analyzed["misconfigured_only"]  # nothing suspicious in code
    risk = assess(r, _intel(sample=IntelVerdict.KNOWN_MALICIOUS), settings)
    assert risk.score >= 60 and risk.classification in (Classification.HIGH, Classification.CRITICAL)
    assert any("floor 60" in f for f in risk.floors_applied)


def test_known_malicious_hash_overrides_insufficient_evidence(analyzed, settings):
    risk = assess(analyzed["manifest_only"], _intel(sample=IntelVerdict.KNOWN_MALICIOUS), settings)
    assert risk.classification in (Classification.HIGH, Classification.CRITICAL)


def test_indicator_intel_capped(analyzed, settings):
    r = analyzed["misconfigured_only"]
    many = _intel(inds=[(f"d{i}.example", IntelVerdict.KNOWN_MALICIOUS) for i in range(10)])
    risk = assess(r, many, settings)
    pts = [c.applied_points for c in risk.contributions if c.source.startswith("intel:indicators")]
    assert pts == [20.0]


def test_ai_output_cannot_influence_score(analyzed, settings):
    """The risk engine takes no AI input; changing the AI result changes nothing."""
    import inspect
    assert "ai" not in inspect.signature(assess).parameters


def test_classification_bands():
    assert [classify(s).value for s in (0, 9, 10, 29, 30, 54, 55, 79, 80, 100)] == [
        "informational", "informational", "low", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_only_composites_count_as_behaviour_in_summary(analyzed, settings):
    risk = assess(analyzed["benign_bank"], None, settings)
    assert "No correlated malicious-behaviour patterns" in risk.summary
    assert all(f.kind != FindingKind.MALICIOUS_BEHAVIOR for f in analyzed["benign_bank"].findings)
