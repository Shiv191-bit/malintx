"""Static analysis behaviour on synthetic (inert) scenarios."""

from __future__ import annotations

import re

from malintx.schemas.common import Confidence, EvidenceKind, FindingKind, IndicatorType


def ids(result):
    return {f.rule_id for f in result.findings}


def test_manifest_and_sample_metadata(analyzed):
    r = analyzed["banking_trojan"]
    assert r.sample.package_name == "com.fake.update.service"
    assert r.sample.version_name == "2.1.0" and r.sample.version_code == "7"
    assert (r.sample.min_sdk, r.sample.target_sdk) == (24, 34)
    assert r.manifest.accessibility_services == ["com.fake.update.service.AccService"]
    assert r.manifest.device_admin_receivers == ["com.fake.update.service.AdminRx"]
    assert "android.permission.SEND_SMS" in r.manifest.permission_names()
    sms_rx = next(c for c in r.manifest.components if c.name.endswith("SmsRx"))
    assert sms_rx.intent_filters[0].priority == 1000


def test_signing_certificate_extracted(analyzed):
    r = analyzed["banking_trojan"]
    assert r.sample.signing_schemes == ["v1"]
    cert = r.sample.certificates[0]
    assert re.fullmatch(r"[0-9a-f]{64}", cert.sha256) and "MALINT-X Synthetic Test" in cert.subject
    assert cert.self_signed


def test_trojan_pattern_yields_correlated_behaviours(analyzed):
    r = analyzed["banking_trojan"]
    expected = {
        "COMP-SMS-FORWARDING", "COMP-SMS-EXFIL-HARDCODED", "COMP-SMS-SUPPRESSION", "COMP-OVERLAY-ACCESSIBILITY",
        "COMP-BANKING-TROJAN-PATTERN", "COMP-DROPPER", "COMP-DYNAMIC-PAYLOAD-STAGING", "COMP-DEVICE-ADMIN-PERSISTENCE",
        "COMP-STEALTH-WITH-CAPABILITY", "STR-TARGET-APP-ENUM",
    }
    assert expected <= ids(r)


def test_benign_otp_bank_has_no_behaviour_correlation(analyzed):
    r = analyzed["benign_bank"]
    assert not [f for f in r.findings if f.kind == FindingKind.MALICIOUS_BEHAVIOR]
    sms = [f for f in r.findings if f.rule_id in ("API-SMS-READ", "MAN-SMS-PERMISSIONS")]
    assert sms, "SMS capability should still be reported"
    assert all(f.suppressed_by == ["CTX-SMS-RETRIEVER"] and f.severity.value == "low" for f in sms)


def test_every_finding_has_resolvable_evidence(analyzed):
    for name, r in analyzed.items():
        by_id = r.evidence_by_id()
        for f in r.findings:
            assert f.evidence_ids, f"{name}:{f.id} has no evidence"
            assert all(e in by_id for e in f.evidence_ids), f"{name}:{f.id} references unknown evidence"
        for m in r.mitre:
            assert all(e in by_id for e in m.evidence_ids)
        for i in r.indicators:
            assert all(e in by_id for e in i.evidence_ids)


def test_evidence_preserves_provenance(analyzed):
    r = analyzed["banking_trojan"]
    api = [e for e in r.evidence if e.kind == EvidenceKind.API_CALL and e.rule_id == "API-SMS-SEND"]
    assert api
    e = api[0]
    assert e.class_name == "Lcom/fake/update/service/SmsRx;" and e.method_name == "onReceive"
    assert e.api == "Landroid/telephony/SmsManager;->sendTextMessage"
    assert e.bytecode_offset is not None and e.source_file == "classes.dex"
    assert e.extraction_method == "androguard-bytecode" and e.limitations
    assert "sendTextMessage" in e.snippet and ">>" in e.snippet
    man = next(x for x in r.evidence if x.kind == EvidenceKind.MANIFEST and x.rule_id == "MAN-SMS-PRIORITY")
    assert man.source_file == "AndroidManifest.xml" and 'android:priority="1000"' in man.snippet


def test_evidence_ids_are_deterministic(analyzed, tmp_path):
    from conftest import run_static
    from scenarios import banking_trojan

    from malintx.config import Settings

    s = Settings(data_dir=tmp_path / "var", _env_file=None)
    s.ensure_dirs()
    again, _ = run_static(banking_trojan(), tmp_path, s)
    first = analyzed["banking_trojan"]
    assert {e.id for e in again.evidence} == {e.id for e in first.evidence}
    assert [f.id for f in again.findings] == [f.id for f in first.findings]


def test_indicators_extracted_and_noise_filtered(analyzed):
    t = analyzed["banking_trojan"]
    urls = {i.value for i in t.indicators if i.type == IndicatorType.URL}
    assert "http://cdn-update-check.top/api/sms.php" in urls
    pk = {i.value for i in t.indicators if i.type == IndicatorType.PACKAGE_REF}
    assert len(pk) == 12
    b = analyzed["benign_bank"]
    assert any(i.value == "https://api.examplebank.in/v1/login" for i in b.indicators)


def test_misconfiguration_is_kept_separate_from_malice(analyzed):
    r = analyzed["misconfigured_only"]
    kinds = {f.kind for f in r.findings}
    assert not kinds & {FindingKind.MALICIOUS_BEHAVIOR, FindingKind.SUSPICIOUS_CAPABILITY}
    assert FindingKind.SECURITY_MISCONFIGURATION in kinds
    assert {"MAN-DEBUGGABLE", "MAN-CLEARTEXT", "MAN-EXPORTED-COMPONENTS", "MAN-ALLOW-BACKUP", "MAN-LOW-TARGET-SDK"} <= ids(r)
    assert not r.mitre  # misconfigurations never map to adversary techniques
    assert all(f.masvs for f in r.findings if f.kind == FindingKind.SECURITY_MISCONFIGURATION)


def test_packer_and_coverage_flags(analyzed):
    p = analyzed["packed_app"]
    assert p.coverage.packer_hints
    assert "ARC-PACKER" in ids(p)
    assert any("native" in x for x in p.coverage.limitations)
    m = analyzed["manifest_only"]
    assert not m.coverage.usable_code and m.coverage.manifest_parsed
    b = analyzed["broken_dex"]
    assert b.coverage.dex_files_failed and "no usable DEX" in " ".join(b.warnings)


def test_mitre_mappings_carry_evidence_and_official_names(analyzed):
    r = analyzed["banking_trojan"]
    by_id = {m.technique_id: m for m in r.mitre}
    assert by_id["T1636.004"].technique_name == "SMS Messages"
    assert by_id["T1453"].technique_name == "Abuse Accessibility Features"
    for m in r.mitre:
        assert m.evidence_ids and m.finding_ids and m.rationale and m.source.startswith("MITRE ATT&CK for Mobile v")
        assert m.url.startswith("https://attack.mitre.org/")
        assert m.origin == "deterministic_rule"


def test_capability_only_mapping_never_high_confidence(analyzed):
    r = analyzed["benign_bank"]
    sms = next(m for m in r.mitre if m.technique_id == "T1636.004")
    assert sms.confidence <= Confidence.MEDIUM


def test_hardcoded_endpoint_composite_needs_same_class(analyzed):
    """Benign app has SMS read + network + URL, but never in the same class → no exfil composite."""
    assert "COMP-SMS-EXFIL-HARDCODED" not in ids(analyzed["benign_bank"])
    assert "COMP-SMS-EXFIL-HARDCODED" in ids(analyzed["banking_trojan"])
