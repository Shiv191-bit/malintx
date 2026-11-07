"""Deterministic, explainable risk scoring.

Inputs are limited to: static findings (with their evidence-backed severity/confidence), threat-intel
verdicts and analysis coverage. **No AI output is read here.** Given identical inputs the result is
identical (verified by tests); `inputs_digest` fingerprints the exact inputs.
"""

from __future__ import annotations

import hashlib
import json

from malintx.config import Settings
from malintx.schemas.analysis import Finding, StaticAnalysisResult
from malintx.schemas.common import Classification, Confidence, FindingKind, IntelVerdict, Severity
from malintx.schemas.results import IntelReport, RiskContribution, RiskResult

ENGINE_VERSION = "1.0"

SEVERITY_POINTS = {Severity.INFO: 0.0, Severity.LOW: 2.0, Severity.MEDIUM: 6.0, Severity.HIGH: 12.0, Severity.CRITICAL: 20.0}
KIND_WEIGHT = {FindingKind.MALICIOUS_BEHAVIOR: 1.0, FindingKind.SUSPICIOUS_CAPABILITY: 0.6}
CONFIDENCE_WEIGHT = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.7, Confidence.LOW: 0.4}
DIMINISHING = (1.0, 0.5, 0.25)  # 1st, 2nd, then every further finding in the same behaviour group
GROUP_CAP = 24.0
COMPOSITE_COVERED_FACTOR = 0.5
TRUSTED_SIGNER_FACTOR = 0.5

INTEL_SAMPLE_MALICIOUS = 30.0
INTEL_SAMPLE_SUSPICIOUS = 10.0
INTEL_INDICATOR_MALICIOUS, INTEL_INDICATOR_MALICIOUS_CAP = 10.0, 20.0
INTEL_INDICATOR_SUSPICIOUS, INTEL_INDICATOR_SUSPICIOUS_CAP = 3.0, 6.0

THRESHOLDS = ((80, Classification.CRITICAL), (55, Classification.HIGH), (30, Classification.MEDIUM),
              (10, Classification.LOW), (0, Classification.INFORMATIONAL))

_GROUP = {
    "sms_perm": "sms", "sms_read": "sms", "sms_send": "sms", "sms_suppress": "sms", "sms_intercept": "sms",
    "sms_default": "sms", "accessibility_svc": "accessibility", "accessibility": "accessibility",
    "overlay_perm": "overlay", "overlay": "overlay", "device_admin_decl": "device_admin",
    "device_admin": "device_admin", "dropper_perm": "dropper", "dropper": "dropper",
    "notification_decl": "notification", "notification": "notification", "persistence_boot": "persistence",
    "usage_stats": "app_awareness", "app_enum": "app_awareness", "anti_analysis": "evasion", "evasion": "evasion",
    "packing": "evasion", "obfuscation": "evasion", "dynamic_code": "dynamic_code", "command_exec": "command_exec",
}


def group_of(category: str) -> str:
    return _GROUP.get(category, category)


def classify(score: float) -> Classification:
    for threshold, label in THRESHOLDS:
        if score >= threshold:
            return label
    return Classification.INFORMATIONAL


def _digest(static: StaticAnalysisResult, intel: IntelReport | None, trusted: bool) -> str:
    payload = {
        "engine": ENGINE_VERSION,
        "ruleset": static.ruleset_version,
        "findings": sorted(
            (f.id, f.severity.value, f.kind.value, f.confidence.value, f.category, sorted(f.composite_of),
             sorted(f.suppressed_by)) for f in static.findings
        ),
        "coverage": [static.coverage.manifest_parsed, static.coverage.usable_code,
                     sorted(static.coverage.packer_hints), len(static.coverage.dex_files_failed),
                     static.coverage.obfuscation_ratio],
        "intel": None if not intel or not intel.requested else {
            "sample": intel.sample_verdict.value,
            "indicators": sorted((i.value, i.verdict.value) for i in intel.indicators),
        },
        "trusted_signer": trusted,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def trusted_signer(static: StaticAnalysisResult, settings: Settings) -> bool:
    trusted = settings.trusted_cert_set
    return bool(trusted) and any(c.sha256.lower() in trusted for c in static.sample.certificates)


def assess(static: StaticAnalysisResult | None, intel: IntelReport | None, settings: Settings) -> RiskResult:
    from malintx.analysis.rules.catalog import RULESET_VERSION

    if static is None:
        return RiskResult(
            classification=Classification.ANALYSIS_FAILED, score=None,
            summary="Static analysis did not complete, so no risk assessment can be made. This is not a clean result.",
            engine_version=ENGINE_VERSION, ruleset_version=RULESET_VERSION, inputs_digest="",
            limitations=["No analysis output is available for this sample."],
            recommendations=["Re-run the analysis, check the failure reason, or analyse the sample manually."],
        )

    trusted = trusted_signer(static, settings)
    contributions: list[RiskContribution] = []
    adjustments: list[str] = []
    suppressions: list[str] = []

    composites = [f for f in static.findings if f.kind == FindingKind.MALICIOUS_BEHAVIOR]
    covered = {rid: c.id for c in composites for rid in c.composite_of}

    # ---- 1. findings → per-finding points ------------------------------------------------
    per_group: dict[str, list[RiskContribution]] = {}
    for f in static.findings:
        if f.kind not in KIND_WEIGHT:
            continue
        base = SEVERITY_POINTS[f.severity]
        if base == 0:
            continue
        mult = KIND_WEIGHT[f.kind] * CONFIDENCE_WEIGHT[f.confidence]
        notes = [f"{f.kind.value}, {f.severity.value} severity, {f.confidence.value} confidence"]
        if f.kind == FindingKind.SUSPICIOUS_CAPABILITY:
            if f.rule_id in covered:
                mult *= COMPOSITE_COVERED_FACTOR
                notes.append(f"halved: already counted inside {covered[f.rule_id]}")
            if trusted:
                mult *= TRUSTED_SIGNER_FACTOR
                notes.append("halved: operator-trusted signing certificate")
        if f.suppressed_by:
            suppressions.append(f"{f.id}: severity lowered by {', '.join(f.suppressed_by)}")
        c = RiskContribution(source=f.id, label=f.title, category=group_of(f.category), base_points=base,
                             multiplier=round(mult, 4), applied_points=0.0, note="; ".join(notes))
        per_group.setdefault(c.category, []).append(c)

    subtotal = 0.0
    for group in sorted(per_group):
        items = sorted(per_group[group], key=lambda c: (-(c.base_points * c.multiplier), c.source))
        running = 0.0
        for i, c in enumerate(items):
            factor = DIMINISHING[min(i, len(DIMINISHING) - 1)]
            c.applied_points = round(c.base_points * c.multiplier * factor, 3)
            if factor < 1.0:
                c.note += f"; diminishing-returns factor {factor} (#{i + 1} in group '{group}')"
            running += c.applied_points
        if running > GROUP_CAP:
            scale = GROUP_CAP / running
            for c in items:
                c.applied_points = round(c.applied_points * scale, 3)
            adjustments.append(f"group '{group}' capped at {GROUP_CAP:g} points")
        subtotal += sum(c.applied_points for c in items)
        contributions.extend(items)

    # ---- 2. threat-intel corroboration ---------------------------------------------------
    intel_points = 0.0
    sample_verdict = IntelVerdict.UNKNOWN
    if intel and intel.requested:
        sample_verdict = intel.sample_verdict
        if sample_verdict == IntelVerdict.KNOWN_MALICIOUS:
            contributions.append(RiskContribution(
                source="intel:sample", label="Sample hash known malicious", category="intel",
                base_points=INTEL_SAMPLE_MALICIOUS, multiplier=1.0, applied_points=INTEL_SAMPLE_MALICIOUS,
                note="; ".join(f"{lk.provider}: {lk.malicious} malicious" for lk in intel.sample_lookups if lk.verdict == IntelVerdict.KNOWN_MALICIOUS)))
            intel_points += INTEL_SAMPLE_MALICIOUS
        elif sample_verdict == IntelVerdict.SUSPICIOUS:
            contributions.append(RiskContribution(
                source="intel:sample", label="Sample hash flagged suspicious", category="intel",
                base_points=INTEL_SAMPLE_SUSPICIOUS, multiplier=1.0, applied_points=INTEL_SAMPLE_SUSPICIOUS))
            intel_points += INTEL_SAMPLE_SUSPICIOUS
        mal = [i for i in intel.indicators if i.verdict == IntelVerdict.KNOWN_MALICIOUS]
        sus = [i for i in intel.indicators if i.verdict == IntelVerdict.SUSPICIOUS]
        for items, per, cap, label in ((mal, INTEL_INDICATOR_MALICIOUS, INTEL_INDICATOR_MALICIOUS_CAP, "known-malicious"),
                                       (sus, INTEL_INDICATOR_SUSPICIOUS, INTEL_INDICATOR_SUSPICIOUS_CAP, "suspicious")):
            if items:
                pts = min(cap, per * len(items))
                contributions.append(RiskContribution(
                    source=f"intel:indicators:{label}", label=f"{len(items)} {label} indicator(s) embedded in the app",
                    category="intel", base_points=per * len(items), multiplier=1.0, applied_points=pts,
                    note=f"{per:g} each, capped at {cap:g}: " + ", ".join(i.value[:60] for i in items[:4])))
                intel_points += pts
        adjustments.append("indicators with no threat-intel data are scored as UNKNOWN (0 points), never as benign")
    else:
        adjustments.append("threat intelligence was not requested or unavailable: no intel points applied")

    raw = subtotal + intel_points

    # ---- 3. floors (explicit, documented) -------------------------------------------------
    floors: list[str] = []
    score = raw
    strong = [f for f in composites if f.severity >= Severity.HIGH and f.confidence >= Confidence.MEDIUM]
    if sample_verdict == IntelVerdict.KNOWN_MALICIOUS and score < 60:
        score = 60
        floors.append("sample hash is known-malicious in threat intelligence → floor 60 (High)")
    if len(strong) >= 2 and score < 55:
        score = 55
        floors.append(f"{len(strong)} independent high-severity behaviour correlations → floor 55 (High)")
    elif any(f.severity == Severity.CRITICAL and f.confidence >= Confidence.MEDIUM for f in composites) and score < 45:
        score = 45
        floors.append("critical behaviour pattern present → floor 45 (Medium)")
    elif strong and score < 30:
        score = 30
        floors.append("a high-severity correlated behaviour is present → floor 30 (Medium)")
    score_i = int(round(min(100.0, score)))

    # ---- 4. classification with non-binary outcomes -----------------------------------------
    cov = static.coverage
    classification = classify(score_i)
    limitations = [
        "Static analysis only: the sample was never executed, so runtime-only, server-driven or time-delayed behaviour is invisible.",
        "Bytecode references show capability, not proof of execution or intent.",
        "Native (JNI) code, encrypted payloads and server-side logic are not analysed.",
        f"Scores are produced by rule set {static.ruleset_version} / engine {ENGINE_VERSION}; weights are expert-set and have not been statistically calibrated.",
        "A low score does not certify an application as safe.",
    ]
    reason = ""
    intel_malicious = sample_verdict == IntelVerdict.KNOWN_MALICIOUS
    if not cov.manifest_parsed or not cov.usable_code:
        if not intel_malicious:
            classification = Classification.INSUFFICIENT_EVIDENCE
            reason = ("the manifest could not be parsed" if not cov.manifest_parsed else "no analysable DEX code was found")
    if classification in (Classification.INFORMATIONAL, Classification.LOW) and not intel_malicious:
        why = []
        if cov.packer_hints:
            why.append("a commercial packer/protector was detected (" + ", ".join(cov.packer_hints[:2]) + ")")
        if cov.dex_files_failed:
            why.append(f"{len(cov.dex_files_failed)} DEX file(s) failed to parse")
        if (cov.obfuscation_ratio or 0) >= 0.8 and any(f.rule_id == "API-DYNAMIC-CODE-LOAD" for f in static.findings):
            why.append("heavily obfuscated code combined with dynamic code loading")
        if why:
            classification = Classification.INCONCLUSIVE
            reason = "; ".join(why)
    if reason:
        limitations.insert(0, f"Verdict withheld: {reason}. The visible code may not represent the app's behaviour.")

    misconfig = [f for f in static.findings if f.kind == FindingKind.SECURITY_MISCONFIGURATION]
    summary = _summary(classification, score_i, static, composites, reason, trusted)
    return RiskResult(
        classification=classification, score=score_i, summary=summary,
        contributions=sorted(contributions, key=lambda c: (-c.applied_points, c.source)),
        adjustments=adjustments, floors_applied=floors, suppressions=suppressions,
        security_posture_issues=len(misconfig), misconfiguration_finding_ids=[f.id for f in misconfig],
        engine_version=ENGINE_VERSION, ruleset_version=static.ruleset_version,
        inputs_digest=_digest(static, intel, trusted), limitations=limitations,
        recommendations=_recommendations(classification, composites, static, intel, misconfig),
    )


def _summary(cls: Classification, score: int, static: StaticAnalysisResult, composites: list[Finding],
             reason: str, trusted: bool) -> str:
    n_cap = sum(1 for f in static.findings if f.kind == FindingKind.SUSPICIOUS_CAPABILITY)
    if cls == Classification.INSUFFICIENT_EVIDENCE:
        return f"Insufficient evidence to assess this sample: {reason}. Observed evidence-based score {score}/100 is not a verdict."
    if cls == Classification.INCONCLUSIVE:
        return (f"Inconclusive: {reason}. Visible evidence scores {score}/100, but the code that matters may be hidden, "
                "so this must not be read as benign.")
    parts = [f"{cls.value.title()} risk, evidence-based score {score}/100."]
    if composites:
        parts.append(f"{len(composites)} correlated malicious-behaviour pattern(s): " + "; ".join(f.title for f in composites[:4]) + ".")
    else:
        parts.append("No correlated malicious-behaviour patterns were found.")
    parts.append(f"{n_cap} standalone capability finding(s) contribute with reduced weight.")
    if trusted:
        parts.append("Signed by an operator-trusted certificate (capability weights halved).")
    return " ".join(parts)


def _recommendations(cls: Classification, composites: list[Finding], static: StaticAnalysisResult,
                     intel: IntelReport | None, misconfig: list[Finding]) -> list[str]:
    rec: list[str] = []
    rules = {c.rule_id for c in composites}
    if cls in (Classification.HIGH, Classification.CRITICAL):
        rec.append("Treat as potentially malicious: do not install on managed devices; isolate and review the cited evidence manually.")
    if rules & {"COMP-SMS-FORWARDING", "COMP-SMS-EXFIL-HARDCODED", "COMP-SMS-SUPPRESSION"}:
        rec.append("Review the SMS handling evidence for forwarding destinations and hard-coded endpoints; assume OTPs on affected devices are exposed.")
    if rules & {"COMP-OVERLAY-ACCESSIBILITY", "COMP-BANKING-TROJAN-PATTERN"}:
        rec.append("Check which target applications the overlay/accessibility code references; alert the affected institutions' fraud teams.")
    if static.indicators and cls != Classification.INFORMATIONAL:
        rec.append("Block or monitor the extracted network indicators (do not connect to them directly).")
    if cls in (Classification.INCONCLUSIVE, Classification.INSUFFICIENT_EVIDENCE):
        rec.append("Perform manual unpacking or dynamic analysis in an isolated lab; static results here are incomplete.")
    if intel is None or not intel.requested:
        rec.append("Re-run with threat-intelligence enrichment enabled to corroborate hashes and network indicators.")
    if misconfig:
        rec.append(f"{len(misconfig)} security-posture issue(s) were found; these are hardening items, not evidence of malice.")
    if cls in (Classification.INFORMATIONAL, Classification.LOW):
        rec.append("No malicious pattern was found by the rules in this release; this is not proof the app is safe.")
    return rec
