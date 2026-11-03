"""Threat-intel, AI, risk, job and top-level result contracts."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from .analysis import StaticAnalysisResult
from .common import (
    Classification,
    Confidence,
    IndicatorType,
    IntelVerdict,
    JobStatus,
    Model,
    ProviderStatus,
    StageState,
)


# ---- Threat intelligence ----------------------------------------------------
class IntelLookup(Model):
    provider: str
    subject: str  # the indicator value or sample hash that was looked up
    subject_type: str
    status: ProviderStatus
    verdict: IntelVerdict = IntelVerdict.UNKNOWN
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    undetected: int | None = None
    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    asn: str | None = None
    as_owner: str | None = None
    country: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    reference_url: str | None = None
    retrieved_at: str
    cached: bool = False
    detail: str | None = None  # human-readable status/error text (never contains secrets)


class IndicatorIntel(Model):
    indicator_id: str
    value: str
    type: IndicatorType
    verdict: IntelVerdict
    lookups: list[IntelLookup] = Field(default_factory=list)
    explanation: str = ""


class IntelReport(Model):
    requested: bool
    providers: dict[str, ProviderStatus] = Field(default_factory=dict)
    sample_lookups: list[IntelLookup] = Field(default_factory=list)
    sample_verdict: IntelVerdict = IntelVerdict.UNKNOWN
    indicators: list[IndicatorIntel] = Field(default_factory=list)
    skipped_indicators: int = 0
    notes: list[str] = Field(default_factory=list)


# ---- AI ---------------------------------------------------------------------
class AIClaim(Model):
    title: str
    explanation: str
    assessment: str  # malicious_intent | suspicious | legitimate_functionality | inconclusive
    confidence: Confidence
    evidence_ids: list[str]
    mitre_ids: list[str] = Field(default_factory=list)
    uncertainty: str = ""


class AIAssessment(Model):
    overall: str  # likely_malicious | suspicious | likely_legitimate | inconclusive
    summary: str
    claims: list[AIClaim] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class AIResult(Model):
    status: str  # not_requested | unconfigured | completed | failed | invalid_output
    provider: str | None = None
    model: str | None = None
    assessment: AIAssessment | None = None
    dropped_claims: list[str] = Field(default_factory=list)
    accepted_mitre: list[str] = Field(default_factory=list)
    attempts: int = 0
    context_evidence_count: int = 0
    context_truncated: bool = False
    error: str | None = None
    note: str = "AI output is advisory interpretation. It never sets the risk score or verdict."


# ---- Risk -------------------------------------------------------------------
class RiskContribution(Model):
    source: str  # finding id, intel id or adjustment name
    label: str
    category: str
    base_points: float
    multiplier: float
    applied_points: float
    note: str = ""


class RiskResult(Model):
    classification: Classification
    score: int | None  # None when classification is inconclusive/insufficient/failed
    summary: str
    contributions: list[RiskContribution] = Field(default_factory=list)
    adjustments: list[str] = Field(default_factory=list)
    floors_applied: list[str] = Field(default_factory=list)
    suppressions: list[str] = Field(default_factory=list)
    security_posture_issues: int = 0
    misconfiguration_finding_ids: list[str] = Field(default_factory=list)
    engine_version: str
    ruleset_version: str
    inputs_digest: str
    limitations: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


# ---- Job / result -----------------------------------------------------------
class StageRecord(Model):
    name: str
    state: StageState = StageState.PENDING
    started_at: str | None = None
    finished_at: str | None = None
    message: str = ""


class JobInfo(Model):
    id: str
    sample_sha256: str | None = None
    display_name: str
    status: JobStatus
    created_at: str
    updated_at: str
    enrich_requested: bool = False
    ai_requested: bool = False
    error_code: str | None = None
    error_message: str | None = None
    stages: list[StageRecord] = Field(default_factory=list)
    duplicate_of_job: str | None = None


class AnalysisResult(Model):
    schema_version: str
    job: JobInfo
    static: StaticAnalysisResult | None = None
    intel: IntelReport | None = None
    ai: AIResult | None = None
    risk: RiskResult | None = None
    report_available: bool = False
    platform_version: str = ""
    generated_at: datetime | None = None


class IndicatorRef(Model):
    """Minimal pointer type used by the API for indicator listings."""

    id: str
    type: IndicatorType
    value: str
