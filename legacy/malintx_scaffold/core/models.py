"""
MALINT-X Core Data Models.

All data structures used across the pipeline are defined here as Pydantic models.
This is the interface contract between extraction, inference, and reporting layers.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, computed_field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    """Risk severity levels."""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """LLM confidence levels for technique detection."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IoCType(str, Enum):
    """Indicator of Compromise types."""
    IPV4 = "ipv4"
    URL = "url"
    DOMAIN = "domain"


class OverallAssessment(str, Enum):
    """LLM overall assessment of APK."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


class AnalysisPhase(str, Enum):
    """Pipeline analysis phases for progress tracking."""
    UPLOAD = "upload"
    DECOMPILATION = "decompilation"
    EXTRACTION = "extraction"
    THREAT_INTEL = "threat_intel"
    LLM_REASONING = "llm_reasoning"
    SCORING = "scoring"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# APK Metadata
# ---------------------------------------------------------------------------
class APKMetadata(BaseModel):
    """Metadata about the uploaded APK file."""
    file_name: str
    file_path: str
    file_size_bytes: int
    sha256: str
    md5: str
    upload_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_file(cls, file_path: Path) -> "APKMetadata":
        """Create metadata from an APK file on disk."""
        data = file_path.read_bytes()
        return cls(
            file_name=file_path.name,
            file_path=str(file_path),
            file_size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
        )


# ---------------------------------------------------------------------------
# Decompilation Result
# ---------------------------------------------------------------------------
class DecompilationResult(BaseModel):
    """Result of the decompilation phase."""
    success: bool
    manifest_path: str | None = None
    source_root: str | None = None
    resources_root: str | None = None
    decompiler_used: str = ""  # "jadx", "apktool", "androguard"
    error_message: str | None = None
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Manifest Data
# ---------------------------------------------------------------------------
class AndroidComponent(BaseModel):
    """An Android component (activity, service, receiver, provider)."""
    name: str
    component_type: str  # "activity", "service", "receiver", "provider"
    exported: bool | None = None
    intent_filters: list[str] = Field(default_factory=list)


class ManifestData(BaseModel):
    """Parsed AndroidManifest.xml data."""
    package_name: str = ""
    version_code: str | None = None
    version_name: str | None = None
    min_sdk_version: int | None = None
    target_sdk_version: int | None = None
    permissions: list[str] = Field(default_factory=list)
    dangerous_permissions: list[str] = Field(default_factory=list)
    activities: list[AndroidComponent] = Field(default_factory=list)
    services: list[AndroidComponent] = Field(default_factory=list)
    receivers: list[AndroidComponent] = Field(default_factory=list)
    providers: list[AndroidComponent] = Field(default_factory=list)
    intent_filters: list[str] = Field(default_factory=list)
    uses_features: list[str] = Field(default_factory=list)

    @computed_field
    @property
    def total_components(self) -> int:
        return (
            len(self.activities)
            + len(self.services)
            + len(self.receivers)
            + len(self.providers)
        )

    @computed_field
    @property
    def exported_components(self) -> int:
        all_comps = self.activities + self.services + self.receivers + self.providers
        return sum(1 for c in all_comps if c.exported is True)


# ---------------------------------------------------------------------------
# Code Slicing
# ---------------------------------------------------------------------------
class CodeSlice(BaseModel):
    """A localized code slice around a high-risk API call."""
    file_path: str
    file_name: str
    line_number: int
    matched_pattern: str
    pattern_category: str
    pattern_description: str
    severity: str
    code_context: str  # The ±25-line code window
    match_line: str  # The exact matching line


# ---------------------------------------------------------------------------
# Indicators of Compromise
# ---------------------------------------------------------------------------
class IoC(BaseModel):
    """An extracted Indicator of Compromise."""
    value: str
    ioc_type: IoCType
    source_file: str | None = None
    line_number: int | None = None
    context: str | None = None  # Surrounding code for context


class VTEnrichment(BaseModel):
    """VirusTotal enrichment data for an IoC."""
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    community_score: int = 0
    last_analysis_date: str | None = None
    tags: list[str] = Field(default_factory=list)
    country: str | None = None
    asn: int | None = None
    as_owner: str | None = None

    @computed_field
    @property
    def is_malicious(self) -> bool:
        return self.malicious_count > 0

    @computed_field
    @property
    def total_detections(self) -> int:
        return self.malicious_count + self.suspicious_count


class EnrichedIoC(BaseModel):
    """An IoC enriched with threat intelligence data."""
    ioc: IoC
    enrichment: VTEnrichment | None = None
    enrichment_source: str = "virustotal"
    enriched: bool = False
    error: str | None = None


# ---------------------------------------------------------------------------
# LLM Output Models
# ---------------------------------------------------------------------------
class DetectedTechnique(BaseModel):
    """A MITRE ATT&CK technique detected by the LLM."""
    technique_id: str
    technique_name: str
    confidence: Confidence
    evidence: str
    source_file: str | None = None
    line_number: int | None = None


class LLMVerdict(BaseModel):
    """Structured output from the LLM reasoning engine."""
    detected_techniques: list[DetectedTechnique] = Field(default_factory=list)
    overall_assessment: OverallAssessment = OverallAssessment.BENIGN
    reasoning_summary: str = ""
    owasp_findings: list[str] = Field(default_factory=list)
    raw_response: str | None = None  # For debugging
    model_used: str = ""
    inference_duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Analysis Payload (JSON Interface Contract)
# ---------------------------------------------------------------------------
class AnalysisPayload(BaseModel):
    """
    The complete extraction payload passed to the LLM and scoring engine.
    This is the strict JSON interface contract between extraction and inference.
    """
    apk_metadata: APKMetadata
    manifest_data: ManifestData
    code_slices: list[CodeSlice] = Field(default_factory=list)
    iocs: list[IoC] = Field(default_factory=list)
    enriched_iocs: list[EnrichedIoC] = Field(default_factory=list)

    @computed_field
    @property
    def total_code_slices(self) -> int:
        return len(self.code_slices)

    @computed_field
    @property
    def total_iocs(self) -> int:
        return len(self.iocs)

    @computed_field
    @property
    def malicious_iocs(self) -> int:
        return sum(
            1
            for eioc in self.enriched_iocs
            if eioc.enrichment and eioc.enrichment.is_malicious
        )


# ---------------------------------------------------------------------------
# Risk Score
# ---------------------------------------------------------------------------
class RiskScore(BaseModel):
    """Deterministic risk score with breakdown."""
    score: int = Field(ge=0, le=100)
    label: str  # Clean, Low, Medium, High, Critical
    color: str  # Hex color for UI
    technique_score: int = 0  # Points from MITRE techniques
    ioc_score: int = 0  # Points from malicious IoCs
    permission_score: int = 0  # Points from dangerous permissions
    breakdown: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Full Analysis Result
# ---------------------------------------------------------------------------
class AnalysisResult(BaseModel):
    """Complete analysis result — the top-level output of the pipeline."""
    analysis_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    apk_metadata: APKMetadata
    decompilation: DecompilationResult
    manifest_data: ManifestData
    code_slices: list[CodeSlice] = Field(default_factory=list)
    iocs: list[IoC] = Field(default_factory=list)
    enriched_iocs: list[EnrichedIoC] = Field(default_factory=list)
    llm_verdict: LLMVerdict | None = None
    risk_score: RiskScore | None = None
    report_path: str | None = None
    duration_seconds: float = 0.0
    errors: list[str] = Field(default_factory=list)
    phase: AnalysisPhase = AnalysisPhase.UPLOAD

    @computed_field
    @property
    def is_complete(self) -> bool:
        return self.phase == AnalysisPhase.COMPLETE

    @computed_field
    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


# ---------------------------------------------------------------------------
# Progress Tracking
# ---------------------------------------------------------------------------
class AnalysisProgress(BaseModel):
    """Real-time progress tracking for the UI."""
    analysis_id: str
    phase: AnalysisPhase
    phase_index: int = 0
    total_phases: int = 7
    message: str = ""
    percent_complete: float = 0.0
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    errors: list[str] = Field(default_factory=list)

