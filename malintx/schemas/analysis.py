"""Evidence, findings, indicators and the static-analysis result contract."""

from __future__ import annotations

from pydantic import Field

from .common import Confidence, EvidenceKind, FindingKind, IndicatorType, Model, Severity
from .sample import ManifestInfo, SampleInfo


class Evidence(Model):
    """One verifiable observation. IDs are deterministic (hash of the observation's identity)."""

    id: str
    kind: EvidenceKind
    rule_id: str | None = None
    source_file: str  # e.g. classes.dex, AndroidManifest.xml
    class_name: str | None = None
    method_name: str | None = None
    line_number: int | None = None  # only when the backend provides source lines (JADX)
    bytecode_offset: int | None = None
    api: str | None = None
    artifact: str | None = None
    snippet: str | None = None
    extraction_method: str
    confidence: Confidence = Confidence.HIGH
    limitations: str | None = None


class MitreMapping(Model):
    technique_id: str
    technique_name: str
    tactics: list[str] = Field(default_factory=list)
    description: str = ""
    source: str  # dataset reference, e.g. "MITRE ATT&CK for Mobile v20.0"
    url: str = ""
    evidence_ids: list[str]
    finding_ids: list[str]
    rationale: str
    confidence: Confidence
    origin: str = "deterministic_rule"  # deterministic_rule | ai_interpretation


class Finding(Model):
    id: str
    rule_id: str
    title: str
    description: str
    kind: FindingKind
    severity: Severity
    confidence: Confidence
    category: str  # behaviour category, used for diminishing returns in scoring
    evidence_ids: list[str]
    mitre_ids: list[str] = Field(default_factory=list)
    masvs: list[str] = Field(default_factory=list)
    composite_of: list[str] = Field(default_factory=list)  # rule ids this composite is built from
    false_positive_notes: str | None = None
    suppressed_by: list[str] = Field(default_factory=list)  # deterministic context rules that fired
    limitations: str | None = None


class Indicator(Model):
    id: str
    type: IndicatorType
    value: str
    evidence_ids: list[str] = Field(default_factory=list)
    occurrences: int = 1
    note: str | None = None


class AnalysisCoverage(Model):
    backend: str
    backend_version: str = ""
    dex_files_parsed: int = 0
    dex_files_failed: list[str] = Field(default_factory=list)
    classes: int = 0
    methods: int = 0
    strings: int = 0
    native_libraries: list[str] = Field(default_factory=list)
    packer_hints: list[str] = Field(default_factory=list)
    obfuscation_ratio: float | None = None  # share of short/meaningless class names
    manifest_parsed: bool = False
    source_scan: str = "bytecode"  # bytecode | decompiled_source
    duration_s: float = 0.0
    limitations: list[str] = Field(default_factory=list)

    @property
    def usable_code(self) -> bool:
        return self.dex_files_parsed > 0 and self.methods > 0


class LineageFingerprint(Model):
    """Hash-free behavioural fingerprint (see malintx/lineage)."""

    api_count: int
    minhash: str  # 128-slot MinHash over framework APIs called by the app's own code
    permissions: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)  # capability/behaviour findings (not posture/info)
    signer_sha256: list[str] = Field(default_factory=list)


class NearMiss(Model):
    """A high-severity behaviour rule that did NOT fire, and exactly what was missing."""

    rule_id: str
    title: str
    satisfied: int
    total: int
    missing: list[str]  # human-readable: which requirement groups had no supporting signal
    note: str = ""


class StaticAnalysisResult(Model):
    sample: SampleInfo
    manifest: ManifestInfo
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    mitre: list[MitreMapping] = Field(default_factory=list)
    coverage: AnalysisCoverage
    ruleset_version: str
    warnings: list[str] = Field(default_factory=list)
    lineage: LineageFingerprint | None = None
    near_misses: list[NearMiss] = Field(default_factory=list)

    def evidence_by_id(self) -> dict[str, Evidence]:
        return {e.id: e for e in self.evidence}
