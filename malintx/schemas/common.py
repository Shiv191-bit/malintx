"""Shared enums and base model for all MALINT-X contracts."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class Model(BaseModel):
    """Base for every contract: strict on unknown fields so schema drift is loud."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class OrderedEnum(str, Enum):
    @classmethod
    def order(cls) -> list[OrderedEnum]:
        return list(cls)

    @property
    def rank(self) -> int:
        return self.order().index(self)

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        return isinstance(other, type(self)) and self.rank < other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        return isinstance(other, type(self)) and self.rank <= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        return isinstance(other, type(self)) and self.rank > other.rank

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        return isinstance(other, type(self)) and self.rank >= other.rank


class Severity(OrderedEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(OrderedEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingKind(str, Enum):
    """Keeps malicious behaviour distinct from misconfiguration (a vulnerable app is not malware)."""

    MALICIOUS_BEHAVIOR = "malicious_behavior"
    SUSPICIOUS_CAPABILITY = "suspicious_capability"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    INFORMATIONAL = "informational"


class EvidenceKind(str, Enum):
    MANIFEST = "manifest"
    API_CALL = "api_call"
    CLASS_STRUCTURE = "class_structure"
    STRING = "string"
    INDICATOR = "indicator"
    CERTIFICATE = "certificate"
    ARCHIVE = "archive"


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_PATH = "file_path"
    PACKAGE_REF = "package_ref"
    SUSPICIOUS_STRING = "suspicious_string"


class IntelVerdict(str, Enum):
    """Never conflate 'no data' with 'safe'."""

    KNOWN_MALICIOUS = "known_malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    BENIGN_OBSERVED = "benign_observed"


class ProviderStatus(str, Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    UNCONFIGURED = "unconfigured"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class Classification(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    INCONCLUSIVE = "inconclusive"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    ANALYSIS_FAILED = "analysis_failed"


class JobStatus(str, Enum):
    QUEUED = "queued"
    INGESTING = "ingesting"
    STATIC_ANALYSIS = "static_analysis"
    THREAT_INTEL = "threat_intel"
    AI_REASONING = "ai_reasoning"
    SCORING = "scoring"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in (JobStatus.COMPLETED, JobStatus.FAILED)


class StageState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"
