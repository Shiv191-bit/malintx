"""Explicit error types. Every failure mode the platform expects has its own class."""

from __future__ import annotations


class MalintxError(Exception):
    """Base class for all expected MALINT-X errors."""

    code = "malintx_error"


# ---- Ingestion -------------------------------------------------------------
class InvalidSampleError(MalintxError):
    """The uploaded file cannot be accepted for analysis."""

    code = "invalid_sample"


class OversizedUploadError(InvalidSampleError):
    code = "oversized_upload"


class NotAnApkError(InvalidSampleError):
    code = "not_an_apk"


class CorruptArchiveError(InvalidSampleError):
    code = "corrupt_archive"


class UnsafeArchiveError(InvalidSampleError):
    """Zip-bomb, entry-count explosion, or similar resource-abuse structure."""

    code = "unsafe_archive"


# ---- Analysis --------------------------------------------------------------
class AnalysisError(MalintxError):
    code = "analysis_error"


class AnalysisTimeoutError(AnalysisError):
    code = "analysis_timeout"


class ToolUnavailableError(AnalysisError):
    code = "tool_unavailable"


class ToolFailedError(AnalysisError):
    code = "tool_failed"


# ---- Intelligence / AI -----------------------------------------------------
class ProviderError(MalintxError):
    code = "provider_error"


class ProviderUnconfiguredError(ProviderError):
    code = "provider_unconfigured"


class ProviderRateLimitedError(ProviderError):
    code = "provider_rate_limited"


class ProviderUnavailableError(ProviderError):
    code = "provider_unavailable"


class AIOutputInvalidError(ProviderError):
    code = "ai_output_invalid"


# ---- Storage ---------------------------------------------------------------
class StorageError(MalintxError):
    code = "storage_error"


class NotFoundError(StorageError):
    code = "not_found"
