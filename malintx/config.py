"""Centralised configuration. All settings come from environment variables or `.env`.

Importing this module has no side effects (no directories are created); call
`Settings.ensure_dirs()` explicitly at process start.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _alias(*names: str) -> AliasChoices:
    return AliasChoices(*names)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", populate_by_name=True
    )

    # ---- storage -----------------------------------------------------------
    data_dir: Path = Field(PROJECT_ROOT / "var", validation_alias=_alias("MALINTX_DATA_DIR"))

    # ---- ingestion limits --------------------------------------------------
    max_upload_mb: int = Field(150, validation_alias=_alias("MALINTX_MAX_UPLOAD_MB", "MAX_APK_SIZE_MB"))
    max_zip_entries: int = Field(30000, validation_alias=_alias("MALINTX_MAX_ZIP_ENTRIES"))
    max_uncompressed_mb: int = Field(1500, validation_alias=_alias("MALINTX_MAX_UNCOMPRESSED_MB"))
    max_compression_ratio: int = Field(1000, validation_alias=_alias("MALINTX_MAX_COMPRESSION_RATIO"))

    # ---- analysis ----------------------------------------------------------
    analysis_timeout_s: int = Field(600, validation_alias=_alias("MALINTX_ANALYSIS_TIMEOUT_S"))
    worker_threads: int = Field(2, validation_alias=_alias("MALINTX_WORKER_THREADS"))
    worker_memory_mb: int = Field(3072, validation_alias=_alias("MALINTX_WORKER_MEMORY_MB"))
    java_path: str = Field("", validation_alias=_alias("MALINTX_JAVA"))
    jadx_path: str = Field("", validation_alias=_alias("MALINTX_JADX"))
    apktool_path: str = Field("", validation_alias=_alias("MALINTX_APKTOOL"))
    decompiler_timeout_s: int = Field(300, validation_alias=_alias("MALINTX_DECOMPILER_TIMEOUT_S"))
    slice_radius_lines: int = Field(25, validation_alias=_alias("MALINTX_SLICE_RADIUS"))
    # SHA-256 fingerprints (hex) of signing certificates the operator trusts.
    # A match lowers confidence in capability findings; it never zeroes a score.
    trusted_cert_sha256: str = Field("", validation_alias=_alias("MALINTX_TRUSTED_CERT_SHA256"))

    # ---- threat intelligence (passive lookups only) ------------------------
    vt_api_key: SecretStr = Field(SecretStr(""), validation_alias=_alias("VT_API_KEY", "MALINTX_VT_API_KEY"))
    shodan_api_key: SecretStr = Field(
        SecretStr(""), validation_alias=_alias("SHODAN_API_KEY", "MALINTX_SHODAN_API_KEY")
    )
    abusech_auth_key: SecretStr = Field(
        SecretStr(""), validation_alias=_alias("ABUSECH_AUTH_KEY", "MALINTX_ABUSECH_AUTH_KEY")
    )
    koodous_token: SecretStr = Field(
        SecretStr(""), validation_alias=_alias("KOODOUS_TOKEN", "MALINTX_KOODOUS_TOKEN")
    )
    vt_requests_per_minute: int = Field(4, validation_alias=_alias("VT_RATE_LIMIT_PER_MINUTE"))
    intel_timeout_s: float = Field(15.0, validation_alias=_alias("MALINTX_INTEL_TIMEOUT_S"))
    intel_max_retries: int = Field(3, validation_alias=_alias("MALINTX_INTEL_MAX_RETRIES"))
    intel_cache_ttl_s: int = Field(86400, validation_alias=_alias("MALINTX_INTEL_CACHE_TTL_S"))
    intel_max_indicators: int = Field(40, validation_alias=_alias("MALINTX_INTEL_MAX_INDICATORS"))

    # ---- AI reasoning (optional) -------------------------------------------
    ai_provider: str = Field("none", validation_alias=_alias("MALINTX_AI_PROVIDER"))
    anthropic_api_key: SecretStr = Field(
        SecretStr(""), validation_alias=_alias("ANTHROPIC_API_KEY", "MALINTX_ANTHROPIC_API_KEY")
    )
    anthropic_model: str = Field("claude-sonnet-5-5", validation_alias=_alias("MALINTX_ANTHROPIC_MODEL"))
    gemini_api_key: SecretStr = Field(
        SecretStr(""), validation_alias=_alias("GEMINI_API_KEY", "MALINTX_GEMINI_API_KEY")
    )
    gemini_model: str = Field("gemini-2.5-flash", validation_alias=_alias("MALINTX_GEMINI_MODEL"))
    openai_api_key: SecretStr = Field(
        SecretStr(""), validation_alias=_alias("OPENAI_API_KEY", "MALINTX_OPENAI_API_KEY")
    )
    openai_base_url: str = Field("https://api.openai.com/v1", validation_alias=_alias("MALINTX_OPENAI_BASE_URL"))
    openai_model: str = Field("gpt-4o-mini", validation_alias=_alias("MALINTX_OPENAI_MODEL"))
    ai_timeout_s: float = Field(90.0, validation_alias=_alias("MALINTX_AI_TIMEOUT_S"))
    ai_max_retries: int = Field(2, validation_alias=_alias("MALINTX_AI_MAX_RETRIES"))
    ai_max_context_chars: int = Field(60000, validation_alias=_alias("MALINTX_AI_MAX_CONTEXT_CHARS"))

    # ---- API ---------------------------------------------------------------
    api_host: str = Field("127.0.0.1", validation_alias=_alias("MALINTX_API_HOST"))
    api_port: int = Field(8750, validation_alias=_alias("MALINTX_API_PORT"))
    # When set, every API call must carry `Authorization: Bearer <token>`.
    api_token: SecretStr = Field(SecretStr(""), validation_alias=_alias("MALINTX_API_TOKEN"))
    api_rate_limit_per_minute: int = Field(120, validation_alias=_alias("MALINTX_API_RATE_LIMIT"))
    upload_rate_limit_per_minute: int = Field(10, validation_alias=_alias("MALINTX_UPLOAD_RATE_LIMIT"))

    log_level: str = Field("INFO", validation_alias=_alias("MALINTX_LOG_LEVEL"))

    # ---- derived paths -----------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.data_dir / "malintx.sqlite3"

    @property
    def samples_dir(self) -> Path:
        return self.data_dir / "samples"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def workspaces_dir(self) -> Path:
        return self.data_dir / "workspaces"

    @property
    def mitre_dataset(self) -> Path:
        return PROJECT_ROOT / "data" / "mitre" / "mobile-attack-20.0.json"

    @property
    def trusted_cert_set(self) -> frozenset[str]:
        return frozenset(c.strip().lower() for c in self.trusted_cert_sha256.split(",") if c.strip())

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.samples_dir, self.reports_dir, self.workspaces_dir):
            d.mkdir(parents=True, exist_ok=True)

    def integrations(self) -> dict[str, bool]:
        """Which integrations have credentials configured (never exposes the values)."""
        return {
            "virustotal": bool(self.vt_api_key.get_secret_value()),
            "shodan": bool(self.shodan_api_key.get_secret_value()),
            "malwarebazaar": bool(self.abusech_auth_key.get_secret_value()),
            "koodous": bool(self.koodous_token.get_secret_value()),
            "anthropic": bool(self.anthropic_api_key.get_secret_value()),
            "gemini": bool(self.gemini_api_key.get_secret_value()),
            "openai_compatible": bool(self.openai_api_key.get_secret_value()),
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
