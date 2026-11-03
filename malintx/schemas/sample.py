"""Sample, archive and manifest contracts."""

from __future__ import annotations

from pydantic import Field

from .common import Model


class CertificateInfo(Model):
    sha256: str
    sha1: str
    md5: str
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str | None = None
    not_after: str | None = None
    signature_algorithm: str = ""
    scheme: str = ""  # v1 | v2 | v3
    self_signed: bool = False


class ZipInspection(Model):
    entry_count: int
    total_uncompressed_bytes: int
    max_compression_ratio: float
    dex_files: list[str] = Field(default_factory=list)
    native_abis: list[str] = Field(default_factory=list)
    asset_count: int = 0
    encrypted_entries: int = 0
    duplicate_entry_names: list[str] = Field(default_factory=list)
    suspicious_entries: list[str] = Field(default_factory=list)
    earliest_entry_time: str | None = None
    latest_entry_time: str | None = None


class SampleInfo(Model):
    sha256: str
    sha1: str
    md5: str
    size_bytes: int
    # The uploaded filename is untrusted; stored sanitised for display only.
    display_name: str
    first_seen: str
    package_name: str | None = None
    app_label: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    certificates: list[CertificateInfo] = Field(default_factory=list)
    signing_schemes: list[str] = Field(default_factory=list)
    archive: ZipInspection | None = None


class PermissionUse(Model):
    name: str
    is_platform: bool  # android.permission.* / well-known platform namespace
    sensitivity: str = "normal"  # normal | dangerous | special | signature


class CustomPermission(Model):
    name: str
    protection_level: str | None = None


class IntentFilterInfo(Model):
    actions: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    data_schemes: list[str] = Field(default_factory=list)
    priority: int | None = None


class ComponentInfo(Model):
    kind: str  # activity | service | receiver | provider
    name: str
    exported: bool  # effective exported state
    exported_explicit: bool | None = None
    permission: str | None = None
    enabled: bool = True
    intent_filters: list[IntentFilterInfo] = Field(default_factory=list)
    task_affinity: str | None = None
    allow_task_reparenting: bool | None = None
    extra: dict[str, str] = Field(default_factory=dict)


class ManifestInfo(Model):
    package: str = ""
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    max_sdk: int | None = None
    permissions: list[PermissionUse] = Field(default_factory=list)
    custom_permissions: list[CustomPermission] = Field(default_factory=list)
    components: list[ComponentInfo] = Field(default_factory=list)
    uses_features: list[str] = Field(default_factory=list)
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    test_only: bool | None = None
    shared_user_id: str | None = None
    application_class: str | None = None
    accessibility_services: list[str] = Field(default_factory=list)
    device_admin_receivers: list[str] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)

    def permission_names(self) -> set[str]:
        return {p.name for p in self.permissions}
