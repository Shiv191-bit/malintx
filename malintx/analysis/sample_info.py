"""SampleInfo assembly: package metadata and signing certificates from the parsed APK."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from malintx.schemas.sample import CertificateInfo, SampleInfo, ZipInspection

log = logging.getLogger(__name__)


def _cert_info(cert: Any, scheme: str) -> CertificateInfo:
    der = cert.dump()
    try:
        algo = str(cert.signature_algo) + "/" + str(cert.hash_algo)
    except Exception:  # noqa: BLE001 - asn1crypto raises assorted errors on odd certificates
        algo = ""
    return CertificateInfo(
        sha256=hashlib.sha256(der).hexdigest(),
        sha1=hashlib.sha1(der).hexdigest(),  # noqa: S324 - fingerprint
        md5=hashlib.md5(der).hexdigest(),  # noqa: S324 - fingerprint
        subject=cert.subject.human_friendly,
        issuer=cert.issuer.human_friendly,
        serial=str(cert.serial_number),
        not_before=cert.not_valid_before.isoformat() if cert.not_valid_before else None,
        not_after=cert.not_valid_after.isoformat() if cert.not_valid_after else None,
        signature_algorithm=algo,
        scheme=scheme,
        self_signed=str(getattr(cert, "self_signed", "")).lower() in ("yes", "maybe"),
    )


def collect_certificates(apk: Any, warnings: list[str]) -> tuple[list[CertificateInfo], list[str]]:
    certs: dict[str, CertificateInfo] = {}
    schemes: list[str] = []
    for scheme, getter in (("v1", "get_certificates_v1"), ("v2", "get_certificates_v2"), ("v3", "get_certificates_v3")):
        try:
            found = getattr(apk, getter)()
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"signing certificate extraction ({scheme}) failed: {type(exc).__name__}")
            continue
        if found:
            schemes.append(scheme)
        for c in found or []:
            info = _cert_info(c, scheme)
            prev = certs.get(info.sha256)
            if prev is None:
                certs[info.sha256] = info
            elif scheme not in prev.scheme.split("+"):
                certs[info.sha256] = prev.model_copy(update={"scheme": prev.scheme + "+" + scheme})
    return list(certs.values()), schemes


def build_sample_info(ingested: dict[str, Any], apk: Any, manifest: Any, archive: ZipInspection | None,
                      warnings: list[str]) -> SampleInfo:
    certs, schemes = collect_certificates(apk, warnings)
    label = None
    try:
        label = apk.get_app_name()
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"app label could not be resolved: {type(exc).__name__}")
    return SampleInfo(
        sha256=ingested["sha256"], sha1=ingested["sha1"], md5=ingested["md5"],
        size_bytes=ingested["size_bytes"], display_name=ingested["display_name"],
        first_seen=ingested["first_seen"], package_name=manifest.package or None, app_label=label,
        version_name=manifest.version_name, version_code=manifest.version_code,
        min_sdk=manifest.min_sdk, target_sdk=manifest.target_sdk, certificates=certs,
        signing_schemes=schemes, archive=archive,
    )
