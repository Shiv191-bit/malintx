"""Indicator extraction from DEX string pools and text resources."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from malintx.analysis.backends.base import CodeBackend, StringRef, is_library_class, outer_class
from malintx.analysis.rules.evidence import EvidenceStore
from malintx.schemas.analysis import Indicator
from malintx.schemas.common import Confidence, EvidenceKind, IndicatorType

EXTRACTION = "dex-string-pool"

_URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>\\^`{}|]{3,}", re.I)
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}\b")
_PATH = re.compile(r"(?<![\w/])/(?:data|sdcard|storage|system|proc|sys|dev|mnt|cache|vendor|etc)/[\w.@%+\-/]{2,}")
_PKG = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}$")
_B64 = re.compile(r"^[A-Za-z0-9+/]{120,}={0,2}$")
_HEX = re.compile(r"^[0-9a-fA-F]{64,}$")

_TLDS = (
    "com net org io info biz xyz top ru cn tk ml ga cf gq cc pw de uk fr br in jp au ca nl eu se no fi "
    "dk ch at za co me tv ws pro mobi tel asia name onion app dev cloud site online live club shop vip "
    "icu cyou fun link click work store tech space website today life world stream download win bid "
    "loan men trade party review date racing ir ua kz by tr id vn th kr tw hk sg my ph mx ar cl pe ve "
    "pl cz sk hu ro bg gr it es pt be ie lt lv ee rs hr si sa ae eg ng ke gh"
).split()
_DOMAIN = re.compile(
    r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + "|".join(_TLDS) + r"))(?![\w-])", re.I
)
_PKG_ROOTS = {"com", "org", "net", "io", "android", "androidx", "java", "javax", "kotlin", "dalvik", "de", "fr", "in", "co", "me", "ru", "cn", "jp", "br"}
_FRAMEWORK_PKG = ("android.", "java.", "javax.", "kotlin.", "kotlinx.", "androidx.", "dalvik.", "com.android.", "com.google.", "org.apache.", "org.json.", "org.xml.", "org.w3c.", "sun.", "libcore.")

NOISE_DOMAIN_SUFFIXES = (
    "schemas.android.com", "w3.org", "apache.org", "xmlpull.org", "xml.org", "android.com", "googleapis.com",
    "gstatic.com", "google.com", "googleusercontent.com", "googlesyndication.com", "doubleclick.net",
    "google-analytics.com", "crashlytics.com", "mozilla.org", "oracle.com", "sun.com", "openssl.org",
    "eclipse.org", "example.com", "example.org", "example.net", "localhost", "kotlinlang.org", "gradle.org",
    "slf4j.org", "jetbrains.com", "xmlsoap.org", "ietf.org", "unicode.org", "iana.org", "openid.net",
)
# X.500 / ISO object-identifier arcs look exactly like IPv4 addresses ("2.5.29.14" is an X.509 extension OID, very common in
# bundled crypto libraries). Found as noise in real apps (BouncyCastle); no C2 lives in these arcs.
_OID_ARCS = ("0.9.", "1.2.", "1.3.", "2.5.", "2.16.")
# Reverse-DNS roots that are code identifiers, not hostnames ("java.net", "android.app").
_CODE_ROOTS = {"java", "javax", "android", "androidx", "kotlin", "kotlinx", "dalvik", "libcore", "jdk", "sun"}
# "Domains" with these TLDs are overwhelmingly field/column/property names ("workspec.id", "user.name", "camerax.core.target.name").
_FIELDLIKE_TLDS = {"id", "name", "info", "date", "space"}
WELL_KNOWN_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}

_TRAIL = ".,;:)]}'\"!?>"


def _is_noise_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in NOISE_DOMAIN_SUFFIXES)


def _url_host(url: str) -> str:
    rest = url.split("://", 1)[1]
    host = re.split(r"[/?#]", rest, maxsplit=1)[0].rsplit("@", 1)[-1]
    if host.startswith("["):
        return host
    return host.split(":", 1)[0].lower()


@dataclass
class _Acc:
    type: IndicatorType
    value: str
    refs: list[StringRef] = field(default_factory=list)
    source: str = "classes.dex"
    occurrences: int = 0
    note: str | None = None


class IndicatorCollector:
    def __init__(self, store: EvidenceStore, backend: CodeBackend | None, package: str, radius: int) -> None:
        self._store = store
        self._backend = backend
        self._radius = radius
        parts = package.split(".")
        self._own_prefix = ".".join(parts[:2]) + "." if len(parts) >= 2 else package + "."
        self._acc: dict[tuple[IndicatorType, str], _Acc] = {}
        self._pkg_by_class: dict[str, set[str]] = {}

    def package_refs_by_class(self) -> dict[str, set[str]]:
        return self._pkg_by_class

    # ------------------------------------------------------------------ intake
    def _add(self, itype: IndicatorType, value: str, ref: StringRef, source: str, note: str | None = None) -> None:
        key = (itype, value)
        acc = self._acc.get(key)
        if acc is None:
            acc = self._acc[key] = _Acc(itype, value, source=source, note=note)
        acc.occurrences += 1
        if itype == IndicatorType.PACKAGE_REF and ref.caller_class:
            self._pkg_by_class.setdefault(outer_class(ref.caller_class), set()).add(value)
        if len(acc.refs) < 3:
            acc.refs.append(ref)

    def scan(self, refs: Iterable[StringRef], source: str = "classes.dex") -> None:
        for ref in refs:
            self._scan_one(ref, source)

    def scan_text(self, source_file: str, text: str) -> None:
        for line in text.splitlines()[:5000]:
            if line.strip():
                self._scan_one(StringRef(line[:2000], None, None, None, source_file), source_file)

    def _scan_one(self, ref: StringRef, source: str) -> None:
        s = ref.value
        if len(s) < 4 or len(s) > 4000:
            return
        url_hosts: set[str] = set()
        for m in _URL.finditer(s):
            url = m.group(0).rstrip(_TRAIL)[:300]
            host = _url_host(url)
            url_hosts.add(host)
            if _is_noise_host(host):
                continue
            self._add(IndicatorType.URL, url, ref, source)
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_global and host not in WELL_KNOWN_RESOLVERS:
                    self._add(IndicatorType.IPV4, host, ref, source)
            except ValueError:
                pass
        for m in _IPV4.finditer(s):
            ip_s = m.group(0)
            if ip_s in url_hosts:
                continue
            ip = ipaddress.ip_address(ip_s)
            if not ip.is_global or ip.is_multicast or ip_s.startswith(_OID_ARCS):
                continue
            octets = [int(o) for o in ip_s.split(".")]
            if octets[2] == 0 and octets[3] == 0:
                continue  # network/CIDR base address (carrier range tables), not a host
            # Version-string guard: a bare "x.y.z.w" with small octets is far more often a version.
            if s.strip() == ip_s and max(octets) < 20 and ip_s not in WELL_KNOWN_RESOLVERS:
                continue
            note = "well-known public DNS resolver" if ip_s in WELL_KNOWN_RESOLVERS else None
            self._add(IndicatorType.IPV4, ip_s, ref, source, note)
        for m in _EMAIL.finditer(s):
            email = m.group(0).lower()
            if not _is_noise_host(email.split("@", 1)[1]):
                self._add(IndicatorType.EMAIL, email, ref, source)
        for m in _PATH.finditer(s):
            self._add(IndicatorType.FILE_PATH, m.group(0).rstrip(_TRAIL)[:200], ref, source)
        if "://" not in s and " " not in s:
            self._maybe_domain_or_package(s, ref, source, url_hosts)
        elif "://" not in s:
            for m in _DOMAIN.finditer(s):
                self._maybe_domain_or_package(m.group(1), ref, source, url_hosts)
        if _B64.match(s) or _HEX.match(s):
            kind = "hex" if _HEX.match(s) else "base64"
            self._add(IndicatorType.SUSPICIOUS_STRING, s[:96] + ("…" if len(s) > 96 else ""), ref, source,
                      f"long {kind}-encoded blob ({len(s)} chars): possibly embedded/encrypted payload or key")

    def _maybe_domain_or_package(self, cand: str, ref: StringRef, source: str, url_hosts: set[str]) -> None:
        c = cand.strip().strip(_TRAIL)
        if not c or c.lower() in url_hosts:
            return
        labels = c.split(".")
        if _PKG.match(c) and labels[0] in _PKG_ROOTS and not c.startswith(_FRAMEWORK_PKG) and not c.startswith(self._own_prefix):
            # Looks like a reverse-DNS application id referenced as data.
            self._add(IndicatorType.PACKAGE_REF, c, ref, source)
            return
        if labels[0].lower() in _PKG_ROOTS and len(labels) >= 3:
            return  # package/class-like, not a hostname
        if labels[0].lower() in _CODE_ROOTS or labels[-1].lower() in _FIELDLIKE_TLDS:
            return
        if _DOMAIN.fullmatch(c.lower()) and not _is_noise_host(c):
            self._add(IndicatorType.DOMAIN, c.lower(), ref, source)

    # ------------------------------------------------------------------ output
    def results(self) -> tuple[list[Indicator], dict[str, set[str]]]:
        """Returns (indicators, endpoint_classes) where endpoint_classes maps indicator id→outer classes
        for network-style indicators (URL/IP/domain) referenced from app code."""
        out: list[Indicator] = []
        endpoint_classes: dict[str, set[str]] = {}
        for (itype, value), acc in sorted(self._acc.items(), key=lambda kv: (kv[0][0].value, kv[0][1])):
            iid = "IND-" + hashlib.sha1(f"{itype.value}|{value}".encode()).hexdigest()[:10]  # noqa: S324
            ev_ids: list[str] = []
            app_classes: set[str] = set()
            lib_classes: set[str] = set()
            for i, ref in enumerate(acc.refs):
                snippet = None
                if i == 0 and self._backend is not None and acc.source == "classes.dex":
                    snippet = self._backend.string_snippet(ref, self._radius)
                ev = self._store.add(
                    kind=EvidenceKind.INDICATOR, rule_id=f"IND-{itype.value}", source_file=ref.dex_file,
                    extraction_method=EXTRACTION if acc.source == "classes.dex" else "resource-text-scan",
                    class_name=ref.caller_class, method_name=ref.caller_method, bytecode_offset=ref.offset,
                    artifact=value, snippet=snippet or (f"{acc.source}: {ref.value[:300]}" if acc.source != "classes.dex" else None),
                    confidence=Confidence.HIGH,
                    limitations="String constant exists in the package; whether it is used at runtime is not established.",
                )
                if ev:
                    ev_ids.append(ev.id)
                if ref.caller_class:
                    (lib_classes if is_library_class(ref.caller_class) else app_classes).add(outer_class(ref.caller_class))
            note = acc.note
            if lib_classes and not app_classes:
                note = (note + "; " if note else "") + "referenced only from third-party library code"
            out.append(Indicator(id=iid, type=itype, value=value, evidence_ids=ev_ids,
                                 occurrences=acc.occurrences, note=note))
            if itype in (IndicatorType.URL, IndicatorType.IPV4, IndicatorType.DOMAIN) and app_classes:
                if not (acc.note and "resolver" in acc.note):
                    endpoint_classes[iid] = app_classes
        return out, endpoint_classes
