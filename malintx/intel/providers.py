"""Threat-intelligence provider adapters (VirusTotal, Shodan, MalwareBazaar, Koodous).

Terms/access notes live in docs/SECURITY_MODEL.md and docs/TECHNICAL_DECISIONS.md. The adapters are
unit-tested against mocked transports only; they have NOT been exercised against the live services
in this repository's CI because no credentials are provisioned.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from malintx.config import Settings
from malintx.errors import ProviderError
from malintx.intel.http import PassiveHTTP, RateLimiter
from malintx.schemas.common import IndicatorType, IntelVerdict, ProviderStatus
from malintx.schemas.results import IntelLookup

VT_MALICIOUS_THRESHOLD = 3  # engines flagging malicious required for KNOWN_MALICIOUS

_TOKENISH = re.compile(r"/bot\d{6,}:|[?&](?:token|key|apikey|secret|password)=", re.I)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_url_for_lookup(url: str) -> str | None:
    """Strip query/fragment and refuse URLs that embed credentials, before sharing with a third party."""
    if _TOKENISH.search(url):
        return None
    parts = urlsplit(url)
    if parts.username or parts.password:
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _ts(epoch: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError, OverflowError):
        return None


class Provider:
    name = ""
    supports: tuple[IndicatorType, ...] = ()
    supports_hash = False
    experimental = False

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None, sleep=None) -> None:
        self.settings = settings
        self._transport = transport
        self._sleep = sleep

    def configured(self) -> bool:
        raise NotImplementedError

    def lookup_indicator(self, itype: IndicatorType, value: str) -> IntelLookup:
        raise NotImplementedError

    def lookup_hash(self, sha256: str) -> IntelLookup:
        raise NotImplementedError

    def _http(self, base: str, per_minute: int) -> PassiveHTTP:
        kwargs: dict[str, Any] = {}
        if self._sleep:
            kwargs["sleep"] = self._sleep
        limiter = RateLimiter(per_minute, **({"sleep": self._sleep} if self._sleep else {}))
        return PassiveHTTP(self.name, base, timeout_s=self.settings.intel_timeout_s,
                           max_retries=self.settings.intel_max_retries, limiter=limiter,
                           transport=self._transport, **kwargs)

    def _base(self, subject: str, stype: str, status: ProviderStatus, **kw: Any) -> IntelLookup:
        return IntelLookup(provider=self.name, subject=subject, subject_type=stype, status=status,
                           retrieved_at=now_iso(), **kw)

    def _http_failure(self, subject: str, stype: str, resp: httpx.Response) -> IntelLookup:
        if resp.status_code in (401, 403):
            return self._base(subject, stype, ProviderStatus.ERROR,
                              detail="authentication rejected: check the API key and plan")
        return self._base(subject, stype, ProviderStatus.ERROR, detail=f"unexpected HTTP {resp.status_code}")

    def _json(self, resp: httpx.Response) -> dict[str, Any]:
        try:
            data = resp.json()
        except ValueError as exc:
            raise ProviderError(f"{self.name}: response was not valid JSON") from exc
        if not isinstance(data, dict):
            raise ProviderError(f"{self.name}: unexpected response shape")
        return data


# --------------------------------------------------------------------------------------------
class VirusTotal(Provider):
    name = "virustotal"
    supports = (IndicatorType.IPV4, IndicatorType.DOMAIN, IndicatorType.URL)
    supports_hash = True
    BASE = "https://www.virustotal.com"

    def configured(self) -> bool:
        return bool(self.settings.vt_api_key.get_secret_value())

    def _get(self, path: str):
        http = self._http(self.BASE, self.settings.vt_requests_per_minute)
        try:
            return http.request("GET", path, headers={"x-apikey": self.settings.vt_api_key.get_secret_value()})
        finally:
            http.close()

    def lookup_indicator(self, itype: IndicatorType, value: str) -> IntelLookup:
        if itype == IndicatorType.IPV4:
            path, gui, stype = f"/api/v3/ip_addresses/{value}", f"https://www.virustotal.com/gui/ip-address/{value}", "ipv4"
        elif itype == IndicatorType.DOMAIN:
            path, gui, stype = f"/api/v3/domains/{value}", f"https://www.virustotal.com/gui/domain/{value}", "domain"
        elif itype == IndicatorType.URL:
            safe = safe_url_for_lookup(value)
            if safe is None:
                return self._base(value[:80], "url", ProviderStatus.SKIPPED,
                                  detail="URL embeds a token/credential; not shared with third parties")
            uid = base64.urlsafe_b64encode(safe.encode()).decode().rstrip("=")
            path, gui, stype, value = f"/api/v3/urls/{uid}", f"https://www.virustotal.com/gui/url/{uid}", "url", safe
        else:
            return self._base(value, itype.value, ProviderStatus.SKIPPED, detail="indicator type not supported")
        return self._parse(self._get(path), value, stype, gui)

    def lookup_hash(self, sha256: str) -> IntelLookup:
        return self._parse(self._get(f"/api/v3/files/{sha256}"), sha256, "sha256",
                           f"https://www.virustotal.com/gui/file/{sha256}")

    def _parse(self, resp: httpx.Response, subject: str, stype: str, gui: str) -> IntelLookup:
        if resp.status_code == 404:
            return self._base(subject, stype, ProviderStatus.NOT_FOUND,
                              detail="not known to VirusTotal (absence is not evidence of safety)")
        if resp.status_code != 200:
            return self._http_failure(subject, stype, resp)
        attrs = self._json(resp).get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        har, und = int(stats.get("harmless", 0)), int(stats.get("undetected", 0))
        if mal >= VT_MALICIOUS_THRESHOLD:
            verdict = IntelVerdict.KNOWN_MALICIOUS
        elif mal >= 2 or sus >= 3:  # a lone engine hit is routine noise (seen live: 1/90 engines flagged 8.8.8.8)
            verdict = IntelVerdict.SUSPICIOUS
        elif mal == 0 and sus == 0 and (har + und) >= 5:  # any detection at all rules out "benign observed"
            verdict = IntelVerdict.BENIGN_OBSERVED
        else:
            verdict = IntelVerdict.UNKNOWN
        families: list[str] = []
        ptc = attrs.get("popular_threat_classification") or {}
        if ptc.get("suggested_threat_label"):
            families.append(str(ptc["suggested_threat_label"]))
        families += [str(x.get("value")) for x in (ptc.get("popular_threat_name") or [])[:3] if x.get("value")]
        asn = attrs.get("asn")
        return self._base(
            subject, stype, ProviderStatus.OK, verdict=verdict, malicious=mal, suspicious=sus, harmless=har,
            undetected=und, tags=[str(t) for t in (attrs.get("tags") or [])][:12], malware_families=families,
            asn=f"AS{asn}" if asn else None, as_owner=attrs.get("as_owner"), country=attrs.get("country"),
            first_seen=_ts(attrs.get("first_submission_date") or attrs.get("creation_date")),
            last_seen=_ts(attrs.get("last_analysis_date")), reference_url=gui,
            detail=f"{mal} malicious / {sus} suspicious / {har} harmless / {und} undetected engine verdicts",
        )


# --------------------------------------------------------------------------------------------
class Shodan(Provider):
    name = "shodan"
    supports = (IndicatorType.IPV4,)
    BASE = "https://api.shodan.io"
    _SUSPICIOUS_TAGS = {"c2", "malware", "compromised", "botnet", "tor"}

    def configured(self) -> bool:
        return bool(self.settings.shodan_api_key.get_secret_value())

    def lookup_indicator(self, itype: IndicatorType, value: str) -> IntelLookup:
        if itype != IndicatorType.IPV4:
            return self._base(value, itype.value, ProviderStatus.SKIPPED, detail="Shodan lookup supports IPv4 only")
        http = self._http(self.BASE, 60)
        try:
            resp = http.request("GET", f"/shodan/host/{value}", params={"key": self.settings.shodan_api_key.get_secret_value()})
        finally:
            http.close()
        if resp.status_code == 404:
            return self._base(value, "ipv4", ProviderStatus.NOT_FOUND,
                              detail="no Shodan data for this IP (absence is not evidence of safety)")
        if resp.status_code != 200:
            return self._http_failure(value, "ipv4", resp)
        d = self._json(resp)
        tags = [str(t).lower() for t in d.get("tags") or []]
        products = sorted({str(x.get("product")) for x in d.get("data") or [] if isinstance(x, dict) and x.get("product")})
        verdict = IntelVerdict.SUSPICIOUS if self._SUSPICIOUS_TAGS & set(tags) else IntelVerdict.UNKNOWN
        asn = d.get("asn")
        return self._base(
            value, "ipv4", ProviderStatus.OK, verdict=verdict, tags=tags[:12], asn=str(asn) if asn else None,
            as_owner=d.get("org") or d.get("isp"), country=d.get("country_name"),
            open_ports=sorted(int(p) for p in d.get("ports") or [] if isinstance(p, int))[:30],
            last_seen=d.get("last_update"), reference_url=f"https://www.shodan.io/host/{value}",
            detail=("services: " + ", ".join(products[:6]) if products else "host indexed; no suspicious Shodan tags")
            + ("; tags: " + ", ".join(tags[:6]) if tags else ""),
        )


# --------------------------------------------------------------------------------------------
class MalwareBazaar(Provider):
    name = "malwarebazaar"
    supports = ()
    supports_hash = True
    BASE = "https://mb-api.abuse.ch"

    def configured(self) -> bool:
        return bool(self.settings.abusech_auth_key.get_secret_value())

    def lookup_hash(self, sha256: str) -> IntelLookup:
        http = self._http(self.BASE, 30)
        try:
            resp = http.request("POST", "/api/v1/", headers={"Auth-Key": self.settings.abusech_auth_key.get_secret_value()},
                                data={"query": "get_info", "hash": sha256})
        finally:
            http.close()
        if resp.status_code != 200:
            return self._http_failure(sha256, "sha256", resp)
        d = self._json(resp)
        status = d.get("query_status")
        if status in ("hash_not_found", "no_results"):
            return self._base(sha256, "sha256", ProviderStatus.NOT_FOUND,
                              detail="hash not present in MalwareBazaar (absence is not evidence of safety)")
        if status != "ok" or not d.get("data"):
            return self._base(sha256, "sha256", ProviderStatus.ERROR, detail=f"query_status={status}")
        row = d["data"][0]
        fam = [row["signature"]] if row.get("signature") else []
        return self._base(
            sha256, "sha256", ProviderStatus.OK, verdict=IntelVerdict.KNOWN_MALICIOUS, malware_families=fam,
            tags=[str(t) for t in row.get("tags") or []][:12], first_seen=row.get("first_seen"),
            last_seen=row.get("last_seen"), reference_url=f"https://bazaar.abuse.ch/sample/{sha256}/",
            detail=f"present in MalwareBazaar (file_type={row.get('file_type')}, reporter={row.get('reporter')})",
        )


# --------------------------------------------------------------------------------------------
class Koodous(Provider):
    """Experimental: the Koodous developer API has changed over time and access depends on plan/terms."""

    name = "koodous"
    supports = ()
    supports_hash = True
    experimental = True
    BASE = "https://developer.koodous.com"

    def configured(self) -> bool:
        return bool(self.settings.koodous_token.get_secret_value())

    def lookup_hash(self, sha256: str) -> IntelLookup:
        http = self._http(self.BASE, 20)
        try:
            resp = http.request("GET", f"/apks/{sha256}/",
                                headers={"Authorization": f"Token {self.settings.koodous_token.get_secret_value()}"})
        finally:
            http.close()
        if resp.status_code == 404:
            return self._base(sha256, "sha256", ProviderStatus.NOT_FOUND,
                              detail="sample not known to Koodous (absence is not evidence of safety)")
        if resp.status_code != 200:
            return self._http_failure(sha256, "sha256", resp)
        d = self._json(resp)
        detected, trusted = d.get("detected"), d.get("trusted")
        rating = d.get("rating")
        if detected is True:
            verdict = IntelVerdict.KNOWN_MALICIOUS
        elif trusted is True:
            verdict = IntelVerdict.BENIGN_OBSERVED
        else:
            verdict = IntelVerdict.UNKNOWN
        return self._base(
            sha256, "sha256", ProviderStatus.OK, verdict=verdict,
            tags=[str(t) for t in d.get("tags") or []][:12], reference_url=f"https://koodous.com/apks/{sha256}",
            detail=f"detected={detected}, trusted={trusted}, rating={rating} (experimental adapter)",
        )


ALL_PROVIDERS: tuple[type[Provider], ...] = (VirusTotal, Shodan, MalwareBazaar, Koodous)
