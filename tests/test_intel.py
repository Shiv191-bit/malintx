from __future__ import annotations

import base64
import json

import httpx
import pytest

from malintx.config import Settings
from malintx.errors import ProviderRateLimitedError, ProviderUnavailableError
from malintx.intel.http import PassiveHTTP, RateLimiter
from malintx.intel.providers import Koodous, MalwareBazaar, Shodan, VirusTotal, safe_url_for_lookup
from malintx.intel.service import IntelService, aggregate
from malintx.schemas.common import IndicatorType, IntelVerdict, ProviderStatus
from malintx.storage.db import Database
from malintx.storage.repository import Repository

NOSLEEP = lambda s: None  # noqa: E731


def S(tmp_path, **kw) -> Settings:
    return Settings(data_dir=tmp_path / "var", _env_file=None, vt_api_key="VT-SECRET-KEY", shodan_api_key="SH-SECRET",
                    abusech_auth_key="AB-SECRET", koodous_token="KO-SECRET", **kw)


def vt_body(mal=0, sus=0, har=0, und=0, **extra):
    attrs = {"last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": har, "undetected": und},
             "last_analysis_date": 1700000000, **extra}
    return {"data": {"attributes": attrs}}


def provider(cls, tmp_path, handler, **kw):
    return cls(S(tmp_path, **kw), httpx.MockTransport(handler), NOSLEEP)


# ---------------------------------------------------------------------------------------------- VirusTotal
def test_vt_ip_malicious_parsed_with_context(tmp_path):
    seen = {}

    def h(req: httpx.Request):
        seen.update(url=str(req.url), key=req.headers.get("x-apikey"), method=req.method)
        return httpx.Response(200, json=vt_body(mal=14, har=50, asn=64500, as_owner="BadHost LLC", country="NL", tags=["c2"]))

    lk = provider(VirusTotal, tmp_path, h).lookup_indicator(IndicatorType.IPV4, "198.51.100.7")
    assert seen["url"] == "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.7" and seen["method"] == "GET"
    assert seen["key"] == "VT-SECRET-KEY"
    assert (lk.status, lk.verdict, lk.malicious) == (ProviderStatus.OK, IntelVerdict.KNOWN_MALICIOUS, 14)
    assert (lk.asn, lk.as_owner, lk.country) == ("AS64500", "BadHost LLC", "NL")
    assert lk.reference_url.startswith("https://www.virustotal.com/gui/ip-address/")


@pytest.mark.parametrize("mal,sus,har,und,expected", [
    (0, 0, 0, 0, IntelVerdict.UNKNOWN), (0, 0, 40, 20, IntelVerdict.BENIGN_OBSERVED), (1, 0, 60, 5, IntelVerdict.SUSPICIOUS),
    (0, 4, 60, 5, IntelVerdict.SUSPICIOUS), (3, 0, 60, 5, IntelVerdict.KNOWN_MALICIOUS)])
def test_vt_verdict_thresholds(tmp_path, mal, sus, har, und, expected):
    lk = provider(VirusTotal, tmp_path, lambda r: httpx.Response(200, json=vt_body(mal, sus, har, und))).lookup_indicator(IndicatorType.DOMAIN, "x.example")
    assert lk.verdict == expected


def test_vt_not_found_is_not_safe(tmp_path):
    lk = provider(VirusTotal, tmp_path, lambda r: httpx.Response(404, json={"error": {}})).lookup_indicator(IndicatorType.DOMAIN, "new.example")
    assert lk.status == ProviderStatus.NOT_FOUND and lk.verdict == IntelVerdict.UNKNOWN
    assert "not evidence of safety" in lk.detail


def test_vt_url_lookup_is_by_id_only_and_strips_query(tmp_path):
    seen = []
    p = provider(VirusTotal, tmp_path, lambda r: (seen.append(r), httpx.Response(404))[1])
    p.lookup_indicator(IndicatorType.URL, "http://evil.example/a/b?id=1#frag")
    assert all(r.method == "GET" for r in seen), "must never submit URLs for scanning"
    uid = str(seen[0].url).rsplit("/", 1)[1]
    assert base64.urlsafe_b64decode(uid + "=" * (-len(uid) % 4)).decode() == "http://evil.example/a/b"


def test_url_with_embedded_token_never_leaves_the_host(tmp_path):
    calls = []
    p = provider(VirusTotal, tmp_path, lambda r: (calls.append(r), httpx.Response(200))[1])
    lk = p.lookup_indicator(IndicatorType.URL, "https://api.telegram.org/bot123456789:AAEhBP0av28kXXXXXXXXXXXXXXXXXXXXXXX/sendMessage")
    assert lk.status == ProviderStatus.SKIPPED and not calls
    assert safe_url_for_lookup("http://u:p@x.example/") is None and safe_url_for_lookup("http://x.example/?token=abc") is None


def test_vt_auth_failure_reports_without_leaking_key(tmp_path):
    lk = provider(VirusTotal, tmp_path, lambda r: httpx.Response(401, json={})).lookup_indicator(IndicatorType.DOMAIN, "x.example")
    assert lk.status == ProviderStatus.ERROR and "VT-SECRET-KEY" not in lk.model_dump_json()


def test_vt_hash_lookup_families(tmp_path):
    body = vt_body(mal=40, har=0, und=20, popular_threat_classification={"suggested_threat_label": "trojan.banker/anubis",
                                                                          "popular_threat_name": [{"value": "anubis", "count": 9}]})
    lk = provider(VirusTotal, tmp_path, lambda r: httpx.Response(200, json=body)).lookup_hash("a" * 64)
    assert lk.verdict == IntelVerdict.KNOWN_MALICIOUS and "trojan.banker/anubis" in lk.malware_families


def test_429_retried_with_retry_after(tmp_path):
    n = {"c": 0}
    sleeps: list[float] = []

    def h(r):
        n["c"] += 1
        return httpx.Response(429, headers={"Retry-After": "7"}) if n["c"] == 1 else httpx.Response(200, json=vt_body(0, 0, 30, 30))

    p = VirusTotal(S(tmp_path), httpx.MockTransport(h), sleeps.append)
    assert p.lookup_indicator(IndicatorType.IPV4, "198.51.100.9").verdict == IntelVerdict.BENIGN_OBSERVED
    assert n["c"] == 2 and 7.0 in sleeps


def test_persistent_5xx_raises_unavailable(tmp_path):
    p = provider(VirusTotal, tmp_path, lambda r: httpx.Response(503))
    with pytest.raises(ProviderUnavailableError):
        p.lookup_indicator(IndicatorType.IPV4, "198.51.100.9")


def test_timeouts_retry_then_unavailable(tmp_path):
    n = {"c": 0}

    def h(r):
        n["c"] += 1
        raise httpx.ConnectTimeout("slow")

    p = provider(VirusTotal, tmp_path, h)
    with pytest.raises(ProviderUnavailableError):
        p.lookup_indicator(IndicatorType.IPV4, "198.51.100.9")
    assert n["c"] == 4  # 1 + 3 retries


def test_requests_pinned_to_provider_host(tmp_path):
    http = PassiveHTTP("vt", "https://www.virustotal.com", timeout_s=5, max_retries=0, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(ProviderUnavailableError, match="unexpected host"):
        http.request("GET", "@evil.example/x")
    with pytest.raises(ProviderUnavailableError):
        http.request("GET", ".evil.example/x")


def test_rate_limiter_blocks_when_budget_exceeded():
    t = {"now": 0.0}
    sleeps: list[float] = []
    rl = RateLimiter(2, clock=lambda: t["now"], sleep=sleeps.append)
    rl.acquire(100)
    rl.acquire(100)
    rl.acquire(100)  # third must wait ~60s
    assert sleeps and 59 < sleeps[0] < 61
    t["now"] = 0.0
    rl2 = RateLimiter(1, clock=lambda: t["now"], sleep=sleeps.append)
    rl2.acquire(5)
    with pytest.raises(ProviderRateLimitedError):
        rl2.acquire(5)


# ---------------------------------------------------------------------------------------------- others
def test_shodan_host_parse_and_suspicious_tag(tmp_path):
    seen = {}

    def h(r):
        seen["host"], seen["params"] = r.url.host, dict(r.url.params)
        return httpx.Response(200, json={"ip_str": "198.51.100.7", "ports": [443, 8443], "org": "Shady Hosting", "asn": "AS64500",
                                         "country_name": "Netherlands", "tags": ["c2", "cloud"], "data": [{"product": "Cobalt Strike Beacon"}]})

    lk = provider(Shodan, tmp_path, h).lookup_indicator(IndicatorType.IPV4, "198.51.100.7")
    assert seen["host"] == "api.shodan.io" and seen["params"] == {"key": "SH-SECRET"}
    assert lk.verdict == IntelVerdict.SUSPICIOUS and lk.open_ports == [443, 8443] and lk.as_owner == "Shady Hosting"
    assert "Cobalt Strike" in lk.detail


def test_shodan_404_not_found_and_domain_skipped(tmp_path):
    p = provider(Shodan, tmp_path, lambda r: httpx.Response(404, json={"error": "No information available for that IP."}))
    assert p.lookup_indicator(IndicatorType.IPV4, "198.51.100.7").status == ProviderStatus.NOT_FOUND
    assert p.lookup_indicator(IndicatorType.DOMAIN, "x.example").status == ProviderStatus.SKIPPED


def test_malwarebazaar_hash_hit_and_miss(tmp_path):
    seen = {}

    def hit(r):
        seen.update(h=r.headers.get("auth-key"), body=r.content.decode(), m=r.method)
        return httpx.Response(200, json={"query_status": "ok", "data": [{"signature": "Hydra", "tags": ["apk", "banker"], "file_type": "apk",
                                                                          "first_seen": "2024-01-01 00:00:00", "reporter": "x"}]})

    lk = provider(MalwareBazaar, tmp_path, hit).lookup_hash("b" * 64)
    assert seen["h"] == "AB-SECRET" and "get_info" in seen["body"] and seen["m"] == "POST"
    assert lk.verdict == IntelVerdict.KNOWN_MALICIOUS and lk.malware_families == ["Hydra"]
    miss = provider(MalwareBazaar, tmp_path, lambda r: httpx.Response(200, json={"query_status": "hash_not_found"})).lookup_hash("b" * 64)
    assert miss.status == ProviderStatus.NOT_FOUND and miss.verdict == IntelVerdict.UNKNOWN


def test_koodous_experimental_adapter(tmp_path):
    seen = {}

    def h(r):
        seen["auth"] = r.headers.get("authorization")
        return httpx.Response(200, json={"detected": True, "rating": -4, "tags": ["banker"]})

    p = provider(Koodous, tmp_path, h)
    assert p.experimental
    assert p.lookup_hash("c" * 64).verdict == IntelVerdict.KNOWN_MALICIOUS and seen["auth"] == "Token KO-SECRET"
    assert provider(Koodous, tmp_path, lambda r: httpx.Response(404)).lookup_hash("c" * 64).status == ProviderStatus.NOT_FOUND


# ---------------------------------------------------------------------------------------------- service
def test_aggregate_never_treats_missing_data_as_safe():
    from malintx.schemas.results import IntelLookup

    def lk(status, verdict=IntelVerdict.UNKNOWN):
        return IntelLookup(provider="p", subject="s", subject_type="t", status=status, verdict=verdict, retrieved_at="t")

    assert aggregate([]) == IntelVerdict.UNKNOWN
    assert aggregate([lk(ProviderStatus.NOT_FOUND), lk(ProviderStatus.UNAVAILABLE), lk(ProviderStatus.ERROR)]) == IntelVerdict.UNKNOWN
    assert aggregate([lk(ProviderStatus.OK, IntelVerdict.BENIGN_OBSERVED), lk(ProviderStatus.OK, IntelVerdict.SUSPICIOUS)]) == IntelVerdict.SUSPICIOUS
    assert aggregate([lk(ProviderStatus.OK, IntelVerdict.SUSPICIOUS), lk(ProviderStatus.OK, IntelVerdict.KNOWN_MALICIOUS)]) == IntelVerdict.KNOWN_MALICIOUS


def test_service_unconfigured_degrades_gracefully(analyzed, tmp_path):
    s = Settings(data_dir=tmp_path / "var", _env_file=None)
    rep = IntelService(s).enrich(analyzed["banking_trojan"])
    assert rep.requested and all(v == ProviderStatus.UNCONFIGURED for v in rep.providers.values())
    assert not rep.indicators and "not safe" in " ".join(rep.notes)


def test_service_enriches_caches_and_skips_noise(analyzed, tmp_path):
    s = S(tmp_path)
    repo = Repository(Database(tmp_path / "t.db"))
    calls = []

    def h(r: httpx.Request):
        calls.append(r.url.host + r.url.path)
        if r.url.host == "mb-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "hash_not_found"})
        if r.url.host in ("developer.koodous.com", "api.shodan.io"):
            return httpx.Response(404)
        if "/files/" in r.url.path:
            return httpx.Response(200, json=vt_body(mal=30, und=20))
        return httpx.Response(200, json=vt_body(mal=8, har=10))

    svc = IntelService(s, repo, transport=httpx.MockTransport(h), sleep=NOSLEEP)
    static = analyzed["banking_trojan"]
    rep = svc.enrich(static)
    assert rep.sample_verdict == IntelVerdict.KNOWN_MALICIOUS
    assert sorted(i.value for i in rep.indicators) == ["http://cdn-update-check.top/api/sms.php", "http://cdn-update-check.top/stage2.bin"]
    assert rep.indicators[0].verdict == IntelVerdict.KNOWN_MALICIOUS
    assert all(host.startswith(("www.virustotal.com", "api.shodan.io", "mb-api.abuse.ch", "developer.koodous.com")) for host in calls)
    first = len(calls)
    rep2 = svc.enrich(static)
    assert len(calls) == first, "second run must be served from the cache"
    assert rep2.indicators[0].lookups[0].cached


def test_service_provider_outage_does_not_break_enrichment(analyzed, tmp_path):
    s = S(tmp_path)
    svc = IntelService(s, None, transport=httpx.MockTransport(lambda r: httpx.Response(503)), sleep=NOSLEEP)
    rep = svc.enrich(analyzed["banking_trojan"])
    assert rep.sample_verdict == IntelVerdict.UNKNOWN
    assert any(v in (ProviderStatus.UNAVAILABLE, ProviderStatus.RATE_LIMITED) for v in rep.providers.values())
    assert all(i.verdict == IntelVerdict.UNKNOWN for i in rep.indicators)


def test_service_never_contacts_extracted_infrastructure(analyzed, tmp_path):
    hosts = set()
    svc = IntelService(S(tmp_path), None, transport=httpx.MockTransport(lambda r: (hosts.add(r.url.host), httpx.Response(404))[1]), sleep=NOSLEEP)
    svc.enrich(analyzed["banking_trojan"])
    assert "cdn-update-check.top" not in hosts and hosts <= {"www.virustotal.com", "api.shodan.io", "mb-api.abuse.ch", "developer.koodous.com"}


def test_indicator_budget_and_library_only_skipped(analyzed, tmp_path):
    s = S(tmp_path, intel_max_indicators=1)
    svc = IntelService(s, None, transport=httpx.MockTransport(lambda r: httpx.Response(404)), sleep=NOSLEEP)
    chosen, skipped = svc.select_indicators(analyzed["banking_trojan"].indicators + [
        analyzed["banking_trojan"].indicators[0].model_copy(update={"id": "IND-x", "type": IndicatorType.DOMAIN, "value": "lib.example",
                                                                    "note": "referenced only from third-party library code"})])
    assert len(chosen) == 1 and all("library" not in (c.note or "") for c in chosen) and skipped == 1  # the second URL exceeds the budget


def test_status_never_exposes_secrets(tmp_path):
    out = json.dumps(IntelService(S(tmp_path)).provider_status())
    for secret in ("VT-SECRET-KEY", "SH-SECRET", "AB-SECRET", "KO-SECRET"):
        assert secret not in out
    assert '"configured": true' in out
