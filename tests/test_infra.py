"""Infrastructure ("C2 map") aggregation: roles, intel merge, shared hosts, honesty about unknowns."""

from __future__ import annotations

from malintx import infra


def _ind(i, t, v, note=None):
    return {"id": i, "type": t, "value": v, "evidence_ids": [], "occurrences": 1, "note": note}


def _res(pkg, indicators, intel=None, cls="high"):
    return {"static": {"sample": {"package_name": pkg}, "indicators": indicators}, "risk": {"classification": cls, "score": 70}, "intel": intel}


def _lookup(provider, **kw):
    base = {"provider": provider, "status": "ok", "asn": None, "as_owner": None, "country": None, "open_ports": [], "malware_families": [], "tags": [],
            "malicious": None, "reference_url": None}
    return {**base, **kw}


def test_roles():
    assert infra.role_of("ipv4", "45.33.32.156") == "hardcoded_ip"
    assert infra.role_of("url", "http://45.33.32.156:8080/gate.php") == "ip_literal_url"
    assert infra.role_of("url", "https://api.telegram.org/bot123:abc/sendMessage") == "telegram_bot"
    assert infra.role_of("domain", "cdn-update-check.top") == "domain"
    assert infra.role_of("url", "https://example.org/x") == "url"
    assert infra.host_of("http://User@Host.Example:8080/p?q=1") == "host.example"


def test_shared_host_and_ordering_and_unknown_not_safe():
    a = _res("com.a", [_ind("i1", "ipv4", "45.33.32.156"), _ind("i2", "domain", "evil.top"), _ind("i3", "email", "x@y.z")])
    b = _res("com.b", [_ind("j1", "ipv4", "45.33.32.156")])
    out = infra.build([({"job_id": "A", "name": "a"}, a), ({"job_id": "B", "name": "b"}, b)])
    assert out["summary"] == {"samples": 2, "hosts": 2, "shared_hosts": 1, "shared_ordinary": 0, "queried_hosts": 0, "flagged_hosts": 0, "samples_with_intel": 0}
    shared = next(h for h in out["hosts"] if h["value"] == "45.33.32.156")
    assert sorted(shared["samples"]) == ["A", "B"]
    assert all(h["verdict"] == "unknown" and not h["queried"] for h in out["hosts"])  # no intel requested: unknown, never "safe"
    assert not any(h["type"] == "email" for h in out["hosts"])


def test_intel_merge_and_most_severe_verdict_first():
    intel = {"requested": True, "indicators": [
        {"indicator_id": "i1", "value": "45.33.32.156", "type": "ipv4", "verdict": "suspicious",
         "lookups": [_lookup("shodan", asn="AS63949", as_owner="Akamai Connected Cloud", country="US", open_ports=[22, 80]),
                     _lookup("virustotal", malicious=2, reference_url="https://vt/x"), _lookup("x", status="unavailable", country="ZZ")]},
        {"indicator_id": "i2", "value": "evil.top", "type": "domain", "verdict": "unknown", "lookups": []}]}
    out = infra.build([({"job_id": "A"}, _res("com.a", [_ind("i1", "ipv4", "45.33.32.156"), _ind("i2", "domain", "evil.top")], intel))])
    first = out["hosts"][0]
    assert first["value"] == "45.33.32.156" and first["verdict"] == "suspicious"
    assert first["owner"] == "AS63949 Akamai Connected Cloud" and first["country"] == "US" and first["intel"]["open_ports"] == [22, 80]
    assert first["intel"]["malicious"] == 2 and "ZZ" not in str(first["intel"])  # failed lookups never contribute data
    assert out["owners"][0]["hosts"] == 1 and out["summary"]["flagged_hosts"] == 1 and out["summary"]["queried_hosts"] == 2


def test_results_without_static_are_skipped():
    out = infra.build([({"job_id": "A"}, {"static": None})])
    assert out["samples"] == [] and out["hosts"] == []


def test_extractor_ignores_oids_cidr_bases_and_code_identifiers():
    from malintx.analysis.backends.base import StringRef
    from malintx.analysis.indicators import IndicatorCollector

    col = IndicatorCollector(None, None, "com.own.app", 0)  # intake only: no evidence store needed
    for v in ("2.5.29.14", "1.3.132.0", "174.192.0.0", "224.0.0.251", "java.net", "android.app", "workspec.id", "user.name",
              "http://45.33.32.156:8080/gate.php", "update-check.top"):
        col._scan_one(StringRef(v, None, None, None), "classes.dex")
    assert sorted((t.value, v) for t, v in col._acc) == [("domain", "update-check.top"), ("ipv4", "45.33.32.156"), ("url", "http://45.33.32.156:8080/gate.php")]


def test_graph_escapes_hostile_values_and_is_self_contained():
    from malintx.dashboard import graph

    evil = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'
    data = infra.build([({"job_id": "A", "name": evil}, _res(evil, [_ind("i1", "url", "http://45.33.32.156/" + evil)]))])
    svg = graph.render(data)
    assert "<script" not in svg and "onerror=alert" not in svg.replace("&quot;", "") or "&lt;script" in svg
    assert "<img" not in svg and "href=" not in svg and "http://" not in svg.replace("http://45.33.32.156/", "").replace("http://www.w3.org/2000/svg", "")
