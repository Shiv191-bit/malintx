"""Network-infrastructure view ("C2 map"): what hosts an app references, what passive intel says about them, and which
analysed samples share them.

Honesty rules (see docs/REPOSITORY_AUDIT.md):
* Nothing here contacts any host. Data comes only from static indicators and from passive provider lookups the analyst opted into.
* A host found in code is a *reference*, not proof of command-and-control. Roles describe how the reference looks
  (hard-coded public IP, Telegram bot endpoint, IP-literal URL, ordinary domain); they are rule outputs, not intel verdicts.
* Country/ASN is where a provider says the address is *hosted*, not where an operator is. It is shown only when a provider returned it.
* "unknown" (no provider data) is never presented as "safe".
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

NETWORK_TYPES = ("ipv4", "domain", "url")
_TELEGRAM = re.compile(r"api\.telegram\.org/bot", re.I)
# Lower number = shown first. A role is a description of the reference, not a verdict.
ROLE_ORDER = {"telegram_bot": 0, "ip_literal_url": 1, "hardcoded_ip": 2, "domain": 3, "url": 4, "public_dns": 5}
ROLE_LABEL = {
    "telegram_bot": "Telegram Bot API endpoint",
    "ip_literal_url": "URL with IP-literal host",
    "hardcoded_ip": "Hard-coded public IP",
    "domain": "Domain",
    "url": "URL",
    "public_dns": "Public DNS resolver",
}
VERDICT_ORDER = {"known_malicious": 0, "suspicious": 1, "unknown": 2, "benign_observed": 3}


def host_of(value: str) -> str:
    """Host part of an indicator value (URL, host:port or bare host), lower-cased."""
    v = value.strip()
    if "://" in v:
        try:
            return (urlsplit(v).hostname or "").lower()
        except ValueError:
            return ""
    return v.split("/")[0].split(":")[0].lower()


def role_of(itype: str, value: str) -> str:
    if _TELEGRAM.search(value):
        return "telegram_bot"
    host = host_of(value)
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if itype == "ipv4":
        return "hardcoded_ip"
    if itype == "url":
        return "ip_literal_url" if is_ip else "url"
    return "domain"


def is_notable(h: dict[str, Any]) -> bool:
    """Worth drawing/pivoting on: an unusual reference type, or intel flagged it or returned data for it. Ordinary domains and URLs
    (library docs, mail providers) are kept in tables but not drawn: hundreds of them would bury the signal."""
    return h["role"] not in ("domain", "url", "public_dns") or h["verdict"] != "unknown" or bool(h["queried"])


def _merge_lookups(lookups: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse provider lookups for one host into display fields (first non-empty value wins)."""
    out: dict[str, Any] = {"asn": None, "as_owner": None, "country": None, "open_ports": [], "families": [], "tags": [],
                           "malicious": None, "providers": [], "reference_urls": []}
    for lk in lookups:
        if lk.get("status") not in ("ok", "found"):
            continue
        out["providers"].append(lk["provider"])
        for k in ("asn", "as_owner", "country"):
            out[k] = out[k] or lk.get(k)
        out["open_ports"] = sorted(set(out["open_ports"]) | set(lk.get("open_ports") or []))
        out["families"] = sorted(set(out["families"]) | set(lk.get("malware_families") or []))
        out["tags"] = sorted(set(out["tags"]) | set(lk.get("tags") or []))
        if lk.get("malicious") is not None:
            out["malicious"] = max(out["malicious"] or 0, lk["malicious"])
        if lk.get("reference_url"):
            out["reference_urls"].append(lk["reference_url"])
    return out


def build(items: list[tuple[dict[str, Any], dict[str, Any]]]) -> dict[str, Any]:
    """items: (sample meta, AnalysisResult dict). Meta needs job_id; package/name/classification/score are optional.

    Returns samples, hosts (one per distinct network indicator, with the samples that reference it) and summary counts.
    """
    samples: list[dict[str, Any]] = []
    hosts: dict[tuple[str, str], dict[str, Any]] = {}
    intel_requested = 0
    for meta, res in items:
        static = (res or {}).get("static")
        if not static:
            continue
        risk = res.get("risk") or {}
        samples.append({
            "job_id": meta["job_id"], "label": static["sample"].get("package_name") or meta.get("name") or meta["job_id"],
            "classification": risk.get("classification") or meta.get("classification") or "unknown", "score": risk.get("score", meta.get("score")),
        })
        intel = res.get("intel") or {}
        intel_requested += 1 if intel.get("requested") else 0
        by_id = {i["indicator_id"]: i for i in intel.get("indicators", [])}
        for ind in static.get("indicators", []):
            if ind["type"] not in NETWORK_TYPES:
                continue
            key = (ind["type"], ind["value"])
            h = hosts.get(key)
            if h is None:
                role = "public_dns" if "resolver" in (ind.get("note") or "") else role_of(ind["type"], ind["value"])
                h = hosts[key] = {"value": ind["value"], "type": ind["type"], "host": host_of(ind["value"]), "role": role, "role_label": ROLE_LABEL[role],
                                  "notes": [], "verdict": "unknown", "intel": {}, "samples": [], "queried": False}
            if ind.get("note") and ind["note"] not in h["notes"]:
                h["notes"].append(ind["note"])
            if meta["job_id"] not in h["samples"]:
                h["samples"].append(meta["job_id"])
            ii = by_id.get(ind["id"])
            if ii:
                h["queried"] = True
                merged = _merge_lookups(ii.get("lookups", []))
                # keep the most severe verdict seen across samples
                if VERDICT_ORDER.get(ii["verdict"], 2) < VERDICT_ORDER.get(h["verdict"], 2) or not h["intel"]:
                    h["verdict"] = ii["verdict"]
                for k, v in merged.items():
                    if v and not h["intel"].get(k):
                        h["intel"][k] = v
    rows = sorted(hosts.values(), key=lambda h: (VERDICT_ORDER.get(h["verdict"], 2), ROLE_ORDER[h["role"]], -len(h["samples"]), h["value"]))
    owners: dict[str, dict[str, Any]] = {}
    for h in rows:
        i = h["intel"]
        label = " ".join(x for x in (i.get("asn"), i.get("as_owner")) if x)
        h["owner"] = label or None
        h["country"] = i.get("country")
        if label:
            o = owners.setdefault(label, {"owner": label, "country": i.get("country"), "hosts": 0, "samples": set()})
            o["hosts"] += 1
            o["samples"].update(h["samples"])
    return {
        "samples": samples, "hosts": rows,
        "owners": sorted(({**o, "samples": sorted(o["samples"])} for o in owners.values()), key=lambda o: (-o["hosts"], o["owner"])),
        "summary": {
            "samples": len(samples), "hosts": len(rows), "shared_hosts": sum(1 for h in rows if len(h["samples"]) > 1 and is_notable(h)),
            "shared_ordinary": sum(1 for h in rows if len(h["samples"]) > 1 and not is_notable(h)),
            "queried_hosts": sum(1 for h in rows if h["queried"]), "flagged_hosts": sum(1 for h in rows if h["verdict"] in ("known_malicious", "suspicious")),
            "samples_with_intel": intel_requested,
        },
    }
