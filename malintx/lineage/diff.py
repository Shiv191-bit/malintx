"""Capability delta between a base sample and a suspect variant (repackaging / version drift analysis)."""

from __future__ import annotations

from typing import Any

from malintx.schemas.analysis import StaticAnalysisResult
from malintx.schemas.common import FindingKind

_SIGNAL = (FindingKind.MALICIOUS_BEHAVIOR, FindingKind.SUSPICIOUS_CAPABILITY)


def _findings(r: StaticAnalysisResult) -> dict[str, Any]:
    return {f.rule_id: f for f in r.findings if f.kind in _SIGNAL}


def diff_results(base: StaticAnalysisResult, other: StaticAnalysisResult) -> dict[str, Any]:
    """What `other` has that `base` lacks (and vice versa). Purely deterministic set arithmetic."""
    bp, op = base.manifest.permission_names(), other.manifest.permission_names()
    bf, of = _findings(base), _findings(other)
    bc = {c.name for c in base.manifest.components}
    oc = {c.name for c in other.manifest.components}
    bi = {(i.type.value, i.value) for i in base.indicators if i.type.value in ("url", "ipv4", "domain", "email")}
    oi = {(i.type.value, i.value) for i in other.indicators if i.type.value in ("url", "ipv4", "domain", "email")}
    bcert = {c.sha256 for c in base.sample.certificates}
    ocert = {c.sha256 for c in other.sample.certificates}

    added = sorted(of.keys() - bf.keys())
    return {
        "same_signer": bool(bcert & ocert) if bcert and ocert else None,
        "same_package": base.sample.package_name == other.sample.package_name,
        "permissions_added": sorted(op - bp),
        "permissions_removed": sorted(bp - op),
        "findings_added": [{"rule_id": r, "title": of[r].title, "severity": of[r].severity.value, "kind": of[r].kind.value} for r in added],
        "findings_removed": [{"rule_id": r, "title": bf[r].title, "severity": bf[r].severity.value} for r in sorted(bf.keys() - of.keys())],
        "behaviours_added": [r for r in added if of[r].kind == FindingKind.MALICIOUS_BEHAVIOR],
        "components_added": sorted(oc - bc)[:100],
        "components_removed": sorted(bc - oc)[:100],
        "indicators_added": [{"type": t, "value": v} for t, v in sorted(oi - bi)][:100],
        "indicators_removed": [{"type": t, "value": v} for t, v in sorted(bi - oi)][:100],
        "summary": _summary(base, other, op - bp, added, of, bcert, ocert),
    }


def _summary(base: StaticAnalysisResult, other: StaticAnalysisResult, perms: set[str], added: list[str], of: dict[str, Any],
             bcert: set[str], ocert: set[str]) -> str:
    bits = []
    if base.sample.package_name == other.sample.package_name and bcert and ocert and not (bcert & ocert):
        bits.append("SAME package name but a DIFFERENT signing certificate (classic repackaging signal)")
    sev = [r for r in added if of[r].severity.rank >= 3]
    if sev:
        bits.append(f"{len(sev)} high-or-critical capability/behaviour finding(s) added: " + ", ".join(sev[:5]))
    if perms:
        bits.append(f"{len(perms)} permission(s) added")
    return "; ".join(bits) or "no security-relevant capability was added"
