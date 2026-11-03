"""Builds the bounded, evidence-grounded context given to the language model.

Only extracted evidence is passed: never the APK, never full decompiled projects. Everything that came
from the sample is treated as untrusted data (sanitised, truncated, and flagged if it contains
instruction-like text).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from malintx.schemas.analysis import Evidence, Finding, StaticAnalysisResult
from malintx.schemas.common import FindingKind
from malintx.schemas.results import IntelReport

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_INJECTION = re.compile(
    r"(?i)ignore (?:all |any )?(?:previous|prior|above) (?:instructions|rules)|disregard .{0,20}instructions|"
    r"you are (?:now )?(?:a|an|the) |system prompt|as an ai\b|assistant:|<\s*/?\s*(?:system|instructions?)\s*>|"
    r"respond (?:only )?with|do not (?:report|flag|mention)|classify (?:this|it) as (?:benign|safe|clean)"
)


def clean(text: str | None, limit: int) -> str:
    if not text:
        return ""
    text = _CTRL.sub("", text)
    return text if len(text) <= limit else text[:limit] + "…"


@dataclass
class AIContext:
    payload: dict[str, Any]
    evidence_ids: set[str]
    truncated: bool
    injection_markers: list[str] = field(default_factory=list)


def _ev_view(e: Evidence, snippet_chars: int) -> dict[str, Any]:
    return {
        "id": e.id, "kind": e.kind.value, "rule": e.rule_id, "file": e.source_file,
        "class": clean(e.class_name, 160), "method": clean(e.method_name, 80), "api": clean(e.api, 200),
        "artifact": clean(e.artifact, 240), "line": e.line_number, "offset": e.bytecode_offset,
        "snippet": clean(e.snippet, snippet_chars), "extraction": e.extraction_method,
        "limitations": clean(e.limitations, 160),
    }


def build_context(static: StaticAnalysisResult, intel: IntelReport | None, max_chars: int) -> AIContext:
    findings = [f for f in static.findings if f.kind != FindingKind.INFORMATIONAL or f.evidence_ids][:60]
    findings.sort(key=lambda f: (-f.severity.rank, f.id))
    by_id = static.evidence_by_id()

    budget = max_chars
    truncated = False
    ev_views: dict[str, dict[str, Any]] = {}
    snippet_chars = 700

    def add_evidence(f: Finding, cap: int) -> list[str]:
        nonlocal budget, truncated
        kept = []
        for eid in f.evidence_ids[:cap]:
            e = by_id.get(eid)
            if e is None:
                continue
            if eid not in ev_views:
                view = _ev_view(e, snippet_chars)
                cost = len(str(view))
                if budget - cost < 0:
                    truncated = True
                    continue
                budget -= cost
                ev_views[eid] = view
            kept.append(eid)
        return kept

    finding_views = []
    for f in findings:
        cap = 4 if f.severity.rank >= 3 else 2
        kept = add_evidence(f, cap)
        finding_views.append({
            "id": f.id, "title": f.title, "kind": f.kind.value, "severity": f.severity.value,
            "confidence": f.confidence.value, "what_the_rule_means": clean(f.description, 400),
            "known_false_positive_context": clean(f.false_positive_notes, 240),
            "deterministic_context_adjustments": f.suppressed_by, "mitre_candidates": f.mitre_ids,
            "evidence_ids": kept,
        })

    m = static.manifest
    ind_views = [{"id": i.id, "type": i.type.value, "value": clean(i.value, 200), "note": clean(i.note, 100)}
                 for i in static.indicators if i.type.value in ("url", "ipv4", "domain", "email")][:25]
    intel_view: dict[str, Any] = {"requested": False}
    if intel and intel.requested:
        intel_view = {
            "requested": True, "sample_verdict": intel.sample_verdict.value,
            "providers": {k: v.value for k, v in intel.providers.items()},
            "indicator_verdicts": [{"value": clean(i.value, 120), "verdict": i.verdict.value} for i in intel.indicators[:25]],
            "note": "unknown means no data, not safe",
        }

    payload = {
        "task": "Assess whether the cited evidence supports malicious intent versus legitimate functionality.",
        "sample": {
            "package": m.package, "target_sdk": m.target_sdk, "min_sdk": m.min_sdk,
            "sensitive_permissions": [p.name for p in m.permissions if p.sensitivity != "normal"][:40],
            "accessibility_services": m.accessibility_services[:5], "device_admin_receivers": m.device_admin_receivers[:5],
            "signed_with_schemes": static.sample.signing_schemes,
        },
        "coverage": {
            "backend": static.coverage.backend, "source_scan": static.coverage.source_scan,
            "packer_hints": static.coverage.packer_hints, "limitations": static.coverage.limitations[:6],
        },
        "findings": finding_views,
        "evidence": list(ev_views.values()),
        "indicators": ind_views,
        "threat_intelligence": intel_view,
    }
    markers = sorted({m_.group(0)[:60] for v in ev_views.values() for key in ("snippet", "artifact")
                      if (m_ := _INJECTION.search(v.get(key) or ""))})
    return AIContext(payload=payload, evidence_ids=set(ev_views), truncated=truncated, injection_markers=markers)
