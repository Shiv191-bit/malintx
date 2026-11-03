"""Deterministic Finding → MITRE ATT&CK for Mobile mapping with catalog-validated IDs."""

from __future__ import annotations

import logging

from malintx.mitre import MitreCatalog
from malintx.schemas.analysis import Finding, MitreMapping
from malintx.schemas.common import Confidence, FindingKind

log = logging.getLogger(__name__)

_MAPPABLE = (FindingKind.MALICIOUS_BEHAVIOR, FindingKind.SUSPICIOUS_CAPABILITY)


def build_mappings(findings: list[Finding], catalog: MitreCatalog) -> list[MitreMapping]:
    by_tech: dict[str, list[Finding]] = {}
    for f in findings:
        if f.kind not in _MAPPABLE:
            continue  # misconfigurations and informational findings never map to adversary techniques
        for tid in f.mitre_ids:
            by_tech.setdefault(tid, []).append(f)

    out: list[MitreMapping] = []
    for tid, fs in sorted(by_tech.items()):
        tech = catalog.get(tid)
        if tech is None:
            log.error("rule references unknown ATT&CK id %s; mapping dropped", tid)
            continue
        best = max(f.confidence for f in fs)
        has_behavior = any(f.kind == FindingKind.MALICIOUS_BEHAVIOR for f in fs)
        if not has_behavior and best > Confidence.MEDIUM:
            best = Confidence.MEDIUM  # a capability alone never supports a HIGH technique mapping
        evidence: list[str] = []
        for f in fs:
            for e in f.evidence_ids:
                if e not in evidence:
                    evidence.append(e)
        kinds = "behaviour correlation" if has_behavior else "capability observation"
        rationale = (
            f"Mapped from {kinds}: "
            + "; ".join(f"{f.title} [{f.rule_id}, {f.kind.value}, {f.confidence.value} confidence]" for f in fs)
            + ". Static evidence shows the capability exists in the package; execution was not observed."
        )
        out.append(
            MitreMapping(
                technique_id=tid, technique_name=tech.name, tactics=list(tech.tactics),
                description=tech.description, source=catalog.source, url=tech.url,
                evidence_ids=evidence[:24], finding_ids=[f.id for f in fs], rationale=rationale,
                confidence=best,
            )
        )
    return out
