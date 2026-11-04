"""Static-analysis orchestrator: APK → `StaticAnalysisResult`. Never executes the sample."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from malintx.analysis.backends.androguard_backend import AndroguardBackend
from malintx.analysis.indicators import IndicatorCollector
from malintx.analysis.manifest import parse_manifest_element
from malintx.analysis.mitre_map import build_mappings
from malintx.analysis.rules import catalog as cat
from malintx.analysis.rules import engine
from malintx.analysis.rules.evidence import EvidenceStore
from malintx.analysis.rules.manifest_rules import Hit, evaluate_manifest
from malintx.analysis.sample_info import build_sample_info
from malintx.config import Settings
from malintx.mitre import get_catalog
from malintx.schemas.analysis import Finding, NearMiss, StaticAnalysisResult
from malintx.schemas.common import Confidence, EvidenceKind, FindingKind, Severity
from malintx.schemas.sample import ManifestInfo, ZipInspection

log = logging.getLogger(__name__)

_TEXT_EXT = (".txt", ".json", ".xml", ".html", ".htm", ".js", ".properties", ".cfg", ".conf", ".ini", ".csv", ".yml", ".yaml", ".php", ".dat")
_MAX_RES_FILE = 512 * 1024
_MAX_RES_TOTAL = 8 * 1024 * 1024


def _scan_resources(apk: Any, collector: IndicatorCollector, warnings: list[str]) -> int:
    total = scanned = 0
    for name in apk.get_files():
        if not (name.startswith(("assets/", "res/raw/", "res/xml/")) and name.lower().endswith(_TEXT_EXT)):
            continue
        try:
            data = apk.get_file(name)
        except Exception as exc:  # noqa: BLE001 - corrupt entries are expected in hostile samples
            warnings.append(f"could not read {name}: {type(exc).__name__}")
            continue
        if len(data) > _MAX_RES_FILE or total + len(data) > _MAX_RES_TOTAL:
            continue
        if data.count(b"\x00") > len(data) // 20:  # binary, not text
            continue
        total += len(data)
        scanned += 1
        collector.scan_text(name, data.decode("utf-8", errors="ignore"))
    return scanned


def _archive_findings(archive: ZipInspection | None, packer_hints: list[str], obfuscation: float | None,
                      store: EvidenceStore, classes: int = 0, methods: int = 0) -> list[Hit]:
    hits: list[Hit] = []
    if archive and archive.dex_files and 0 < classes <= 15 and methods <= 80:
        h = Hit("ARC-TINY-CODE", total_sites=1)
        ev = store.add(kind=EvidenceKind.CLASS_STRUCTURE, rule_id=h.rule_id, source_file="classes.dex", extraction_method="class-count",
                       artifact=f"{classes} classes / {methods} methods", snippet=f"application code consists of only {classes} classes and {methods} methods",
                       limitations="Small apps exist legitimately; this is only meaningful together with dynamic code loading or archive anomalies.")
        if ev:
            h.evidence_ids.append(ev.id)
        hits.append(h)
    if archive and archive.suspicious_entries:
        h = Hit("ARC-SUSPICIOUS-ENTRIES", total_sites=len(archive.suspicious_entries))
        for reason in archive.suspicious_entries[:6]:
            ev = store.add(kind=EvidenceKind.ARCHIVE, rule_id=h.rule_id, source_file="(zip central directory)",
                           extraction_method="zip-inspection", artifact=reason[:200], snippet=reason[:300],
                           limitations="Structural property of the archive; may also result from sloppy packaging tools.")
            if ev:
                h.evidence_ids.append(ev.id)
        hits.append(h)
    if packer_hints:
        h = Hit("ARC-PACKER", total_sites=len(packer_hints))
        for p in packer_hints:
            ev = store.add(kind=EvidenceKind.ARCHIVE, rule_id=h.rule_id, source_file="(package contents)",
                           extraction_method="packer-signature", artifact=p, snippet=f"Packer/protector signature: {p}",
                           limitations="Name-based signature; commercial protectors are also used by legitimate apps.")
            if ev:
                h.evidence_ids.append(ev.id)
        hits.append(h)
    if obfuscation is not None and obfuscation >= 0.6:
        h = Hit("ARC-OBFUSCATED-NAMES", total_sites=1)
        ev = store.add(kind=EvidenceKind.CLASS_STRUCTURE, rule_id=h.rule_id, source_file="classes.dex",
                       extraction_method="class-name-statistics", artifact=f"short-name ratio {obfuscation}",
                       snippet=f"{obfuscation:.0%} of app classes have names of two characters or fewer",
                       limitations="Identifier renaming (R8/ProGuard) is standard in legitimate release builds.")
        if ev:
            h.evidence_ids.append(ev.id)
        hits.append(h)
    return hits


_ARCHIVE_META = {
    "ARC-SUSPICIOUS-ENTRIES": ("Malformed or evasive archive structure",
        "The ZIP contains duplicate entry names, path-traversal names or other structure used to confuse analysis tools.",
        "evasion", FindingKind.SUSPICIOUS_CAPABILITY, Severity.MEDIUM, ("T1406",)),
    "ARC-PACKER": ("Commercial packer / protector signature",
        "File or class names match a known app protector. Protected code limits what static analysis can see.",
        "packing", FindingKind.SUSPICIOUS_CAPABILITY, Severity.LOW, ("T1406.002",)),
    "ARC-TINY-CODE": ("Thin-stub application code",
        "The app's own code is only a handful of classes; its real behaviour may live in assets, native code or downloaded payloads.",
        "packing", FindingKind.INFORMATIONAL, Severity.INFO, ()),
    "ARC-OBFUSCATED-NAMES": ("Heavily renamed identifiers",
        "Most app classes use one- or two-character names.", "obfuscation", FindingKind.INFORMATIONAL,
        Severity.INFO, ()),
}


def analyze_apk(apk_path: Path, ingested: dict[str, Any], settings: Settings) -> StaticAnalysisResult:
    catalog = get_catalog(settings)
    warnings: list[str] = []
    radius = settings.slice_radius_lines
    archive = ZipInspection.model_validate(ingested["archive"]) if ingested.get("archive") else None

    backend = AndroguardBackend(apk_path)
    backend.load()
    cov = backend.coverage()
    if not cov.manifest_parsed:
        cov.limitations.append("AndroidManifest.xml could not be decoded")
    if archive and not archive.dex_files:
        cov.limitations.append("package contains no classes.dex; code analysis not possible")
    if cov.native_libraries:
        cov.limitations.append(
            f"{len(cov.native_libraries)} native librar{'y' if len(cov.native_libraries) == 1 else 'ies'} present; "
            "native (ARM/x86) code is not analysed by this engine"
        )
    cov.limitations.append("bytecode-level analysis: reachability and runtime behaviour are not established")

    store = EvidenceStore()
    manifest_el = backend.apk.get_android_manifest_xml()
    manifest = parse_manifest_element(manifest_el) if manifest_el is not None else ManifestInfo()
    sample = build_sample_info(ingested, backend.apk, manifest, archive, warnings)

    hits: dict[str, Hit] = {}
    hits.update(evaluate_manifest(manifest, store))
    strings = []
    if cov.usable_code:
        hits.update(engine.run_api_rules(backend, manifest, store, radius))
        hits.update(engine.run_class_rules(backend, store))
        hits.update(engine.run_receiver_classes(backend, manifest))
        strings = list(backend.strings())
        hits.update(engine.run_string_rules(strings, manifest, store, backend, radius))
    else:
        warnings.append("no usable DEX code: API, class and string rules were skipped")

    collector = IndicatorCollector(store, backend, manifest.package, radius)
    collector.scan(strings)
    resources_scanned = _scan_resources(backend.apk, collector, warnings)
    indicators, endpoint_classes = collector.results()
    hits.update(engine.run_target_app_enum(collector.package_refs_by_class(), store))
    ind_ev = {i.id: i.evidence_ids for i in indicators}
    ep = engine.endpoint_hit(endpoint_classes, ind_ev)
    if ep:
        hits[ep.rule_id] = ep
    for h in _archive_findings(archive, cov.packer_hints, cov.obfuscation_ratio, store, cov.classes, cov.methods):
        hits[h.rule_id] = h

    engine.apply_prerequisites(hits)
    composites = engine.run_composites(hits)
    near = engine.near_misses(hits, composites)
    findings = engine.build_findings({k: v for k, v in hits.items() if not k.startswith("ARC-")}, composites)
    for rid, h in hits.items():
        if rid.startswith("ARC-") and h.evidence_ids:
            title, desc, cat_, kind, sev, mitre = _ARCHIVE_META[rid]
            findings.append(Finding(
                id=f"F-{rid}", rule_id=rid, title=title, description=desc, kind=kind, severity=sev,
                confidence=Confidence.MEDIUM, category=cat_, evidence_ids=h.evidence_ids, mitre_ids=list(mitre),
                limitations="Heuristic structural signal.",
                false_positive_notes="Legitimate release builds may show this property.",
            ))
    findings.sort(key=lambda f: (-f.severity.rank, f.id))

    if store.dropped:
        warnings.append(f"evidence cap reached: {store.dropped} observation(s) were not recorded")
    if resources_scanned:
        cov.limitations.append(f"{resources_scanned} text resource file(s) were scanned for indicators")
    referenced = {e for f in findings for e in f.evidence_ids} | {e for i in indicators for e in i.evidence_ids}
    evidence = [e for e in store.all() if e.id in referenced]

    lineage = None
    if cov.usable_code:
        from malintx.lineage import minhash
        from malintx.schemas.analysis import LineageFingerprint

        apis = backend.framework_api_set()
        lineage = LineageFingerprint(
            api_count=len(apis), minhash=minhash(apis), permissions=sorted(manifest.permission_names()),
            rule_ids=sorted({f.rule_id for f in findings if f.kind in (FindingKind.MALICIOUS_BEHAVIOR, FindingKind.SUSPICIOUS_CAPABILITY)}),
            signer_sha256=sorted(c.sha256 for c in sample.certificates),
        )

    return StaticAnalysisResult(
        sample=sample, manifest=manifest, evidence=evidence, findings=findings, indicators=indicators,
        mitre=build_mappings(findings, catalog), coverage=cov, ruleset_version=cat.RULESET_VERSION,
        warnings=warnings, lineage=lineage, near_misses=[NearMiss(**n) for n in near],
    )
