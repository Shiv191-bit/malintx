"""Rule evaluation: bytecode/strings/manifest → hits → composites → findings."""

from __future__ import annotations

import re
from dataclasses import dataclass

from malintx.analysis.backends.base import CallSite, CodeBackend, StringRef, is_library_class, outer_class
from malintx.analysis.rules import catalog as cat
from malintx.analysis.rules.evidence import EvidenceStore
from malintx.analysis.rules.manifest_rules import MANIFEST_RULES, Hit, ManifestRuleMeta
from malintx.schemas.analysis import Finding
from malintx.schemas.common import Confidence, EvidenceKind, FindingKind, Severity
from malintx.schemas.sample import ManifestInfo

BYTECODE = "androguard-bytecode"
STRINGS = "dex-string-pool"
BYTECODE_LIMIT = "Static reference to the API; whether the call is reachable at runtime is not established."
STRING_LIMIT = "String constant present in the package; runtime use is not established."

TARGET_APP_ENUM = ManifestRuleMeta(
    "STR-TARGET-APP-ENUM", "Embedded list of many third-party application IDs",
    "A single class references many distinct third-party package names, the shape of the target-app "
    "lists banking trojans use to decide which apps to overlay or monitor.",
    "app_enum", FindingKind.SUSPICIOUS_CAPABILITY, Severity.MEDIUM, mitre=("T1418",),
    fp_notes="Launchers, app-lock tools, cross-promotion lists and app stores contain such lists.",
)


def _lower(c: Confidence) -> Confidence:
    return {Confidence.HIGH: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.LOW, Confidence.LOW: Confidence.LOW}[c]


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    description: str
    category: str
    kind: FindingKind
    severity: Severity
    mitre: tuple[str, ...]
    masvs: tuple[str, ...]
    fp_notes: str | None


def all_rule_meta() -> dict[str, RuleMeta]:
    meta: dict[str, RuleMeta] = {}
    for r in (*cat.ALL_API_RULES, *cat.CLASS_RULES, *cat.STRING_RULES):
        meta[r.id] = RuleMeta(r.id, r.title, r.description, r.category, r.kind, r.severity, r.mitre, r.masvs, r.fp_notes)
    for r in (*MANIFEST_RULES.values(), TARGET_APP_ENUM):
        meta[r.id] = RuleMeta(r.id, r.title, r.description, r.category, r.kind, r.severity, r.mitre, r.masvs, r.fp_notes)
    for r in cat.COMPOSITE_RULES:
        meta[r.id] = RuleMeta(r.id, r.title, r.description, r.category, FindingKind.MALICIOUS_BEHAVIOR,
                              r.severity, r.mitre, r.masvs, r.fp_notes)
    return meta


# ------------------------------------------------------------------------------ evaluation
def _permission_confidence(rule_perms: tuple[str, ...], held: set[str]) -> Confidence:
    if rule_perms and not (set(rule_perms) & held):
        return Confidence.MEDIUM
    return Confidence.HIGH


def run_api_rules(backend: CodeBackend, manifest: ManifestInfo, store: EvidenceStore, radius: int) -> dict[str, Hit]:
    held = manifest.permission_names()
    hits: dict[str, Hit] = {}
    for rule in cat.ALL_API_RULES:
        sites: list[CallSite] = backend.call_sites(rule.sigs)
        if len(sites) < rule.min_sites:
            continue
        sites.sort(key=lambda s: (is_library_class(s.caller_class), s.caller_class, s.caller_method, s.offset))
        app_sites = [s for s in sites if not is_library_class(s.caller_class)]
        hit = Hit(rule.id, total_sites=len(sites), library_only=not app_sites)
        hit.classes = {outer_class(s.caller_class) for s in app_sites}
        conf = _permission_confidence(rule.permissions, held)
        if hit.library_only:
            conf = Confidence.LOW
            hit.note = "all call sites are inside third-party library namespaces"
        hit.confidence = conf
        for s in sites[: rule.max_evidence]:
            ev = store.add(
                kind=EvidenceKind.API_CALL, rule_id=rule.id, source_file=s.dex_file,
                extraction_method=BYTECODE, class_name=s.caller_class, method_name=s.caller_method,
                bytecode_offset=s.offset, api=f"{s.callee_class}->{s.callee_method}",
                snippet=backend.snippet(s, radius), confidence=conf, limitations=BYTECODE_LIMIT,
            )
            if ev:
                hit.evidence_ids.append(ev.id)
        hits[rule.id] = hit
    return hits


def run_class_rules(backend: CodeBackend, store: EvidenceStore) -> dict[str, Hit]:
    bases = {b for r in cat.CLASS_RULES for b in r.base_classes}
    subclasses = backend.subclass_map(bases)
    hits: dict[str, Hit] = {}
    for rule in cat.CLASS_RULES:
        classes = sorted({c for b in rule.base_classes for c in subclasses.get(b, [])})
        if not classes:
            continue
        app = [c for c in classes if not is_library_class(c)]
        hit = Hit(rule.id, total_sites=len(classes), library_only=not app,
                  confidence=Confidence.LOW if not app else Confidence.HIGH)
        hit.classes = {outer_class(c) for c in app}
        for c in (app or classes)[:6]:
            ev = store.add(
                kind=EvidenceKind.CLASS_STRUCTURE, rule_id=rule.id, source_file="classes.dex",
                extraction_method=BYTECODE, class_name=c, artifact=f"extends {', '.join(rule.base_classes)}",
                snippet=f"class {c} extends {rule.base_classes[0]}", confidence=hit.confidence,
                limitations="Inheritance relationship from DEX class definitions; registration and use not confirmed.",
            )
            if ev:
                hit.evidence_ids.append(ev.id)
        hits[rule.id] = hit
    return hits


def run_string_rules(strings: list[StringRef], manifest: ManifestInfo, store: EvidenceStore,
                     backend: CodeBackend, radius: int) -> dict[str, Hit]:
    held = manifest.permission_names()
    hits: dict[str, Hit] = {}
    for rule in cat.STRING_RULES:
        rx = re.compile(rule.pattern)
        matched: list[tuple[StringRef, str]] = []
        seen_vals: set[str] = set()
        for ref in strings:
            m = rx.fullmatch(ref.value) if rule.full_match else rx.search(ref.value)
            if m:
                key = ref.value if len(ref.value) < 200 else ref.value[:200]
                if (key, ref.caller_class) in seen_vals:
                    continue
                seen_vals.add((key, ref.caller_class))  # type: ignore[arg-type]
                matched.append((ref, m.group(0)))
        if len({m for _, m in matched}) < rule.min_hits:
            continue
        matched.sort(key=lambda rm: (is_library_class(rm[0].caller_class or ""), rm[0].caller_class or "~", rm[0].offset or 0))
        app = [rm for rm in matched if not (rm[0].caller_class and is_library_class(rm[0].caller_class))]
        conf = _permission_confidence(rule.permissions, held)
        hit = Hit(rule.id, total_sites=len(matched), library_only=not app)
        hit.classes = {outer_class(r.caller_class) for r, _ in app if r.caller_class}
        if hit.library_only:
            conf = Confidence.LOW
            hit.note = "string constants only referenced from third-party library code"
        hit.confidence = conf
        for ref, token in matched[: rule.max_evidence]:
            ev = store.add(
                kind=EvidenceKind.STRING, rule_id=rule.id, source_file=ref.dex_file, extraction_method=STRINGS,
                class_name=ref.caller_class, method_name=ref.caller_method, bytecode_offset=ref.offset,
                artifact=token[:200], snippet=backend.string_snippet(ref, radius), confidence=conf,
                limitations=STRING_LIMIT,
            )
            if ev:
                hit.evidence_ids.append(ev.id)
        hits[rule.id] = hit
    return hits


def run_target_app_enum(package_refs_by_class: dict[str, set[str]], store: EvidenceStore) -> dict[str, Hit]:
    hits: dict[str, Hit] = {}
    for cls, refs in sorted(package_refs_by_class.items()):
        if len(refs) >= 10 and not is_library_class(cls):
            hit = hits.setdefault("STR-TARGET-APP-ENUM", Hit("STR-TARGET-APP-ENUM", confidence=Confidence.MEDIUM))
            hit.classes.add(cls)
            hit.total_sites += 1
            ev = store.add(
                kind=EvidenceKind.STRING, rule_id="STR-TARGET-APP-ENUM", source_file="classes.dex",
                extraction_method=STRINGS, class_name=cls,
                artifact=f"{len(refs)} distinct package ids",
                snippet="\n".join(sorted(refs)[:25]), confidence=Confidence.MEDIUM,
                limitations="Package-name constants in a single class; purpose (target list vs. UI data) is inferred.",
            )
            if ev:
                hit.evidence_ids.append(ev.id)
    return hits


def endpoint_hit(endpoint_classes: dict[str, set[str]], indicator_evidence: dict[str, list[str]]) -> Hit | None:
    if not endpoint_classes:
        return None
    hit = Hit("IND-ENDPOINT")
    for iid, classes in endpoint_classes.items():
        hit.classes |= classes
        hit.evidence_ids += indicator_evidence.get(iid, [])
        hit.total_sites += 1
    return hit


# ------------------------------------------------------------------------------ composites
@dataclass
class CompositeResult:
    rule: cat.CompositeRule
    class_level: bool
    severity: Severity
    confidence: Confidence
    components: list[str]
    evidence_ids: list[str]


def run_composites(hits: dict[str, Hit]) -> list[CompositeResult]:
    out: list[CompositeResult] = []
    for rule in cat.COMPOSITE_RULES:
        groups: list[list[Hit]] = []
        ok = True
        for req in rule.requires:
            present = [hits[r] for r in req.rule_ids if r in hits and not hits[r].library_only]
            if not present:
                ok = False
                break
            groups.append(present)
        if not ok:
            continue
        class_sets = [set().union(*(h.classes for h in g)) for g in groups]
        common = set.intersection(*class_sets) if class_sets else set()
        class_level = bool(common)
        if not class_level and rule.class_scope_only:
            continue
        if class_level:
            severity, conf = rule.severity, Confidence.HIGH
        else:
            severity = rule.app_scope_severity or rule.severity
            conf = Confidence.MEDIUM
        components = sorted({h.rule_id for g in groups for h in g})
        # If any contributing observation is itself low-confidence, so is the composite.
        if any(h.confidence == Confidence.LOW for g in groups for h in g):
            conf = _lower(conf)
        ev: list[str] = []
        for g in groups:
            for h in g:
                preferred = [e for e in h.evidence_ids]
                ev.extend(e for e in preferred[:4] if e not in ev)
        out.append(CompositeResult(rule, class_level, severity, conf, components, ev[:16]))
    return out


# ------------------------------------------------------------------------------ findings
def _desc(meta: RuleMeta, hit: Hit) -> str:
    base = meta.description
    where = f" Observed at {hit.total_sites} location(s)"
    if hit.classes:
        where += f" in {len(hit.classes)} app class(es)"
    where += "."
    if hit.note:
        where += f" Note: {hit.note}."
    return base + where


def build_findings(
    hits: dict[str, Hit], composites: list[CompositeResult],
) -> list[Finding]:
    metas = all_rule_meta()
    findings: list[Finding] = []
    comp_rule_ids = {c.rule.id for c in composites}
    sms_composites = {"COMP-SMS-FORWARDING", "COMP-SMS-EXFIL-HARDCODED", "COMP-SMS-SUPPRESSION"}

    # --- deterministic false-positive context: official OTP retrieval API with no abuse markers ---
    otp_context = (
        "API-SMS-RETRIEVER" in hits and not hits["API-SMS-RETRIEVER"].library_only
        and not (comp_rule_ids & sms_composites)
        and not {"API-SMS-SEND", "MAN-SMS-PRIORITY", "API-SMS-ABORT"} & set(hits)
    )
    sms_read_rules = {"API-SMS-READ", "STR-SMS-PROVIDER", "MAN-SMS-PERMISSIONS"}

    for rid, hit in sorted(hits.items()):
        meta = metas.get(rid)
        if meta is None or not hit.evidence_ids:
            continue
        severity, suppressed = meta.severity, []
        limitations = (
            "Declared in the manifest; use is not confirmed." if rid.startswith("MAN-")
            else STRING_LIMIT if rid.startswith("STR-") else BYTECODE_LIMIT
        )
        if otp_context and rid in sms_read_rules and severity > Severity.LOW:
            severity, suppressed = Severity.LOW, ["CTX-SMS-RETRIEVER"]
        findings.append(Finding(
            id=f"F-{rid}", rule_id=rid, title=meta.title, description=_desc(meta, hit), kind=meta.kind,
            severity=severity, confidence=hit.confidence, category=meta.category,
            evidence_ids=hit.evidence_ids, mitre_ids=list(meta.mitre), masvs=list(meta.masvs),
            false_positive_notes=meta.fp_notes, suppressed_by=suppressed, limitations=limitations,
        ))
        if suppressed:
            findings[-1].description += (
                " Downgraded: the app also uses Google's SMS Retriever/User-Consent API and shows no "
                "SMS sending, suppression or hard-coded-endpoint forwarding, which fits OTP auto-fill."
            )
    for comp in composites:
        meta = metas[comp.rule.id]
        scope = "within the same class" if comp.class_level else "app-wide (not confirmed to be the same code path)"
        findings.append(Finding(
            id=f"F-{comp.rule.id}", rule_id=comp.rule.id, title=meta.title,
            description=f"{meta.description} Correlation scope: {scope}. Built from: {', '.join(comp.components)}.",
            kind=FindingKind.MALICIOUS_BEHAVIOR, severity=comp.severity, confidence=comp.confidence,
            category=meta.category, evidence_ids=comp.evidence_ids, mitre_ids=list(meta.mitre),
            masvs=list(meta.masvs), composite_of=comp.components, false_positive_notes=meta.fp_notes,
            limitations="Behavioural correlation of static signals; no execution was performed.",
        ))
    findings.sort(key=lambda f: (-f.severity.rank, f.id))
    return findings
