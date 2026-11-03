"""Forensic PDF report renderer (ReportLab).

Deterministic findings and AI interpretation are rendered in separate, labelled sections. The report
is traceable to its job id, rule-set version, engine version and risk-input digest. It makes no
chain-of-custody claim: it documents an automated analysis, nothing more.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from malintx.config import Settings
from malintx.schemas.analysis import Evidence, Finding
from malintx.schemas.common import Classification, FindingKind, Severity
from malintx.schemas.results import AnalysisResult

NAVY, SLATE, CYAN = colors.HexColor("#0f1b2d"), colors.HexColor("#475569"), colors.HexColor("#0e7490")
CLASS_COLOR = {
    Classification.INFORMATIONAL: "#475569", Classification.LOW: "#0e7490", Classification.MEDIUM: "#b45309",
    Classification.HIGH: "#c2410c", Classification.CRITICAL: "#b91c1c", Classification.INCONCLUSIVE: "#6d28d9",
    Classification.INSUFFICIENT_EVIDENCE: "#6d28d9", Classification.ANALYSIS_FAILED: "#b91c1c",
}
SEV_COLOR = {Severity.INFO: "#64748b", Severity.LOW: "#0e7490", Severity.MEDIUM: "#b45309",
             Severity.HIGH: "#c2410c", Severity.CRITICAL: "#b91c1c"}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    s = {
        "title": ParagraphStyle("t", parent=base["Title"], textColor=NAVY, fontSize=22, alignment=TA_LEFT, spaceAfter=2),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], textColor=NAVY, fontSize=14, spaceBefore=14, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], textColor=CYAN, fontSize=10.5, spaceBefore=8, spaceAfter=3),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontSize=9, leading=12.5),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontSize=7.5, leading=10, textColor=SLATE),
        "cell": ParagraphStyle("c", parent=base["BodyText"], fontSize=7.8, leading=10),
        "mono": ParagraphStyle("m", parent=base["Code"], fontName="Courier", fontSize=6.6, leading=8, backColor=colors.HexColor("#f1f5f9"),
                               borderPadding=3, leftIndent=2),
        "note": ParagraphStyle("n", parent=base["BodyText"], fontSize=8.5, leading=12, backColor=colors.HexColor("#ecfeff"),
                               borderPadding=5, textColor=colors.HexColor("#134e4a")),
        "warn": ParagraphStyle("w", parent=base["BodyText"], fontSize=8.5, leading=12, backColor=colors.HexColor("#fff7ed"),
                               borderPadding=5, textColor=colors.HexColor("#7c2d12")),
    }
    return s


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "—")), style)


def _table(rows: list[list[Any]], widths: list[float], st: dict[str, ParagraphStyle], header: bool = True) -> Table:
    data: list[list[Paragraph]] = []
    for ri, row in enumerate(rows):
        cells: list[Paragraph] = []
        for c in row:
            if isinstance(c, Paragraph):
                cells.append(c)
            elif header and ri == 0:
                cells.append(Paragraph(f"<font color='white'><b>{escape(str(c))}</b></font>", st["cell"]))
            else:
                cells.append(_p(c, st["cell"]))
        data.append(cells)
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
             ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    t.setStyle(TableStyle(style))
    return t


def _code(text: str, st: dict[str, ParagraphStyle], max_lines: int = 40) -> Preformatted:
    lines = [ln[:118] for ln in (text or "").splitlines()][:max_lines]
    return Preformatted("\n".join(lines), st["mono"])


def _badge(text: str, color: str, st: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(f"<font color='{color}'><b>{escape(text)}</b></font>", st["cell"])


def _footer(job_id: str):
    def draw(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(SLATE)
        canvas.drawString(15 * mm, 9 * mm, f"MALINT-X analysis report · job {job_id} · automated static analysis; not a chain-of-custody record")
        canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    return draw


def render_report(result: AnalysisResult, settings: Settings | None = None) -> bytes:
    st = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=16 * mm,
                            title=f"MALINT-X report {result.job.id}", author="MALINT-X", subject="Android static analysis report")
    W = A4[0] - 30 * mm
    story: list[Any] = []
    static, risk, intel, ai = result.static, result.risk, result.intel, result.ai
    evmap = static.evidence_by_id() if static else {}

    # ---- header / executive summary ---------------------------------------------------------
    story += [_p("MALINT-X", st["title"]), _p("Android malware analysis report", st["body"]), Spacer(1, 6)]
    story.append(_table([
        ["Job", result.job.id, "Generated (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")],
        ["Platform", f"MALINT-X {result.platform_version}", "Schema", result.schema_version],
        ["Rule set", risk.ruleset_version if risk else "—", "Risk engine", risk.engine_version if risk else "—"],
    ], [22 * mm, W / 2 - 22 * mm, 28 * mm, W / 2 - 28 * mm], st, header=False))
    story.append(_p("Executive summary", st["h1"]))
    if risk:
        score = f"{risk.score}/100" if risk.score is not None else "n/a"
        story.append(Paragraph(f"<font size=16 color='{CLASS_COLOR[risk.classification]}'><b>{risk.classification.value.replace('_', ' ').upper()}</b></font>"
                               f"&nbsp;&nbsp;<font size=10>evidence-based score {escape(score)}</font>", st["body"]))
        story += [Spacer(1, 4), _p(risk.summary, st["body"])]
        if risk.classification in (Classification.INFORMATIONAL, Classification.LOW):
            story += [Spacer(1, 3), _p("A low or informational result means no malicious pattern was found by this rule set. It is not a certification that the application is safe.", st["note"])]
        if risk.classification in (Classification.INCONCLUSIVE, Classification.INSUFFICIENT_EVIDENCE, Classification.ANALYSIS_FAILED):
            story += [Spacer(1, 3), _p("No benign or malicious verdict is asserted for this sample.", st["warn"])]
    if result.job.error_message:
        story += [Spacer(1, 3), _p(f"Job failure: [{result.job.error_code}] {result.job.error_message}", st["warn"])]
    if static:
        top = [f for f in static.findings if f.kind in (FindingKind.MALICIOUS_BEHAVIOR, FindingKind.SUSPICIOUS_CAPABILITY)][:6]
        if top:
            story.append(_p("Key findings", st["h2"]))
            story.append(_table([["Severity", "Finding", "Kind", "Confidence", "Evidence"]] + [
                [_badge(f.severity.value.upper(), SEV_COLOR[f.severity], st), f.title, f.kind.value.replace("_", " "),
                 f.confidence.value, ", ".join(f.evidence_ids[:3])] for f in top],
                [18 * mm, 62 * mm, 32 * mm, 20 * mm, W - 132 * mm], st))

    if not static:
        doc.build(story, onFirstPage=_footer(result.job.id), onLaterPages=_footer(result.job.id))
        return buf.getvalue()

    # ---- sample ---------------------------------------------------------------------------------
    sm = static.sample
    story.append(_p("1. Sample metadata", st["h1"]))
    story.append(_table([
        ["SHA-256", sm.sha256], ["SHA-1", sm.sha1], ["MD5", sm.md5], ["Size", f"{sm.size_bytes:,} bytes"],
        ["Original filename (untrusted)", sm.display_name], ["Package", sm.package_name or "—"],
        ["Application label", sm.app_label or "—"], ["Version", f"{sm.version_name or '—'} (code {sm.version_code or '—'})"],
        ["SDK (min / target)", f"{sm.min_sdk or '—'} / {sm.target_sdk or '—'}"], ["Registered", sm.first_seen],
        ["Signing schemes", ", ".join(sm.signing_schemes) or "none detected (unsigned or unreadable)"],
    ], [42 * mm, W - 42 * mm], st, header=False))
    for c in sm.certificates:
        story.append(_p("Signing certificate", st["h2"]))
        story.append(_table([["Subject", c.subject], ["Issuer", c.issuer], ["Self-signed", str(c.self_signed)],
                             ["Validity", f"{c.not_before} → {c.not_after}"], ["SHA-256", c.sha256], ["Algorithm", c.signature_algorithm]],
                            [30 * mm, W - 30 * mm], st, header=False))
    if sm.archive:
        a = sm.archive
        story.append(_p("Archive inspection", st["h2"]))
        story.append(_table([["Entries", a.entry_count], ["DEX files", ", ".join(a.dex_files) or "none"],
                             ["Native ABIs", ", ".join(a.native_abis) or "none"], ["Assets", a.asset_count],
                             ["Max compression ratio", a.max_compression_ratio],
                             ["Entry timestamps", f"{a.earliest_entry_time} … {a.latest_entry_time}"],
                             ["Structural anomalies", "; ".join(a.suspicious_entries) or "none"]],
                            [42 * mm, W - 42 * mm], st, header=False))

    cov = static.coverage
    story.append(_p("2. Analysis environment, coverage and limitations", st["h1"]))
    story.append(_table([["Engine", f"{cov.backend} {cov.backend_version} (source scan: {cov.source_scan})"],
                         ["DEX parsed / failed", f"{cov.dex_files_parsed} / {len(cov.dex_files_failed)}"],
                         ["Classes / methods / strings", f"{cov.classes:,} / {cov.methods:,} / {cov.strings:,}"],
                         ["Packer hints", ", ".join(cov.packer_hints) or "none"],
                         ["Obfuscation ratio", cov.obfuscation_ratio if cov.obfuscation_ratio is not None else "n/a"],
                         ["Analysis duration", f"{cov.duration_s}s"],
                         ["Job created / updated", f"{result.job.created_at} / {result.job.updated_at}"]],
                        [42 * mm, W - 42 * mm], st, header=False))
    story += [Spacer(1, 3)] + [_p("• " + x, st["small"]) for x in cov.limitations + static.warnings]

    # ---- manifest -------------------------------------------------------------------------------
    m = static.manifest
    story.append(_p("3. Manifest findings", st["h1"]))
    sens = [p for p in m.permissions if p.sensitivity != "normal"]
    story.append(_p(f"{len(m.permissions)} permissions requested; {len(sens)} dangerous or special-access.", st["body"]))
    if sens:
        story.append(_table([["Permission", "Class"]] + [[p.name, p.sensitivity] for p in sens], [W - 30 * mm, 30 * mm], st))
    exported = [c for c in m.components if c.exported and not c.permission]
    story.append(_p("Components", st["h2"]))
    story.append(_p(f"{len(m.components)} components; {len(exported)} exported without a guarding permission. "
                    f"Accessibility services: {', '.join(m.accessibility_services) or 'none'}. Device-admin receivers: {', '.join(m.device_admin_receivers) or 'none'}.", st["body"]))
    man_findings = [f for f in static.findings if f.rule_id.startswith("MAN-") and f.kind != FindingKind.SECURITY_MISCONFIGURATION]
    if man_findings:
        story.append(_table([["Severity", "Manifest finding", "Evidence"]] + [
            [_badge(f.severity.value.upper(), SEV_COLOR[f.severity], st), f.title, ", ".join(f.evidence_ids[:4])] for f in man_findings],
            [18 * mm, W - 68 * mm, 50 * mm], st))

    # ---- behaviours -----------------------------------------------------------------------------
    story.append(_p("4. Behavioural findings (deterministic)", st["h1"]))
    story.append(_p("Malicious-behaviour findings are correlations of several signals. Capability findings show that an API or "
                    "permission exists and carry reduced weight. Misconfigurations are reported separately (section 9).", st["small"]))
    beh = [f for f in static.findings if f.kind in (FindingKind.MALICIOUS_BEHAVIOR, FindingKind.SUSPICIOUS_CAPABILITY)]
    for f in beh:
        story.append(KeepTogether(_finding_block(f, evmap, st, W)))
    if not beh:
        story.append(_p("No behavioural findings were produced by the rule set.", st["body"]))

    # ---- evidence ---------------------------------------------------------------------------------
    story.append(_p("5. Code and artifact evidence", st["h1"]))
    shown = 0
    for f in beh:
        if f.severity < Severity.MEDIUM:
            continue
        for eid in f.evidence_ids[:2]:
            e = evmap.get(eid)
            if e and e.snippet and shown < 24:
                shown += 1
                story.append(KeepTogether([_p(f"{e.id} · {f.title}", st["h2"]), _p(_ev_meta(e), st["small"]), _code(e.snippet, st)]))
    if not shown:
        story.append(_p("No medium-or-higher findings with code excerpts.", st["body"]))

    story.append(_p("6. Extracted indicators", st["h1"]))
    if static.indicators:
        story.append(_table([["Type", "Value", "Seen", "Note"]] + [[i.type.value, i.value[:90], i.occurrences, i.note or ""] for i in static.indicators[:80]],
                            [20 * mm, W - 90 * mm, 12 * mm, 58 * mm], st))
    else:
        story.append(_p("No network, e-mail or path indicators were extracted.", st["body"]))

    # ---- intel ----------------------------------------------------------------------------------------
    story.append(_p("7. Threat intelligence", st["h1"]))
    if not intel or not intel.requested:
        story.append(_p("Not requested for this analysis. Indicators are UNKNOWN, not safe.", st["note"]))
    else:
        story.append(_p("Providers: " + ", ".join(f"{k}={v.value}" for k, v in intel.providers.items()), st["body"]))
        story.append(_p(f"Sample hash verdict: {intel.sample_verdict.value}", st["body"]))
        for lk in intel.sample_lookups:
            story.append(_p(f"• {lk.provider}: {lk.status.value} — {lk.detail or ''}", st["small"]))
        if intel.indicators:
            story.append(_table([["Indicator", "Verdict", "Detail"]] + [
                [i.value[:70], i.verdict.value, "; ".join(f"{lk.provider}:{lk.status.value}" + (f" ({lk.as_owner}, {lk.country})" if lk.as_owner else "") for lk in i.lookups)]
                for i in intel.indicators], [70 * mm, 28 * mm, W - 98 * mm], st))
        story += [_p("• " + n, st["small"]) for n in intel.notes]
        story.append(_p("Unknown means no provider returned data. It must never be read as safe.", st["note"]))

    story.append(_p("8. MITRE ATT&CK for Mobile mapping", st["h1"]))
    if static.mitre:
        story.append(_table([["Technique", "Tactic(s)", "Conf.", "Evidence", "Rationale"]] + [
            [f"{t.technique_id} {t.technique_name}", ", ".join(t.tactics), t.confidence.value, ", ".join(t.evidence_ids[:3]), t.rationale[:230]]
            for t in static.mitre], [34 * mm, 24 * mm, 14 * mm, 30 * mm, W - 102 * mm], st))
        story.append(_p(f"Source: {static.mitre[0].source}. Mappings are deterministic rule outputs, not AI inferences.", st["small"]))
    else:
        story.append(_p("No ATT&CK techniques were mapped.", st["body"]))

    story.append(_p("9. Security posture (OWASP MASVS) — separate from malice", st["h1"]))
    mis = [f for f in static.findings if f.kind == FindingKind.SECURITY_MISCONFIGURATION]
    if mis:
        story.append(_table([["Severity", "Issue", "MASVS", "Evidence"]] + [
            [_badge(f.severity.value.upper(), SEV_COLOR[f.severity], st), f.title, ", ".join(f.masvs), ", ".join(f.evidence_ids[:2])] for f in mis],
            [18 * mm, W - 78 * mm, 38 * mm, 22 * mm], st))
        story.append(_p("These are hardening issues. A vulnerable application is not automatically malware and none of these items add to the risk score.", st["small"]))
    else:
        story.append(_p("No posture issues detected by the implemented checks.", st["body"]))

    # ---- scoring ----------------------------------------------------------------------------------------
    story.append(_p("10. Risk score and methodology", st["h1"]))
    if risk:
        story.append(_p("Deterministic, reproducible calculation from validated findings and threat-intel verdicts. AI output is not an input.", st["body"]))
        story.append(_table([["Source", "Group", "Base", "Mult.", "Applied", "Note"]] + [
            [c.label[:46], c.category, f"{c.base_points:g}", f"{c.multiplier:g}", f"{c.applied_points:g}", c.note[:120]] for c in risk.contributions],
            [46 * mm, 22 * mm, 11 * mm, 11 * mm, 14 * mm, W - 104 * mm], st))
        for text in risk.adjustments + risk.floors_applied + risk.suppressions:
            story.append(_p("• " + text, st["small"]))
        story.append(_p("Method: points = severity {low 2, medium 6, high 12, critical 20} × kind weight (behaviour 1.0, capability 0.6) × confidence {high 1.0, medium 0.7, low 0.4}; "
                        "diminishing returns inside a behaviour group (1, 0.5, 0.25…, group cap 24); capabilities already part of a composite count half; threat-intel corroboration "
                        "adds points only when a provider returned data. Bands: <10 informational, <30 low, <55 medium, <80 high, ≥80 critical. "
                        f"Inputs digest: {risk.inputs_digest}", st["small"]))
        story.append(_p("Confidence and limitations", st["h2"]))
        story += [_p("• " + x, st["small"]) for x in risk.limitations]

    story.append(_p("11. Recommendations", st["h1"]))
    if risk:
        story += [_p("• " + r, st["body"]) for r in risk.recommendations]

    # ---- AI ----------------------------------------------------------------------------------------------
    story.append(PageBreak())
    story.append(_p("12. AI-assisted interpretation (advisory, not deterministic)", st["h1"]))
    if not ai or ai.status == "not_requested":
        story.append(_p("AI interpretation was not requested. No evidence was sent to an AI provider.", st["note"]))
    elif ai.status != "completed" or not ai.assessment:
        story.append(_p(f"AI interpretation status: {ai.status}. {ai.error or ''} Deterministic results above are unaffected.", st["warn"]))
    else:
        story.append(_p(f"Provider {ai.provider} / model {ai.model}. Generated text — verify against the cited evidence. The AI did not influence the score or classification.", st["note"]))
        a = ai.assessment
        story += [Spacer(1, 3), _p(f"Overall: {a.overall.replace('_', ' ')}", st["h2"]), _p(a.summary, st["body"])]
        for c in a.claims:
            story.append(KeepTogether([_p(f"{c.title} — {c.assessment.replace('_', ' ')} ({c.confidence.value} confidence)", st["h2"]),
                                       _p(c.explanation, st["body"]), _p(f"Cited evidence: {', '.join(c.evidence_ids)}"
                                                                         + (f" · ATT&CK: {', '.join(c.mitre_ids)}" if c.mitre_ids else ""), st["small"]),
                                       _p(f"Uncertainty: {c.uncertainty or 'not stated'}", st["small"])]))
        if ai.dropped_claims:
            story.append(_p("Discarded by validation (not grounded in evidence):", st["h2"]))
            story += [_p("• " + d, st["small"]) for d in ai.dropped_claims]
        story += [_p("• " + x, st["small"]) for x in a.limitations]

    story.append(_p("13. Traceability", st["h1"]))
    story.append(_table([["Job id", result.job.id], ["Sample SHA-256", sm.sha256], ["Rule set / engine", f"{static.ruleset_version} / {risk.engine_version if risk else '—'}"],
                         ["Risk-input digest", risk.inputs_digest if risk else "—"], ["MITRE dataset", static.mitre[0].source if static.mitre else "MITRE ATT&CK for Mobile (vendored)"]],
                        [36 * mm, W - 36 * mm], st, header=False))
    story.append(_p("This document was produced automatically. It records what the platform observed and how it scored it, and can be reproduced from the "
                    "stored sample and job. It is not a legally validated chain-of-custody record.", st["small"]))
    doc.build(story, onFirstPage=_footer(result.job.id), onLaterPages=_footer(result.job.id))
    return buf.getvalue()


def _ev_meta(e: Evidence) -> str:
    bits = [e.kind.value, e.source_file]
    if e.class_name:
        bits.append(f"{e.class_name}->{e.method_name or ''}")
    if e.api:
        bits.append(e.api)
    if e.bytecode_offset is not None:
        bits.append(f"offset 0x{e.bytecode_offset:x}")
    if e.line_number:
        bits.append(f"line {e.line_number}")
    bits.append(f"via {e.extraction_method}")
    return " · ".join(bits)


def _finding_block(f: Finding, evmap: dict[str, Evidence], st: dict[str, ParagraphStyle], W: float) -> list[Any]:
    out: list[Any] = [Paragraph(f"<font color='{SEV_COLOR[f.severity]}'><b>[{f.severity.value.upper()}]</b></font> <b>{escape(f.title)}</b> "
                                f"<font size=7 color='#475569'>{f.id} · {f.kind.value.replace('_', ' ')} · {f.confidence.value} confidence</font>", st["body"]),
                      _p(f.description, st["small"])]
    if f.false_positive_notes:
        out.append(_p("Legitimate-use context: " + f.false_positive_notes, st["small"]))
    if f.suppressed_by:
        out.append(_p("Deterministic context adjustment applied: " + ", ".join(f.suppressed_by), st["small"]))
    if f.mitre_ids:
        out.append(_p("ATT&CK: " + ", ".join(f.mitre_ids), st["small"]))
    out.append(_p("Evidence: " + ", ".join(f.evidence_ids[:8]) + (f" (+{len(f.evidence_ids) - 8} more)" if len(f.evidence_ids) > 8 else ""), st["small"]))
    out.append(Spacer(1, 4))
    return out
