"""
MALINT-X PDF Report Generator.

Produces a professional forensic-grade PDF report for a completed APK
analysis using ReportLab.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from malintx.config import DANGEROUS_PERMISSIONS, REPORTS_DIR
from malintx.core.models import AnalysisResult, EnrichedIoC

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
_HEADER_BG = colors.HexColor("#1a237e")
_HEADER_FG = colors.white
_TABLE_HEADER_BG = colors.HexColor("#283593")
_TABLE_HEADER_FG = colors.white
_TABLE_STRIPE = colors.HexColor("#e8eaf6")
_RED_TEXT = colors.HexColor("#c62828")
_GREEN_TEXT = colors.HexColor("#2e7d32")
_ORANGE_TEXT = colors.HexColor("#e65100")
_BODY_TEXT = colors.HexColor("#212121")

# ---------------------------------------------------------------------------
# Page dimensions
# ---------------------------------------------------------------------------
_PAGE_W, _PAGE_H = A4
_MARGIN = 0.65 * inch

# Max characters of code shown in appendix per slice
_MAX_CODE_CHARS = 2000


class PDFReportGenerator:
    """Generates a professional forensic PDF report from an :class:`AnalysisResult`."""

    def __init__(self) -> None:
        self._styles = getSampleStyleSheet()
        self._register_custom_styles()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(self, result: AnalysisResult) -> Path:
        """Generate a PDF report and return the file path.

        Parameters
        ----------
        result:
            A completed :class:`AnalysisResult` from the pipeline.

        Returns
        -------
        Path
            Absolute path to the generated ``.pdf`` file.
        """
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = REPORTS_DIR / f"{result.analysis_id}_report.pdf"

        doc = SimpleDocTemplate(
            str(out_path),
            pagesize=A4,
            leftMargin=_MARGIN,
            rightMargin=_MARGIN,
            topMargin=_MARGIN + 0.3 * inch,  # leave room for header
            bottomMargin=_MARGIN + 0.3 * inch,  # leave room for footer
            title="MALINT-X Forensic Analysis Report",
            author="MALINT-X",
        )

        story: list[Any] = []
        self._add_header_section(story, result)
        self._add_executive_summary(story, result)
        self._add_permission_analysis(story, result)
        self._add_mitre_techniques(story, result)
        self._add_iocs(story, result)
        self._add_score_breakdown(story, result)
        self._add_appendix(story, result)

        doc.build(
            story,
            onFirstPage=self._draw_page_chrome,
            onLaterPages=self._draw_page_chrome,
        )

        logger.info("PDF report written to %s", out_path)
        return out_path

    # ------------------------------------------------------------------
    # Custom styles
    # ------------------------------------------------------------------
    def _register_custom_styles(self) -> None:
        """Register additional paragraph styles."""
        self._styles.add(
            ParagraphStyle(
                "SectionTitle",
                parent=self._styles["Heading2"],
                textColor=_HEADER_BG,
                spaceAfter=6,
                spaceBefore=18,
                fontSize=14,
                leading=18,
            )
        )
        self._styles.add(
            ParagraphStyle(
                "BodyCustom",
                parent=self._styles["Normal"],
                textColor=_BODY_TEXT,
                fontSize=9,
                leading=13,
                spaceAfter=4,
            )
        )
        self._styles.add(
            ParagraphStyle(
                "Code",
                parent=self._styles["Normal"],
                fontName="Courier",
                fontSize=7,
                leading=9,
                textColor=_BODY_TEXT,
                backColor=colors.HexColor("#f5f5f5"),
                borderPadding=4,
                spaceAfter=4,
            )
        )
        self._styles.add(
            ParagraphStyle(
                "CenterBig",
                parent=self._styles["Normal"],
                alignment=TA_CENTER,
                fontSize=32,
                leading=38,
                spaceAfter=4,
            )
        )
        self._styles.add(
            ParagraphStyle(
                "CenterLabel",
                parent=self._styles["Normal"],
                alignment=TA_CENTER,
                fontSize=14,
                leading=18,
                spaceAfter=8,
            )
        )

    # ------------------------------------------------------------------
    # Page header / footer
    # ------------------------------------------------------------------
    def _draw_page_chrome(self, canvas: Any, doc: Any) -> None:
        """Draw header and footer on every page."""
        canvas.saveState()

        # --- Header bar ---
        canvas.setFillColor(_HEADER_BG)
        canvas.rect(0, _PAGE_H - 0.5 * inch, _PAGE_W, 0.5 * inch, fill=True, stroke=0)
        canvas.setFillColor(_HEADER_FG)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(_MARGIN, _PAGE_H - 0.33 * inch, "MALINT-X  ·  Forensic Analysis Report")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(
            _PAGE_W - _MARGIN,
            _PAGE_H - 0.33 * inch,
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

        # --- Footer ---
        canvas.setFillColor(_BODY_TEXT)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(
            _MARGIN,
            0.4 * inch,
            "Generated by MALINT-X — Automated Android APK Static Analysis Triage Pipeline",
        )
        canvas.drawRightString(
            _PAGE_W - _MARGIN,
            0.4 * inch,
            f"Page {canvas.getPageNumber()}",
        )

        canvas.restoreState()

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------
    def _section(self, story: list[Any], title: str) -> None:
        """Insert a section heading with a separator line."""
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1, color=_HEADER_BG, spaceAfter=4))
        story.append(Paragraph(title, self._styles["SectionTitle"]))

    def _add_header_section(self, story: list[Any], result: AnalysisResult) -> None:
        """Section 1 — Title & APK metadata."""
        story.append(Spacer(1, 6))
        story.append(
            Paragraph(
                "MALINT-X Forensic Analysis Report",
                ParagraphStyle(
                    "_title",
                    parent=self._styles["Title"],
                    textColor=_HEADER_BG,
                    fontSize=22,
                    spaceAfter=4,
                ),
            )
        )
        ts = result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        story.append(
            Paragraph(f"Scan timestamp: {ts}", self._styles["BodyCustom"])
        )
        story.append(Spacer(1, 6))

        meta = result.apk_metadata
        size_kb = meta.file_size_bytes / 1024
        size_label = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb / 1024:.2f} MB"
        rows = [
            ["Property", "Value"],
            ["APK Name", meta.file_name],
            ["SHA-256", meta.sha256],
            ["MD5", meta.md5],
            ["Size", size_label],
            ["Analysis ID", result.analysis_id],
        ]
        story.append(self._styled_table(rows, col_widths=[1.6 * inch, 5 * inch]))

    def _add_executive_summary(self, story: list[Any], result: AnalysisResult) -> None:
        """Section 2 — Risk score & overall assessment."""
        self._section(story, "Executive Summary")

        if result.risk_score is not None:
            score_color = colors.HexColor(result.risk_score.color)
            story.append(
                Paragraph(
                    f'<font color="{result.risk_score.color}" size="36">'
                    f"<b>{result.risk_score.score}</b></font>"
                    f'<font size="14"> / 100</font>',
                    self._styles["CenterBig"],
                )
            )
            story.append(
                Paragraph(
                    f'<font color="{result.risk_score.color}"><b>'
                    f"{result.risk_score.label}</b></font>",
                    self._styles["CenterLabel"],
                )
            )
        else:
            story.append(Paragraph("Score not available", self._styles["CenterLabel"]))

        if result.llm_verdict is not None:
            assessment = result.llm_verdict.overall_assessment.value.upper()
            story.append(
                Paragraph(
                    f"<b>Overall Assessment:</b> {assessment}",
                    self._styles["BodyCustom"],
                )
            )
            if result.llm_verdict.reasoning_summary:
                story.append(Spacer(1, 4))
                story.append(
                    Paragraph(
                        result.llm_verdict.reasoning_summary,
                        self._styles["BodyCustom"],
                    )
                )

    def _add_permission_analysis(self, story: list[Any], result: AnalysisResult) -> None:
        """Section 3 — Permission table with danger classification."""
        self._section(story, "Permission Analysis")

        perms = result.manifest_data.permissions
        if not perms:
            story.append(Paragraph("No permissions declared.", self._styles["BodyCustom"]))
            return

        rows: list[list[Any]] = [["Permission", "Risk Level", "Description"]]
        for perm in sorted(perms):
            entry = DANGEROUS_PERMISSIONS.get(perm)
            if entry:
                risk = entry["risk"]
                desc = entry["description"]
                risk_display = self._risk_colored(risk)
            else:
                risk_display = "benign"
                desc = "—"
            rows.append([self._truncate(perm, 50), risk_display, desc])

        story.append(
            self._styled_table(rows, col_widths=[2.8 * inch, 1 * inch, 2.8 * inch])
        )

    def _add_mitre_techniques(self, story: list[Any], result: AnalysisResult) -> None:
        """Section 4 — MITRE techniques table."""
        self._section(story, "Detected MITRE ATT&CK Techniques")

        if result.llm_verdict is None or not result.llm_verdict.detected_techniques:
            story.append(Paragraph("No techniques detected.", self._styles["BodyCustom"]))
            return

        rows: list[list[Any]] = [
            ["Technique ID", "Name", "Confidence", "Evidence", "Source File"]
        ]
        for tech in result.llm_verdict.detected_techniques:
            rows.append(
                [
                    tech.technique_id,
                    self._truncate(tech.technique_name, 30),
                    tech.confidence.value,
                    self._truncate(tech.evidence, 60),
                    self._truncate(tech.source_file or "—", 30),
                ]
            )

        story.append(
            self._styled_table(
                rows, col_widths=[0.9 * inch, 1.4 * inch, 0.8 * inch, 2.2 * inch, 1.3 * inch]
            )
        )

    def _add_iocs(self, story: list[Any], result: AnalysisResult) -> None:
        """Section 5 — IoC table with VT verdicts."""
        self._section(story, "Indicators of Compromise")

        enriched = result.enriched_iocs
        if not enriched:
            story.append(Paragraph("No IoCs extracted.", self._styles["BodyCustom"]))
            return

        rows: list[list[Any]] = [["IoC Value", "Type", "VT Verdict"]]
        for eioc in enriched:
            verdict = self._ioc_verdict_label(eioc)
            rows.append(
                [
                    self._truncate(eioc.ioc.value, 55),
                    eioc.ioc.ioc_type.value,
                    verdict,
                ]
            )

        story.append(
            self._styled_table(rows, col_widths=[3.5 * inch, 1 * inch, 2.1 * inch])
        )

    def _add_score_breakdown(self, story: list[Any], result: AnalysisResult) -> None:
        """Section 6 — Score breakdown table."""
        self._section(story, "Score Breakdown")

        if result.risk_score is None or not result.risk_score.breakdown:
            story.append(Paragraph("No breakdown available.", self._styles["BodyCustom"]))
            return

        rows: list[list[Any]] = [["Component", "Description", "Points"]]
        for entry in result.risk_score.breakdown:
            rows.append(
                [
                    entry.get("component", ""),
                    self._truncate(entry.get("description", ""), 80),
                    str(entry.get("points", 0)),
                ]
            )

        story.append(
            self._styled_table(rows, col_widths=[1.2 * inch, 4.4 * inch, 1 * inch])
        )

    def _add_appendix(self, story: list[Any], result: AnalysisResult) -> None:
        """Section 7 — Raw code slices (monospace, truncated)."""
        self._section(story, "Appendix — Raw Code Slices")

        slices = result.code_slices
        if not slices:
            story.append(Paragraph("No code slices captured.", self._styles["BodyCustom"]))
            return

        for idx, cs in enumerate(slices, 1):
            story.append(
                Paragraph(
                    f"<b>Slice {idx}</b> — {_xml_escape(cs.file_name)} "
                    f"(line {cs.line_number}, {cs.pattern_category})",
                    self._styles["BodyCustom"],
                )
            )
            code_text = cs.code_context[:_MAX_CODE_CHARS]
            if len(cs.code_context) > _MAX_CODE_CHARS:
                code_text += "\n… [truncated]"
            # Escape XML entities and preserve newlines
            safe = _xml_escape(code_text).replace("\n", "<br/>")
            story.append(Paragraph(safe, self._styles["Code"]))
            story.append(Spacer(1, 6))

    # ------------------------------------------------------------------
    # Table helper
    # ------------------------------------------------------------------
    def _styled_table(
        self,
        data: list[list[Any]],
        col_widths: list[float] | None = None,
    ) -> Table:
        """Build a consistently styled table from *data* (first row = header)."""
        # Wrap cell text in Paragraphs for word-wrap
        wrapped: list[list[Any]] = []
        for r_idx, row in enumerate(data):
            new_row: list[Any] = []
            for cell in row:
                style = self._styles["BodyCustom"] if r_idx > 0 else ParagraphStyle(
                    "_thdr",
                    parent=self._styles["BodyCustom"],
                    textColor=_TABLE_HEADER_FG,
                    fontName="Helvetica-Bold",
                    fontSize=8,
                )
                new_row.append(Paragraph(str(cell), style))
            wrapped.append(new_row)

        tbl = Table(wrapped, colWidths=col_widths, repeatRows=1)

        style_cmds: list[Any] = [
            ("BACKGROUND", (0, 0), (-1, 0), _TABLE_HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), _TABLE_HEADER_FG),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bdbdbd")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]

        # Alternate row stripes
        for i in range(1, len(data)):
            if i % 2 == 0:
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), _TABLE_STRIPE))

        tbl.setStyle(TableStyle(style_cmds))
        return tbl

    # ------------------------------------------------------------------
    # Tiny helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        """Truncate *text* with an ellipsis if it exceeds *max_len*."""
        if len(text) <= max_len:
            return text
        return text[: max_len - 1] + "…"

    @staticmethod
    def _risk_colored(risk: str) -> str:
        """Return a risk level string with color markup for Paragraph."""
        color_map = {
            "critical": "#c62828",
            "high": "#e65100",
            "medium": "#f57f17",
            "low": "#2e7d32",
        }
        clr = color_map.get(risk, "#212121")
        return f'<font color="{clr}"><b>{risk.upper()}</b></font>'

    @staticmethod
    def _ioc_verdict_label(eioc: EnrichedIoC) -> str:
        """Human-readable VT verdict label."""
        if not eioc.enriched or eioc.enrichment is None:
            return "unenriched"
        if eioc.enrichment.is_malicious:
            detections = eioc.enrichment.total_detections
            return f'<font color="#c62828"><b>MALICIOUS ({detections})</b></font>'
        return f'<font color="#2e7d32">clean</font>'


def _xml_escape(text: str) -> str:
    """Escape text for ReportLab Paragraph XML."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
