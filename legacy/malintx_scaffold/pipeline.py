"""
MALINT-X Analysis Pipeline.

End-to-end orchestrator that drives an APK through decompilation, extraction,
threat-intel enrichment, LLM reasoning, deterministic scoring, and PDF
report generation.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from malintx.config import REPORTS_DIR, settings
from malintx.core.models import (
    AnalysisPayload,
    AnalysisPhase,
    AnalysisProgress,
    AnalysisResult,
    APKMetadata,
    CodeSlice,
    DecompilationResult,
    EnrichedIoC,
    IoC,
    LLMVerdict,
    ManifestData,
    RiskScore,
)

logger = logging.getLogger(__name__)

# Phase metadata for progress reporting
_PHASES: list[tuple[AnalysisPhase, str]] = [
    (AnalysisPhase.UPLOAD, "Preparing APK metadata"),
    (AnalysisPhase.DECOMPILATION, "Decompiling APK"),
    (AnalysisPhase.EXTRACTION, "Extracting manifest, code slices, IoCs"),
    (AnalysisPhase.THREAT_INTEL, "Enriching IoCs with threat intelligence"),
    (AnalysisPhase.LLM_REASONING, "Running LLM reasoning engine"),
    (AnalysisPhase.SCORING, "Computing risk score"),
    (AnalysisPhase.REPORTING, "Generating PDF report"),
]


class AnalysisPipeline:
    """End-to-end orchestrator for MALINT-X APK analysis.

    Usage::

        pipeline = AnalysisPipeline()
        result = await pipeline.analyze(Path("sample.apk"))
    """

    def __init__(self) -> None:
        self._analysis_id: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def analyze(
        self,
        apk_path: Path,
        progress_callback: Optional[Callable[[AnalysisProgress], Any]] = None,
    ) -> AnalysisResult:
        """Run the full analysis pipeline on *apk_path*.

        Parameters
        ----------
        apk_path:
            Path to an ``.apk`` file on disk.
        progress_callback:
            Optional callable invoked with an :class:`AnalysisProgress` at
            every phase transition (useful for the Streamlit dashboard).

        Returns
        -------
        AnalysisResult
            Complete analysis output — even if individual phases fail the
            pipeline continues and records errors.
        """
        self._analysis_id = uuid.uuid4().hex[:16]
        start = time.monotonic()
        errors: list[str] = []

        # ----- placeholders that survive partial failures -----
        apk_meta: APKMetadata | None = None
        decomp_result = DecompilationResult(success=False, error_message="skipped")
        manifest_data = ManifestData()
        code_slices: list[CodeSlice] = []
        iocs: list[IoC] = []
        enriched_iocs: list[EnrichedIoC] = []
        llm_verdict: LLMVerdict | None = None
        risk_score: RiskScore | None = None
        report_path: str | None = None

        # =====================================================================
        # Phase 1 — Upload / APK Metadata
        # =====================================================================
        self._emit_progress(progress_callback, 0, AnalysisPhase.UPLOAD, "Reading APK metadata")
        try:
            apk_meta = APKMetadata.from_file(apk_path)
            logger.info("APK metadata: %s (%s)", apk_meta.file_name, apk_meta.sha256[:16])
        except Exception as exc:
            msg = f"Failed to read APK metadata: {exc}"
            logger.error(msg)
            errors.append(msg)
            # Cannot continue without metadata — build a minimal stub
            apk_meta = APKMetadata(
                file_name=apk_path.name,
                file_path=str(apk_path),
                file_size_bytes=0,
                sha256="unknown",
                md5="unknown",
            )

        # =====================================================================
        # Phase 2 — Decompilation
        # =====================================================================
        self._emit_progress(progress_callback, 1, AnalysisPhase.DECOMPILATION, "Decompiling APK")
        try:
            from malintx.extraction.decompiler import DecompilerWrapper

            decompiler = DecompilerWrapper()
            decomp_result = decompiler.decompile(apk_path)
            if not decomp_result.success:
                errors.append(f"Decompilation failed: {decomp_result.error_message}")
        except Exception as exc:
            msg = f"Decompilation error: {exc}"
            logger.error(msg)
            errors.append(msg)

        # =====================================================================
        # Phase 3 — Extraction (manifest, code slices, IoCs)
        # =====================================================================
        self._emit_progress(progress_callback, 2, AnalysisPhase.EXTRACTION, "Extracting artefacts")
        if decomp_result.success:
            # Manifest --------------------------------------------------------
            try:
                from malintx.extraction.manifest_parser import ManifestParser

                parser = ManifestParser()
                if decomp_result.manifest_path:
                    manifest_data = parser.parse(Path(decomp_result.manifest_path))
                    logger.info(
                        "Manifest: %s, %d permissions",
                        manifest_data.package_name,
                        len(manifest_data.permissions),
                    )
            except Exception as exc:
                msg = f"Manifest parsing error: {exc}"
                logger.error(msg)
                errors.append(msg)

            # Code slicing ----------------------------------------------------
            try:
                from malintx.extraction.code_slicer import CodeSlicer

                slicer = CodeSlicer()
                if decomp_result.source_root:
                    code_slices = slicer.slice(Path(decomp_result.source_root))
                    logger.info("Code slicer found %d slices", len(code_slices))
            except Exception as exc:
                msg = f"Code slicing error: {exc}"
                logger.error(msg)
                errors.append(msg)

            # IoC extraction --------------------------------------------------
            try:
                from malintx.extraction.ioc_extractor import IoCExtractor

                extractor = IoCExtractor()
                if decomp_result.source_root:
                    iocs = extractor.extract(Path(decomp_result.source_root))
                    logger.info("IoC extractor found %d IoCs", len(iocs))
            except Exception as exc:
                msg = f"IoC extraction error: {exc}"
                logger.error(msg)
                errors.append(msg)
        else:
            errors.append("Skipping extraction — decompilation was unsuccessful")

        # =====================================================================
        # Phase 4 — Threat Intel Enrichment
        # =====================================================================
        self._emit_progress(
            progress_callback, 3, AnalysisPhase.THREAT_INTEL, "Enriching IoCs via VirusTotal"
        )
        try:
            from malintx.inference.threat_intel import ThreatIntelClient

            ti_client = ThreatIntelClient()
            enriched_iocs = await ti_client.enrich_iocs(iocs)
            logger.info(
                "Enrichment complete: %d/%d IoCs enriched",
                sum(1 for e in enriched_iocs if e.enriched),
                len(enriched_iocs),
            )
        except Exception as exc:
            msg = f"Threat intel enrichment error: {exc}"
            logger.error(msg)
            errors.append(msg)
            # Graceful degradation — wrap raw IoCs as unenriched
            enriched_iocs = [
                EnrichedIoC(ioc=ioc, enriched=False) for ioc in iocs
            ]

        # =====================================================================
        # Phase 5 — LLM Reasoning
        # =====================================================================
        self._emit_progress(
            progress_callback, 4, AnalysisPhase.LLM_REASONING, "Running LLM analysis"
        )
        try:
            from malintx.inference.llm_client import LLMClient

            payload = AnalysisPayload(
                apk_metadata=apk_meta,
                manifest_data=manifest_data,
                code_slices=code_slices,
                iocs=iocs,
                enriched_iocs=enriched_iocs,
            )
            llm_client = LLMClient()
            llm_verdict = await llm_client.analyze(payload)
            logger.info(
                "LLM verdict: %s, %d techniques detected",
                llm_verdict.overall_assessment.value,
                len(llm_verdict.detected_techniques),
            )
        except Exception as exc:
            msg = f"LLM reasoning error: {exc}"
            logger.error(msg)
            errors.append(msg)

        # =====================================================================
        # Phase 6 — Scoring
        # =====================================================================
        self._emit_progress(progress_callback, 5, AnalysisPhase.SCORING, "Computing risk score")
        try:
            from malintx.core.scorer import RiskScorer

            scorer = RiskScorer()
            verdict_for_scoring = llm_verdict or LLMVerdict()
            risk_score = scorer.score(verdict_for_scoring, enriched_iocs, manifest_data)
            logger.info("Risk score: %d (%s)", risk_score.score, risk_score.label)
        except Exception as exc:
            msg = f"Scoring error: {exc}"
            logger.error(msg)
            errors.append(msg)

        # =====================================================================
        # Phase 7 — PDF Report Generation
        # =====================================================================
        self._emit_progress(
            progress_callback, 6, AnalysisPhase.REPORTING, "Generating PDF report"
        )
        analysis_result = AnalysisResult(
            analysis_id=self._analysis_id,
            apk_metadata=apk_meta,
            decompilation=decomp_result,
            manifest_data=manifest_data,
            code_slices=code_slices,
            iocs=iocs,
            enriched_iocs=enriched_iocs,
            llm_verdict=llm_verdict,
            risk_score=risk_score,
            duration_seconds=time.monotonic() - start,
            errors=errors,
            phase=AnalysisPhase.COMPLETE,
        )
        try:
            from malintx.reports.pdf_generator import PDFReportGenerator

            generator = PDFReportGenerator()
            pdf_path = generator.generate(analysis_result)
            report_path = str(pdf_path)
            analysis_result.report_path = report_path
            logger.info("PDF report saved to %s", report_path)
        except Exception as exc:
            msg = f"PDF report generation error: {exc}"
            logger.error(msg)
            errors.append(msg)
            analysis_result.errors = errors

        # Final timing
        analysis_result.duration_seconds = time.monotonic() - start

        # Emit completion
        self._emit_progress(
            progress_callback,
            7,
            AnalysisPhase.COMPLETE,
            f"Analysis complete in {analysis_result.duration_seconds:.1f}s",
        )

        logger.info(
            "Pipeline finished: %s — score=%s, duration=%.1fs, errors=%d",
            self._analysis_id,
            risk_score.score if risk_score else "N/A",
            analysis_result.duration_seconds,
            len(analysis_result.errors),
        )

        return analysis_result

    # ------------------------------------------------------------------
    # Progress helper
    # ------------------------------------------------------------------
    def _emit_progress(
        self,
        callback: Optional[Callable[[AnalysisProgress], Any]],
        phase_index: int,
        phase: AnalysisPhase,
        message: str,
    ) -> None:
        """Build and emit an :class:`AnalysisProgress` update."""
        total = len(_PHASES)
        pct = min(phase_index / total * 100, 100.0) if total else 0.0

        progress = AnalysisProgress(
            analysis_id=self._analysis_id,
            phase=phase,
            phase_index=phase_index,
            total_phases=total,
            message=message,
            percent_complete=pct,
        )

        logger.debug("Phase %d/%d [%s]: %s", phase_index, total, phase.value, message)

        if callback is not None:
            try:
                callback(progress)
            except Exception:
                logger.warning("Progress callback raised an exception", exc_info=True)
