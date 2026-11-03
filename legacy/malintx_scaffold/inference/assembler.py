"""
MALINT-X Payload Assembler.

Combines all extraction outputs (metadata, manifest, code slices, IoCs,
enriched IoCs) into a single ``AnalysisPayload`` and converts it to a
structured text block for LLM consumption, respecting a token budget so
that inputs stay within context-window limits.
"""

from __future__ import annotations

import logging
from typing import Any

from malintx.config import DANGEROUS_PERMISSIONS
from malintx.core.models import (
    APKMetadata,
    AnalysisPayload,
    CodeSlice,
    EnrichedIoC,
    IoC,
    ManifestData,
)

logger = logging.getLogger(__name__)

# Approximate token budget.  1 token ≈ 4 chars.
_MAX_CODE_TOKENS = 6000
_MAX_CODE_CHARS = _MAX_CODE_TOKENS * 4  # 24 000

# Priority order for code-slice categories (higher index = lower priority).
_CATEGORY_PRIORITY: dict[str, int] = {
    "sms": 0,
    "accessibility": 1,
    "overlay": 2,
    "dynamic_loading": 3,
    "network": 4,
    "device_info": 5,
    "crypto": 6,
}

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


class PayloadAssembler:
    """Assembles extraction artefacts into a single ``AnalysisPayload``."""

    def assemble(
        self,
        apk_metadata: APKMetadata,
        manifest_data: ManifestData,
        code_slices: list[CodeSlice],
        iocs: list[IoC],
        enriched_iocs: list[EnrichedIoC],
    ) -> AnalysisPayload:
        """Build the ``AnalysisPayload``, truncating code slices to budget.

        Slices are prioritised by category (SMS > accessibility > overlay >
        dynamic_loading > network > device_info > crypto > other) and then
        by severity (critical > high > medium > low).  If the total
        character count of the kept slices exceeds ``_MAX_CODE_CHARS``
        the lowest-priority slices are dropped.
        """
        prioritised = self._prioritise_slices(code_slices)
        truncated = self._truncate_to_budget(prioritised)

        if len(truncated) < len(code_slices):
            logger.info(
                "Truncated code slices from %d to %d to stay within token budget (%d tokens)",
                len(code_slices),
                len(truncated),
                _MAX_CODE_TOKENS,
            )

        return AnalysisPayload(
            apk_metadata=apk_metadata,
            manifest_data=manifest_data,
            code_slices=truncated,
            iocs=iocs,
            enriched_iocs=enriched_iocs,
        )

    # ------------------------------------------------------------------
    # LLM context formatting
    # ------------------------------------------------------------------

    def to_llm_context(self, payload: AnalysisPayload) -> str:
        """Format the *AnalysisPayload* as structured text for LLM input.

        The output has clearly delimited sections so the LLM can parse
        manifest data, code evidence, and IoC intelligence reliably.
        """
        sections: list[str] = []

        # -- APK metadata -------------------------------------------------
        meta = payload.apk_metadata
        sections.append(
            "=== APK METADATA ===\n"
            f"File: {meta.file_name}\n"
            f"SHA-256: {meta.sha256}\n"
            f"MD5: {meta.md5}\n"
            f"Size: {meta.file_size_bytes:,} bytes"
        )

        # -- Manifest summary ---------------------------------------------
        m = payload.manifest_data
        perm_lines = self._format_permissions(m.permissions)
        components_lines = self._format_components(m)
        sections.append(
            "=== MANIFEST SUMMARY ===\n"
            f"Package: {m.package_name}\n"
            f"Version: {m.version_name or 'N/A'} (code {m.version_code or 'N/A'})\n"
            f"Min SDK: {m.min_sdk_version}  |  Target SDK: {m.target_sdk_version}\n"
            f"Total components: {m.total_components}  |  Exported: {m.exported_components}\n"
            "\n-- Permissions --\n"
            f"{perm_lines}\n"
            "\n-- Components --\n"
            f"{components_lines}"
        )

        # -- Code slices ---------------------------------------------------
        if payload.code_slices:
            slice_text = self._format_code_slices(payload.code_slices)
            sections.append(f"=== CODE SLICES ({len(payload.code_slices)}) ===\n{slice_text}")
        else:
            sections.append("=== CODE SLICES ===\nNo high-risk code patterns detected.")

        # -- IoCs & enrichment ---------------------------------------------
        if payload.iocs or payload.enriched_iocs:
            ioc_text = self._format_iocs(payload.iocs, payload.enriched_iocs)
            sections.append(f"=== IoC INTELLIGENCE ===\n{ioc_text}")
        else:
            sections.append("=== IoC INTELLIGENCE ===\nNo IoCs extracted.")

        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _prioritise_slices(slices: list[CodeSlice]) -> list[CodeSlice]:
        """Sort slices by category priority then severity."""

        def _sort_key(s: CodeSlice) -> tuple[int, int]:
            cat_pri = _CATEGORY_PRIORITY.get(s.pattern_category, 99)
            sev_pri = _SEVERITY_ORDER.get(s.severity, 99)
            return (cat_pri, sev_pri)

        return sorted(slices, key=_sort_key)

    @staticmethod
    def _truncate_to_budget(slices: list[CodeSlice]) -> list[CodeSlice]:
        """Keep slices until the character budget is exhausted."""
        kept: list[CodeSlice] = []
        total_chars = 0
        for s in slices:
            slice_chars = len(s.code_context) + len(s.match_line) + 100  # overhead
            if total_chars + slice_chars > _MAX_CODE_CHARS:
                break
            kept.append(s)
            total_chars += slice_chars
        return kept

    @staticmethod
    def _format_permissions(permissions: list[str]) -> str:
        """Format permissions with risk annotations."""
        if not permissions:
            return "  (none)"
        lines: list[str] = []
        for perm in permissions:
            info = DANGEROUS_PERMISSIONS.get(perm)
            if info:
                lines.append(f"  [!] {perm}  — {info['risk'].upper()}: {info['description']}")
            else:
                lines.append(f"      {perm}")
        return "\n".join(lines)

    @staticmethod
    def _format_components(manifest: ManifestData) -> str:
        """Format notable components (exported or with intent filters)."""
        lines: list[str] = []
        all_comps = (
            manifest.activities
            + manifest.services
            + manifest.receivers
            + manifest.providers
        )
        notable = [c for c in all_comps if c.exported or c.intent_filters]
        if not notable:
            return "  (no notable exported components)"
        for comp in notable[:30]:  # Cap at 30 to avoid excessive length.
            exported_tag = " [EXPORTED]" if comp.exported else ""
            filters = ", ".join(comp.intent_filters) if comp.intent_filters else ""
            filter_tag = f"  filters=[{filters}]" if filters else ""
            lines.append(
                f"  {comp.component_type}: {comp.name}{exported_tag}{filter_tag}"
            )
        if len(notable) > 30:
            lines.append(f"  ... and {len(notable) - 30} more components")
        return "\n".join(lines)

    @staticmethod
    def _format_code_slices(slices: list[CodeSlice]) -> str:
        """Format code slices for LLM consumption."""
        parts: list[str] = []
        for i, s in enumerate(slices, 1):
            header = (
                f"--- Slice {i}/{len(slices)} ---\n"
                f"File: {s.file_path}\n"
                f"Line: {s.line_number}  |  Category: {s.pattern_category}  |  "
                f"Severity: {s.severity}\n"
                f"Pattern: {s.matched_pattern}  —  {s.pattern_description}\n"
                f"Match: {s.match_line.strip()}\n"
                f"Context:\n{s.code_context}"
            )
            parts.append(header)
        return "\n\n".join(parts)

    @staticmethod
    def _format_iocs(
        iocs: list[IoC],
        enriched: list[EnrichedIoC],
    ) -> str:
        """Format IoCs with enrichment data."""
        # Build a lookup from (type, value) -> enrichment.
        enrichment_map: dict[tuple[str, str], EnrichedIoC] = {}
        for eioc in enriched:
            enrichment_map[(eioc.ioc.ioc_type.value, eioc.ioc.value)] = eioc

        lines: list[str] = []
        for ioc in iocs:
            key = (ioc.ioc_type.value, ioc.value)
            eioc = enrichment_map.get(key)
            line = f"  [{ioc.ioc_type.value.upper()}] {ioc.value}"
            if ioc.source_file:
                line += f"  (source: {ioc.source_file}"
                if ioc.line_number is not None:
                    line += f":{ioc.line_number}"
                line += ")"

            if eioc and eioc.enriched and eioc.enrichment:
                e = eioc.enrichment
                vt_tag = "MALICIOUS" if e.is_malicious else "CLEAN"
                line += (
                    f"\n    VT: {vt_tag} — "
                    f"malicious={e.malicious_count}, "
                    f"suspicious={e.suspicious_count}, "
                    f"harmless={e.harmless_count}, "
                    f"undetected={e.undetected_count}"
                )
                if e.country:
                    line += f", country={e.country}"
                if e.as_owner:
                    line += f", AS={e.as_owner}"
                if e.tags:
                    line += f", tags={e.tags}"
            elif eioc and eioc.error:
                line += f"\n    VT: enrichment failed — {eioc.error}"

            lines.append(line)

        return "\n".join(lines) if lines else "  (none)"
