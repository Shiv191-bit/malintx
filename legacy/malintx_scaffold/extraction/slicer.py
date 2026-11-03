"""
MALINT-X Code Slicer.

Walks a decompiled Java source tree, matches high-risk API patterns defined in
:mod:`malintx.config`, and extracts localised ±25-line code slices around each
match.  Overlapping slices are merged and the final list is sorted by severity.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from malintx.config import HIGH_RISK_PATTERNS
from malintx.core.models import CodeSlice

logger = logging.getLogger(__name__)

# Number of lines of context to include on either side of a match
_CONTEXT_RADIUS = 25

# Severity ordering for sorting (higher index = more severe)
_SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class CodeSlicer:
    """Scans decompiled Java source for high-risk API patterns.

    Usage::

        slicer = CodeSlicer()
        slices = slicer.slice(Path("workdir/jadx_xyz/sources"))
    """

    def __init__(self) -> None:
        # Pre-compile all patterns once for performance
        self._compiled_patterns: list[tuple[re.Pattern[str], dict[str, Any]]] = []
        for entry in HIGH_RISK_PATTERNS:
            try:
                compiled = re.compile(entry["pattern"])
                self._compiled_patterns.append((compiled, entry))
            except re.error as exc:
                logger.warning("Invalid regex pattern %r: %s", entry["pattern"], exc)

    def slice(self, source_root: Path) -> list[CodeSlice]:
        """Walk all ``.java`` files under *source_root* and return code slices.

        Parameters
        ----------
        source_root:
            Directory containing decompiled ``.java`` source files.

        Returns
        -------
        list[CodeSlice]
            Deduplicated, severity-sorted list of code slices.
        """
        source_root = Path(source_root)
        if not source_root.is_dir():
            logger.error("Source root does not exist: %s", source_root)
            return []

        raw_slices: list[CodeSlice] = []
        java_files = list(source_root.rglob("*.java"))
        logger.info("Code slicer scanning %d Java files in %s", len(java_files), source_root)

        for java_file in java_files:
            try:
                slices = self._scan_file(java_file)
                raw_slices.extend(slices)
            except Exception:
                logger.warning("Error scanning %s", java_file, exc_info=True)

        # Deduplicate overlapping slices
        deduped = self._deduplicate(raw_slices)

        # Sort by severity descending, then by file path and line number
        deduped.sort(
            key=lambda s: (
                -_SEVERITY_ORDER.get(s.severity, -1),
                s.file_path,
                s.line_number,
            )
        )

        logger.info(
            "Code slicer produced %d slices (%d before dedup) from %d files",
            len(deduped),
            len(raw_slices),
            len(java_files),
        )
        return deduped

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_file(self, file_path: Path) -> list[CodeSlice]:
        """Scan a single Java file for pattern matches."""
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []

        lines = text.splitlines()
        slices: list[CodeSlice] = []

        for line_idx, line in enumerate(lines):
            for compiled_re, pattern_info in self._compiled_patterns:
                if compiled_re.search(line):
                    code_slice = self._build_slice(
                        file_path=file_path,
                        lines=lines,
                        match_line_idx=line_idx,
                        pattern_info=pattern_info,
                    )
                    slices.append(code_slice)

        return slices

    @staticmethod
    def _build_slice(
        file_path: Path,
        lines: list[str],
        match_line_idx: int,
        pattern_info: dict[str, Any],
    ) -> CodeSlice:
        """Construct a :class:`CodeSlice` around the matched line."""
        total_lines = len(lines)
        start = max(0, match_line_idx - _CONTEXT_RADIUS)
        end = min(total_lines, match_line_idx + _CONTEXT_RADIUS + 1)

        context_lines = lines[start:end]
        code_context = "\n".join(context_lines)
        match_line = lines[match_line_idx]

        return CodeSlice(
            file_path=str(file_path),
            file_name=file_path.name,
            line_number=match_line_idx + 1,  # 1-based
            matched_pattern=pattern_info["pattern"],
            pattern_category=pattern_info["category"],
            pattern_description=pattern_info["description"],
            severity=pattern_info["severity"],
            code_context=code_context,
            match_line=match_line,
        )

    @staticmethod
    def _deduplicate(slices: list[CodeSlice]) -> list[CodeSlice]:
        """Remove slices whose code windows overlap within the same file.

        When two slices in the same file overlap (i.e. their ±25-line windows
        intersect), keep the one with the higher severity.  If severities are
        equal, keep the earlier one.
        """
        if not slices:
            return []

        # Group slices by file
        by_file: dict[str, list[CodeSlice]] = {}
        for s in slices:
            by_file.setdefault(s.file_path, []).append(s)

        result: list[CodeSlice] = []

        for file_slices in by_file.values():
            # Sort by line number
            file_slices.sort(key=lambda s: s.line_number)

            kept: list[CodeSlice] = []
            for candidate in file_slices:
                # Check overlap with previously kept slices
                merged = False
                for i, existing in enumerate(kept):
                    if _windows_overlap(existing, candidate):
                        # Keep the higher-severity one
                        if _SEVERITY_ORDER.get(candidate.severity, -1) > _SEVERITY_ORDER.get(
                            existing.severity, -1
                        ):
                            kept[i] = candidate
                        merged = True
                        break
                if not merged:
                    kept.append(candidate)

            result.extend(kept)

        return result


def _windows_overlap(a: CodeSlice, b: CodeSlice) -> bool:
    """Check whether the context windows of two slices overlap."""
    a_start = a.line_number - _CONTEXT_RADIUS
    a_end = a.line_number + _CONTEXT_RADIUS
    b_start = b.line_number - _CONTEXT_RADIUS
    b_end = b.line_number + _CONTEXT_RADIUS
    return a_start <= b_end and b_start <= a_end
