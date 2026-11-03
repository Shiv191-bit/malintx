"""
MALINT-X Decompiler Wrapper.

Provides a unified interface for decompiling Android APKs using JADX (preferred)
with automatic fallback to Apktool.  Manages temporary working directories and
captures structured results via :class:`DecompilationResult`.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from malintx.config import JADX_DIR, APKTOOL_JAR, WORKDIR, settings
from malintx.core.models import DecompilationResult

logger = logging.getLogger(__name__)

# Well-known manifest locations produced by each tool
_JADX_MANIFEST_REL = Path("resources") / "AndroidManifest.xml"
_APKTOOL_MANIFEST_REL = Path("AndroidManifest.xml")

# Source root directories produced by each tool
_JADX_SOURCE_REL = Path("sources")
_APKTOOL_SOURCE_REL = Path("smali")


class DecompilerWrapper:
    """High-level wrapper around JADX and Apktool decompilers.

    Usage::

        wrapper = DecompilerWrapper()
        result = wrapper.decompile(Path("sample.apk"))
        if result.success:
            print(result.manifest_path, result.source_root)
    """

    def __init__(self) -> None:
        self._jadx_path = self._resolve_jadx()
        self._apktool_jar = self._resolve_apktool()

    # ------------------------------------------------------------------
    # Tool resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_jadx() -> Path | None:
        """Locate the JADX binary on the system or in the tools directory."""
        # Check the tools directory first (platform-specific extension)
        for name in ("jadx.bat", "jadx", "jadx.exe"):
            candidate = JADX_DIR / "bin" / name
            if candidate.is_file():
                logger.debug("Found JADX at %s", candidate)
                return candidate

        # Fall back to system PATH
        system_jadx = shutil.which("jadx")
        if system_jadx:
            logger.debug("Found JADX on PATH: %s", system_jadx)
            return Path(system_jadx)

        logger.warning("JADX not found in tools dir or system PATH")
        return None

    @staticmethod
    def _resolve_apktool() -> Path | None:
        """Locate the Apktool JAR in the tools directory or on PATH."""
        if APKTOOL_JAR.is_file():
            logger.debug("Found Apktool at %s", APKTOOL_JAR)
            return APKTOOL_JAR

        # Try system PATH for the wrapper script
        system_apktool = shutil.which("apktool")
        if system_apktool:
            logger.debug("Found Apktool on PATH: %s", system_apktool)
            return Path(system_apktool)

        logger.warning("Apktool not found in tools dir or system PATH")
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def decompile(self, apk_path: Path) -> DecompilationResult:
        """Decompile an APK, trying JADX first, then Apktool.

        Parameters
        ----------
        apk_path:
            Absolute path to the ``.apk`` file.

        Returns
        -------
        DecompilationResult
            Populated result with paths on success or an error message on
            failure.
        """
        apk_path = Path(apk_path).resolve()
        if not apk_path.is_file():
            return DecompilationResult(
                success=False,
                error_message=f"APK file not found: {apk_path}",
            )

        # Try JADX first
        if self._jadx_path is not None:
            result = self._run_jadx(apk_path)
            if result.success:
                return result
            logger.warning("JADX failed (%s), falling back to Apktool", result.error_message)

        # Fallback to Apktool
        if self._apktool_jar is not None:
            result = self._run_apktool(apk_path)
            if result.success:
                return result
            logger.error("Apktool also failed: %s", result.error_message)
            return result

        # Neither tool available
        msg = "No decompiler available. Install JADX or Apktool."
        logger.error(msg)
        return DecompilationResult(success=False, error_message=msg)

    # ------------------------------------------------------------------
    # Internal runners
    # ------------------------------------------------------------------

    def _make_output_dir(self, tool_name: str) -> Path:
        """Create a unique output directory under the global workdir."""
        output_dir = WORKDIR / f"{tool_name}_{uuid.uuid4().hex[:12]}"
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _run_jadx(self, apk_path: Path) -> DecompilationResult:
        """Run JADX on the given APK."""
        output_dir = self._make_output_dir("jadx")
        cmd = [
            str(self._jadx_path),
            "--no-res",
            "--no-debug-info",
            "-d",
            str(output_dir),
            str(apk_path),
        ]
        logger.info("Running JADX: %s", " ".join(cmd))

        start = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.jadx_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - start
            return DecompilationResult(
                success=False,
                decompiler_used="jadx",
                error_message=f"JADX timed out after {settings.jadx_timeout_seconds}s",
                duration_seconds=round(elapsed, 2),
            )
        except FileNotFoundError:
            return DecompilationResult(
                success=False,
                decompiler_used="jadx",
                error_message=f"JADX binary not executable: {self._jadx_path}",
            )
        except OSError as exc:
            return DecompilationResult(
                success=False,
                decompiler_used="jadx",
                error_message=f"OS error running JADX: {exc}",
            )

        elapsed = time.perf_counter() - start

        if proc.returncode != 0:
            stderr_snippet = (proc.stderr or "")[:500]
            return DecompilationResult(
                success=False,
                decompiler_used="jadx",
                error_message=f"JADX exited with code {proc.returncode}: {stderr_snippet}",
                duration_seconds=round(elapsed, 2),
            )

        # Locate artefacts
        manifest_path = self._find_manifest(output_dir, _JADX_MANIFEST_REL)
        source_root = self._find_source_root(output_dir, _JADX_SOURCE_REL)

        return DecompilationResult(
            success=True,
            decompiler_used="jadx",
            manifest_path=str(manifest_path) if manifest_path else None,
            source_root=str(source_root) if source_root else None,
            resources_root=str(output_dir / "resources") if (output_dir / "resources").is_dir() else None,
            duration_seconds=round(elapsed, 2),
        )

    def _run_apktool(self, apk_path: Path) -> DecompilationResult:
        """Run Apktool on the given APK."""
        output_dir = self._make_output_dir("apktool")

        # Determine how to invoke Apktool
        apktool_path = self._apktool_jar
        assert apktool_path is not None

        if apktool_path.suffix == ".jar":
            cmd = [
                "java", "-jar", str(apktool_path),
                "d", "-f",
                "-o", str(output_dir),
                str(apk_path),
            ]
        else:
            # Wrapper script on PATH
            cmd = [
                str(apktool_path),
                "d", "-f",
                "-o", str(output_dir),
                str(apk_path),
            ]

        logger.info("Running Apktool: %s", " ".join(cmd))

        start = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.apktool_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - start
            return DecompilationResult(
                success=False,
                decompiler_used="apktool",
                error_message=f"Apktool timed out after {settings.apktool_timeout_seconds}s",
                duration_seconds=round(elapsed, 2),
            )
        except FileNotFoundError as exc:
            return DecompilationResult(
                success=False,
                decompiler_used="apktool",
                error_message=f"Apktool/Java not found: {exc}",
            )
        except OSError as exc:
            return DecompilationResult(
                success=False,
                decompiler_used="apktool",
                error_message=f"OS error running Apktool: {exc}",
            )

        elapsed = time.perf_counter() - start

        if proc.returncode != 0:
            stderr_snippet = (proc.stderr or "")[:500]
            return DecompilationResult(
                success=False,
                decompiler_used="apktool",
                error_message=f"Apktool exited with code {proc.returncode}: {stderr_snippet}",
                duration_seconds=round(elapsed, 2),
            )

        manifest_path = self._find_manifest(output_dir, _APKTOOL_MANIFEST_REL)
        source_root = self._find_source_root(output_dir, _APKTOOL_SOURCE_REL)

        return DecompilationResult(
            success=True,
            decompiler_used="apktool",
            manifest_path=str(manifest_path) if manifest_path else None,
            source_root=str(source_root) if source_root else None,
            resources_root=str(output_dir / "res") if (output_dir / "res").is_dir() else None,
            duration_seconds=round(elapsed, 2),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_manifest(output_dir: Path, expected_rel: Path) -> Path | None:
        """Find AndroidManifest.xml in the output directory."""
        candidate = output_dir / expected_rel
        if candidate.is_file():
            return candidate

        # Brute-force search as fallback
        for f in output_dir.rglob("AndroidManifest.xml"):
            return f

        logger.warning("AndroidManifest.xml not found in %s", output_dir)
        return None

    @staticmethod
    def _find_source_root(output_dir: Path, expected_rel: Path) -> Path | None:
        """Find the source root directory in the output."""
        candidate = output_dir / expected_rel
        if candidate.is_dir():
            return candidate

        # JADX sometimes nests sources differently; check common alternatives
        for alt in ("sources", "smali", "smali_classes2", "src"):
            alt_path = output_dir / alt
            if alt_path.is_dir():
                return alt_path

        # Last resort: return the output dir itself if it contains .java files
        java_files = list(output_dir.rglob("*.java"))
        if java_files:
            return output_dir

        logger.warning("Source root not found in %s", output_dir)
        return None
