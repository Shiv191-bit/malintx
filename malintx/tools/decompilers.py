"""Optional JADX / Apktool adapters.

Bytecode analysis (androguard) is always the ground truth. When a JRE + JADX are available, decompiled
Java source is used to attach line numbers and a ±N-line source slice to API-call evidence.
When Apktool is available, its decoded manifest is cross-checked against the native manifest parse
to expose manifest-tampering that fools one parser but not another.
"""

from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from malintx.analysis.manifest import parse_manifest_text
from malintx.config import Settings
from malintx.schemas.analysis import Evidence
from malintx.schemas.common import EvidenceKind
from malintx.schemas.sample import ManifestInfo
from malintx.tools.runner import minimal_env, run_isolated

log = logging.getLogger(__name__)


def _java_env(tools: ToolPaths, cwd: Path) -> dict[str, str]:
    """Scrubbed env plus JAVA_HOME derived from the configured java, so launchers find the JVM."""
    env = minimal_env(cwd)
    if tools.java:
        env["JAVA_HOME"] = str(Path(tools.java).resolve().parent.parent)
    return env


@dataclass(frozen=True)
class ToolPaths:
    java: str | None
    jadx: str | None
    apktool: str | None

    @property
    def can_decompile(self) -> bool:
        return bool(self.java and self.jadx)

    @property
    def can_decode(self) -> bool:
        return bool(self.java and self.apktool)


def _which(configured: str, *names: str) -> str | None:
    if configured:
        p = Path(configured)
        return str(p) if p.is_file() else None
    for n in names:
        found = shutil.which(n)
        if found:
            return found
    return None


def find_tools(settings: Settings) -> ToolPaths:
    return ToolPaths(
        java=_which(settings.java_path, "java"),
        jadx=_which(settings.jadx_path, "jadx", "jadx.bat"),
        apktool=_which(settings.apktool_path, "apktool", "apktool.bat"),
    )


# ------------------------------------------------------------------------------- JADX
def run_jadx(tools: ToolPaths, apk: Path, out_dir: Path, settings: Settings, warnings: list[str]) -> Path | None:
    """Decompile to Java sources. JADX exits non-zero on partial decompilation errors; the output is
    still used if a sources directory exists."""
    if not tools.can_decompile:
        return None
    cmd = [tools.jadx or "", "--no-res", "--no-debug-info", "--threads-count", "2", "-d", str(out_dir), str(apk)]
    res = run_isolated(cmd, cwd=out_dir.parent, timeout_s=settings.decompiler_timeout_s,
                       memory_mb=settings.worker_memory_mb, env=_java_env(tools, out_dir.parent))
    if res.timed_out:
        warnings.append(f"JADX timed out after {settings.decompiler_timeout_s}s; source slices unavailable")
        return None
    sources = out_dir / "sources"
    if not sources.is_dir():
        warnings.append(f"JADX produced no sources (exit {res.returncode}): {(res.stderr + res.stdout)[-300:].strip()}")
        return None
    if res.returncode:
        warnings.append(f"JADX reported errors (exit {res.returncode}); some classes may be missing or partial")
    return sources


_MAX_SOURCE_BYTES = 2 * 1024 * 1024


class SourceIndex:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._cache: dict[str, list[str] | None] = {}

    def _file_for(self, class_desc: str) -> Path | None:
        rel = class_desc[1:-1].split("$", 1)[0]
        path = (self.root / (rel + ".java")).resolve()
        # confine to the decompiler output directory (class names come from untrusted DEX data)
        if self.root not in path.parents or not path.is_file():
            return None
        return path

    def _lines(self, class_desc: str) -> tuple[Path, list[str]] | None:
        path = self._file_for(class_desc)
        if path is None:
            return None
        key = str(path)
        if key not in self._cache:
            try:
                if path.stat().st_size > _MAX_SOURCE_BYTES:
                    self._cache[key] = None
                else:
                    self._cache[key] = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._cache[key] = None
        lines = self._cache[key]
        return (path, lines) if lines else None

    def locate(self, class_desc: str, caller_method: str, callee_method: str, radius: int) -> tuple[int, str] | None:
        got = self._lines(class_desc)
        if not got:
            return None
        _, lines = got
        callee = "<init>" if callee_method == "<init>" else callee_method
        needle = re.compile(r"\bnew\s+\w+\s*\(" if callee == "<init>" else r"\b" + re.escape(callee) + r"\s*\(")
        start = 0
        if caller_method not in ("<init>", "<clinit>"):
            decl = re.compile(r"\b" + re.escape(caller_method) + r"\s*\([^;{]*\)\s*(?:throws[^{]*)?\{")
            for i, ln in enumerate(lines):
                if decl.search(ln):
                    start = i
                    break
        for i in range(start, len(lines)):
            if needle.search(lines[i]):
                lo, hi = max(0, i - radius), min(len(lines), i + radius + 1)
                body = "\n".join(
                    f"{'>>' if j == i else '  '} {j + 1:5d}: {lines[j][:200]}" for j in range(lo, hi)
                )
                return i + 1, body
        return None


def enrich_with_source(evidence: list[Evidence], index: SourceIndex, radius: int) -> tuple[list[Evidence], int]:
    out: list[Evidence] = []
    enriched = 0
    for ev in evidence:
        if ev.kind == EvidenceKind.API_CALL and ev.class_name and ev.method_name and ev.api and "->" in ev.api:
            found = index.locate(ev.class_name, ev.method_name, ev.api.split("->", 1)[1], radius)
            if found:
                line, text = found
                snippet = text + ("\n\n--- Dalvik bytecode ---\n" + ev.snippet if ev.snippet else "")
                out.append(ev.model_copy(update={
                    "line_number": line, "snippet": snippet[:6000],
                    "extraction_method": ev.extraction_method + "+jadx-source",
                }))
                enriched += 1
                continue
        out.append(ev)
    return out, enriched


# ----------------------------------------------------------------------------- Apktool
def decode_manifest_with_apktool(tools: ToolPaths, apk: Path, out_dir: Path, settings: Settings,
                                 warnings: list[str]) -> ManifestInfo | None:
    if not tools.can_decode:
        return None
    cmd = [tools.apktool or "", "d", "-f", "-s", "-o", str(out_dir), str(apk)]
    res = run_isolated(cmd, cwd=out_dir.parent, timeout_s=settings.decompiler_timeout_s,
                       memory_mb=settings.worker_memory_mb, env=_java_env(tools, out_dir.parent))
    manifest = out_dir / "AndroidManifest.xml"
    if res.timed_out or not manifest.is_file():
        warnings.append(f"Apktool did not produce a manifest (exit {res.returncode}, timeout={res.timed_out})")
        return None
    try:
        return parse_manifest_text(manifest.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001 - defusedxml raises several types on hostile XML
        warnings.append(f"Apktool manifest could not be parsed safely: {type(exc).__name__}")
        return None


def cross_check_manifests(native: ManifestInfo, apktool: ManifestInfo) -> list[str]:
    issues = []
    if native.package != apktool.package:
        issues.append(f"package differs between parsers: {native.package!r} vs {apktool.package!r}")
    a, b = native.permission_names(), apktool.permission_names()
    if a != b:
        issues.append(
            f"permission sets differ between parsers (native-only: {sorted(a - b)[:5]}, apktool-only: {sorted(b - a)[:5]})"
        )
    ca, cb = {c.name for c in native.components}, {c.name for c in apktool.components}
    if ca != cb:
        issues.append(f"component sets differ between parsers ({len(ca ^ cb)} differing entries)")
    return issues
