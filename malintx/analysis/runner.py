"""Parent-side launcher for the isolated analysis worker."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from malintx.config import Settings
from malintx.errors import AnalysisError, AnalysisTimeoutError, ToolFailedError
from malintx.schemas.analysis import StaticAnalysisResult
from malintx.tools.runner import run_isolated

_SETTINGS_KEYS = (
    "data_dir", "assets_dir", "slice_radius_lines", "trusted_cert_sha256", "java_path", "jadx_path", "apktool_path",
    "decompiler_timeout_s", "worker_memory_mb",
)


def run_static_analysis(apk_path: Path, ingested: dict, settings: Settings, workdir: Path,
                        use_decompilers: bool = True) -> StaticAnalysisResult:
    result_path = workdir / "result.json"
    job = {
        "apk_path": str(apk_path),
        "ingested": ingested,
        "workdir": str(workdir),
        "result_path": str(result_path),
        "use_decompilers": use_decompilers,
        "settings": {k: (str(getattr(settings, k)) if k in ("data_dir", "assets_dir") else getattr(settings, k)) for k in _SETTINGS_KEYS},
    }
    job_path = workdir / "job.json"
    job_path.write_text(json.dumps(job), encoding="utf-8")
    cmd = [sys.executable, "-I", "-X", "utf8", "-m", "malintx.analysis.worker", str(job_path)]
    res = run_isolated(cmd, cwd=workdir, timeout_s=settings.analysis_timeout_s, memory_mb=settings.worker_memory_mb)

    if res.timed_out:
        raise AnalysisTimeoutError(f"static analysis exceeded {settings.analysis_timeout_s}s and was terminated")
    if not result_path.is_file():
        tail = (res.stderr or "").strip()[-400:]
        raise ToolFailedError(f"analysis worker exited with code {res.returncode} without a result"
                              + (f": {tail}" if tail else " (possible memory-limit kill)"))
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    if not payload.get("ok"):
        if payload.get("error_type") == "MemoryError":
            raise AnalysisError(f"analysis exceeded the {settings.worker_memory_mb} MiB worker memory limit "
                                "(raise MALINTX_WORKER_MEMORY_MB for very large or heavily split APKs)")
        raise AnalysisError(f"{payload.get('error_type')}: {payload.get('message')}")
    result = StaticAnalysisResult.model_validate(payload["result"])
    for note in res.limits_failed:
        result.coverage.limitations.append(f"resource limit could not be applied: {note}")
    return result
