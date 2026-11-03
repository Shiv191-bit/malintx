"""Out-of-process analysis worker.

Runs `python -I -m malintx.analysis.worker <job.json>` inside an isolated workspace with a scrubbed
environment. A crash, hang or memory blow-up in the third-party parsers therefore cannot take down
the API process, and no credentials are visible to code that touches hostile input.

Exit codes: 0 success (result written), 3 expected analysis failure (error JSON written).
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path


def _run(job: dict) -> dict:
    from malintx.analysis.static import analyze_apk
    from malintx.config import Settings
    from malintx.tools.decompilers import (
        SourceIndex,
        cross_check_manifests,
        decode_manifest_with_apktool,
        enrich_with_source,
        find_tools,
        run_jadx,
    )

    settings = Settings(**job["settings"])
    apk = Path(job["apk_path"])
    work = Path(job["workdir"])
    result = analyze_apk(apk, job["ingested"], settings)

    tools = find_tools(settings)
    cov = result.coverage
    if job.get("use_decompilers", True):
        if tools.can_decompile:
            src = run_jadx(tools, apk, work / "jadx_out", settings, result.warnings)
            if src:
                new_ev, n = enrich_with_source(result.evidence, SourceIndex(src), settings.slice_radius_lines)
                result.evidence = new_ev
                cov.source_scan = "bytecode+decompiled_source"
                cov.limitations.append(f"JADX source slices attached to {n} API-call evidence item(s)")
        else:
            cov.limitations.append("JADX/JRE not available: evidence contains Dalvik bytecode slices, not Java source")
        if tools.can_decode:
            other = decode_manifest_with_apktool(tools, apk, work / "apktool_out", settings, result.warnings)
            if other:
                issues = cross_check_manifests(result.manifest, other)
                result.warnings += [f"manifest cross-check: {i}" for i in issues]
                cov.limitations.append("manifest cross-checked against Apktool" + (" (MISMATCH)" if issues else " (consistent)"))
    return json.loads(result.model_dump_json())


def main(argv: list[str]) -> int:
    job_path = Path(argv[1])
    job = json.loads(job_path.read_text(encoding="utf-8"))
    out = Path(job["result_path"])
    try:
        payload = {"ok": True, "result": _run(job)}
        code = 0
    except Exception as exc:  # noqa: BLE001 - boundary: converts any failure to a structured error
        payload = {"ok": False, "error_type": type(exc).__name__, "message": str(exc)[:500],
                   "trace": traceback.format_exc()[-1500:]}
        code = 3
    out.write_text(json.dumps(payload), encoding="utf-8")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
