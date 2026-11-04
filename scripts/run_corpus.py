"""Run the real MALINT-X pipeline (ingest → isolated analysis → scoring) over a manifest's samples and summarise.

Usage: python scripts/run_corpus.py corpus/fdroid/manifest.json out.json [--decompilers]
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

from malintx.analysis.runner import run_static_analysis  # noqa: E402
from malintx.config import Settings  # noqa: E402
from malintx.evaluation.dataset import load_manifest  # noqa: E402
from malintx.ingestion import ingest_path, workspace  # noqa: E402
from malintx.risk.engine import assess  # noqa: E402
from malintx.schemas.common import FindingKind  # noqa: E402


def main() -> None:
    manifest, root = load_manifest(Path(sys.argv[1]))
    out = Path(sys.argv[2])
    use_dec = "--decompilers" in sys.argv
    kw = {}
    if use_dec:
        kw = dict(java_path=r"C:\Program Files\Microsoft\jdk-21.0.13.21-hotspot\bin\java.exe",
                  jadx_path=str(Path("tools/jadx/bin/jadx.bat").resolve()), apktool_path=str(Path("tools/apktool/apktool.bat").resolve()))
    s = Settings(data_dir=Path(tempfile.mkdtemp()), _env_file=None, analysis_timeout_s=900, **kw)
    s.ensure_dirs()
    rows = []
    for e in manifest.samples:
        t = time.perf_counter()
        row = {"sample": e.notes.split(" versionCode")[0], "label": e.label, "size_mb": round((root / e.path).stat().st_size / 2**20, 1)}
        try:
            ing = ingest_path(root / e.path, s)
            d = {"sha256": ing.sha256, "sha1": ing.sha1, "md5": ing.md5, "size_bytes": ing.size_bytes, "display_name": ing.display_name,
                 "first_seen": ing.first_seen, "archive": ing.archive.model_dump(mode="json")}
            with workspace(s.workspaces_dir, "c-") as ws:
                st = run_static_analysis(ing.stored_path, d, s, ws, use_decompilers=use_dec)
            risk = assess(st, None, s)
            row.update(
                seconds=round(time.perf_counter() - t, 1), classification=risk.classification.value, score=risk.score,
                classes=st.coverage.classes, methods=st.coverage.methods, dex=st.coverage.dex_files_parsed, dex_failed=len(st.coverage.dex_files_failed),
                packer=st.coverage.packer_hints, obf=st.coverage.obfuscation_ratio, source_scan=st.coverage.source_scan,
                composites=[f.rule_id for f in st.findings if f.kind == FindingKind.MALICIOUS_BEHAVIOR],
                high_caps=[f.rule_id for f in st.findings if f.kind == FindingKind.SUSPICIOUS_CAPABILITY and f.severity.rank >= 3],
                n_findings=len(st.findings), n_ind=len(st.indicators), pkg=st.sample.package_name, warnings=st.warnings[:3],
                sha256=st.sample.sha256, signed=st.sample.signing_schemes,
            )
        except Exception as exc:  # noqa: BLE001 - corpus runs record per-sample failures
            row.update(seconds=round(time.perf_counter() - t, 1), error=f"{type(exc).__name__}: {str(exc)[:200]}")
        rows.append(row)
        print(f"{row['sample'][:38]:38} {row['size_mb']:>5}MB {row.get('seconds', 0):>6}s  {row.get('classification', 'ERR'):>13} {str(row.get('score')):>4}  {row.get('composites', row.get('error'))}", flush=True)
    out.write_text(json.dumps(rows, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
