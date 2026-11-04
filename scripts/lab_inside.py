"""Runs INSIDE the offline analysis container. Unzips samples into tmpfs, analyses them statically, writes JSON.

Static analysis only: nothing is installed or executed. Output is per-sample classification/score/composites so the host can
compute precision/recall with Wilson intervals (see docs/MALWARE_LAB.md).
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import warnings
import zipfile
from pathlib import Path

warnings.filterwarnings("ignore")

from malintx.analysis.runner import run_static_analysis  # noqa: E402
from malintx.config import Settings  # noqa: E402
from malintx.ingestion import ingest_path, workspace  # noqa: E402
from malintx.risk.engine import assess  # noqa: E402
from malintx.schemas.common import FindingKind  # noqa: E402

WORK = Path("/work")


def analyse(apk: Path, label: str, meta: dict, s: Settings) -> dict:
    t = time.perf_counter()
    row = {"sha256_name": apk.stem, "label": label, **meta}
    try:
        ing = ingest_path(apk, s)
        d = {"sha256": ing.sha256, "sha1": ing.sha1, "md5": ing.md5, "size_bytes": ing.size_bytes, "display_name": "sample.apk",
             "first_seen": ing.first_seen, "archive": ing.archive.model_dump(mode="json")}
        with workspace(s.workspaces_dir, "lab-") as ws:
            st = run_static_analysis(ing.stored_path, d, s, ws, use_decompilers=False)
        risk = assess(st, None, s)
        row.update(classification=risk.classification.value, score=risk.score, seconds=round(time.perf_counter() - t, 1),
                   composites=[f.rule_id for f in st.findings if f.kind == FindingKind.MALICIOUS_BEHAVIOR],
                   near_misses=[n.rule_id for n in st.near_misses],
                   near_miss_detail=[{"rule": n.rule_id, "sat": f"{n.satisfied}/{n.total}", "missing": n.missing} for n in st.near_misses], packer=st.coverage.packer_hints, pkg=st.sample.package_name,
                   cov={"classes": st.coverage.classes, "methods": st.coverage.methods, "dex": st.coverage.dex_files_parsed, "dex_failed": len(st.coverage.dex_files_failed),
                        "obf": st.coverage.obfuscation_ratio, "native": len(st.coverage.native_libraries), "api_count": st.lineage.api_count if st.lineage else 0,
                        "assets": st.sample.archive.asset_count if st.sample.archive else None, "zip_anomalies": len(st.sample.archive.suspicious_entries) if st.sample.archive else 0,
                        "perms": len(st.manifest.permissions), "sdk": [st.manifest.min_sdk, st.manifest.target_sdk]},
                   top=[f.rule_id for f in st.findings if f.kind != FindingKind.INFORMATIONAL and f.severity.rank >= 2][:8])
    except Exception as exc:  # noqa: BLE001 - lab runs record per-sample failures
        row.update(error=f"{type(exc).__name__}: {str(exc)[:160]}", seconds=round(time.perf_counter() - t, 1))
        try:  # structure of rejected archives, to learn how they evade parsers (names only; nothing is executed)
            with zipfile.ZipFile(apk) as zf:
                row["zip_names"] = [i.filename[:60] for i in zf.infolist()][:12]
        except Exception as exc2:  # noqa: BLE001
            row["zip_names"] = f"unreadable: {type(exc2).__name__}"
            row["magic"] = apk.read_bytes()[:8].hex()
    return row


def main() -> None:
    s = Settings(data_dir=WORK / "data", _env_file=None, analysis_timeout_s=900)
    s.ensure_dirs()
    meta = {m["sha256"]: m for m in json.loads(Path("/samples/malware_meta.json").read_text())} if Path("/samples/malware_meta.json").exists() else {}
    rows = []
    dev = set(json.loads(Path("/dev_set.json").read_text())) if Path("/dev_set.json").exists() else set()
    only = [x for x in os.environ.get("MALINTX_LAB_ONLY", "").split(",") if x]  # diagnostic re-run of chosen sample-hash prefixes
    for z in sorted(Path("/samples").glob("*.zip")):
        if only and not any(z.stem.startswith(o) for o in only):
            continue
        try:
            try:
                import pyzipper  # MalwareBazaar uses WinZip-AES, which the standard library cannot read

                zf_cls = pyzipper.AESZipFile
            except ImportError:
                zf_cls = zipfile.ZipFile
            with zf_cls(z) as zf:
                zf.setpassword(b"infected")
                name = next(n for n in zf.namelist() if not n.endswith("/"))
                dest = WORK / f"{z.stem}.apk"
                dest.write_bytes(zf.read(name))
        except (RuntimeError, NotImplementedError, zipfile.BadZipFile, StopIteration) as exc:
            rows.append({"sha256_name": z.stem, "label": "malicious", "error": f"unzip failed: {type(exc).__name__}"})
            continue
        rows.append(analyse(dest, "malicious", {"signature": meta.get(z.stem, {}).get("signature"), "split": "dev" if z.stem in dev else "heldout"}, s))
        if "error" in rows[-1] and any(str(n).endswith(".class") for n in rows[-1].get("zip_names") or []):
            rows[-1]["not_android"] = True  # a Java archive mislabelled as APK upstream; excluded from recall
        dest.unlink(missing_ok=True)
        print(rows[-1].get("classification", rows[-1].get("error")), flush=True)
    for apk in sorted(Path("/benign").glob("*.apk")) if Path("/benign").exists() else []:
        rows.append(analyse(apk, "benign", {}, s))
    Path("/results").joinpath("lab_results.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    print(f"wrote {len(rows)} rows", tempfile.gettempdir())


if __name__ == "__main__":
    main()
