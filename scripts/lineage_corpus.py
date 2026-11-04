"""Compute behavioural fingerprints for every APK in the given manifests (isolated worker, real analysis).

Usage: python scripts/lineage_corpus.py OUT.json manifest1.json [manifest2.json ...]
"""

from __future__ import annotations

import json
import sys
import tempfile
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

from malintx.analysis.runner import run_static_analysis  # noqa: E402
from malintx.config import Settings  # noqa: E402
from malintx.evaluation.dataset import load_manifest  # noqa: E402
from malintx.ingestion import ingest_path, workspace  # noqa: E402


def main() -> None:
    out = Path(sys.argv[1])
    s = Settings(data_dir=Path(tempfile.mkdtemp()), _env_file=None, analysis_timeout_s=900)
    s.ensure_dirs()
    rows = []
    for mp in sys.argv[2:]:
        manifest, root = load_manifest(Path(mp))
        for e in manifest.samples:
            try:
                ing = ingest_path(root / e.path, s)
                d = {"sha256": ing.sha256, "sha1": ing.sha1, "md5": ing.md5, "size_bytes": ing.size_bytes, "display_name": ing.display_name,
                     "first_seen": ing.first_seen, "archive": ing.archive.model_dump(mode="json")}
                with workspace(s.workspaces_dir, "l-") as ws:
                    st = run_static_analysis(ing.stored_path, d, s, ws, use_decompilers=False)
                rows.append({"app": e.notes.split(" versionCode")[0], "pkg": st.sample.package_name, "lineage": st.lineage.model_dump() if st.lineage else None,
                             "signer": [c.sha256 for c in st.sample.certificates]})
                print("ok", e.notes.split(" ")[0], st.lineage.api_count if st.lineage else None, flush=True)
            except Exception as exc:  # noqa: BLE001
                print("ERR", e.path, type(exc).__name__, str(exc)[:80], flush=True)
    out.write_text(json.dumps(rows), encoding="utf-8")


if __name__ == "__main__":
    main()
