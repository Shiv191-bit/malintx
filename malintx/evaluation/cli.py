"""`malintx-eval` command line interface."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from malintx.config import Settings
from malintx.evaluation.dataset import init_manifest, load_manifest
from malintx.evaluation.runner import LADDER, calibrate, run_from_files


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="malintx-eval", description="Reproducible MALINT-X evaluation (never downloads samples).")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate a dataset manifest (schema, hashes, provenance, split leakage)")
    v.add_argument("manifest", type=Path)
    i = sub.add_parser("init", help="create a manifest skeleton from DIR/{malicious,benign}/ (provenance defaults to unknown)")
    i.add_argument("directory", type=Path)
    i.add_argument("--name", required=True)
    i.add_argument("--version", default="0.1")
    c = sub.add_parser("calibrate", help="pick a decision threshold on the calibration split only")
    c.add_argument("manifest", type=Path)
    r = sub.add_parser("run", help="evaluate a split and write results.json + report.md")
    r.add_argument("manifest", type=Path)
    r.add_argument("--split", default="test", choices=["calibration", "test"])
    r.add_argument("--threshold", default="high", choices=LADDER[1:])
    r.add_argument("--repeats", type=int, default=1, help="repeat analyses to measure scoring consistency")
    r.add_argument("--ai", action="store_true", help="also evaluate AI technique mapping (requires configured provider; sends evidence to it)")
    r.add_argument("--out", type=Path, default=Path("eval_out"))
    a = p.parse_args(argv)

    if a.cmd == "init":
        print(json.dumps(init_manifest(a.directory, a.name, a.version), indent=2))
        return 0
    if a.cmd == "validate":
        m, _ = load_manifest(a.manifest)
        print(f"OK: {m.name} v{m.version}: {len(m.samples)} samples; hashes verified; no split leakage")
        return 0
    if a.cmd == "calibrate":
        m, root = load_manifest(a.manifest)
        with tempfile.TemporaryDirectory() as tmp:
            s = Settings(data_dir=Path(tmp), _env_file=None)
            s.ensure_dirs()
            print(json.dumps(calibrate(m, root, s), indent=2))
        return 0
    rep = run_from_files(a.manifest, a.out, split=a.split, threshold=a.threshold, repeats=a.repeats, ai=a.ai)
    print(f"wrote {a.out / 'results.json'} and {a.out / 'report.md'}")
    for w in rep["warnings"]:
        print("WARNING:", w, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
