"""Seeded random sample of the F-Droid repository (unbiased held-out benign set).

Usage: python scripts/fetch_fdroid_random.py OUT_DIR N SEED [EXCLUDE_MANIFEST ...]
Picks N apps uniformly at random from F-Droid's index (size ≤ 45 MB), excluding packages in the given manifests
(e.g. the corpus the rules were developed on), downloads them, writes OUT_DIR/manifest.json with real provenance.
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

MAX_BYTES = 45 * 1024 * 1024


def main() -> None:
    out, n, seed = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    exclude: set[str] = set()
    for mp in sys.argv[4:]:
        for s in json.loads(Path(mp).read_text())["samples"]:
            exclude.add(s["path"].rsplit("_", 1)[0])
    out.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=120, follow_redirects=True) as c:
        idx = c.get("https://f-droid.org/repo/index-v1.json").json()
        cands = []
        for pkg, versions in idx["packages"].items():
            if pkg in exclude or not versions:
                continue
            v = max(versions, key=lambda x: x["versionCode"])
            if v.get("size", 10**9) <= MAX_BYTES and v["apkName"].endswith(".apk"):
                cands.append((pkg, v["apkName"], v["versionCode"], v.get("size", 0)))
        cands.sort()
        random.Random(seed).shuffle(cands)
        samples = []
        for pkg, apk, vc, size in cands:
            if len(samples) >= n:
                break
            url = f"https://f-droid.org/repo/{apk}"
            dest = out / apk
            try:
                data = c.get(url).content
            except httpx.HTTPError:
                continue
            dest.write_bytes(data)
            samples.append({"path": apk, "sha256": hashlib.sha256(data).hexdigest(), "label": "benign", "split": "test", "family": None, "expected_techniques": [],
                            "source": {"name": "F-Droid", "provenance": "open_source_build", "url": url,
                                       "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "license_note": "open-source app; per-app licence applies"},
                            "notes": f"{pkg} versionCode {vc}"})
            print("ok", apk, len(data) // 1024, "KiB", flush=True)
    (out / "manifest.json").write_text(json.dumps({"name": f"fdroid-random-seed{seed}", "version": datetime.now(timezone.utc).strftime("%Y.%m.%d"),
                                                   "description": f"Uniform random sample (seed {seed}) of F-Droid excluding the development corpus.",
                                                   "samples": samples}, indent=2), encoding="utf-8")
    print(len(samples), "samples")


if __name__ == "__main__":
    main()
