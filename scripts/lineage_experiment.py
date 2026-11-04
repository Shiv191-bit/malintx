"""Dump the raw framework-API sets of every corpus APK so fingerprint variants can be compared offline."""

from __future__ import annotations

import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

from malintx.analysis.backends.androguard_backend import AndroguardBackend  # noqa: E402
from malintx.analysis.manifest import parse_manifest_element  # noqa: E402
from malintx.evaluation.dataset import load_manifest  # noqa: E402

out = Path(sys.argv[1])
rows = []
for mp in sys.argv[2:]:
    manifest, root = load_manifest(Path(mp))
    for e in manifest.samples:
        try:
            b = AndroguardBackend(root / e.path)
            b.load()
            man = parse_manifest_element(b.apk.get_android_manifest_xml())
            rows.append({"pkg": man.package, "apis": sorted(b.framework_api_set())})
            print("ok", man.package, len(rows[-1]["apis"]), flush=True)
        except Exception as exc:  # noqa: BLE001
            print("ERR", e.path, type(exc).__name__, flush=True)
out.write_text(json.dumps(rows), encoding="utf-8")
