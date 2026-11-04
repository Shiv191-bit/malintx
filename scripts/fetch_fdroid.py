"""Download a benign, open-source APK corpus from F-Droid and write a MALINT-X evaluation manifest.

Usage: python scripts/fetch_fdroid.py corpus/fdroid [package ...]

Only public F-Droid repository files are fetched (https://f-droid.org/repo/). Each entry records source URL,
retrieval time and SHA-256, so provenance is real and reproducible. Apps are open-source; follow each app's
licence if you redistribute (this script never uploads anything).
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

DEFAULT = """org.fdroid.fdroid org.smssecure.smssecure org.fossify.messages org.fossify.phone com.termux eu.faircode.netguard
de.blinkt.openvpn org.schabi.newpipe com.menny.android.anysoftkeyboard org.kde.kdeconnect_tp org.openhab.habdroid
com.amaze.filemanager com.aurora.store org.fossify.contacts org.fossify.gallery org.fossify.clock org.fossify.calendar
com.automattic.simplenote org.mozilla.fennec_fdroid net.osmand.plus app.organicmaps org.wikipedia com.fsck.k9 net.thunderbird.android
org.briarproject.briar.android com.ichi2.anki org.tasks org.moire.opensudoku at.bitfire.davdroid com.nextcloud.client
org.jellyfin.mobile org.mariotaku.twidere io.github.muntashirakon.AppManager me.zhanghai.android.files""".split()
MAX_BYTES = 70 * 1024 * 1024


def main() -> None:
    out = Path(sys.argv[1])
    pkgs = sys.argv[2:] or DEFAULT
    out.mkdir(parents=True, exist_ok=True)
    samples, skipped = [], []
    with httpx.Client(timeout=60, follow_redirects=True) as c:
        for pkg in pkgs:
            try:
                meta = c.get(f"https://f-droid.org/api/v1/packages/{pkg}")
                meta.raise_for_status()
                vc = meta.json()["suggestedVersionCode"]
            except (httpx.HTTPError, KeyError, ValueError):
                skipped.append((pkg, "not in F-Droid API"))
                continue
            url = f"https://f-droid.org/repo/{pkg}_{vc}.apk"
            dest = out / f"{pkg}_{vc}.apk"
            if not dest.exists():
                with c.stream("GET", url) as r:
                    if r.status_code != 200 or int(r.headers.get("content-length", 0)) > MAX_BYTES:
                        skipped.append((pkg, f"HTTP {r.status_code} / too large"))
                        continue
                    h = hashlib.sha256()
                    with dest.open("wb") as fh:
                        for chunk in r.iter_bytes(1 << 20):
                            fh.write(chunk)
                            h.update(chunk)
            sha = hashlib.sha256(dest.read_bytes()).hexdigest()
            samples.append({
                "path": dest.name, "sha256": sha, "label": "benign", "split": "test", "family": None, "expected_techniques": [],
                "source": {"name": "F-Droid", "provenance": "open_source_build", "url": url,
                           "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           "license_note": "open-source app; per-app licence applies"},
                "notes": f"{pkg} versionCode {vc}",
            })
            print(f"ok  {dest.name}  {dest.stat().st_size // 1024} KiB")
    (out / "manifest.json").write_text(json.dumps({"name": "fdroid-benign", "version": datetime.now(timezone.utc).strftime("%Y.%m.%d"),
                                                   "description": "Open-source F-Droid apps; label=benign by provenance (open-source, audited repo), not by VirusTotal.",
                                                   "samples": samples}, indent=2), encoding="utf-8")
    for pkg, why in skipped:
        print("skip", pkg, why)
    print(f"{len(samples)} samples, {len(skipped)} skipped")


if __name__ == "__main__":
    main()
