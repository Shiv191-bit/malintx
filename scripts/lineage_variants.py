"""Compare fingerprint variants offline on dumped API sets (exact Jaccard; MinHash only approximates it)."""

from __future__ import annotations

import itertools
import json
import math
import statistics
import sys

CAP_PREFIXES = (
    "Landroid/telephony/", "Landroid/accessibilityservice/", "Landroid/view/accessibility/", "Landroid/net/", "Ljava/net/", "Ljavax/net/",
    "Landroid/content/pm/", "Landroid/app/admin/", "Landroid/location/", "Landroid/media/", "Landroid/hardware/", "Landroid/provider/",
    "Landroid/webkit/", "Landroid/bluetooth/", "Landroid/nfc/", "Landroid/security/", "Ljavax/crypto/", "Ljava/security/", "Ldalvik/system/",
    "Ljava/lang/reflect/", "Landroid/accounts/", "Landroid/app/NotificationManager", "Landroid/service/", "Landroid/net/wifi/",
    "Landroid/content/ContentResolver", "Landroid/content/BroadcastReceiver", "Landroid/os/PowerManager", "Landroid/os/Process",
    "Ljava/lang/Runtime", "Ljava/lang/ProcessBuilder", "Ljava/lang/Process", "Landroid/app/AlarmManager", "Landroid/app/DownloadManager",
    "Landroid/content/pm/PackageInstaller", "Landroid/view/WindowManager", "Landroid/content/ClipboardManager", "Landroid/os/Environment",
)


def family(pkg: str) -> str | None:
    if pkg.startswith("org.fossify."):
        return "fossify"
    if pkg in ("com.fsck.k9", "net.thunderbird.android"):
        return "k9"
    if pkg.startswith("com.anysoftkeyboard.") or pkg == "com.menny.android.anysoftkeyboard":
        return "asky"
    if pkg.startswith("info.metadude.android.") and pkg.endswith(".schedule"):
        return "metadude"  # added after seeing the first run: same developer's schedule-app template
    return None


def jacc(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a | b else 0.0


def main() -> None:
    rows = json.load(open(sys.argv[1]))
    rows = [{"pkg": r["pkg"], "apis": set(r["apis"])} for r in rows if len(r["apis"]) >= 200]
    n = len(rows)
    df: dict[str, int] = {}
    for r in rows:
        for a in r["apis"]:
            df[a] = df.get(a, 0) + 1
    idf = {a: math.log(n / c) for a, c in df.items()}

    def wj(a: set, b: set) -> float:
        inter = sum(idf[x] for x in a & b)
        union = sum(idf[x] for x in a | b)
        return inter / union if union else 0.0

    variants = {
        "A all-APIs": lambda r: r["apis"],
        "B capability-namespaces": lambda r: {a for a in r["apis"] if a.startswith(CAP_PREFIXES)},
    }
    for name, f in variants.items():
        sets = [f(r) for r in rows]
        rel, unrel = [], []
        for (i, ri), (j, rj) in itertools.combinations(enumerate(rows), 2):
            s = jacc(sets[i], sets[j])
            fa, fb = family(ri["pkg"]), family(rj["pkg"])
            if fa and fa == fb:
                rel.append(s)
            elif not (fa and fb):
                unrel.append(s)
        unrel.sort()
        p99 = unrel[int(0.99 * len(unrel))]
        auc = sum(1 for r_ in rel for u in unrel[::5] if r_ > u) / (len(rel) * len(unrel[::5]))
        print(f"{name:26} related median {statistics.median(rel):.2f} | unrelated median {statistics.median(unrel):.2f} p99 {p99:.2f} | related above unrelated-p99: {sum(1 for x in rel if x > p99)}/{len(rel)} | AUC~{auc:.3f}")
    # IDF-weighted variant (needs corpus statistics, so not usable per-sample at ingest time; shown for reference)
    rel, unrel = [], []
    for (i, ri), (j, rj) in itertools.combinations(enumerate(rows), 2):
        s = wj(ri["apis"], rj["apis"])
        fa, fb = family(ri["pkg"]), family(rj["pkg"])
        if fa and fa == fb:
            rel.append(s)
        elif not (fa and fb):
            unrel.append(s)
    unrel.sort()
    p99 = unrel[int(0.99 * len(unrel))]
    auc = sum(1 for r_ in rel for u in unrel[::5] if r_ > u) / (len(rel) * len(unrel[::5]))
    print(f"{'C IDF-weighted (reference)':26} related median {statistics.median(rel):.2f} | unrelated median {statistics.median(unrel):.2f} p99 {p99:.2f} | related above unrelated-p99: {sum(1 for x in rel if x > p99)}/{len(rel)} | AUC~{auc:.3f}")
    print(f"apps {n}, avg API-set size {statistics.mean(len(r['apis']) for r in rows):.0f}")


if __name__ == "__main__":
    main()
