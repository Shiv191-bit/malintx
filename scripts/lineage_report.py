"""Evaluate lineage similarity on a fingerprinted real corpus using *package-family* ground truth.

Ground truth ("related") = same upstream family by package namespace: org.fossify.* (one codebase template),
com.fsck.k9 <-> net.thunderbird.android (Thunderbird is K-9's successor), com.anysoftkeyboard.* / com.menny.android.anysoftkeyboard.
Everything else is treated as unrelated (an approximation: some unrelated pairs may share libraries).
"""

from __future__ import annotations

import itertools
import json
import statistics
import sys

from malintx.lineage import similarity


def family(pkg: str) -> str | None:
    if pkg.startswith("org.fossify."):
        return "fossify"
    if pkg in ("com.fsck.k9", "net.thunderbird.android"):
        return "k9-thunderbird"
    if pkg.startswith("com.anysoftkeyboard.") or pkg == "com.menny.android.anysoftkeyboard":
        return "anysoftkeyboard"
    return None


def main() -> None:
    rows = [r for r in json.load(open(sys.argv[1])) if r["lineage"] and r["lineage"]["api_count"] >= 200]  # skip tiny stub apps
    related, unrelated = [], []
    detail = []
    for a, b in itertools.combinations(rows, 2):
        s = similarity(a["lineage"]["minhash"], b["lineage"]["minhash"])
        if s is None:
            continue
        fa, fb = family(a["pkg"]), family(b["pkg"])
        if fa and fa == fb:
            related.append(s)
            detail.append((s, a["pkg"], b["pkg"]))
        elif not (fa and fb):
            unrelated.append(s)

    def pct(xs, q):
        xs = sorted(xs)
        return xs[min(len(xs) - 1, int(q * len(xs)))]

    print(f"apps compared: {len(rows)}  related pairs: {len(related)}  unrelated pairs: {len(unrelated)}")
    print(f"RELATED   min {min(related):.2f}  median {statistics.median(related):.2f}  max {max(related):.2f}")
    print(f"UNRELATED p50 {pct(unrelated, .5):.2f}  p95 {pct(unrelated, .95):.2f}  p99 {pct(unrelated, .99):.2f}  max {max(unrelated):.2f}")
    for th in (0.45, 0.55, 0.65, 0.75, 0.85):
        tp = sum(1 for s in related if s >= th)
        fp = sum(1 for s in unrelated if s >= th)
        print(f"threshold {th:.2f}: related recovered {tp}/{len(related)} ({tp / len(related):.0%}), unrelated falsely linked {fp}/{len(unrelated)} ({fp / len(unrelated):.2%})")
    print("lowest related pairs:", sorted(detail)[:4])
    top = []
    for a, b in itertools.combinations(rows, 2):
        s = similarity(a["lineage"]["minhash"], b["lineage"]["minhash"])
        if s and not (family(a["pkg"]) and family(a["pkg"]) == family(b["pkg"])):
            top.append((s, a["pkg"], b["pkg"]))
    print("highest-scoring pairs NOT in my ground-truth families:")
    for s, a, b in sorted(top, reverse=True)[:8]:
        print(f"   {s:.2f}  {a}  <->  {b}")


if __name__ == "__main__":
    main()
