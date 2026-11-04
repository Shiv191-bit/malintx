"""Summarise lab_results.json: recall with Wilson intervals, per split, abstentions and non-Android files reported separately."""

from __future__ import annotations

import collections
import json
import sys

from malintx.evaluation.metrics import Confusion

rows = json.load(open(sys.argv[1]))
POS = ("high", "critical")


def summarise(sub: list[dict], name: str) -> None:
    android = [r for r in sub if not r.get("not_android")]
    c = Confusion()
    for r in android:
        k = r.get("classification")
        if k in POS:
            c.tp += 1
        elif k in ("informational", "low", "medium"):
            c.fn += 1
        else:
            c.abstain_malicious += 1  # inconclusive / insufficient / failed / unreadable: never counted as caught
    s = c.summary()
    mediumplus = sum(1 for r in android if r.get("classification") in ("medium", *POS))
    unsure = sum(1 for r in android if r.get("classification") in ("inconclusive", "insufficient_evidence") or "error" in r)
    print(f"\n== {name}: {len(sub)} files, {len(sub) - len(android)} non-Android (excluded), {len(android)} Android")
    print("   classes:", dict(collections.Counter(r.get("classification", "ERROR") for r in android)))
    print(f"   recall @ >=high      : {c.tp}/{len(android)} = {s['recall']:.1%}  95% CI {s['recall_ci95']}")
    from malintx.evaluation.metrics import wilson
    print(f"   flagged @ >=medium   : {mediumplus}/{len(android)} = {mediumplus / len(android):.1%}  95% CI {wilson(mediumplus, len(android))}")
    print(f"   flagged or withheld  : {mediumplus + unsure}/{len(android)} = {(mediumplus + unsure) / len(android):.1%} (medium+ plus inconclusive/errors: 'not called clean')")
    print("   still called clean (info/low):", [(r["sha256_name"][:8], r.get("signature"), r.get("score")) for r in android if r.get("classification") in ("informational", "low")][:12])


for split in ("dev", "heldout"):
    summarise([r for r in rows if r.get("split") == split], f"{split.upper()} malware split")
