# Behavioural lineage and near-miss analysis

## Why
SENTINEL's goal is to judge intent "without relying on file hashes". Hashes change on every re-sign or recompile and class names are trivially obfuscated, but **framework API names cannot be renamed**. MALINT-X fingerprints the *set of framework APIs the app's own (non-library) code calls* with a 128-slot MinHash. Two builds of one codebase, a repack, or an identifier-obfuscated copy stay similar while every file hash differs.

## Capabilities
* `GET /api/v1/analyses/{id}/similar`: other analysed samples ranked by estimated Jaccard similarity, plus permission/behaviour similarity and same-signer flag.
* `GET /api/v1/diff?base=&other=`: deterministic capability delta (permissions, findings, components, indicators), with a repackaging signal: *same package, different signer* and added high-severity capabilities.
* Dashboard **Lineage** tab and the **Near misses** panel in Behaviours.
* **Near misses**: high-severity behaviour patterns that did *not* fire, and the single missing requirement. This explains benign results ("this is not a banking trojan because it lacks SMS interception / C2 markers") and shows what an evader would have to add.

## Properties verified by tests
Deterministic; independent of set order; estimates true Jaccard within ±0.12 (128 slots); unchanged by class renaming (similarity 1.0); a repack adding SMS sending + dynamic loading is close but distinguishable and the diff names exactly what was added.

## Honest limits
It is similarity evidence, not attribution or a verdict, and never affects the risk score. Apps that share large frameworks look similar; very small apps look alike; calibration used three real families (see REAL_DATA_VERIFICATION.md). A malicious variant that adds many new APIs can reduce similarity.
