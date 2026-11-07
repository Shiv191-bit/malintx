# Real-data verification (2026-11-03)

First run of MALINT-X on **real APKs** (87, from F-Droid). All raw per-sample results are in [`evidence/`](evidence/); the scripts that produced them are in `scripts/` and are reproducible.

## What was (and was not) measured
* **Label provenance**: every sample is `open_source_build` from F-Droid with URL, retrieval time and SHA-256 in the manifest. "Benign" means *open-source and from an audited repo*, **not** "VirusTotal-verified" (no VT key yet).
* **There is no real malware in this verification.** Recall, family detection and every statement about trojans remain **unmeasured** on real data.

## Datasets
| Set | n | Use |
|---|---|---|
| Development corpus (`evidence/dev_manifest.json`) | 27 hand-picked apps chosen to *stress* the rules: SMS clients, an app store, VPNs, a keyboard, KDE Connect, AppManager… | Rules were tuned here (r1 → r3). **Not a measurement.** |
| Held-out set (`evidence/holdout_manifest.json`) | 60 apps, uniform random sample of the F-Droid index (seed 20261103), excluding the development apps | Rules frozen at **r3** *before* running; run once. This is the measurement. |

## Findings that changed the product (all from real data)
| # | Observation on real apps | Fix |
|---|---|---|
| 1 | Worker and JADX shared capture filenames → crash (found when real JADX first ran) | unique capture files per run |
| 2 | **KDE Connect rated HIGH (67)** by the "banking-trojan" composite; it really has accessibility + overlay + SMS + network | composites now require an *abuse marker* (SMS-priority interception, target-app list, IP-literal/Telegram C2, packer…) |
| 3 | `AccessibilityNodeInfo.performAction` fired on F-Droid, Fossify (ordinary delegate code; minified libraries defeat namespace filtering) | API rule now requires the app to be an accessibility service |
| 4 | `setResultCode` used by AndroidX/Coil receivers counted as an SMS-abort signal | only `abortBroadcast` counts |
| 5 | F-Droid/Aurora/Amaze/Material Files flagged "dropper"; Fossify "SMS forwarding"/"stealth" | dropper/stealth need a C2/stealth marker; SMS composites require a BroadcastReceiver class; overlay+accessibility app-wide is only MEDIUM |
| 6 | AppManager (27 MB, multi-DEX) hit the 3 GB worker limit | default 6 GB + explicit error message |
| 7 | A `.env` with `MALINTX_DATA_DIR=./var` broke the isolated worker (relative path, other cwd) | paths resolved to absolute |

## Held-out result (rules r3, n = 60, run once)
| Metric | Result |
|---|---|
| Classified high or critical | **0 / 60** (Wilson 95% upper bound **6.0%**) |
| Classified medium | 3 / 60 = 5% (95% CI 1.7–13.7%): a wristwatch app with SMS-send, a translator with an accessibility overlay + screen capture (a real remote-control-like capability set), one other |
| Low / informational | 17 / 40 |
| Analysis failures | 0 |
| Time (isolated analysis, no JADX) | median 5.6 s, p95 20.4 s, max 53.8 s: the 90 s target held on all 60 |
Combined with the development set the number of high/critical on 87 real apps is 0 (upper bound 4.2%), but only the 60 are an unbiased estimate. **This bounds false positives on open-source apps. It says nothing about banking apps (none were sampled) or about detection of malware.**

## Behavioural lineage (new feature) on the real corpus
Ground truth = package-family (Fossify suite, K-9↔Thunderbird, AnySoftKeyboard, one metadude schedule family that I only recognised *after* the first run, which is noted here because it inflates the second experiment's fit).
* Fingerprint over *all* framework APIs: related-family median similarity 0.78 vs 0.22 for unrelated; AUC ≈ 0.994 (`evidence/lineage_variants.txt`).
* My hypothesis that a *capability-only* namespace subset would separate better was **wrong** (AUC 0.987), so it was not adopted. IDF weighting is marginally better but needs corpus statistics, so it is not used.
* Calibrated bands: unrelated pairs reach 0.53 (p95) / 0.64 (p99): ≥ 0.65 "closely related", ≥ 0.85 "near-identical". At 0.85, 19% of related pairs are recovered with 0.04% false links; at 0.65, 81% / 1.2% (first run, before adding the metadude family: `evidence/lineage_report.txt`).
* K-9 Mail ↔ Thunderbird: API similarity 1.00 (same codebase), correctly the top match in the live dashboard.
Limitations: only three real families; bands are descriptive, not a classifier; tiny apps look alike (generic APIs).

## Claim ledger
| Claim | Status after this run |
|---|---|
| Pipeline robust on real APKs (multi-DEX, 3–60 MB) | ✅ 87/87 after fixes (1 initial memory failure fixed) |
| 90 s per APK | ✅ on 60/60 held-out (no JADX); JADX adds time (untimed at scale) |
| SMS/accessibility capabilities in legit apps do not produce high/critical | ✅ for open-source apps (0/60, ≤ 6%); ❌ unmeasured for banking apps |
| Detects banking trojans | ❌ **Measured and weak:** 10.7% recall at high/critical on 28 held-out real malware APKs (a mixed recent-upload batch, not banking-specific); see MALWARE_RESULTS.md |
| Low false-positive rate "near zero" | ❌ not claimed; upper bound 6% at n = 60 |
| Lineage separates related apps | ✅ on 3–4 real families; small sample |
| Live VT/Shodan/MalwareBazaar | ✅ first live calls parsed correctly (found and fixed a single-engine-hit false 'suspicious' on 8.8.8.8) |
| Koodous / LLM providers | ⛔ no credentials |
