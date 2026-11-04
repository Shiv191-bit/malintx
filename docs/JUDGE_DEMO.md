# Demo guide for judges (about 8 minutes)

**Pitch in one line:** an Android malware analyser whose verdicts you can audit. Every finding points at evidence, scoring is deterministic, AI is advisory only, and the project reports its own failures with confidence intervals.

## Before the demo (5 minutes, once)
```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock.txt
.venv\Scripts\python -m pip install -e . --no-deps
copy .env.example .env                                   # no keys needed for the demo
.venv\Scripts\python scripts/make_demo_samples.py        # writes demo_samples\*.apk (synthetic, no malware)
.venv\Scripts\python -m malintx.api.app                  # terminal 1
.venv\Scripts\python -m streamlit run malintx/dashboard/app.py   # terminal 2 -> http://localhost:8501
```
Optional: pre-analyse all six samples before judges arrive so results are instant. Keep `docs/MALWARE_RESULTS.md` open in another tab.

## Live script
Outcomes below are what the six synthetic samples actually produce with ruleset r4.

| Min | Do | Say / show |
|---|---|---|
| 0-1 | Overview page | "No API key, no network, no Java needed. Static analysis only; nothing is executed." |
| 1-2 | Analyze `01_benign_bank.apk` | **informational (3/100).** SMS and network APIs exist in a legitimate banking app: capability is not intent. Open the Evidence tab: each finding links to its code location. |
| 2-4 | Analyze `02_banking_trojan_pattern.apk` | **critical (100)** with 11 composite behaviours (SMS exfiltration, overlay + accessibility, SMS interception, loader, dropper...). Risk tab: the score is built line by line. ATT&CK tab: mapped techniques. Report tab: download the forensic PDF. |
| 4-5 | Analyze `04_remote_control_like.apk` | A legitimate remote-control app (accessibility + overlay + SMS) is only **medium (32)**, because composites need abuse markers. This is the false-positive control; real-data testing found KDE Connect rated HIGH and we fixed it. |
| 5-6 | `03_packed_loader_stub.apk`, then `06_manifest_only_no_code.apk` | Packed stub: **medium (30)** via the loader rule. No code at all: **insufficient_evidence**, not "safe". "Unknown is not safe." Show the near-miss panel: what single signal separates an app from the trojan pattern. |
| 6-7 | `05_prompt_injection.apk` (contains "IGNORE ALL PREVIOUS INSTRUCTIONS...") | **informational (5)**. Strings in the sample are data, never instructions; the AI layer cannot set the verdict. (Live AI is optional and was only tested with mocks.) |
| 7 | Lineage tab | Hash-free behavioural similarity and capability diff between two apps. On real apps K-9 Mail vs Thunderbird scored 1.00. |
| 7-8 | Open MALWARE_RESULTS.md | Say the honest numbers below. |

## The numbers to say out loud (do not round up)
* False positives: **0/60 + 0/60** random real F-Droid apps rated high/critical (95% upper bound 6% each), median about 6 s per APK.
* Detection is **weak**: 10.7% recall at high/critical on 28 held-out real malware APKs; 25.6% (CI 17.3-36.3%) on 78 held-out banking-trojan samples (23.9% after removing near-duplicates). About 65% reach medium or higher.
* "We tuned on a dev set, froze the rules, then measured once on samples we had never seen. Dev looked like 46% at medium or higher; the honest held-out figure was 29%."
* Real malware only ever ran through the **offline Docker lab**: `--network none`, read-only filesystem, all capabilities dropped. Nothing was installed or executed.

## Optional live extras
* A real benign APK: `python scripts/fetch_fdroid_random.py corpus/demo 3 12345 corpus/fdroid/manifest.json`, then upload one (about 6 s).
* Threat intel: needs keys in `.env`; hashes go to providers only when the opt-in box is ticked.
* Tests: `.venv\Scripts\python -m pytest tests -q` (193 pass, about 1 minute).

## Likely judge questions
| Question | Honest answer |
|---|---|
| "What is the detection rate?" | Low: 10-26% at high/critical on never-seen real malware; about 65% at medium or higher on banking families. Today's strength is explainability and few false alarms. |
| "Why not just train a classifier?" | Verdicts must be auditable and reproducible. The score is a deterministic function of evidence; AI explains but cannot decide. |
| "Is the AI doing the detection?" | No. It is not an input to the score, and it has only been tested with mocks (no key), which we say openly. |
| "Did you overfit to your test data?" | We separated dev from held-out, froze the rules, measured once, and reported the drop. The 78 family samples are now dev data; new rule changes need a fresh batch. |
| "What is next?" | Score escalation when several composites fire, "inconclusive" for stripped manifests, native/reflection analysis, ZIP recovery (ordered plan in MALWARE_RESULTS.md). |
| "Is the demo safe?" | Yes. The demo APKs are synthetic fixtures; real malware stays inside the offline container. |
