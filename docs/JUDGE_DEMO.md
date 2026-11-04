# Demo guide for judges (about 8 minutes)

**Pitch in one line:** an Android malware analyser whose verdicts you can audit. Every finding points at evidence, scoring is deterministic, AI is advisory only, and the project reports its own failures with confidence intervals.

## Before the demo (once, about 5 minutes)
```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock.txt
.venv\Scripts\python -m pip install -e . --no-deps
copy .env.example .env                       # no keys needed; add VT_API_KEY / SHODAN_API_KEY only if you want live passive intel
```
Start with a **clean data directory** so judges see only demo data:
```bash
set MALINTX_DATA_DIR=var_demo
.venv\Scripts\python -m malintx.api.app                                   # terminal 1  (API on :8750)
.venv\Scripts\python scripts/seed_demo.py --enrich                        # terminal 2  (--enrich = passive lookups for ONE sample; omit for fully offline)
.venv\Scripts\python -m streamlit run malintx/dashboard/app.py            # terminal 3  (http://localhost:8501)
```
`seed_demo.py` loads eight analyses: six synthetic samples (generated test fixtures, not malware), a second trojan-pattern variant that shares infrastructure with the first, and, if you pass `--real corpus/fdroid/com.fsck.k9_39046.apk corpus/fdroid/net.thunderbird.android_33.apk`, two real benign apps for the lineage demo. Keep `docs/MALWARE_RESULTS.md` open in another tab. Use a window at least 1200 px wide.

## Live script
Outcomes are what the samples actually produce with ruleset r4.

| Min | Do | Say / show |
|---|---|---|
| 0-1 | **Overview** | "No API key, no network, no Java needed. Static analysis only; nothing is executed." Point at the classification chart. |
| 1-2 | **History** -> open `benign_bank.apk` | **informational (3/100)**. SMS and network APIs exist in a legitimate banking app: capability is not intent. Evidence tab: each finding links to its code location. |
| 2-4 | Open `banking_trojan_pattern.apk` | **critical (100)**, 11 composite behaviours. Risk tab: the score is built line by line. ATT&CK tab: techniques. Report tab: forensic PDF. |
| 4-6 | **Network / C2 tab**, then the **Infrastructure** page | The C2 view. Per sample: hard-coded public IP, IP-literal URL, Telegram bot endpoint and the dropper domain, drawn sample -> reference -> hosting owner. With `--enrich`, the IP shows AS63949 / country / ports from Shodan. On the Infrastructure page the two trojan variants are linked **by the shared IP**: a campaign pivot. Say: "A host in code is a lead, not proof of C2; country is where it is hosted, not who runs it; no data is not safe." |
| 6-7 | `remote_control_like.apk`, `packed_loader_stub.apk`, `manifest_only_no_code.apk` | Legit remote-control app is only **medium (32)** (composites need abuse markers; real-data testing caught KDE Connect at HIGH and we fixed it). Packed stub **medium (30)**. No code at all: **insufficient_evidence**, never "safe". Show the near-miss panel in Behaviours. |
| 7 | `prompt_injection.apk` | **informational (5)**: strings in the sample are data, never instructions. (Live AI is optional; it has only been tested with mocks.) |
| 7-8 | **Lineage tab** of K-9 Mail | Hash-free similarity: Thunderbird scores 1.00 (same codebase). Then open MALWARE_RESULTS.md and say the numbers below. |

## The numbers to say out loud (do not round up)
* False positives: **0/60 + 0/60** random real F-Droid apps rated high/critical (95% upper bound 6% each); median about 6 s per APK.
* Detection is **weak**: 10.7% recall at high/critical on 28 held-out real malware APKs; 25.6% (CI 17.3-36.3%) on 78 held-out banking-trojan samples (23.9% de-duplicated); about 65% reach medium or higher.
* "We tuned on a dev set, froze the rules, then measured once on samples we had never seen. Dev looked like 46% at medium or higher; the honest held-out figure was 29%."
* Real malware only ever ran through the **offline Docker lab** (`--network none`, read-only filesystem, no capabilities). Nothing was installed or executed.

## What not to claim
Do not state accuracy, "near-zero false positives" or "zero-day detection" figures from any older slide or paper: they are not results of this project. Use [PRESENTATION.md](PRESENTATION.md) for slide-ready, defensible wording.

## Likely judge questions
| Question | Honest answer |
|---|---|
| "What is the detection rate?" | Low: 10-26% at high/critical on never-seen real malware; about 65% at medium or higher on banking families. Today's strength is explainability and few false alarms on real apps. |
| "Is the C2 map live reconnaissance?" | No. It is passive: static indicators plus opt-in provider lookups (Shodan, VirusTotal). We never touch the hosts. Active probing is unsafe and out of scope. |
| "Why no world map?" | A provider's country for an IP is its hosting location, not an operator's; plotting it implies attribution we cannot support. We show hosting owner and country as labelled data. |
| "Why not just train a classifier?" | Verdicts must be auditable and reproducible. The score is a deterministic function of evidence; AI explains but cannot decide. |
| "Is the AI doing the detection?" | No. It is not an input to the score and has only been tested with mocks, which we say openly. |
| "Did you overfit?" | We separated dev from held-out, froze the rules, measured once, and reported the drop. The 78 family samples are now dev data; new rule changes need a fresh batch. |
| "What is next?" | Score escalation when several composites fire, "inconclusive" for stripped manifests, native/reflection analysis, ZIP recovery (ordered plan in MALWARE_RESULTS.md). |
| "Is the demo safe?" | Yes. Demo APKs are synthetic fixtures; the only network lookups are opt-in and passive. |
