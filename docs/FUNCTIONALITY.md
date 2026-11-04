# MALINT-X: what it does

Static Android malware analysis and threat-intel platform. **Evidence first, intelligence second, AI third.** Samples are never executed. Everything below exists in this repository and is covered by tests (201 passing); weak or unmeasured items are marked.

## 1. Pipeline (one APK in, one explainable assessment out)
| Stage | What it does | Notes |
|---|---|---|
| Ingestion | Size/type limits, magic-byte check, SHA-256/SHA-1/MD5, ZIP anomaly scan (duplicate names, traversal, suspicious entries), safe storage | Streaming upload cap; rejects non-APKs (e.g. Java JARs mislabelled upstream) |
| Isolated analysis worker | Parsing runs in a separate process: scrubbed environment, timeout with tree-kill, memory limit (Windows Job Object / POSIX RLIMIT), capped output | A crashing or hostile APK cannot take down the API |
| Manifest intelligence | Permissions, SDK levels, components, exported surfaces, intent filters (e.g. SMS receivers with elevated priority), signing certificate | androguard 4.1.4 |
| Bytecode analysis | Per-DEX call sites, API usage, strings, class structure, packer/obfuscation hints, native libraries | Native code is **not** analysed (known gap) |
| Rule engine (ruleset `2026.11-r4`) | API/class/string/manifest rules plus composite behaviours with exact-class correlation, prerequisites, library-namespace filtering, `unless` guards | Findings carry evidence IDs back to concrete code or manifest locations |
| Near-miss analysis | For each high-severity behaviour that did **not** fire: how many requirements were met and exactly what was missing | Explains why an app is *not* called a trojan |
| Behavioural lineage | MinHash (128) fingerprint over framework APIs used by app code; `/similar` and `/diff` find related apps without hashes and show capability differences | Calibrated on real apps (related median 0.78 vs unrelated 0.22); only a few real families tested |
| Infrastructure ("C2") view | Network indicators (hard-coded public IPs, IP-literal URLs, Telegram bot endpoints, domains) are drawn sample -> reference -> hosting owner, ranked by how unusual the reference is, with ASN/owner/country/open ports/detections only when a passive provider lookup returned them; hosts shared by several samples are listed as pivots. Never contacts any host | A reference is a lead, not proof of C2; country is hosting location, not operator; no data is never shown as safe. OID strings, CIDR bases and Java identifiers are filtered from the extractor |
| Threat intel (opt-in, passive) | VirusTotal, Shodan, MalwareBazaar (+ experimental Koodous): retry/backoff, rate limiting, caching, host-pinned, consent-gated | Verified live for VT/Shodan/MalwareBazaar; Koodous unverified |
| AI interpretation (opt-in, advisory) | Anthropic / Gemini / OpenAI-compatible; claims must cite evidence IDs and pass schema validation; prompt-injection isolated; **never a scoring input** | Verified with mocks only (no key available) |
| MITRE ATT&CK for Mobile | Findings mapped to technique IDs (dataset v20) | IDs integrity-tested |
| Risk engine | Deterministic: severity x kind weight x confidence weight, diminishing returns, floors, `inputs_digest` for reproducibility | Outcomes: `informational` .. `critical`, plus `inconclusive`, `insufficient_evidence`, `analysis_failed` |
| Outputs | REST API v1, Streamlit dashboard, forensic PDF, schema contract 1.1 | |

## 2. Finding kinds (capability is not intent is not vulnerability)
`malicious_behavior` (composites only) | `suspicious_capability` | `security_misconfiguration` | `informational`. Misconfigurations never add to the risk score.

## 3. Interfaces
* **API** (`python -m malintx.api.app`, `127.0.0.1:8750`, optional bearer token, rate limits): `GET /health`, `/config`, `/overview`, `/infrastructure`; `POST /analyses`; `GET /analyses`, `/analyses/{id}`, `/analyses/{id}/result`, `/analyses/{id}/report` (PDF), `/analyses/{id}/similar`, `/diff`.
* **Dashboard** (`streamlit run malintx/dashboard/app.py`): pages Overview, Analyze, Analysis, Infrastructure, History, Configuration. Flat light design (no gradients, glow or translucency). The Analysis page has tabs Summary, Manifest, Behaviours, Evidence, Network / C2, Threat intel, ATT&CK, Risk, Lineage, AI, Report. Deep link: `?job=<id>`.
* **Evaluation CLI** (`python -m malintx.evaluation.cli`): manifest-provenance rules, Wilson confidence intervals, abstention accounting, calibration on a separate split.
* **Malware lab** (`scripts/malware_lab.py build|fetch|analyze`): Docker-only. Fetch container (network on, never unzips) and analysis container (`--network none`, read-only fs, all capabilities dropped, no-new-privileges, memory/pids limits). Nothing is installed or executed.
* **Demo data**: `scripts/make_demo_samples.py` writes synthetic APKs; `scripts/seed_demo.py` loads them into a running API (optionally with passive intel).

## 4. Measured results (real data, rules frozen before measuring; see MALWARE_RESULTS.md and REAL_DATA_VERIFICATION.md)
| Claim | Result |
|---|---|
| False positives, real open-source apps | 0/60 and 0/60 random F-Droid apps rated high/critical (95% upper bound 6% each); median ~6 s per APK |
| Recall, mixed recent real malware (28 held-out) | **10.7%** at high/critical (CI 3.7-27.2%), 28.6% at medium+ |
| Recall, banking-trojan families (78 held-out, 67 distinct) | **25.6%** at high/critical (CI 17.3-36.3%), 65% at medium+; deduplicated 23.9% |
| Strongest / weakest families | SharkBot 6/6 and Ermac 5/6; Cerberus, FluBot, BankBot, GodFather 0/6 |

## 5. Honest limits
* **Not a malware detector today.** It is a low-false-positive triage and explanation tool; most banking trojans are not rated high.
* Misses: behaviour hidden in native code or reflection, stripped manifests, damaged ZIPs (no lenient recovery yet), very large apps (over the 6 GiB worker memory limit).
* Triage of the misses and the ordered fix plan: MALWARE_RESULTS.md. Any rule change needs a fresh held-out batch.
* Rule weights are expert-set, not calibrated. A low score is never a safety certificate. Live LLM calls and Koodous are unverified.
