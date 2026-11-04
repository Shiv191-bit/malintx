# Presentation content (Phaltan Hackathon 2K26 format, 12 slides)

Slide-ready wording that this repository can defend. **Read the first section before reusing the existing PPT.**

## 0. Claims in the current slide template that this project does NOT support
The draft deck states several figures that are not results of MALINT-X and are contradicted or untested by our own measurements. Presenting them as ours would be wrong, and a judge asking for the evidence cannot be answered. Replace them:

| Draft claim | Why it cannot stand | Use instead |
|---|---|---|
| "Near 0% false positive rate" | We measured 0/60 and 0/60 on open-source apps (95% upper bound 6% each); banking apps were never sampled | "0 of 120 randomly sampled real apps rated high/critical (upper bound about 6% each)" |
| "Flags 98.4% of zero-day payload patterns" / "97.8% accuracy" / "96% F1 on DREBIN" | Not measured here. The DREBIN/F1 numbers are other people's published results, not ours | "Recall on never-seen real malware: 10.7% (28 mixed samples) and 25.6% (78 banking-trojan samples) at high/critical" |
| "Tested on Cerberus, Anubis, Hydra" as validation | Tested, but results are weak: Cerberus 0/6, Anubis 1/6, Hydra 1/6 at high/critical | Show the per-family table honestly (see slide 7) |
| "45 minutes to under 30 seconds", "70% less SecOps effort" | Time: median about 6 s per APK measured. The 45-minute and 70% figures are unmeasured | "Median 6 s, p95 20 s, max 54 s on 60 real apps" |
| "Active C2 reconnaissance" | We do passive lookups only; we never contact the hosts | "Passive C2 infrastructure intelligence" |
| "Gemini 1.5 Flash structured reasoning verified" | AI is provider-independent and only mock-tested (no key); it never sets the verdict | "Optional, advisory AI layer with evidence-grounded, validated output" |
| "Zero integration failure points" | Not demonstrable | "Typed JSON contract (schema 1.1), 201 automated tests" |
| TRL 5/6 | Real-sample lab validation, no operational pilot | "TRL 4: validated on real samples in an isolated lab" |

## Slide-by-slide
**1. Problem.** Banking-fraud teams face evasive Android malware; hash blacklists fail against recompilation and sandboxes mislabel legitimate banking apps. Triage today is slow and hard to audit.

**2. Solution.** MALINT-X: deterministic static analysis of an APK that returns an auditable verdict: evidence-linked findings, MITRE ATT&CK for Mobile mapping, passive threat-intel on embedded network indicators, a forensic PDF. Samples are never executed.

**3. Innovation (what is different).**
* Evidence-first scoring: every point in the score traces to a finding; the AI is not an input.
* Honest outcomes: `inconclusive`, `insufficient_evidence`, `analysis_failed` instead of forcing malware/benign.
* Near-miss explanations: what single missing signal separates an app from a trojan pattern.
* Hash-free behavioural lineage: relates variants by the framework APIs they call.

**4. Architecture.** Ingestion -> isolated analysis worker (scrubbed env, timeout, memory limit) -> manifest + bytecode rules -> indicators -> opt-in passive intel -> optional AI -> ATT&CK mapping -> deterministic risk engine -> API, dashboard, PDF. (Diagram: README or ARCHITECTURE.md.)

**5. Unique features and workflow.**
1. Composite behaviour rules with abuse markers (cut false positives on real apps; KDE Connect was HIGH before, medium after).
2. **C2 infrastructure map**: embedded IPs, IP-literal URLs, Telegram bot endpoints, domains; passive ASN/country/ports/detections; samples linked by shared hosts.
3. Near-miss and lineage views.

**6. Market application.** Bank SOC and fraud teams, app-store vetting, audit/compliance (MASVS and ATT&CK-mapped reports). Value: explainable triage that says "I cannot tell" when that is the truth.

**7. Project readiness (use the real numbers).**
* 201 automated tests, lint clean; verified on 87 real F-Droid apps and 147 real malware files (141 Android APKs) in an isolated offline Docker lab.
* False positives: 0/60 and 0/60 random real apps at high/critical.
* Detection: 10.7% (28 mixed samples), 25.6% (78 banking-trojan samples, 67 distinct) at high/critical; about 65% at medium or higher. Per-family: SharkBot 6/6, Ermac 5/6, Vultur 3/6; Cerberus, FluBot, BankBot, GodFather 0/6.
* Method: tuned on a development set, rules frozen, measured once on unseen samples.
* Known gaps, stated up front: native-code and reflection-hidden behaviour, stripped manifests, damaged archives. Ordered fix plan in MALWARE_RESULTS.md.
* Readiness: TRL 4.

**8. Cost and IP.** (Team to complete.) Note third-party components: androguard, JADX, Apktool, MITRE ATT&CK data, provider APIs (VirusTotal, Shodan, MalwareBazaar).

**9. Impact (defensible).** Triage with a reproducible, explainable verdict and a quantified failure rate; a method other teams can audit (open evaluation harness, provenance-checked manifests, Wilson intervals). Do not quote unmeasured percentages.

**10. Research and references.** DroidMat (2012), Sara and Hossain (2023), Bakour et al. survey, with our own measured results shown separately from theirs. Never mix the papers' accuracy figures into our results.

**11. Team.** As in the template.

**12. Value proposition.**
* One line: "An Android malware triage platform you can audit: evidence-linked, deterministic, and honest about what it cannot see."
* Strongest proof: 0/120 false positives on real apps; and, unusually, a published held-out failure analysis with a concrete fix plan.

## Live demo
Follow [JUDGE_DEMO.md](JUDGE_DEMO.md). Seed the demo data first so every page has content.
