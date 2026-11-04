# MALINT-X

Android malware analysis and threat-intelligence platform. Upload an APK; get validated metadata, manifest intelligence, evidence-backed behavioural findings, extracted indicators, optional passive threat-intel and AI interpretation, MITRE ATT&CK for Mobile mapping, a deterministic explainable risk assessment, a dashboard and a forensic PDF.

**Evidence first. Intelligence second. AI third.** The AI can never invent evidence or set the verdict; the core pipeline needs no API key, network or Java.

* Static analysis only. Samples are never executed.
* Honest outcomes: `informational … critical`, plus `inconclusive`, `insufficient_evidence`, `analysis_failed`. A low score is not a safety certificate.
* Capability ≠ intent ≠ vulnerability: SMS APIs in a banking app are not malice; misconfigurations are reported separately and never add to the score.
* **Hash-free behavioural lineage** and **near-miss explanations** (what single signal separates an app from a trojan pattern): [docs/LINEAGE.md](docs/LINEAGE.md).
* **Measured on real data, honestly:** 0/60 + 0/60 randomly sampled real F-Droid apps rated high/critical (95% upper bound 6% each), median ~6 s. **On never-seen real malware recall is weak: 10.7% at high/critical on 28 mixed recent APKs, 25.6% (CI 17.3–36.3%) on 78 banking-trojan family samples, 65% at medium+.** Today this is a low-false-positive triage/explanation tool, not a malware detector. See [docs/MALWARE_RESULTS.md](docs/MALWARE_RESULTS.md) and [docs/REAL_DATA_VERIFICATION.md](docs/REAL_DATA_VERIFICATION.md).

## Quick start
See [docs/SETUP.md](docs/SETUP.md). In short: install `requirements.lock.txt`, run `python -m malintx.api.app` and `streamlit run malintx/dashboard/app.py`.

## Verified status (this repository)
Automated suite (183 tests) passes, ruff clean. Verified in a browser, with real JADX 1.5.6 / Apktool 3.0.3, and on 87 real F-Droid APKs. Live VirusTotal, Shodan and MalwareBazaar calls verified; Docker image builds and the isolated malware lab ran. **Not verified**: banking-trojan families specifically, banking apps as benign controls, Koodous, any LLM provider (no key). Details in [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md).

## Documentation
[Product requirements](docs/PRODUCT_REQUIREMENTS.md) · [Architecture](docs/ARCHITECTURE.md) · [Roadmap](docs/IMPLEMENTATION_ROADMAP.md) · [Security model](docs/SECURITY_MODEL.md) · [API contracts](docs/API_CONTRACTS.md) · [Technical decisions](docs/TECHNICAL_DECISIONS.md) · [Repository audit](docs/REPOSITORY_AUDIT.md) · [Datasets & evaluation](docs/DATASETS_AND_EVALUATION.md) · [Real-data verification](docs/REAL_DATA_VERIFICATION.md) · [Lineage](docs/LINEAGE.md) · [Malware results](docs/MALWARE_RESULTS.md) · [Malware lab](docs/MALWARE_LAB.md) · [Agent handoff](docs/AGENT_HANDOFF.md)

`legacy/` holds the archived pre-0.2 scaffold (non-functional; kept for reference).
