# MALINT-X

Android malware analysis and threat-intelligence platform. Upload an APK; get validated metadata, manifest intelligence, evidence-backed behavioural findings, extracted indicators, optional passive threat-intel and AI interpretation, MITRE ATT&CK for Mobile mapping, a deterministic explainable risk assessment, a dashboard and a forensic PDF.

**Evidence first. Intelligence second. AI third.** The AI can never invent evidence or set the verdict; the core pipeline needs no API key, network or Java.

* Static analysis only. Samples are never executed.
* Honest outcomes: `informational … critical`, plus `inconclusive`, `insufficient_evidence`, `analysis_failed`. A low score is not a safety certificate.
* Capability ≠ intent ≠ vulnerability: SMS APIs in a banking app are not malice; misconfigurations are reported separately and never add to the score.
* **No detection-accuracy figure is claimed.** The evaluation framework exists; no real corpus has been run. See [docs/DATASETS_AND_EVALUATION.md](docs/DATASETS_AND_EVALUATION.md).

## Quick start
See [docs/SETUP.md](docs/SETUP.md). In short: install `requirements.lock.txt`, run `python -m malintx.api.app` and `streamlit run malintx/dashboard/app.py`.

## Verified status (this repository)
Full automated suite passes (unit, integration, API e2e, dashboard, report, evaluation), ruff clean. Verified in a browser against live API data. JADX 1.5.6 / Apktool 3.0.3 were verified on synthetic APKs. **Not verified**: real-world APKs, live VirusTotal/Shodan/MalwareBazaar/Koodous, live LLM providers, Docker build, any real malware/benign corpus. Details in [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md).

## Documentation
[Product requirements](docs/PRODUCT_REQUIREMENTS.md) · [Architecture](docs/ARCHITECTURE.md) · [Roadmap](docs/IMPLEMENTATION_ROADMAP.md) · [Security model](docs/SECURITY_MODEL.md) · [API contracts](docs/API_CONTRACTS.md) · [Technical decisions](docs/TECHNICAL_DECISIONS.md) · [Repository audit](docs/REPOSITORY_AUDIT.md) · [Datasets & evaluation](docs/DATASETS_AND_EVALUATION.md) · [Agent handoff](docs/AGENT_HANDOFF.md)

`legacy/` holds the archived pre-0.2 scaffold (non-functional; kept for reference).
