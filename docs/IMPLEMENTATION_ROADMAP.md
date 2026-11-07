# MALINT-X Implementation Roadmap (single source of truth)

Status legend: ✅ done and tested · 🟡 implemented, only partly verified (reason given) · ⛔ blocked · ⬜ not started.
"Tested" means automated tests in `tests/` pass in this repository (`pytest`: see AGENT_HANDOFF.md for the last real result).

## Phase 0: Repository audit ✅
Findings are in [REPOSITORY_AUDIT.md](REPOSITORY_AUDIT.md). The pre-existing scaffold was archived to `legacy/` (not deleted); nothing in it ran.

## Phase 1: Architecture and foundation ✅
Typed versioned schemas (`malintx/schemas`, contract 1.0), centralised settings with no import-time side effects, explicit error types, SQLite storage with ordered migrations, secret-redacting structured logging, isolated workspaces.

## Phase 2: APK ingestion ✅
Streaming upload with hard size cap, magic/ZIP validation, zip-bomb/entry-count/ratio limits, duplicate detection (SHA-256 content-addressed store), traversal/duplicate-entry flagging, SHA-256/SHA-1/MD5, ZIP timestamps, DEX/native/asset inventory. Never executes the sample; filename and MIME never trusted.

## Phase 3: Static analysis ✅
* ✅ Androguard backend: binary manifest, DEX per-file resilience, signing certificates (v1/v2/v3), cross-references with byte offsets, bytecode slices (±25 instructions).
* ✅ Manifest analysis: permissions, custom permissions, exported components, intent filters + priority, accessibility/device-admin, cleartext/backup/debuggable, SDK levels.
* ✅ Rule catalog 2026.11-r1: 21 API rules, 5 class rules, 10 string rules, 21 manifest rules (+1 target-app-list string heuristic), 10 composite behaviours.
* ✅ JADX source slices (line numbers, ±25 source lines) and the Apktool manifest cross-check were verified against **real JADX 1.5.6 and Apktool 3.0.3 on Microsoft OpenJDK 21** (JADX/Apktool in git-ignored `tools/`). Only synthetic APKs were decompiled (JADX reports expected errors on them); real-world obfuscated/multi-DEX APKs remain untested.

## Phase 4: Artifact extraction and evidence ✅
IPs (global only; resolvers annotated), URLs, domains, e-mails, file paths, package references, high-entropy blobs, text assets. Deterministic evidence IDs with full provenance and limitations.

## Phase 5: Threat intelligence 🟡
VirusTotal v3, Shodan, MalwareBazaar, Koodous (experimental) adapters with host pinning, retries/backoff, `Retry-After`, per-provider rate limits, caching, wait budget, graceful degradation. **Tested only against mocked transports; no credentials were available, so no live call was ever made.**

## Phase 6: GenAI reasoning 🟡
Provider-independent layer (Anthropic tool-use, Gemini responseSchema, OpenAI-compatible), strict schema validation, evidence-ID grounding (claims citing unknown evidence are dropped), ATT&CK ID validation, retries with error feedback, prompt-injection isolation. **Wire formats tested against mocks only; never run against a live model.**

## Phase 7: Risk engine ✅
Deterministic, order-independent, explainable; diminishing returns; composites; intel corroboration; floors; classifications including inconclusive / insufficient_evidence / analysis_failed.

## Phase 8: Dashboard ✅
Streamlit app: Overview, Analyze (upload + consent), Progress, Analysis (Summary, Manifest, Behaviours, Evidence, Threat intel, ATT&CK, Risk, AI, Report), History, Configuration. Backed only by the API. Verified in a real browser against live API data and with AppTest.

## Phase 9: Forensic reporting ✅
ReportLab PDF with all required sections, deterministic/AI separation, traceability digest, explicit non-chain-of-custody statement.

## Phase 10: Testing, hardening, deployment 🟡
* ✅ Unit, integration and end-to-end tests (API upload → isolated worker → scoring → PDF → dashboard), ruff clean, dependency lock.
* 🟡 Dockerfile / compose written but **not built** in this environment.
* ⬜ CI pipeline, SBOM, signed images.

## Evaluation framework ✅ (framework) / ⛔ (measurements)
Manifest with enforced provenance and split hygiene, metrics with CIs and abstentions, consistency and ATT&CK-mapping scoring, calibration on calibration split only. **No real malware/benign corpus has been run; no accuracy claim is made anywhere.**

## Real-data verification ✅ (benign) / ⛔ (malware)
87 real F-Droid APKs analysed; rules tuned on 27, frozen (r3) and measured on 60 random held-out apps: see [REAL_DATA_VERIFICATION.md](REAL_DATA_VERIFICATION.md). **No real malware yet: needs an abuse.ch Auth-Key and an isolated analysis environment.**

## Behavioural lineage + near-miss ✅
See [LINEAGE.md](LINEAGE.md).

## Next tasks (priority order)
1. (done) Real benign APKs through the pipeline; JADX on large real APKs is still untimed.
2a. (done) Isolated malware lab run: see [MALWARE_RESULTS.md](MALWARE_RESULTS.md). **Recall is low (10.7% at high+): the main open problem.** Next: family-targeted batch, triage of missed samples, lenient ZIP recovery.
2. Provide credentials and run each intel adapter once against the live service; record actual response shapes.
3. Assemble an evaluation corpus (see DATASETS_AND_EVALUATION.md) inside an isolated lab VM; run `malintx-eval`.
4. Calibrate rule weights on the calibration split; add rules for families found in the corpus (e.g. ATS/overlay variants, native-code loaders).
5. Build and scan the container image; add CI.
6. Multi-user auth (current model is single trusted operator + optional bearer token).
