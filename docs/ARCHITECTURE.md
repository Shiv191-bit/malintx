# MALINT-X Architecture

A **modular monolith**: one Python package, one process for API + job runner, with the one component that touches hostile bytes (static analysis) isolated in a child process. No microservices: nothing here needs independent scaling, and the module boundaries (typed schemas) allow splitting later.

```
 upload ─► ingestion ─► [subprocess worker: androguard (+JADX/Apktool)] ─► StaticAnalysisResult
 (API/UI)  validate,       manifest, DEX rules, strings, indicators,         │ evidence, findings,
           hash, store     composites, ATT&CK map                            │ indicators, mitre
                                                                              ▼
              optional, consent-gated:  IntelService ──► IntelReport ──┐
                                        AI service  ──► AIResult ──────┤ (advisory only)
                                                                       ▼
                                   risk.assess(static, intel)  ──► RiskResult (no AI input)
                                                                       ▼
                               SQLite (jobs/results) + PDF report ─► API ─► Streamlit dashboard
```

## Principles
1. **Evidence first, intelligence second, AI third.** AI receives only extracted evidence, cannot add evidence, and its claims are discarded unless they cite real evidence IDs. It never feeds the risk engine.
2. **Extraction is independent of every external service.** The pipeline completes with no keys, no network and no JRE.
3. **Capability ≠ intent ≠ vulnerability.** Single signals are `suspicious_capability`; only correlated patterns are `malicious_behavior`; misconfigurations are a separate posture channel that never adds to the score.
4. **Never force a verdict.** Classifications include `inconclusive`, `insufficient_evidence`, `analysis_failed`.
5. **Unknown is not safe** at every layer (intel, packers, failed parsers).

## Modules
| Package | Responsibility |
|---|---|
| `schemas` | Pydantic contracts, `schema_version` 1.0 (`extra="forbid"`) |
| `config`, `errors`, `logging_setup` | Settings (env/.env), error taxonomy, JSON logs with secret redaction |
| `ingestion` | Streaming upload cap, ZIP inspection and limits, hashing, content-addressed store, workspaces |
| `tools` | `runner` (sandboxed subprocess), `decompilers` (JADX/Apktool adapters, `SourceIndex`) |
| `analysis` | `backends` (androguard), `manifest`, `rules` (catalog/engine/manifest rules/evidence), `indicators`, `mitre_map`, `static` orchestrator, `worker` + `runner` (isolation) |
| `mitre` | Loader for the vendored ATT&CK for Mobile v20.0 STIX bundle (SHA-256 recorded) |
| `intel` | `http` (host-pinned passive client), `providers`, `service` (cache, budget, verdict aggregation) |
| `ai` | `context` (bounded evidence payload), `prompts`, `providers`, `service` (validation/grounding/retries) |
| `risk` | Deterministic engine and methodology |
| `reports` | ReportLab PDF |
| `pipeline` | `JobRunner`: stages, fault isolation, duplicate detection, crash recovery |
| `storage` | SQLite + migrations, repository, intel cache |
| `api` | FastAPI v1, auth, rate limit, upload cap |
| `dashboard` | Streamlit UI over the API |
| `evaluation` | Dataset manifests, metrics, runner, CLI |

## Analysis details
* **Backend**: androguard parses DEX per file (a corrupt `classesN.dex` reduces coverage instead of aborting). Call sites come from method cross-references with byte offsets; slices are disassembly windows around the call.
* **Rules** are data (`rules/catalog.py`). Hits record which *exact class* they occurred in; composites require that the supporting signals co-occur in the same class (high confidence) or only app-wide (medium confidence, often lower severity, some rules refuse app-wide). Nested classes are deliberately **not** folded into their owner, to avoid joining an activity's inner OTP receiver with unrelated networking code.
* **Library attribution**: hits only inside well-known SDK namespaces get low confidence and are ignored by composites.
* **Context suppression**: use of Google's SMS Retriever / User Consent API, with no SMS sending, abort or hard-coded-endpoint forwarding, lowers SMS-read findings to low severity (disclosed in the result).
* **Coverage flags** (packer signatures, failed DEX, no code, obfuscation ratio) drive the non-binary classifications.

## Job states
`queued → static_analysis → threat_intel → ai_reasoning → scoring → reporting → completed | failed`. Optional stages record `skipped` when not requested or not configured. Jobs interrupted by a crash are marked `failed/interrupted` at the next start.

## Known limitations
Bytecode references do not prove reachability; native code, encrypted/packed payloads, reflection-built calls and server-side logic are invisible; JADX/Apktool paths need a JRE; weights are expert-set, not calibrated; single-operator security model.
