# API contracts (v1, schema_version "1.1")

Base path `/api/v1`. All errors use `{"error": {"code": str, "message": str}}`. If `MALINTX_API_TOKEN` is set every call needs `Authorization: Bearer <token>`. Interactive OpenAPI: `/api/docs`. Every response carries `X-Request-ID`.

| Method & path | Purpose | Notes |
|---|---|---|
| `GET /health` | liveness, version, schema, DB migration | |
| `GET /config` | versions (platform, schema, ruleset, risk engine, ATT&CK + dataset SHA-256), provider configured-flags, decompiler availability, limits | never returns secrets |
| `GET /overview` | counts: jobs, samples, by status, by classification | |
| `POST /analyses` (multipart) | fields: `file` (required), `enrich` (bool), `ai` (bool), `force` (bool) → **202** `{job, reused_existing}` | 400 `not_an_apk`/`corrupt_archive`/`unsafe_archive`/`invalid_sample`; 413 `oversized_upload`; 429 `rate_limited`. Identical bytes reuse the latest completed job unless `force` (or the requested options exceed that job's) |
| `GET /analyses?limit&offset` | history rows with headline result | |
| `GET /analyses/{id}` | `JobInfo` with per-stage state/message | poll until `status ∈ {completed, failed}` |
| `GET /analyses/{id}/result` | full `AnalysisResult` (200) or `{job, result:null}` (202 while running); 404 if none | failed jobs still have a result (`analysis_failed`) |
| `GET /analyses/{id}/similar?limit&min_similarity` | hash-free lineage matches (MinHash over framework APIs) | `available:false` when the sample has no analysable code |
| `GET /infrastructure?limit=` | network hosts referenced by analysed samples (latest result per sample): role, passive-intel summary (ASN/owner/country/ports/families only when a provider returned them), which samples share each host | `queried:false` hosts have verdict `unknown` (never "safe"); roles are descriptions of the reference, not verdicts |
| `GET /diff?base=&other=` | capability delta between two analyses + similarity | 404 unless both have static results |
| `GET /analyses/{id}/report` | PDF, header `X-Report-SHA256` | 404 if not generated |

## Core types (see `malintx/schemas`, `extra="forbid"`)
* `AnalysisResult{schema_version, job, static, intel, ai, risk, report_available, platform_version}`
* `StaticAnalysisResult{sample, manifest, evidence[], findings[], indicators[], mitre[], coverage, ruleset_version, warnings[]}`
* `Evidence{id "EV-…", kind, rule_id, source_file, class_name, method_name, line_number?, bytecode_offset?, api?, artifact?, snippet?, extraction_method, confidence, limitations}`: IDs are deterministic.
* `Finding{id, rule_id, kind(malicious_behavior|suspicious_capability|security_misconfiguration|informational), severity, confidence, category, evidence_ids[], mitre_ids[], masvs[], composite_of[], false_positive_notes, suppressed_by[], limitations}`
* `MitreMapping{technique_id, technique_name, tactics[], source, url, evidence_ids[], finding_ids[], rationale, confidence, origin}`
* `IntelReport{requested, providers{name→status}, sample_lookups[], sample_verdict, indicators[], skipped_indicators, notes[]}`; verdicts `known_malicious|suspicious|unknown|benign_observed`; lookup statuses `ok|not_found|unconfigured|skipped|unavailable|rate_limited|error`.
* `AIResult{status(not_requested|unconfigured|completed|failed|invalid_output), assessment?, dropped_claims[], accepted_mitre[], attempts, …}`
* `RiskResult{classification(informational|low|medium|high|critical|inconclusive|insufficient_evidence|analysis_failed), score|null, summary, contributions[], adjustments[], floors_applied[], suppressions[], security_posture_issues, inputs_digest, engine_version, ruleset_version, limitations[], recommendations[]}`: `score` is null only when analysis failed.

## 1.1 additions
`StaticAnalysisResult.lineage {api_count, minhash, permissions, rule_ids, signer_sha256}` and `near_misses[{rule_id, title, satisfied, total, missing[]}]`: additive and optional; 1.0 results remain valid.

## Versioning
Breaking changes to these shapes bump `SCHEMA_VERSION`; stored results carry the version they were written with. `ruleset_version` and `engine_version` change when detection or scoring behaviour changes, so an `inputs_digest` comparison identifies whether two results are comparable.

## Job stages
`ingest, static_analysis, threat_intel, ai_reasoning, scoring, reporting`, each `pending|running|done|skipped|failed`.
