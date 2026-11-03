# Technical decisions

Original scaffold decisions TD-001…TD-010 are kept below with their current status; new decisions follow.

## Status of the original decisions
| ID | Original | Status |
|---|---|---|
| TD-001 | Python monolith | **Kept** (modular monolith; analysis in an isolated child process) |
| TD-002 | Deterministic scoring, LLM detects techniques | **Strengthened**: the LLM is no longer a scoring input at all; techniques come from deterministic rules |
| TD-003 | JADX + Apktool with graceful degradation | **Changed**: androguard bytecode analysis is the primary, always-available engine; JADX/Apktool are optional enrichers |
| TD-004 | Gemini 1.5 Flash primary | **Superseded**: provider-independent layer; models are configuration (1.5 Flash is retired) |
| TD-005 | JSON contract between stages | **Kept**, now versioned Pydantic schemas with `extra="forbid"` |
| TD-006 | 50-line slices, not full source | **Kept** (±25 instructions/lines), evidence-ID-addressed, size-budgeted for AI |
| TD-007 | VT only, Shodan deferred | **Superseded**: VT, Shodan, MalwareBazaar, Koodous adapters |
| TD-008 | Streamlit | **Kept** as UI (reference stack), reading only the API |
| TD-009 | ReportLab | **Kept** |
| TD-010 | ~6000-token budget by truncation | **Replaced** by `ai_max_context_chars` + severity-prioritised evidence selection |

## New decisions
* **TD-011 Androguard as the primary engine.** Pure Python, installs on 3.14, yields manifests, certificates and xrefs without a JVM, so the platform works where Java is absent. Cost: Dalvik-bytecode snippets instead of Java; mitigated by the optional JADX enrichment. Alternatives considered: own AXML/DEX parsers (too much surface), `apkInspector` (less analysis support).
* **TD-012 Out-of-process analysis worker.** Third-party parsers consume hostile input; a child process with scrubbed env, timeout and memory limits contains crashes/hangs and keeps secrets away. Cost: ~0.5 s start-up per job.
* **TD-013 Exact-class correlation.** Composite behaviours correlate signals in the *same class*, not the outer class, to avoid false positives from OTP receivers nested in activities. Cost: lower recall when malware splits behaviour across helper classes (reported as app-wide, medium confidence, where a rule allows it).
* **TD-014 Capabilities vs behaviours vs posture.** Three channels; only behaviours score at full weight, capabilities at 0.6, posture at 0. Implements "SMS in a banking app is not malice" and "vulnerable ≠ malware".
* **TD-015 Operator-trusted certificate fingerprints instead of package allow-lists.** Package names are attacker-chosen; fingerprints are not. Effect is a weight reduction, never a zero.
* **TD-016 Passive intel only, opt-in per analysis.** Replaces SENTINEL's "active reconnaissance". Hosts are pinned; credential-bearing URLs never leave.
* **TD-017 Official ATT&CK STIX vendored with SHA-256**, loaded at runtime; a test fails if any rule references a non-existent ID.
* **TD-018 SQLite, no ORM.** Single-node, small schema, explicit migrations; results are stored as validated JSON documents.
* **TD-019 Thread-pool job runner in the API process.** No broker for a single-operator tool; interrupted jobs are failed on restart. Revisit if multi-node scanning is needed.
* **TD-020 httpx directly for LLM/intel HTTP** instead of vendor SDKs: fewer dependencies, one retry/host-pinning implementation, easy to mock.
* **TD-021 Score bands and weights are expert-set and documented**, not fitted. They must be calibrated on a real corpus before being relied upon (see DATASETS_AND_EVALUATION.md).
