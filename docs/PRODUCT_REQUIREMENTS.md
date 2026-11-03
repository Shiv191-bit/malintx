# MALINT-X Product Requirements

**Product**: Android malware analysis & threat-intelligence platform for researchers and responders. Given an APK it answers: what does it do, which capabilities does it hold, what is the evidence, which ATT&CK for Mobile techniques are relevant, how confident are we, and how should an analyst read it.

**Design philosophy**: evidence first, intelligence second, AI-assisted interpretation third. AI never invents evidence and never decides the verdict.

## Users
Malware analysts, incident responders, bank fraud/threat-intel teams triaging suspect APKs. Single operator or small trusted team.

## Functional requirements and status
| # | Requirement | Status |
|---|---|---|
| F1 | Upload APK; validate type/size/structure; hash; register; detect duplicates | ✅ |
| F2 | Manifest, permissions, components, intent filters, signing certs, SDK, ZIP/DEX inventory | ✅ |
| F3 | Behaviour detection with per-finding evidence (file/class/method/offset/line*, snippet, rule, method, confidence, limitations) | ✅ (*line numbers need JADX: 🟡) |
| F4 | Indicator extraction (IP, domain, URL, e-mail, paths, packages) | ✅ |
| F5 | Passive threat-intel enrichment (VT, Shodan, MalwareBazaar, Koodous) with graceful degradation | 🟡 mock-tested only |
| F6 | Optional, provider-independent AI reasoning with grounded structured output | 🟡 mock-tested only |
| F7 | ATT&CK for Mobile mapping with evidence, rationale, confidence, source; MASVS for posture | ✅ |
| F8 | Deterministic, explainable 0–100 score + non-binary classifications | ✅ |
| F9 | Analyst dashboard (13 views) on real data | ✅ |
| F10 | Forensic PDF report | ✅ |
| F11 | Evaluation framework with provenance and split hygiene | ✅ (no corpus run) |
| F12 | Job tracking, progress, failure states, history | ✅ |

## Non-functional requirements
Safe handling of hostile input (isolated worker, limits, no execution); no hard dependency on external services (core works offline without a JRE); reproducible results (deterministic IDs, scores, digests); typed versioned contracts; explicit error types; tests at unit/integration/e2e level; secrets only via environment; consent-gated data sharing.

## Explicit non-goals / honest limits
Dynamic analysis, native-code analysis, unpacking, iOS; automatic family attribution; any claim of "zero false positives" or "zero-day detection"; chain-of-custody guarantees; active probing of C2 infrastructure (the SENTINEL "live reconnaissance" is replaced by passive lookups).

## Success criteria for a release
The complete workflow (upload → validate → hash → analyse → evidence → optional intel/AI → ATT&CK → score → dashboard → PDF → traceable) works on both suspicious and legitimate APKs and fails gracefully. **Detection quality is unmeasured until the evaluation framework has been run on a documented real corpus.**
