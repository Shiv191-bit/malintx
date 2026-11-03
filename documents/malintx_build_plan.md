# MALINT-X Build Plan

## 1. Product Objective & Minimum Viable Scope

**Problem.** Financial institutions face a growing volume of evasive Android malware (banking trojans, SMS-stealing overlays) that bypasses signature-based detection. Manual reverse engineering is too slow for active campaigns, and generic dynamic sandboxes produce unacceptable false-positive rates on legitimate banking apps.

**Product.** MALINT-X is an automated static analysis triage pipeline that evaluates the *intent* of an uploaded Android APK within 90 seconds—without executing the app or relying on file hashes—and produces a compliance-ready forensic report with code-level evidence.

**Minimum Viable Scope (demo-ready).** A single-user web application that:

1. Accepts an APK upload.
2. Decompiles it (JADX + Apktool).
3. Parses `AndroidManifest.xml` for permissions, components, intent filters, and target SDK.
4. Extracts localized code slices (≤50 lines each) around pre-defined high-risk API patterns.
5. Extracts hardcoded IPs/URLs/domains and enriches them via VirusTotal.
6. Passes the structured extraction payload to an LLM with a MITRE ATT&CK Mobile–constrained prompt.
7. Computes a deterministic 0–100 risk score from the LLM's technique detections.
8. Renders results in a Streamlit dashboard (score, evidence table, C2 map).
9. Generates a downloadable PDF report.

**Out of MVP scope (deferred).** Multi-node scanning, enterprise SSO, Shodan integration, CI/CD plugin, fine-tuned local models, benign-calibration pipeline.

---

## 2. Architecture & End-to-End Data Flow

```
┌─────────────┐
│  APK Upload  │
│  (Streamlit) │
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│  Phase 1:        │
│  Decompilation   │
│  (JADX + Apktool)│
└──────┬───────────┘
       │  AndroidManifest.xml + Java source tree
       ▼
┌──────────────────┐
│  Phase 2:        │
│  Extraction      │
│  Engine          │
│  - Manifest      │
│    parser        │
│  - Code slicer   │
│  - IoC extractor │
└──────┬───────────┘
       │  Structured JSON payload
       ├──────────────────────────┐
       ▼                          ▼
┌──────────────────┐   ┌──────────────────┐
│  Phase 3:        │   │  Phase 3b:       │
│  Threat Intel    │   │  GenAI Reasoning │
│  Enrichment      │   │  Engine          │
│  (VirusTotal)    │   │  (Gemini / GPT)  │
└──────┬───────────┘   └──────┬───────────┘
       │                      │
       └──────────┬───────────┘
                  │  Enriched analysis + MITRE techniques
                  ▼
       ┌──────────────────┐
       │  Phase 4:        │
       │  Scoring &       │
       │  Reporting       │
       │  (Deterministic  │
       │   Python engine) │
       └──────┬───────────┘
              │
              ▼
       ┌──────────────────┐
       │  Phase 5:        │
       │  Dashboard &     │
       │  PDF Report      │
       │  (Streamlit +    │
       │   ReportLab)     │
       └──────────────────┘
```

**Key architectural principle:** The extraction pipeline (Phases 1–3) is entirely decoupled from the inference engine (Phase 3b) via a strict JSON interface contract. This allows each subsystem to be developed, tested, and improved independently.

---

## 3. Key Components

| # | Component | Responsibility | Interface |
|---|-----------|---------------|-----------|
| 1 | **APK Ingester** | Upload validation, temp storage, hash computation | File → `{apk_path, sha256, size}` |
| 2 | **Decompiler Wrapper** | Invokes JADX-CLI + Apktool subprocess, manages output directories | `apk_path` → `{manifest_path, source_root, resources_root}` |
| 3 | **Manifest Parser** | Extracts permissions, activities, services, receivers, providers, intent filters, min/target SDK | `manifest_path` → `ManifestData` (structured dict) |
| 4 | **Code Slicer** | Scans Java source for high-risk API patterns via regex; extracts ±25-line context windows | `source_root` → `List[CodeSlice]` |
| 5 | **IoC Extractor** | Regex extraction of IPv4 addresses, URLs, domain names from source code and resources | `source_root` → `List[IoC]` |
| 6 | **Threat Intel Client** | Async queries to VirusTotal API v3 for IoC enrichment | `List[IoC]` → `List[EnrichedIoC]` |
| 7 | **Payload Assembler** | Combines outputs of components 3–6 into a single JSON schema | All extraction outputs → `AnalysisPayload` |
| 8 | **LLM Reasoning Engine** | System prompt engineering, JSON schema output enforcement, MITRE ATT&CK mapping | `AnalysisPayload` → `LLMVerdict` |
| 9 | **Risk Scorer** | Deterministic scoring from LLM output using weighted technique severity | `LLMVerdict` → `RiskScore` (0–100) |
| 10 | **Dashboard** | Streamlit UI: upload, progress, score display, evidence table, IoC map | User-facing web interface |
| 11 | **PDF Generator** | ReportLab-based forensic report generation | `AnalysisPayload` + `RiskScore` → PDF file |

---

## 4. Technical Choices & Justifications

| Decision | Choice | Justification | Alternative |
|----------|--------|---------------|-------------|
| Decompiler | JADX-CLI | Produces readable Java source; widely used in malware research; scriptable via subprocess | Procyon (less maintained), Fernflower |
| Manifest parsing | Apktool for XML decode + Python `xml.etree` | Apktool handles binary XML reliably; Python's stdlib parser is sufficient | `androguard` (heavier dependency) |
| Code slicing | Python `re` (regex) + line-window extraction | Simple, fast, deterministic; avoids AST complexity for MVP | Full Java AST via `javalang` (future enhancement) |
| LLM | Google Gemini 1.5 Flash (primary), OpenAI GPT-4o-mini (fallback) | Flash is fast and cheap for structured output; GPT-4o-mini as backup | Local Llama/Qwen (future: latency savings, offline) |
| LLM output control | JSON schema enforcement via `response_mime_type` | Prevents narrative hallucination; ensures parseable structured output | Free-text + post-hoc parsing (fragile) |
| Threat framework | MITRE ATT&CK for Mobile | Industry standard; constrained taxonomy prevents arbitrary risk narratives | Custom taxonomy (lacks credibility) |
| Scoring | Weighted technique severity (deterministic Python) | Reproducible; LLM provides detections, not scores; eliminates scoring hallucination | LLM-generated scores (non-deterministic) |
| Frontend | Streamlit | Fastest path to interactive demo; Python-native; sufficient for single-user MVP | FastAPI + React (overkill for MVP) |
| PDF | ReportLab | Mature Python library; full layout control for forensic reports | WeasyPrint, fpdf2 |
| Language | Python 3.10+ | Team's primary language; all dependencies available; fastest prototyping cycle | Go/Rust (unnecessary at this scale) |

---

## 5. Development Stages

### Stage 0: Project Scaffolding
**Objective:** Set up the project structure, dependencies, and development environment.

**Tasks:**
- [ ] Create project directory structure: `malintx/{core,extraction,inference,dashboard,reports,tests,data}/`
- [ ] Create `pyproject.toml` with dependencies: `streamlit`, `reportlab`, `requests`, `google-generativeai` (or `openai`), `folium`
- [ ] Set up `.env` template for API keys (VT_API_KEY, GEMINI_API_KEY)
- [ ] Verify JADX-CLI and Apktool are installed and accessible from PATH
- [ ] Create `config.py` with constants: API patterns list, scoring weights, prompt templates

**Acceptance criteria:** `python -c "import malintx"` succeeds. JADX and Apktool callable from Python subprocess.

**Deliverables:** Project skeleton, `requirements.txt` / `pyproject.toml`, configuration module.

---

### Stage 1: Decompilation Pipeline
**Objective:** Accept an APK file and produce a decompiled Java source tree + decoded AndroidManifest.xml.

**Tasks:**
- [ ] Implement `DecompilerWrapper` class:
  - `decompile(apk_path: Path) -> DecompilationResult`
  - Invokes `jadx --no-res --no-debug-info -d {output_dir} {apk_path}`
  - Invokes `apktool d -f -o {resources_dir} {apk_path}` (for manifest + resources)
  - Handles subprocess errors, timeouts (60s), and missing tools
  - Returns structured result with paths to manifest and source root
- [ ] Implement cleanup: temp directory lifecycle management
- [ ] Write unit tests with a known benign APK and a known malware sample (if available)

**Acceptance criteria:** Given a valid APK, the pipeline produces a directory containing `AndroidManifest.xml` (decoded) and `.java` files. Given an invalid file, it returns a clear error.

**Verification:** Run against 3 sample APKs; manually verify decompiled output exists and manifest is valid XML.

---

### Stage 2: Extraction Engine
**Objective:** Parse the decompiled output into structured threat-relevant artifacts.

**Tasks:**
- [ ] **Manifest Parser** (`extraction/manifest.py`):
  - Parse `<uses-permission>` tags → list of permission strings
  - Parse `<activity>`, `<service>`, `<receiver>`, `<provider>` → component inventory with `exported` status
  - Parse `<intent-filter>` → list of registered actions/categories
  - Extract `minSdkVersion`, `targetSdkVersion`, `package` name
  - Output: `ManifestData` dataclass

- [ ] **Code Slicer** (`extraction/slicer.py`):
  - Define `HIGH_RISK_PATTERNS`: regex list covering:
    - SMS: `SmsManager`, `sendTextMessage`, `RECEIVE_SMS`
    - Network: `HttpURLConnection`, `OkHttpClient`, `URL.openConnection`
    - Device info: `getDeviceId`, `getSubscriberId`, `getSimSerialNumber`
    - Crypto: `Cipher.getInstance`, `SecretKeySpec`
    - Dynamic loading: `DexClassLoader`, `loadClass`, `Runtime.exec`
    - Accessibility: `AccessibilityService`
  - Walk `.java` files, search for patterns, extract ±25-line context window
  - Record: filename, line number, matched pattern, surrounding code
  - Output: `List[CodeSlice]` dataclass

- [ ] **IoC Extractor** (`extraction/ioc.py`):
  - Regex patterns for: IPv4 addresses, URLs (`http://`, `https://`), domain names
  - Filter out common benign domains (google.com, android.com, etc.)
  - Deduplicate
  - Output: `List[IoC]` with type classification (ip/url/domain)

- [ ] Write unit tests for each extractor with hand-crafted test data

**Acceptance criteria:** Given decompiled output from Stage 1, each extractor produces valid structured output. Manifest parser handles both well-formed and minimal manifests. Code slicer finds known patterns in test Java files. IoC extractor identifies embedded IPs/URLs.

**Verification:** Run full extraction on 2 known-malicious and 2 known-benign APKs. Manually verify extracted artifacts against ground truth.

---

### Stage 3: Threat Intelligence Enrichment
**Objective:** Enrich extracted IoCs with external threat intelligence.

**Tasks:**
- [ ] Implement `ThreatIntelClient` (`inference/threat_intel.py`):
  - VirusTotal API v3 client: `/api/v3/ip_addresses/{ip}`, `/api/v3/domains/{domain}`, `/api/v3/urls`
  - Rate limiting (4 requests/minute for free tier)
  - Async batch processing with `asyncio` + `aiohttp`
  - Parse VT response: `malicious` count, `suspicious` count, community score, last analysis date
  - Graceful degradation: if API unavailable, mark IoCs as `unenriched` and continue
  - Output: `List[EnrichedIoC]`

- [ ] Implement caching layer (simple file-based or dict-based cache to avoid redundant API calls)

**Acceptance criteria:** Given a list of IoCs, the client returns enrichment data for each. Rate limiting is respected. Pipeline does not fail if VT API is unavailable.

**Verification:** Test with 3 known-malicious IPs/domains and 3 benign ones. Verify VT results match expected reputation.

---

### Stage 4: LLM Reasoning Engine
**Objective:** Pass structured extraction data to an LLM for behavioral intent analysis against MITRE ATT&CK Mobile.

**Tasks:**
- [ ] **Payload Assembler** (`inference/assembler.py`):
  - Combine `ManifestData`, `List[CodeSlice]`, `List[IoC]`, `List[EnrichedIoC]` into a single `AnalysisPayload` JSON
  - Enforce token budget: truncate code slices if total exceeds ~6000 tokens
  - Prioritize slices by pattern severity (SMS/C2 > crypto > device info)

- [ ] **Prompt Engineering** (`inference/prompts.py`):
  - System prompt: "You are an Android malware reverse engineer. Analyze the following APK extraction data and determine whether the code exhibits malicious intent."
  - Constrain output to JSON schema:
    ```json
    {
      "detected_techniques": [
        {
          "technique_id": "T1636.004",
          "technique_name": "SMS Messages",
          "confidence": "high|medium|low",
          "evidence": "Brief description of code evidence",
          "source_file": "filename.java",
          "line_number": 42
        }
      ],
      "overall_assessment": "malicious|suspicious|benign",
      "reasoning_summary": "2-3 sentence summary"
    }
    ```
  - Include MITRE Mobile technique ID reference list in prompt context
  - Include OWASP MASVS compliance check points

- [ ] **LLM Client** (`inference/llm_client.py`):
  - Gemini 1.5 Flash as primary (via `google-generativeai`)
  - GPT-4o-mini as fallback (via `openai`)
  - JSON mode / structured output enforcement
  - Retry logic with exponential backoff
  - Response validation: parsed JSON must conform to expected schema

- [ ] Write integration tests with saved extraction payloads

**Acceptance criteria:** Given a well-formed `AnalysisPayload`, the engine returns a valid `LLMVerdict` with at least one detected technique for a known-malicious sample and zero or minimal detections for a known-benign sample. JSON output is machine-parseable.

**Verification:** Run against 5 extraction payloads (3 malicious, 2 benign). Manually verify MITRE technique attributions against known sample behaviors.

---

### Stage 5: Scoring & Reporting
**Objective:** Compute a deterministic risk score and generate visual + PDF outputs.

**Tasks:**
- [ ] **Risk Scorer** (`core/scorer.py`):
  - Define severity weights per MITRE technique category:
    - SMS interception (T1636): weight 20
    - C2 communication (T1071): weight 15
    - Credential theft (T1417): weight 20
    - Data exfiltration (T1532): weight 15
    - Privilege escalation (T1404): weight 10
    - etc.
  - Score = Σ(technique_weight × confidence_multiplier), capped at 100
  - Confidence multipliers: high=1.0, medium=0.6, low=0.3
  - IoC enrichment bonus: add 5 points per malicious-flagged IoC (max 15)
  - Output: integer score 0–100 with severity label (Clean/Low/Medium/High/Critical)

- [ ] **PDF Report Generator** (`reports/pdf_generator.py`):
  - ReportLab-based template:
    - Header: MALINT-X logo, scan timestamp, APK metadata (name, hash, size)
    - Executive summary: score, severity, overall assessment
    - Permissions analysis table
    - Detected MITRE techniques table with evidence
    - IoC table with VT enrichment
    - Appendix: raw code slices
  - Output: downloadable PDF file

**Acceptance criteria:** Score is deterministic—same input always produces same score. PDF is well-formatted and contains all sections. Score of 0 for clean F-Droid apps; score ≥60 for known banking trojans.

**Verification:** Generate reports for 4 test samples. Review PDF layout and verify score consistency across repeated runs.

---

### Stage 6: Dashboard Integration
**Objective:** Wire everything together into a Streamlit web application.

**Tasks:**
- [ ] **Main app** (`dashboard/app.py`):
  - File upload widget (accept `.apk` only, max 100MB)
  - Progress bar through 5 phases
  - Results page:
    - Risk score gauge/dial
    - Permissions radar chart or table
    - MITRE technique cards with expand-to-evidence
    - IoC table with VT verdicts
    - Folium map visualization of geolocated IPs (if available)
    - Download PDF button
  - Error handling and user feedback for all failure modes

- [ ] End-to-end integration test: upload APK → receive complete analysis

**Acceptance criteria:** A non-technical user can upload an APK and receive a complete analysis within 90 seconds (excluding VT rate-limiting delays). All UI components render correctly. PDF download works.

**Verification:** Live demo with 3 APKs: one known-malicious, one known-benign, one ambiguous (legitimate banking app with OTP permissions).

---

## 6. Datasets & Validation

### Calibration Datasets (from source documents)

| Tier | Source | Purpose | Format | Access |
|------|--------|---------|--------|--------|
| 1 - Threat | MalwareBazaar (abuse.ch) | Active banking trojans (Cerberus, Anubis, Hydra) | Raw .apk | Free API |
| 1 - Threat | Koodous | Community-flagged Android malware with YARA rules | Raw .apk + YARA | Free API |
| 2 - Benign | AndroZoo | Clean apps (0 VT detections); Indian banking apps specifically | Raw .apk | Academic access required |
| 2 - Benign | F-Droid | Open-source, audited apps as noise-free baseline | Raw .apk + source | Free |
| 3 - Ontology | MITRE ATT&CK Mobile | Technique taxonomy for LLM constraint | JSON matrix | Free |
| 3 - Ontology | OWASP MASVS | Mobile security verification standard | Framework | Free |

### Validation Plan

| Metric | Target | Measurement |
|--------|--------|-------------|
| True Positive Rate (known malware detected) | ≥ 85% | Run against 20+ MalwareBazaar samples |
| False Positive Rate (benign flagged as malicious) | ≤ 5% | Run against 20+ F-Droid/AndroZoo apps |
| Analysis time (end-to-end) | ≤ 90 seconds | Wall-clock measurement excluding VT rate limits |
| Score determinism | 100% | Same APK → same score across 5 runs |
| MITRE mapping accuracy | Manual audit | Expert review of technique attributions on 10 samples |

> [!WARNING]
> The PPT claims "97.8% accuracy" and "98.4% zero-day detection"—these figures are taken from the referenced research papers' ML models (DroidMat, Sara & Hossain), not from MALINT-X itself. Do not present these as MALINT-X performance metrics until the system's own evaluation is complete.

---

## 7. Technical Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| JADX fails on obfuscated/packed APKs | Medium | Pipeline produces no source code | Fallback to Apktool smali output; detect failure and report "decompilation limited" |
| LLM hallucinates MITRE techniques | Medium | False detections inflate score | Constrained JSON schema; cross-check detected techniques against actual extracted code patterns; deterministic scoring overrides LLM confidence |
| Code slicing misses obfuscated API calls (reflection, string encryption) | High | Misses evasive malware | Known limitation of static analysis; document it; future: add pattern for reflection-based invocation |
| VirusTotal rate limits (free tier: 4 req/min) | High | Slow enrichment for IoC-heavy samples | Cache results; batch processing; degrade gracefully; paid tier for production |
| LLM API cost at scale | Low (MVP) | Budget overrun if scanning many APKs | Gemini Flash is cheap ($0.075/1M tokens); monitor usage; future: local model |
| Legitimate banking apps trigger false positives (OTP auto-fill uses SMS APIs) | Medium | Undermines trust with SOC teams | Benign calibration: maintain allowlist of known-legitimate package signatures; contextual analysis in prompt |

---

## 8. Missing Information & Unresolved Questions

1. **No existing codebase.** The SENTINEL document claims TRL 5/6 ("Core Pipeline Operational"), but no code is present in the project directory. This plan treats the project as greenfield.

2. **Benign calibration methodology.** The proposal mentions calibrating against Indian banking apps from AndroZoo, but the specific calibration mechanism (allowlists? negative training?) is not defined. The MVP will use a simpler package-name allowlist approach.

3. **Shodan integration details.** The proposal lists Shodan for C2 infrastructure mapping, but the free tier is highly limited. Deferred to post-MVP with paid API key.

4. **Prompt optimization.** The exact system prompt needs iterative refinement against real malware samples. Stage 4 delivers a v1 prompt; expect 2–3 revision cycles.

5. **Scoring weights.** Technique severity weights are proposed but not empirically validated. They should be tuned based on SOC analyst feedback during pilot testing.

---

## 9. Implementation Guidance for AI Coding Agents

Each stage above is designed for incremental implementation in Antigravity sessions:

- **Bounded scope:** Each task has a single responsibility and clear input/output types.
- **Inspect before edit:** Always read existing module interfaces before adding new code.
- **Interface consistency:** All components communicate via Python dataclasses defined in `core/models.py`. Define these first.
- **Incremental testing:** Each stage includes its own verification step. Run tests before proceeding to the next stage.
- **Small changes:** Prefer small, tested commits over large multi-file changes.
- **No premature optimization:** Get the pipeline working end-to-end first, then optimize extraction patterns, prompt engineering, and scoring weights.

**Recommended implementation order:** Stage 0 → Stage 1 → Stage 2 → Stage 4 (LLM, in parallel with Stage 3) → Stage 3 → Stage 5 → Stage 6.

Stage 3 (VT enrichment) and Stage 4 (LLM) can be developed in parallel since they share no dependencies. Stage 6 (dashboard) should be the last step, wiring together all tested components.
