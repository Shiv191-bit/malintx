"""
MALINT-X Prompt Templates.

Engineering-grade prompt templates that instruct an LLM to act as an
Android malware reverse-engineer, analyse extraction artefacts, map
findings to MITRE ATT&CK Mobile techniques, and emit strict JSON
matching the ``LLMVerdict`` schema.

All templates are plain string constants so they can be composed at
call-time with simple ``.format()`` / f-string interpolation.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# System prompt — sets the LLM persona and behavioural constraints
# ---------------------------------------------------------------------------
SYSTEM_PROMPT: str = """\
You are an expert Android malware reverse-engineer and threat analyst.
You work inside the MALINT-X automated triage pipeline.  Your ONLY task
is to analyse the static-analysis extraction artefacts you are given and
produce a structured JSON verdict.

## Rules — Follow these STRICTLY

1. **Evidence-Only**: Report ONLY techniques for which you find concrete
   evidence in the provided manifest, code slices, or IoC intelligence.
   If the evidence is ambiguous, set confidence to "low".  NEVER
   hallucinate or infer techniques that are not directly supported by
   the data.

2. **MITRE ATT&CK Mobile**: Map every finding to a MITRE ATT&CK Mobile
   technique ID from the reference list below.  Use the most specific
   sub-technique ID when one applies.

3. **OWASP MASVS**: Check the provided OWASP MASVS reference and list
   any violated checkpoints.

4. **Confidence Levels**:
   - "high" — unambiguous code evidence (e.g., `SmsManager.sendTextMessage()`)
   - "medium" — strong indicators that are common in malware but also
     seen in legitimate apps (e.g., `AccessibilityService` in a banking
     app)
   - "low" — weak or circumstantial evidence

5. **Overall Assessment**:
   - "malicious" — clear combination of malicious capabilities
   - "suspicious" — some concerning indicators, needs manual review
   - "benign" — no significant malicious indicators found

6. **Output format**: Respond with ONLY valid JSON matching the schema
   below.  No markdown, no code fences, no explanatory text before or
   after the JSON.
"""

# ---------------------------------------------------------------------------
# MITRE ATT&CK Mobile condensed reference
# ---------------------------------------------------------------------------
MITRE_MOBILE_REFERENCE: str = """\
## MITRE ATT&CK Mobile — Key Technique Reference

### Collection
- T1636      Input Capture
- T1636.001  Input Capture: Keylogging
- T1636.004  Input Capture: SMS Messages

### Command and Control
- T1071      Application Layer Protocol
- T1071.001  Application Layer Protocol: Web Protocols
- T1104      Multi-Stage Channels

### Credential Access
- T1417      Input Capture
- T1417.001  Input Capture: Keylogging
- T1417.002  Input Capture: GUI Input Capture

### Exfiltration
- T1532      Archive Collected Data
- T1437      Application Layer Protocol
- T1646      Exfiltration Over C2 Channel

### Privilege Escalation
- T1404      Exploitation for Privilege Escalation
- T1626      Abuse Elevation Control Mechanism

### Defense Evasion
- T1406      Obfuscated Files or Information
- T1406.002  Obfuscated Files or Information: Software Packing
- T1628      Hide Artifacts
- T1627      Execution Guardrails

### Discovery
- T1426      System Information Discovery
- T1418      Software Discovery
- T1422      System Network Configuration Discovery

### Impact
- T1447      Delete Device Data
- T1448      Carrier Billing Fraud

### Persistence
- T1398      Boot or Logon Autostart Execution
- T1624      Event Triggered Execution

### Initial Access
- T1476      Deliver Malicious App via Other Means
"""

# ---------------------------------------------------------------------------
# OWASP MASVS compliance checkpoints
# ---------------------------------------------------------------------------
OWASP_MASVS_CHECKS: str = """\
## OWASP MASVS Compliance Checkpoints

### MASVS-STORAGE
- MSTG-STORAGE-1: Sensitive data not stored in plaintext on the device
- MSTG-STORAGE-2: No sensitive data written to application logs
- MSTG-STORAGE-7: No sensitive data shared via IPC mechanisms (exported components)

### MASVS-CRYPTO
- MSTG-CRYPTO-1: No reliance on symmetric cryptography with hardcoded keys
- MSTG-CRYPTO-3: Uses proven cryptographic primitives, not custom implementations
- MSTG-CRYPTO-6: All random values generated using a sufficiently secure RNG

### MASVS-NETWORK
- MSTG-NETWORK-1: All data exchanged over TLS (no cleartext HTTP)
- MSTG-NETWORK-2: Proper TLS certificate verification (no TrustManager overrides)
- MSTG-NETWORK-3: No acceptance of self-signed / untrusted CA certificates in production

### MASVS-PLATFORM
- MSTG-PLATFORM-1: Minimum necessary permissions requested
- MSTG-PLATFORM-2: Input from external sources validated and sanitised
- MSTG-PLATFORM-3: No export of sensitive functionality via custom URL schemes without validation
- MSTG-PLATFORM-5: WebView JavaScript execution disabled unless explicitly required

### MASVS-CODE
- MSTG-CODE-2: App signed with valid certificate (not debug)
- MSTG-CODE-3: Debugging symbols removed from native binaries
- MSTG-CODE-4: No debugging code or verbose error messages left in production
- MSTG-CODE-9: Obfuscation applied to sensitive logic (ProGuard / R8)

### MASVS-RESILIENCE
- MSTG-RESILIENCE-1: Anti-tampering mechanisms present
- MSTG-RESILIENCE-3: Root / emulator detection present
- MSTG-RESILIENCE-5: No dynamic code loading from untrusted sources
"""

# ---------------------------------------------------------------------------
# Strict output JSON schema (matches LLMVerdict model)
# ---------------------------------------------------------------------------
OUTPUT_SCHEMA: str = """\
{
  "detected_techniques": [
    {
      "technique_id": "T1636.004",
      "technique_name": "Input Capture: SMS Messages",
      "confidence": "high | medium | low",
      "evidence": "Concise description of the evidence found in the extraction data",
      "source_file": "path/to/SourceFile.java (or null if not applicable)",
      "line_number": 42
    }
  ],
  "overall_assessment": "malicious | suspicious | benign",
  "reasoning_summary": "A 2-4 sentence summary explaining the overall assessment and key findings.",
  "owasp_findings": [
    "MSTG-PLATFORM-1: App requests excessive dangerous permissions including SEND_SMS, READ_CONTACTS"
  ]
}
"""

# ---------------------------------------------------------------------------
# Analysis prompt template — user message with placeholder for context
# ---------------------------------------------------------------------------
ANALYSIS_PROMPT_TEMPLATE: str = """\
Analyse the following Android APK static-analysis extraction data and
produce a structured JSON verdict.

{mitre_reference}

{owasp_checks}

## Required JSON Output Schema

```json
{output_schema}
```

## Extraction Data

{analysis_context}

## Instructions

1. Examine the manifest permissions, exported components, code slices,
   and IoC intelligence.
2. For EACH suspicious or malicious pattern you identify, map it to the
   most specific MITRE ATT&CK Mobile technique from the reference above.
3. Provide the concrete code evidence (exact API call, file path, line
   number) for each technique.
4. Check the OWASP MASVS reference and list any violations you observe.
5. Set "overall_assessment" based on the totality of the evidence.
6. Respond with ONLY the JSON object — no additional text.
"""
