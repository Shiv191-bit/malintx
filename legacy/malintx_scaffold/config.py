"""
MALINT-X Configuration.

Central configuration module. All tunable parameters, API pattern definitions,
MITRE technique weights, and prompt templates are defined here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

load_dotenv()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
JADX_DIR = TOOLS_DIR / "jadx"
APKTOOL_JAR = TOOLS_DIR / "apktool" / "apktool.jar"
WORKDIR = PROJECT_ROOT / "workdir"
UPLOADS_DIR = PROJECT_ROOT / "uploads"
REPORTS_DIR = PROJECT_ROOT / "reports_output"
DATA_DIR = PROJECT_ROOT / "data"

# Ensure key directories exist
for _d in (TOOLS_DIR, WORKDIR, UPLOADS_DIR, REPORTS_DIR, DATA_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Settings (from .env)
# ---------------------------------------------------------------------------
class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    gemini_api_key: str = ""
    openai_api_key: str = ""
    vt_api_key: str = ""
    shodan_api_key: str = ""

    max_apk_size_mb: int = 100
    analysis_timeout_seconds: int = 90
    vt_rate_limit_per_minute: int = 4

    # LLM settings
    gemini_model: str = "gemini-1.5-flash"
    openai_model: str = "gpt-4o-mini"
    llm_max_retries: int = 3
    llm_temperature: float = 0.1

    # Decompiler settings
    jadx_timeout_seconds: int = 60
    apktool_timeout_seconds: int = 60

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()


# ---------------------------------------------------------------------------
# High-Risk API Patterns for Code Slicing
# ---------------------------------------------------------------------------
# Each entry: (category, pattern_regex, description, severity_weight)
HIGH_RISK_PATTERNS: list[dict[str, Any]] = [
    # SMS interception & theft
    {
        "category": "sms",
        "pattern": r"\bSmsManager\b",
        "description": "SMS manager access — potential SMS interception/sending",
        "severity": "critical",
    },
    {
        "category": "sms",
        "pattern": r"\bsendTextMessage\b",
        "description": "Programmatic SMS sending",
        "severity": "critical",
    },
    {
        "category": "sms",
        "pattern": r"\bRECEIVE_SMS\b",
        "description": "SMS receive intent — potential SMS theft",
        "severity": "critical",
    },
    {
        "category": "sms",
        "pattern": r"\bSMS_RECEIVED\b",
        "description": "SMS received broadcast — potential SMS interception",
        "severity": "critical",
    },
    # Network / C2 communication
    {
        "category": "network",
        "pattern": r"\bHttpURLConnection\b",
        "description": "HTTP connection — potential C2 communication",
        "severity": "high",
    },
    {
        "category": "network",
        "pattern": r"\bOkHttpClient\b",
        "description": "OkHttp client — potential C2 communication",
        "severity": "high",
    },
    {
        "category": "network",
        "pattern": r"\bURL\s*\(\s*[\"']https?://",
        "description": "Hardcoded URL construction",
        "severity": "high",
    },
    {
        "category": "network",
        "pattern": r"\bopenConnection\b",
        "description": "URL connection opening",
        "severity": "high",
    },
    {
        "category": "network",
        "pattern": r"\bWebSocket\b",
        "description": "WebSocket connection — potential persistent C2 channel",
        "severity": "high",
    },
    # Device info exfiltration
    {
        "category": "device_info",
        "pattern": r"\bgetDeviceId\b",
        "description": "Device ID extraction — fingerprinting/tracking",
        "severity": "high",
    },
    {
        "category": "device_info",
        "pattern": r"\bgetSubscriberId\b",
        "description": "Subscriber ID (IMSI) extraction",
        "severity": "high",
    },
    {
        "category": "device_info",
        "pattern": r"\bgetSimSerialNumber\b",
        "description": "SIM serial number extraction",
        "severity": "high",
    },
    {
        "category": "device_info",
        "pattern": r"\bgetLine1Number\b",
        "description": "Phone number extraction",
        "severity": "high",
    },
    {
        "category": "device_info",
        "pattern": r"\bBuild\.(SERIAL|MODEL|MANUFACTURER|FINGERPRINT)\b",
        "description": "Device build info extraction — fingerprinting",
        "severity": "medium",
    },
    # Cryptographic operations (potential data encryption for exfil)
    {
        "category": "crypto",
        "pattern": r"\bCipher\.getInstance\b",
        "description": "Cryptographic cipher usage — potential data encryption for exfiltration",
        "severity": "medium",
    },
    {
        "category": "crypto",
        "pattern": r"\bSecretKeySpec\b",
        "description": "Cryptographic key specification",
        "severity": "medium",
    },
    {
        "category": "crypto",
        "pattern": r"\bKeyGenerator\b",
        "description": "Cryptographic key generation",
        "severity": "medium",
    },
    # Dynamic code loading (evasion)
    {
        "category": "dynamic_loading",
        "pattern": r"\bDexClassLoader\b",
        "description": "Dynamic DEX loading — evasion technique",
        "severity": "critical",
    },
    {
        "category": "dynamic_loading",
        "pattern": r"\bPathClassLoader\b",
        "description": "Dynamic class loading",
        "severity": "high",
    },
    {
        "category": "dynamic_loading",
        "pattern": r"\bRuntime\.getRuntime\(\)\.exec\b",
        "description": "Runtime command execution — potential root exploit",
        "severity": "critical",
    },
    {
        "category": "dynamic_loading",
        "pattern": r"\bProcessBuilder\b",
        "description": "Process builder — potential command execution",
        "severity": "high",
    },
    {
        "category": "dynamic_loading",
        "pattern": r"\bClass\.forName\b",
        "description": "Reflection-based class loading — evasion",
        "severity": "high",
    },
    # Accessibility abuse (overlay attacks)
    {
        "category": "accessibility",
        "pattern": r"\bAccessibilityService\b",
        "description": "Accessibility service — potential overlay/keylogging attack",
        "severity": "critical",
    },
    {
        "category": "accessibility",
        "pattern": r"\bAccessibilityEvent\b",
        "description": "Accessibility event handling — potential UI monitoring",
        "severity": "high",
    },
    # Overlay attacks
    {
        "category": "overlay",
        "pattern": r"\bTYPE_APPLICATION_OVERLAY\b",
        "description": "Application overlay window — credential phishing",
        "severity": "critical",
    },
    {
        "category": "overlay",
        "pattern": r"\bSYSTEM_ALERT_WINDOW\b",
        "description": "System alert window — overlay attack",
        "severity": "critical",
    },
    # Keylogging / input capture
    {
        "category": "input_capture",
        "pattern": r"\bInputMethodService\b",
        "description": "Input method service — potential keylogger",
        "severity": "critical",
    },
    {
        "category": "input_capture",
        "pattern": r"\bClipboardManager\b",
        "description": "Clipboard access — potential data theft",
        "severity": "medium",
    },
    # File system access
    {
        "category": "file_access",
        "pattern": r"\bgetExternalStorageDirectory\b",
        "description": "External storage access",
        "severity": "medium",
    },
    {
        "category": "file_access",
        "pattern": r"\bContentResolver\b.*\bquery\b",
        "description": "Content resolver query — potential contact/SMS theft",
        "severity": "high",
    },
    # Camera / audio
    {
        "category": "surveillance",
        "pattern": r"\bCamera\.open\b|android\.hardware\.camera",
        "description": "Camera access — potential surveillance",
        "severity": "high",
    },
    {
        "category": "surveillance",
        "pattern": r"\bMediaRecorder\b",
        "description": "Media recording — potential audio/video surveillance",
        "severity": "high",
    },
    # Package management (install other apps)
    {
        "category": "package",
        "pattern": r"\bPackageInstaller\b|ACTION_INSTALL_PACKAGE",
        "description": "Package installation — potential dropper behavior",
        "severity": "critical",
    },
]


# ---------------------------------------------------------------------------
# Dangerous Android Permissions (for manifest analysis)
# ---------------------------------------------------------------------------
DANGEROUS_PERMISSIONS: dict[str, dict[str, str]] = {
    "android.permission.SEND_SMS": {
        "risk": "critical",
        "description": "Send SMS messages — premium rate fraud or C2 communication",
    },
    "android.permission.RECEIVE_SMS": {
        "risk": "critical",
        "description": "Receive SMS — OTP/2FA interception",
    },
    "android.permission.READ_SMS": {
        "risk": "critical",
        "description": "Read SMS messages — data theft",
    },
    "android.permission.READ_CONTACTS": {
        "risk": "high",
        "description": "Read contact list — social engineering/spam",
    },
    "android.permission.READ_CALL_LOG": {
        "risk": "high",
        "description": "Read call log — surveillance",
    },
    "android.permission.CAMERA": {
        "risk": "high",
        "description": "Camera access — surveillance",
    },
    "android.permission.RECORD_AUDIO": {
        "risk": "high",
        "description": "Microphone access — audio surveillance",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "risk": "high",
        "description": "Fine GPS location — tracking",
    },
    "android.permission.READ_PHONE_STATE": {
        "risk": "high",
        "description": "Phone state (IMEI, IMSI) — device fingerprinting",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "risk": "medium",
        "description": "Write external storage",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "risk": "medium",
        "description": "Read external storage — data access",
    },
    "android.permission.INTERNET": {
        "risk": "low",
        "description": "Internet access (common but required for C2)",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "risk": "critical",
        "description": "Draw over other apps — overlay/phishing attacks",
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "risk": "critical",
        "description": "Accessibility service binding — UI manipulation",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "risk": "critical",
        "description": "Request package installation — dropper behavior",
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "risk": "critical",
        "description": "Device admin — anti-uninstall, remote wipe",
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "risk": "high",
        "description": "Read phone numbers",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "risk": "medium",
        "description": "Auto-start on boot — persistence mechanism",
    },
    "android.permission.WAKE_LOCK": {
        "risk": "low",
        "description": "Prevent sleep — background persistence",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "risk": "low",
        "description": "Foreground service — persistence",
    },
    "android.permission.USE_BIOMETRIC": {
        "risk": "medium",
        "description": "Biometric authentication access",
    },
}


# ---------------------------------------------------------------------------
# MITRE ATT&CK Mobile Technique Weights (for deterministic scoring)
# ---------------------------------------------------------------------------
MITRE_TECHNIQUE_WEIGHTS: dict[str, dict[str, Any]] = {
    # SMS / Communication interception
    "T1636": {"name": "Input Capture", "weight": 15, "category": "collection"},
    "T1636.004": {"name": "SMS Messages", "weight": 20, "category": "collection"},
    "T1636.001": {"name": "Keylogging", "weight": 18, "category": "collection"},
    # C2 communication
    "T1071": {"name": "Application Layer Protocol", "weight": 15, "category": "command_and_control"},
    "T1071.001": {
        "name": "Web Protocols",
        "weight": 12,
        "category": "command_and_control",
    },
    "T1104": {"name": "Multi-Stage Channels", "weight": 15, "category": "command_and_control"},
    # Credential access
    "T1417": {"name": "Input Capture", "weight": 20, "category": "credential_access"},
    "T1417.001": {
        "name": "Keylogging",
        "weight": 18,
        "category": "credential_access",
    },
    "T1417.002": {
        "name": "GUI Input Capture",
        "weight": 20,
        "category": "credential_access",
    },
    # Data exfiltration
    "T1532": {
        "name": "Archive Collected Data",
        "weight": 15,
        "category": "exfiltration",
    },
    "T1437": {
        "name": "Application Layer Protocol",
        "weight": 12,
        "category": "exfiltration",
    },
    "T1646": {
        "name": "Exfiltration Over C2 Channel",
        "weight": 15,
        "category": "exfiltration",
    },
    # Privilege escalation
    "T1404": {"name": "Exploitation for Privilege Escalation", "weight": 10, "category": "privilege_escalation"},
    "T1626": {"name": "Abuse Elevation Control Mechanism", "weight": 12, "category": "privilege_escalation"},
    # Defense evasion
    "T1406": {"name": "Obfuscated Files or Information", "weight": 10, "category": "defense_evasion"},
    "T1406.002": {
        "name": "Software Packing",
        "weight": 12,
        "category": "defense_evasion",
    },
    "T1628": {"name": "Hide Artifacts", "weight": 8, "category": "defense_evasion"},
    "T1627": {"name": "Execution Guardrails", "weight": 8, "category": "defense_evasion"},
    # Discovery
    "T1426": {"name": "System Information Discovery", "weight": 8, "category": "discovery"},
    "T1418": {"name": "Software Discovery", "weight": 6, "category": "discovery"},
    "T1422": {"name": "System Network Configuration Discovery", "weight": 8, "category": "discovery"},
    # Impact
    "T1447": {"name": "Delete Device Data", "weight": 15, "category": "impact"},
    "T1448": {"name": "Carrier Billing Fraud", "weight": 18, "category": "impact"},
    # Persistence
    "T1398": {"name": "Boot or Logon Autostart Execution", "weight": 10, "category": "persistence"},
    "T1624": {"name": "Event Triggered Execution", "weight": 10, "category": "persistence"},
    # Initial Access
    "T1476": {"name": "Deliver Malicious App via Other Means", "weight": 8, "category": "initial_access"},
}

# Confidence multipliers for scoring
CONFIDENCE_MULTIPLIERS: dict[str, float] = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
}

# Score classification thresholds
SCORE_LABELS: list[tuple[int, str, str]] = [
    (0, "Clean", "#2ecc71"),       # 0-19
    (20, "Low", "#f1c40f"),        # 20-39
    (40, "Medium", "#e67e22"),     # 40-59
    (60, "High", "#e74c3c"),       # 60-79
    (80, "Critical", "#8e44ad"),   # 80-100
]


# ---------------------------------------------------------------------------
# Benign package allowlist (reduces false positives on legitimate banking apps)
# ---------------------------------------------------------------------------
BENIGN_PACKAGE_PREFIXES: list[str] = [
    "com.google.",
    "com.android.",
    "org.fdroid.",
    "org.mozilla.",
    "org.lineageos.",
    "com.whatsapp",
    # Major Indian banking apps
    "com.sbi.",
    "com.icicibank.",
    "com.hdfcbank.",
    "com.axisbank.",
    "com.kotak.",
    "com.bob.",
    "com.pnb.",
    "net.one97.",  # Paytm
    "com.phonepe.",
    "in.org.npci.",  # BHIM
]


def get_score_label(score: int) -> tuple[str, str]:
    """Return (label, color_hex) for a given 0-100 score."""
    label, color = "Clean", "#2ecc71"
    for threshold, lbl, clr in SCORE_LABELS:
        if score >= threshold:
            label, color = lbl, clr
    return label, color

