"""Detection rule catalog (data only). Logic lives in `engine.py`.

Design rules for entries:
* A single suspicious API call is a *capability*, not malicious intent. Only composites
  (correlated behaviours) are `malicious_behavior`.
* Every rule documents realistic legitimate uses in `fp_notes`.
* MITRE ids are validated against the vendored ATT&CK dataset by the test-suite.
"""

from __future__ import annotations

from dataclasses import dataclass

from malintx.schemas.common import FindingKind, Severity

RULESET_VERSION = "2026.11-r4"

Sig = tuple[str, tuple[str, ...] | None]

CAP = FindingKind.SUSPICIOUS_CAPABILITY
INFO = FindingKind.INFORMATIONAL
MALICIOUS = FindingKind.MALICIOUS_BEHAVIOR
MISCONFIG = FindingKind.SECURITY_MISCONFIGURATION


@dataclass(frozen=True)
class ApiRule:
    id: str
    title: str
    description: str
    category: str
    kind: FindingKind
    severity: Severity
    sigs: tuple[Sig, ...]
    mitre: tuple[str, ...] = ()
    masvs: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()  # supporting permissions (any); absence lowers confidence
    fp_notes: str | None = None
    min_sites: int = 1
    max_evidence: int = 8
    requires_any: tuple[str, ...] = ()  # rule ids; hit is discarded unless one of them also fired


@dataclass(frozen=True)
class ClassRule:
    """Fires for app classes extending a framework base class."""

    id: str
    title: str
    description: str
    category: str
    kind: FindingKind
    severity: Severity
    base_classes: tuple[str, ...]
    mitre: tuple[str, ...] = ()
    masvs: tuple[str, ...] = ()
    fp_notes: str | None = None


@dataclass(frozen=True)
class StringRule:
    id: str
    title: str
    description: str
    category: str
    kind: FindingKind
    severity: Severity
    pattern: str  # regex searched in each string constant
    mitre: tuple[str, ...] = ()
    masvs: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    fp_notes: str | None = None
    full_match: bool = False
    min_hits: int = 1
    max_evidence: int = 6


@dataclass(frozen=True)
class Requirement:
    rule_ids: tuple[str, ...]  # any-of


@dataclass(frozen=True)
class CompositeRule:
    id: str
    title: str
    description: str
    category: str
    severity: Severity
    requires: tuple[Requirement, ...]  # all groups must be satisfied
    mitre: tuple[str, ...] = ()
    scope: str = "class"  # class: same outer class gives HIGH confidence; app: MEDIUM
    app_scope_severity: Severity | None = None  # severity if only app-level co-occurrence
    class_scope_only: bool = False  # do not fire on app-level co-occurrence
    unless: tuple[str, ...] = ()  # do not fire if any of these hits exist...
    unless_overridden_by: tuple[str, ...] = ()  # ...unless one of these also exists
    fp_notes: str | None = None
    masvs: tuple[str, ...] = ()


# =============================================================================
# API rules
# =============================================================================
API_RULES: tuple[ApiRule, ...] = (
    ApiRule(
        "API-SMS-SEND", "Programmatic SMS sending",
        "The app calls SmsManager send APIs, which can send messages without user interaction "
        "(premium-rate fraud, C2 over SMS, OTP forwarding).",
        "sms_send", CAP, Severity.HIGH,
        (("Landroid/telephony/SmsManager;", ("sendTextMessage", "sendMultipartTextMessage", "sendDataMessage", "sendTextMessageWithoutPersisting")),
         ("Landroid/telephony/gsm/SmsManager;", ("sendTextMessage", "sendMultipartTextMessage", "sendDataMessage"))),
        mitre=("T1582",), permissions=("android.permission.SEND_SMS",),
        fp_notes="Messaging apps and some authentication/recovery flows legitimately send SMS.",
    ),
    ApiRule(
        "API-SMS-READ", "Reads incoming SMS content",
        "The app decodes SMS PDUs or message bodies, which is required both for legitimate OTP "
        "auto-fill and for OTP/SMS theft.",
        "sms_read", CAP, Severity.MEDIUM,
        (("Landroid/telephony/SmsMessage;", ("createFromPdu", "getMessageBody", "getDisplayMessageBody", "getOriginatingAddress", "getDisplayOriginatingAddress")),
         ("Landroid/provider/Telephony$Sms$Intents;", ("getMessagesFromIntent",))),
        mitre=("T1636.004",), permissions=("android.permission.RECEIVE_SMS", "android.permission.READ_SMS"),
        fp_notes="Banking, payment and 2FA apps read SMS for OTP auto-fill. Alone this does not indicate malicious intent.",
    ),
    ApiRule(
        "API-SMS-ABORT", "Aborts ordered broadcast",
        "BroadcastReceiver.abortBroadcast() stops lower-priority receivers from seeing an ordered "
        "broadcast; for SMS_RECEIVED it hides messages from the default SMS app.",
        "sms_suppress", CAP, Severity.LOW,
        (("Landroid/content/BroadcastReceiver;", ("abortBroadcast",)),),
        fp_notes="Used by many apps for non-SMS ordered broadcasts.",
    ),
    ApiRule(
        "API-SMS-RETRIEVER", "Uses Google SMS Retriever / User Consent API",
        "Privacy-preserving OTP retrieval API that needs no SMS permission. Strong indicator of "
        "legitimate OTP handling.",
        "otp_context", INFO, Severity.INFO,
        (("Lcom/google/android/gms/auth/api/phone/SmsRetriever;", None),
         ("Lcom/google/android/gms/auth/api/phone/SmsRetrieverClient;", None)),
    ),
    ApiRule(
        "API-TELEPHONY-ID", "Reads device / SIM identifiers",
        "Reads IMEI, IMSI, SIM serial or phone number: device fingerprinting or victim profiling.",
        "device_id", CAP, Severity.LOW,
        (("Landroid/telephony/TelephonyManager;", ("getDeviceId", "getImei", "getMeid", "getSubscriberId", "getSimSerialNumber", "getLine1Number")),),
        mitre=("T1426",), permissions=("android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS"),
        fp_notes="Analytics/ad SDKs and telephony apps read these identifiers.",
    ),
    ApiRule(
        "API-ACCESSIBILITY-AUTOMATION", "Programmatic UI interaction via accessibility",
        "Performs clicks/text input/global actions on other apps' UI through accessibility APIs: "
        "the core mechanism behind on-device fraud (ODF) trojans.",
        "accessibility", CAP, Severity.HIGH,
        (("Landroid/accessibilityservice/AccessibilityService;", ("performGlobalAction", "dispatchGesture", "getRootInActiveWindow", "findFocus")),
         ("Landroid/view/accessibility/AccessibilityNodeInfo;", ("performAction",))),
        mitre=("T1453",), permissions=("android.permission.BIND_ACCESSIBILITY_SERVICE",),
        fp_notes="Assistive tools, password managers and automation apps legitimately use these APIs.",
        # performAction() is ordinary accessibility-delegate code in many apps (and in minified bundled libraries);
        # it is only meaningful when the app is itself an accessibility service. Found on real F-Droid apps.
        requires_any=("MAN-ACCESSIBILITY-SERVICE", "CLS-ACCESSIBILITY-SERVICE"),
    ),
    ApiRule(
        "API-OVERLAY-WINDOW", "Adds floating window views",
        "WindowManager.addView can draw over other apps when the app holds SYSTEM_ALERT_WINDOW "
        "(or an accessibility overlay), enabling credential-phishing overlays.",
        "overlay", CAP, Severity.MEDIUM,
        (("Landroid/view/WindowManager;", ("addView",)),),
        mitre=("T1417.002",), permissions=("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"),
        fp_notes="Chat heads, screen recorders, floating widgets.",
    ),
    ApiRule(
        "API-DYNAMIC-CODE-LOAD", "Dynamic code loading",
        "Loads additional DEX/class code at runtime, a standard way to hide or stage payloads from "
        "static analysis.",
        "dynamic_code", CAP, Severity.HIGH,
        (("Ldalvik/system/DexClassLoader;", ("<init>",)),
         ("Ldalvik/system/InMemoryDexClassLoader;", ("<init>",)),
         ("Ldalvik/system/PathClassLoader;", ("<init>",)),
         ("Ldalvik/system/DexFile;", ("loadDex", "<init>"))),
        mitre=("T1407",),
        fp_notes="Plugin frameworks, hot-fix SDKs (Tinker/Robust) and some app bundles do this legitimately.",
    ),
    ApiRule(
        "API-COMMAND-EXEC", "Executes OS commands",
        "Runs shell commands via Runtime.exec / ProcessBuilder (root checks, root exploits, payload "
        "installation).",
        "command_exec", CAP, Severity.MEDIUM,
        (("Ljava/lang/Runtime;", ("exec",)), ("Ljava/lang/ProcessBuilder;", ("start",))),
        mitre=("T1623",),
        fp_notes="Root-detection libraries and diagnostics tools call exec().",
    ),
    ApiRule(
        "API-REFLECTION-HEAVY", "Heavy reflection use",
        "Large numbers of reflective calls hide the real call graph from static analysis.",
        "evasion", CAP, Severity.LOW,
        (("Ljava/lang/Class;", ("forName", "getDeclaredMethod", "getMethod")),
         ("Ljava/lang/reflect/Method;", ("invoke",))),
        min_sites=40, masvs=("MASVS-RESILIENCE-3",),
        fp_notes="Common in frameworks, DI containers and serialization libraries.",
    ),
    ApiRule(
        "API-NETWORK", "Network communication APIs",
        "HTTP/HTTPS/socket APIs. Recorded as supporting evidence for exfiltration/C2 correlation; "
        "not suspicious by itself.",
        "network", INFO, Severity.INFO,
        (("Ljava/net/HttpURLConnection;", ("connect", "getInputStream", "getOutputStream", "getResponseCode")),
         ("Ljavax/net/ssl/HttpsURLConnection;", ("connect", "getInputStream", "getOutputStream", "getResponseCode")),
         ("Ljava/net/URL;", ("openConnection", "openStream")),
         ("Ljava/net/Socket;", ("<init>", "connect")),
         ("Ljava/net/DatagramSocket;", ("send",)),
         ("Lokhttp3/OkHttpClient;", ("newCall",)),
         ("Lokhttp3/Call;", ("execute", "enqueue")),
         ("Lorg/apache/http/client/HttpClient;", ("execute",))),
        max_evidence=10,
    ),
    ApiRule(
        "API-CLIPBOARD-READ", "Reads the clipboard",
        "Reads clipboard content or listens for clipboard changes (credential / crypto-address theft).",
        "clipboard", CAP, Severity.MEDIUM,
        (("Landroid/content/ClipboardManager;", ("getPrimaryClip", "addPrimaryClipChangedListener", "getText")),),
        mitre=("T1414",), fp_notes="Password managers, keyboards and note-taking apps read the clipboard.",
    ),
    ApiRule(
        "API-DEVICE-ADMIN-CONTROL", "Device-administrator control calls",
        "Locks the device, resets the password or wipes data via DevicePolicyManager (ransomware / "
        "anti-removal behaviour).",
        "device_admin", CAP, Severity.HIGH,
        (("Landroid/app/admin/DevicePolicyManager;", ("lockNow", "resetPassword", "wipeData", "resetPasswordWithToken", "setKeyguardDisabledFeatures", "removeActiveAdmin")),),
        mitre=("T1626.001", "T1629.002"),
        fp_notes="MDM/EMM agents and parental-control apps are legitimate device administrators.",
    ),
    ApiRule(
        "API-PACKAGE-INSTALL", "Installs other packages",
        "Uses PackageInstaller sessions to install additional APKs (dropper behaviour).",
        "dropper", CAP, Severity.MEDIUM,
        (("Landroid/content/pm/PackageInstaller;", ("createSession", "openSession")),
         ("Landroid/content/pm/PackageInstaller$Session;", ("commit", "openWrite"))),
        permissions=("android.permission.REQUEST_INSTALL_PACKAGES",),
        fp_notes="App stores and self-updating enterprise apps install packages.",
    ),
    ApiRule(
        "API-HIDE-LAUNCHER-ICON", "Toggles component enabled state",
        "PackageManager.setComponentEnabledSetting can disable the launcher activity to hide the "
        "app icon.",
        "stealth", CAP, Severity.MEDIUM,
        (("Landroid/content/pm/PackageManager;", ("setComponentEnabledSetting",)),),
        mitre=("T1628.001",), fp_notes="Apps with switchable launcher icons (activity-alias) use this API.",
    ),
    ApiRule(
        "API-AUDIO-CAPTURE", "Records audio",
        "Starts microphone recording.",
        "audio", CAP, Severity.MEDIUM,
        (("Landroid/media/AudioRecord;", ("startRecording",)),
         ("Landroid/media/MediaRecorder;", ("setAudioSource",))),
        mitre=("T1429",), permissions=("android.permission.RECORD_AUDIO",),
        fp_notes="Voice, call, messaging and recording apps.",
    ),
    ApiRule(
        "API-SCREEN-CAPTURE", "Captures the screen",
        "MediaProjection screen capture / virtual display (screen-streaming RATs).",
        "screen", CAP, Severity.MEDIUM,
        (("Landroid/media/projection/MediaProjectionManager;", ("createScreenCaptureIntent", "getMediaProjection")),
         ("Landroid/media/projection/MediaProjection;", ("createVirtualDisplay",))),
        mitre=("T1513",), fp_notes="Screen recording and casting apps.",
    ),
    ApiRule(
        "API-LOCATION", "Reads device location",
        "Requests or reads device location.",
        "location", CAP, Severity.LOW,
        (("Landroid/location/LocationManager;", ("requestLocationUpdates", "getLastKnownLocation", "requestSingleUpdate")),
         ("Lcom/google/android/gms/location/FusedLocationProviderClient;", ("getLastLocation", "requestLocationUpdates"))),
        mitre=("T1430",), permissions=("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"),
        fp_notes="Maps, delivery, ride-hailing, weather.",
    ),
    ApiRule(
        "API-WEBVIEW-JS-BRIDGE", "WebView JavaScript bridge",
        "addJavascriptInterface exposes Java objects to page JavaScript; exploitable if untrusted "
        "content is loaded.",
        "webview", MISCONFIG, Severity.MEDIUM,
        (("Landroid/webkit/WebView;", ("addJavascriptInterface",)),),
        masvs=("MASVS-PLATFORM-2",),
        fp_notes="Common in hybrid apps; risk depends on what content the WebView loads.",
    ),
    ApiRule(
        "API-WEBVIEW-FILE-ACCESS", "WebView file-URL access enabled",
        "Enables universal/file-URL access from file URLs in WebView settings.",
        "webview", MISCONFIG, Severity.MEDIUM,
        (("Landroid/webkit/WebSettings;", ("setAllowUniversalAccessFromFileURLs", "setAllowFileAccessFromFileURLs")),),
        masvs=("MASVS-PLATFORM-2",),
    ),
)

# =============================================================================
# Class (inheritance) rules
# =============================================================================
CLASS_RULES: tuple[ClassRule, ...] = (
    ClassRule(
        "CLS-ACCESSIBILITY-SERVICE", "Implements an AccessibilityService",
        "The app ships its own accessibility service and can observe and drive other apps' UIs.",
        "accessibility", CAP, Severity.HIGH,
        ("Landroid/accessibilityservice/AccessibilityService;",),
        mitre=("T1453",),
        fp_notes="Assistive technology, password managers, automation and macro apps.",
    ),
    ClassRule(
        "CLS-DEVICE-ADMIN", "Implements a DeviceAdminReceiver",
        "The app registers as a device administrator (hinders uninstall, enables lock/wipe).",
        "device_admin", CAP, Severity.HIGH,
        ("Landroid/app/admin/DeviceAdminReceiver;",),
        mitre=("T1626.001",), fp_notes="MDM agents and parental-control apps.",
    ),
    ClassRule(
        "CLS-NOTIFICATION-LISTENER", "Implements a NotificationListenerService",
        "Can read all notifications (OTP and messenger content) when the user grants access.",
        "notification", CAP, Severity.MEDIUM,
        ("Landroid/service/notification/NotificationListenerService;",),
        mitre=("T1517",), fp_notes="Smartwatch companions, notification managers.",
    ),
    ClassRule(
        "CLS-INPUT-METHOD", "Implements an InputMethodService (custom keyboard)",
        "A custom IME sees every keystroke the user types in any app.",
        "input_capture", CAP, Severity.MEDIUM,
        ("Landroid/inputmethodservice/InputMethodService;",),
        mitre=("T1417.001",), fp_notes="Legitimate third-party keyboards.",
    ),
    ClassRule(
        "CLS-VPN-SERVICE", "Implements a VpnService",
        "Can intercept device traffic once the user accepts the VPN prompt.",
        "network_intercept", CAP, Severity.LOW,
        ("Landroid/net/VpnService;",), fp_notes="VPN apps, ad blockers, network monitors.",
    ),
)

# =============================================================================
# String rules
# =============================================================================
STRING_RULES: tuple[StringRule, ...] = (
    StringRule(
        "STR-SMS-PROVIDER", "Accesses the SMS content provider",
        "References content://sms or content://mms, allowing bulk reading of stored messages.",
        "sms_read", CAP, Severity.MEDIUM, r"content://(?:sms|mms)\b",
        mitre=("T1636.004",), permissions=("android.permission.READ_SMS",),
        fp_notes="SMS backup tools and default messaging apps.",
    ),
    StringRule(
        "STR-CONTACTS-PROVIDER", "Accesses the contacts provider",
        "References the contacts content provider (contact-list harvesting).",
        "contacts", CAP, Severity.LOW, r"content://com\.android\.contacts",
        mitre=("T1636.003",), permissions=("android.permission.READ_CONTACTS",),
        fp_notes="Messengers and dialers.",
    ),
    StringRule(
        "STR-CALLLOG-PROVIDER", "Accesses the call-log provider",
        "References the call-log content provider.",
        "calllog", CAP, Severity.LOW, r"content://call_log",
        mitre=("T1636.002",), permissions=("android.permission.READ_CALL_LOG",),
    ),
    StringRule(
        "STR-TELEGRAM-BOT-API", "Embedded Telegram Bot API endpoint",
        "A Telegram bot token embedded in the app is a common low-cost C2 / exfiltration channel.",
        "c2", CAP, Severity.MEDIUM, r"api\.telegram\.org/bot[0-9]{6,}:[A-Za-z0-9_-]{20,}",
        mitre=("T1481",), fp_notes="Developer notification/logging bots exist but are uncommon in production apps.",
    ),
    StringRule(
        "STR-IP-LITERAL-ENDPOINT", "URL with a public IP-literal host",
        "Hard-coded http(s) endpoint addressed by public IP instead of a domain name.",
        "c2", CAP, Severity.MEDIUM,
        r"https?://(?!(?:10|127|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!169\.254\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?",
        mitre=("T1437.001",), fp_notes="Internal test servers or captive-portal checks occasionally use IP literals.",
    ),
    StringRule(
        "STR-EMULATOR-CHECKS", "Emulator / analysis-environment checks",
        "Strings associated with emulator or instrumentation detection.",
        "anti_analysis", CAP, Severity.LOW,
        r"(?i)\b(?:goldfish|ranchu|vbox86|genymotion|ro\.kernel\.qemu|sdk_gphone|frida|xposed)\b",
        mitre=("T1633.001",), masvs=("MASVS-RESILIENCE-4",), min_hits=2,
        fp_notes="Legitimate banking/RASP protections include the same checks. Treat as context, not intent.",
    ),
    StringRule(
        "STR-ROOT-CHECKS", "Root-detection strings",
        "References to su binaries or root-management packages.",
        "anti_analysis", INFO, Severity.INFO,
        r"/system/(?:x?bin)/su\b|Superuser\.apk|com\.topjohnwu\.magisk|com\.noshufou\.android\.su",
        masvs=("MASVS-RESILIENCE-1",), fp_notes="Standard defensive control in banking apps.",
    ),
    StringRule(
        "STR-SHELL-COMMANDS", "Shell command strings",
        "Embedded shell commands (privilege changes, silent installs).",
        "command_exec", CAP, Severity.LOW,
        r"\bsu\s+-c\b|\bpm\s+(?:install|grant|disable)\b|\bchmod\s+[0-7]{3,4}\b",
        mitre=("T1623",),
    ),
    StringRule(
        "STR-APK-MIME", "References the APK MIME type",
        "application/vnd.android.package-archive is used when handing an APK to the installer.",
        "dropper", CAP, Severity.LOW, r"application/vnd\.android\.package-archive",
        permissions=("android.permission.REQUEST_INSTALL_PACKAGES",),
    ),
    StringRule(
        "STR-WEAK-CRYPTO", "Weak cryptographic algorithm names",
        "Algorithm identifiers for DES/RC4/ECB mode/MD5/SHA-1 appear as string constants.",
        "crypto", MISCONFIG, Severity.LOW,
        r"^(?:DES|DESede|RC2|RC4|ARC4|Blowfish)(?:/[A-Za-z0-9/]+)?$|^AES/ECB/|^(?:MD5|SHA-?1)$",
        masvs=("MASVS-CRYPTO-1",), full_match=False, max_evidence=5,
        fp_notes="MD5/SHA-1 are often used for non-security checksums. Review the usage context.",
    ),
)

# =============================================================================
# Composite (behaviour) rules
# =============================================================================
R = Requirement
COMPOSITE_RULES: tuple[CompositeRule, ...] = (
    CompositeRule(
        "COMP-SMS-FORWARDING", "SMS received and forwarded by SMS",
        "The same component reads incoming SMS content and sends SMS programmatically, matching "
        "SMS forwarding / OTP relay behaviour.",
        "behavior:sms_forwarding", Severity.HIGH,
        (R(("API-SMS-READ", "STR-SMS-PROVIDER")), R(("API-SMS-SEND",)), R(("CLS-BROADCAST-RECEIVER",))),
        mitre=("T1636.004", "T1582"), class_scope_only=True,
        fp_notes="Auto-reply and relay apps do this legitimately; check destination numbers.",
    ),
    CompositeRule(
        "COMP-SMS-EXFIL-HARDCODED", "SMS read and sent to a hard-coded endpoint",
        "A single class reads SMS content, performs network I/O and references a hard-coded "
        "non-allow-listed URL/IP, matching SMS exfiltration to attacker infrastructure.",
        "behavior:sms_exfiltration", Severity.HIGH,
        (R(("API-SMS-READ", "STR-SMS-PROVIDER")), R(("API-NETWORK",)), R(("IND-ENDPOINT",)), R(("CLS-BROADCAST-RECEIVER",))),
        mitre=("T1636.004", "T1646"), class_scope_only=True,
        fp_notes="A bank app can legitimately POST an OTP to its own server; the differentiators here are an unallow-listed hard-coded endpoint in the same class as raw SMS handling.",
    ),
    CompositeRule(
        "COMP-LOADER-STUB", "Thin loader stub with dynamic code loading",
        "The visible application is a tiny stub (a handful of classes) that loads code dynamically and/or has structural archive "
        "anomalies or a packer signature: the real logic lives outside what static analysis can see. Typical of packed droppers.",
        "behavior:loader_stub", Severity.HIGH,
        (R(("API-DYNAMIC-CODE-LOAD",)), R(("ARC-TINY-CODE", "ARC-SUSPICIOUS-ENTRIES", "ARC-PACKER")), R(("ARC-TINY-CODE", "ARC-SUSPICIOUS-ENTRIES"))),
        mitre=("T1407", "T1406"), scope="app",
        # commercial protectors (Jiagu etc.) are used by legitimate apps and are reported as 'inconclusive' instead,
        # unless the archive also shows evasion anomalies
        unless=("ARC-PACKER",), unless_overridden_by=("ARC-SUSPICIOUS-ENTRIES",),
        fp_notes="No benign app in the 87-app real corpus had a <=15-class app with DexClassLoader; plugin hosts with tiny cores could.",
    ),
    CompositeRule(
        "COMP-SMS-INTERCEPT-REGISTRATION", "Registers a high-priority SMS receiver and holds SMS permissions",
        "The manifest registers a receiver for incoming SMS with elevated priority and requests SMS permissions, the standard "
        "registration used to see OTPs before other apps. (Downgraded for full SMS-client apps.)",
        "behavior:sms_intercept_registration", Severity.HIGH,
        (R(("MAN-SMS-PRIORITY",)), R(("MAN-SMS-PERMISSIONS",))),
        mitre=("T1636.004",), scope="app",
        fp_notes="Legacy/third-party SMS clients (e.g. SMSSecure) register high-priority receivers; the default-SMS-handler context lowers severity.",
    ),
    CompositeRule(
        "COMP-SMS-SUPPRESSION", "High-priority SMS receiver that aborts the broadcast",
        "An SMS receiver registered with elevated priority also aborts the broadcast, hiding "
        "incoming messages (OTP interception).",
        "behavior:sms_suppression", Severity.HIGH,
        (R(("MAN-SMS-PRIORITY",)), R(("API-SMS-ABORT",))),
        mitre=("T1636.004", "T1582"), scope="class", app_scope_severity=Severity.MEDIUM,
    ),
    CompositeRule(
        "COMP-OVERLAY-ACCESSIBILITY", "Accessibility service plus screen overlay",
        "The app combines an accessibility service with overlay capability, the standard "
        "mechanism for credential-phishing overlays and on-device fraud.",
        "behavior:overlay_accessibility", Severity.HIGH,
        (R(("MAN-ACCESSIBILITY-SERVICE", "CLS-ACCESSIBILITY-SERVICE")),
         R(("MAN-OVERLAY-PERM", "API-OVERLAY-WINDOW"))),
        mitre=("T1453", "T1417.002"), scope="app", app_scope_severity=Severity.MEDIUM,
        fp_notes="Remote-control (e.g. KDE Connect), screen-reader and automation apps legitimately hold both capabilities.",
    ),
    CompositeRule(
        "COMP-BANKING-TROJAN-PATTERN", "Banking-trojan capability pattern",
        "Accessibility abuse and overlay capability combined with SMS/notification interception "
        "and a command channel (network, device admin or dynamic code loading).",
        "behavior:banking_trojan", Severity.CRITICAL,
        (R(("MAN-ACCESSIBILITY-SERVICE", "CLS-ACCESSIBILITY-SERVICE")),
         R(("MAN-OVERLAY-PERM", "API-OVERLAY-WINDOW")),
         R(("API-SMS-READ", "STR-SMS-PROVIDER", "API-SMS-SEND", "CLS-NOTIFICATION-LISTENER")),
         R(("API-NETWORK", "CLS-DEVICE-ADMIN", "MAN-DEVICE-ADMIN", "API-DYNAMIC-CODE-LOAD")),
         # abuse marker: something a legitimate app has no reason to do
         R(("MAN-SMS-PRIORITY", "COMP-SMS-SUPPRESSION", "STR-TARGET-APP-ENUM", "STR-IP-LITERAL-ENDPOINT", "STR-TELEGRAM-BOT-API",
            "ARC-SUSPICIOUS-ENTRIES", "COMP-DYNAMIC-PAYLOAD-STAGING"))),
        mitre=("T1453", "T1417.002", "T1636.004", "T1517"), scope="app",
        fp_notes="Co-occurrence is app-level, not proof of a single attack chain; review the linked evidence.",
    ),
    CompositeRule(
        "COMP-DROPPER", "Installs additional packages with a delivery channel",
        "The app can install APKs and can fetch or decrypt code (network or dynamic loading).",
        "behavior:dropper", Severity.HIGH,
        (R(("API-PACKAGE-INSTALL", "MAN-INSTALL-PACKAGES-PERM")),
         R(("API-DYNAMIC-CODE-LOAD", "API-NETWORK")),
         R(("MAN-SMS-PRIORITY", "ARC-PACKER", "STR-IP-LITERAL-ENDPOINT", "STR-TELEGRAM-BOT-API", "ARC-SUSPICIOUS-ENTRIES"))),
        mitre=("T1407",), scope="app", app_scope_severity=Severity.MEDIUM,
        fp_notes="App stores and in-app updaters share this shape.",
    ),
    CompositeRule(
        "COMP-DYNAMIC-PAYLOAD-STAGING", "Dynamic code loading with network and cryptography",
        "A class loads code dynamically, uses network I/O and performs cryptographic operations, "
        "consistent with downloading and decrypting a second-stage payload.",
        "behavior:payload_staging", Severity.HIGH,
        (R(("API-DYNAMIC-CODE-LOAD",)), R(("API-NETWORK",)), R(("API-CRYPTO",))),
        mitre=("T1407",), class_scope_only=True,
    ),
    CompositeRule(
        "COMP-DEVICE-ADMIN-PERSISTENCE", "Device admin with boot persistence and lock/wipe",
        "A device administrator that restarts on boot and calls lock/wipe/password APIs.",
        "behavior:admin_persistence", Severity.HIGH,
        (R(("CLS-DEVICE-ADMIN", "MAN-DEVICE-ADMIN")), R(("MAN-BOOT-RECEIVER",)), R(("API-DEVICE-ADMIN-CONTROL",))),
        mitre=("T1626.001", "T1629.002"), scope="app",
    ),
    CompositeRule(
        "COMP-STEALTH-WITH-CAPABILITY", "Hides launcher icon while holding sensitive capabilities",
        "The app can hide its launcher icon and holds SMS, accessibility or device-admin capability.",
        "behavior:stealth", Severity.HIGH,
        (R(("API-HIDE-LAUNCHER-ICON",)),
         R(("MAN-SMS-PRIORITY", "STR-TELEGRAM-BOT-API", "STR-IP-LITERAL-ENDPOINT", "ARC-PACKER", "ARC-SUSPICIOUS-ENTRIES"))),
        mitre=("T1628.001",), scope="app", app_scope_severity=Severity.MEDIUM,
    ),
    CompositeRule(
        "COMP-SCREEN-REMOTE-CONTROL", "Screen capture with accessibility control",
        "Screen capture combined with accessibility automation and a network channel, matching "
        "remote-access trojan behaviour.",
        "behavior:remote_access", Severity.HIGH,
        (R(("API-SCREEN-CAPTURE",)),
         R(("MAN-ACCESSIBILITY-SERVICE", "CLS-ACCESSIBILITY-SERVICE", "API-ACCESSIBILITY-AUTOMATION")),
         R(("API-NETWORK",))),
        mitre=("T1513", "T1453"), scope="app", app_scope_severity=Severity.MEDIUM,
        fp_notes="Remote-support apps (screen sharing tools) have the same shape; verify publisher.",
    ),
)

# crypto is referenced by composites; defined as an info rule separate from the tuple above
CRYPTO_RULE = ApiRule(
    "API-CRYPTO", "Cryptographic API usage",
    "javax.crypto Cipher/SecretKeySpec usage. Supporting evidence only.",
    "crypto_use", INFO, Severity.INFO,
    (("Ljavax/crypto/Cipher;", ("getInstance", "doFinal")), ("Ljavax/crypto/spec/SecretKeySpec;", ("<init>",))),
    max_evidence=6,
)
ALL_API_RULES: tuple[ApiRule, ...] = API_RULES + (CRYPTO_RULE,)
