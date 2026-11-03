"""Manifest-derived findings. Keeps malicious-capability signals separate from misconfigurations."""

from __future__ import annotations

from dataclasses import dataclass, field

from malintx.analysis.rules.evidence import EvidenceStore
from malintx.schemas.common import Confidence, EvidenceKind, FindingKind, Severity
from malintx.schemas.sample import ComponentInfo, ManifestInfo

SRC = "AndroidManifest.xml"
METHOD = "androguard-axml"
RECON = "Snippet reconstructed from the parsed manifest, not raw XML bytes."

SMS_PERMS = (
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS", "android.permission.WRITE_SMS", "android.permission.RECEIVE_WAP_PUSH",
)
SMS_RECEIVED = "android.provider.Telephony.SMS_RECEIVED"
SMS_DELIVER_ACTIONS = (
    "android.provider.Telephony.SMS_DELIVER", "android.intent.action.RESPOND_VIA_MESSAGE",
    "android.provider.Telephony.WAP_PUSH_DELIVER",
)
BOOT_ACTIONS = ("android.intent.action.BOOT_COMPLETED", "android.intent.action.QUICKBOOT_POWERON")


@dataclass(frozen=True)
class ManifestRuleMeta:
    id: str
    title: str
    description: str
    category: str
    kind: FindingKind
    severity: Severity
    mitre: tuple[str, ...] = ()
    masvs: tuple[str, ...] = ()
    fp_notes: str | None = None


M = ManifestRuleMeta
CAP, INFO, MIS = FindingKind.SUSPICIOUS_CAPABILITY, FindingKind.INFORMATIONAL, FindingKind.SECURITY_MISCONFIGURATION

MANIFEST_RULES: dict[str, ManifestRuleMeta] = {
    m.id: m
    for m in (
        M("MAN-SMS-PERMISSIONS", "Requests SMS permissions",
          "The manifest requests SMS read/receive/send permissions.", "sms_perm", CAP, Severity.MEDIUM,
          mitre=("T1636.004",),
          fp_notes="Banking/payment apps request SMS permissions for OTP auto-fill. Not malicious on its own."),
        M("MAN-SMS-PRIORITY", "SMS receiver registered with elevated priority",
          "A receiver for SMS_RECEIVED/SMS_DELIVER sets an intent-filter priority ≥ 900 so it sees "
          "incoming messages before the default SMS app, a classic OTP-interception trait.",
          "sms_intercept", CAP, Severity.HIGH, mitre=("T1636.004",)),
        M("MAN-DEFAULT-SMS-HANDLER", "Declares default-SMS-app components",
          "The app declares components required to be the default SMS application.", "sms_default",
          CAP, Severity.MEDIUM, mitre=("T1636.004", "T1582"),
          fp_notes="Required by legitimate messaging apps."),
        M("MAN-ACCESSIBILITY-SERVICE", "Declares an accessibility service",
          "The app declares a service bound with BIND_ACCESSIBILITY_SERVICE.", "accessibility_svc",
          CAP, Severity.HIGH, mitre=("T1453",),
          fp_notes="Assistive tech, password managers and automation tools."),
        M("MAN-DEVICE-ADMIN", "Declares a device-administrator receiver",
          "The app declares a device-admin receiver.", "device_admin_decl", CAP, Severity.HIGH,
          mitre=("T1626.001",), fp_notes="MDM agents and parental-control tools."),
        M("MAN-OVERLAY-PERM", "Requests SYSTEM_ALERT_WINDOW",
          "The app can draw over other apps.", "overlay_perm", CAP, Severity.MEDIUM, mitre=("T1417.002",),
          fp_notes="Chat heads, screen filters, floating tools."),
        M("MAN-INSTALL-PACKAGES-PERM", "Requests REQUEST_INSTALL_PACKAGES",
          "The app can prompt installation of other APKs.", "dropper_perm", CAP, Severity.MEDIUM,
          fp_notes="App stores, browsers and file managers."),
        M("MAN-NOTIFICATION-LISTENER", "Declares a notification-listener service",
          "The app can read notifications (including OTP messages) if the user grants access.",
          "notification_decl", CAP, Severity.MEDIUM, mitre=("T1517",)),
        M("MAN-BOOT-RECEIVER", "Starts on device boot",
          "A receiver is registered for BOOT_COMPLETED.", "persistence_boot", CAP, Severity.LOW,
          mitre=("T1624.001",), fp_notes="Extremely common in benign apps (alarms, sync)."),
        M("MAN-USAGE-STATS", "Requests PACKAGE_USAGE_STATS",
          "Allows learning which app is in the foreground (used to time overlays).", "usage_stats", CAP,
          Severity.MEDIUM, mitre=("T1424",), fp_notes="Digital-wellbeing, parental-control and security apps."),
        M("MAN-TASK-AFFINITY", "Activity with foreign task affinity and reparenting",
          "An activity sets a taskAffinity different from the package with allowTaskReparenting, "
          "the pattern used by task-hijacking (StrandHogg-style) attacks.", "task_hijack", CAP,
          Severity.MEDIUM),
        M("MAN-QUERY-ALL-PACKAGES", "Requests QUERY_ALL_PACKAGES",
          "Can enumerate every installed app.", "app_enum", CAP, Severity.LOW, mitre=("T1418",),
          fp_notes="Launchers, security and backup tools."),
        M("MAN-PERMISSION-INVENTORY", "Sensitive permission inventory",
          "Dangerous and special-access permissions requested by the app.", "permissions", INFO, Severity.INFO),
        M("MAN-DEBUGGABLE", "Application is debuggable",
          "android:debuggable=true allows attaching a debugger and reading app data on release builds.",
          "posture", MIS, Severity.MEDIUM, masvs=("MASVS-RESILIENCE-2",)),
        M("MAN-ALLOW-BACKUP", "Application data backup allowed",
          "android:allowBackup is true (or unset, defaulting to true).", "posture", MIS, Severity.LOW,
          masvs=("MASVS-STORAGE-2",)),
        M("MAN-CLEARTEXT", "Cleartext HTTP traffic permitted",
          "The app permits cleartext HTTP (explicitly, or by default on target SDK < 28).", "posture", MIS,
          Severity.MEDIUM, masvs=("MASVS-NETWORK-1",)),
        M("MAN-EXPORTED-COMPONENTS", "Exported components without permission protection",
          "Components reachable by any app on the device without a guarding permission.", "posture", MIS,
          Severity.MEDIUM, masvs=("MASVS-PLATFORM-1",)),
        M("MAN-LOW-TARGET-SDK", "Targets an outdated Android SDK",
          "A low targetSdkVersion opts out of newer platform protections.", "posture", MIS, Severity.LOW,
          masvs=("MASVS-CODE-1",)),
        M("MAN-TEST-ONLY", "Application marked testOnly", "android:testOnly=true is set.", "posture", MIS,
          Severity.LOW, masvs=("MASVS-RESILIENCE-2",)),
        M("MAN-SHARED-UID", "Uses sharedUserId", "Deprecated shared UID weakens app isolation.", "posture",
          MIS, Severity.LOW, masvs=("MASVS-PLATFORM-1",)),
        M("MAN-WEAK-CUSTOM-PERMISSION", "Custom permission with normal protection level",
          "Any app can obtain a normal-level custom permission, so it does not protect the component.",
          "posture", MIS, Severity.LOW, masvs=("MASVS-PLATFORM-1",)),
    )
}


@dataclass
class Hit:
    """Aggregated observation of a rule, used for correlation by the composite stage."""

    rule_id: str
    evidence_ids: list[str] = field(default_factory=list)
    classes: set[str] = field(default_factory=set)  # outer class descriptors, e.g. Lcom/x/Foo;
    library_only: bool = False
    total_sites: int = 0
    note: str = ""
    confidence: Confidence = Confidence.HIGH


def class_desc(dotted: str) -> str:
    return "L" + dotted.replace(".", "/") + ";"


def _tag(c: ComponentInfo) -> str:
    return {"activity": "activity", "service": "service", "receiver": "receiver", "provider": "provider"}[c.kind]


def _comp_snippet(c: ComponentInfo) -> str:
    lines = [f'<{_tag(c)} android:name="{c.name}" android:exported="{str(c.exported).lower()}"'
             + (f' android:permission="{c.permission}"' if c.permission else "") + ">"]
    for f in c.intent_filters:
        pr = f' android:priority="{f.priority}"' if f.priority is not None else ""
        lines.append(f"  <intent-filter{pr}>")
        lines += [f'    <action android:name="{a}"/>' for a in f.actions]
        lines.append("  </intent-filter>")
    lines.append(f"</{_tag(c)}>")
    return "\n".join(lines)


def evaluate_manifest(m: ManifestInfo, store: EvidenceStore) -> dict[str, Hit]:
    hits: dict[str, Hit] = {}

    def hit(rule_id: str, *, artifact: str, snippet: str, cls: str | None = None, api: str | None = None) -> Hit:
        h = hits.setdefault(rule_id, Hit(rule_id))
        ev = store.add(
            kind=EvidenceKind.MANIFEST, rule_id=rule_id, source_file=SRC, extraction_method=METHOD,
            class_name=cls, api=api, artifact=artifact, snippet=snippet, confidence=Confidence.HIGH,
            limitations=RECON,
        )
        if ev and ev.id not in h.evidence_ids:
            h.evidence_ids.append(ev.id)
        if cls:
            h.classes.add(class_desc(cls))
        h.total_sites += 1
        return h

    perms = m.permission_names()
    perm_line = lambda p: f'<uses-permission android:name="{p}"/>'  # noqa: E731

    for p in SMS_PERMS:
        if p in perms:
            hit("MAN-SMS-PERMISSIONS", artifact=p, snippet=perm_line(p))
    if "android.permission.SYSTEM_ALERT_WINDOW" in perms:
        hit("MAN-OVERLAY-PERM", artifact="android.permission.SYSTEM_ALERT_WINDOW",
            snippet=perm_line("android.permission.SYSTEM_ALERT_WINDOW"))
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        hit("MAN-INSTALL-PACKAGES-PERM", artifact="android.permission.REQUEST_INSTALL_PACKAGES",
            snippet=perm_line("android.permission.REQUEST_INSTALL_PACKAGES"))
    if "android.permission.PACKAGE_USAGE_STATS" in perms:
        hit("MAN-USAGE-STATS", artifact="android.permission.PACKAGE_USAGE_STATS",
            snippet=perm_line("android.permission.PACKAGE_USAGE_STATS"))
    if "android.permission.QUERY_ALL_PACKAGES" in perms:
        hit("MAN-QUERY-ALL-PACKAGES", artifact="android.permission.QUERY_ALL_PACKAGES",
            snippet=perm_line("android.permission.QUERY_ALL_PACKAGES"))
    for p in m.permissions:
        if p.sensitivity in ("dangerous", "special"):
            hit("MAN-PERMISSION-INVENTORY", artifact=p.name, snippet=perm_line(p.name))

    for c in m.components:
        actions = {a for f in c.intent_filters for a in f.actions}
        if c.kind == "receiver":
            for f in c.intent_filters:
                if (SMS_RECEIVED in f.actions or "android.provider.Telephony.SMS_DELIVER" in f.actions) and (f.priority or 0) >= 900:
                    hit("MAN-SMS-PRIORITY", artifact=f"{c.name} priority={f.priority}", snippet=_comp_snippet(c), cls=c.name)
            if actions & set(BOOT_ACTIONS):
                hit("MAN-BOOT-RECEIVER", artifact=c.name, snippet=_comp_snippet(c), cls=c.name)
        if actions & set(SMS_DELIVER_ACTIONS):
            hit("MAN-DEFAULT-SMS-HANDLER", artifact=c.name, snippet=_comp_snippet(c), cls=c.name)
        if c.kind == "service" and c.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
            hit("MAN-NOTIFICATION-LISTENER", artifact=c.name, snippet=_comp_snippet(c), cls=c.name)
        if c.kind == "activity" and c.task_affinity and c.allow_task_reparenting:
            if c.task_affinity != m.package and not c.task_affinity.startswith(m.package + "."):
                hit("MAN-TASK-AFFINITY", artifact=f"{c.name} taskAffinity={c.task_affinity}",
                    snippet=_comp_snippet(c), cls=c.name)
    for name in m.accessibility_services:
        comp = next((c for c in m.components if c.name == name), None)
        hit("MAN-ACCESSIBILITY-SERVICE", artifact=name, snippet=_comp_snippet(comp) if comp else name, cls=name)
    for name in m.device_admin_receivers:
        comp = next((c for c in m.components if c.name == name), None)
        hit("MAN-DEVICE-ADMIN", artifact=name, snippet=_comp_snippet(comp) if comp else name, cls=name)

    # ---- posture (misconfiguration, never malice) ----
    if m.debuggable:
        hit("MAN-DEBUGGABLE", artifact="android:debuggable=true", snippet='<application android:debuggable="true">')
    if m.allow_backup is None or m.allow_backup:
        hit("MAN-ALLOW-BACKUP", artifact=f"android:allowBackup={m.allow_backup}",
            snippet=f'<application android:allowBackup="{str(m.allow_backup).lower() if m.allow_backup is not None else "(unset → true)"}">')
    if m.uses_cleartext_traffic or (m.uses_cleartext_traffic is None and m.network_security_config is None
                                    and (m.target_sdk or 0) and (m.target_sdk or 0) < 28):
        hit("MAN-CLEARTEXT", artifact=f"usesCleartextTraffic={m.uses_cleartext_traffic} targetSdk={m.target_sdk}",
            snippet='<application android:usesCleartextTraffic="true">' if m.uses_cleartext_traffic
            else f"targetSdkVersion={m.target_sdk}: cleartext permitted by platform default")
    for c in m.components:
        launcher = any("android.intent.category.LAUNCHER" in f.categories for f in c.intent_filters)
        if c.exported and not c.permission and not launcher and c.enabled:
            hit("MAN-EXPORTED-COMPONENTS", artifact=f"{c.kind}:{c.name}", snippet=_comp_snippet(c), cls=c.name)
    if m.target_sdk is not None and m.target_sdk < 29:
        hit("MAN-LOW-TARGET-SDK", artifact=f"targetSdkVersion={m.target_sdk}",
            snippet=f'<uses-sdk android:targetSdkVersion="{m.target_sdk}"/>')
    if m.test_only:
        hit("MAN-TEST-ONLY", artifact="android:testOnly=true", snippet='<application android:testOnly="true">')
    if m.shared_user_id:
        hit("MAN-SHARED-UID", artifact=m.shared_user_id, snippet=f'<manifest android:sharedUserId="{m.shared_user_id}">')
    for cp in m.custom_permissions:
        if cp.protection_level in (None, "0", "0x0", "normal", "dangerous", "1", "0x1"):
            hit("MAN-WEAK-CUSTOM-PERMISSION", artifact=f"{cp.name} protectionLevel={cp.protection_level}",
                snippet=f'<permission android:name="{cp.name}" android:protectionLevel="{cp.protection_level}"/>')
    return hits
