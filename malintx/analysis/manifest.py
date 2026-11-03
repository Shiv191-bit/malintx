"""AndroidManifest.xml → `ManifestInfo`.

Works on any element tree exposing `.get/.find/.findall/.iter` (androguard's decoded lxml tree for
binary manifests, or a `defusedxml`-parsed tree for Apktool's text output).
"""

from __future__ import annotations

from typing import Any

from defusedxml import ElementTree as SafeET

from malintx.schemas.sample import (
    ComponentInfo,
    CustomPermission,
    IntentFilterInfo,
    ManifestInfo,
    PermissionUse,
)

NS = "{http://schemas.android.com/apk/res/android}"

# Runtime ("dangerous") permissions per the Android platform documentation.
DANGEROUS = frozenset(
    "android.permission." + p
    for p in (
        "READ_SMS SEND_SMS RECEIVE_SMS RECEIVE_MMS RECEIVE_WAP_PUSH READ_CONTACTS WRITE_CONTACTS "
        "GET_ACCOUNTS READ_CALL_LOG WRITE_CALL_LOG PROCESS_OUTGOING_CALLS READ_PHONE_STATE "
        "READ_PHONE_NUMBERS CALL_PHONE ANSWER_PHONE_CALLS ADD_VOICEMAIL USE_SIP CAMERA RECORD_AUDIO "
        "ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION ACCESS_BACKGROUND_LOCATION "
        "READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE READ_CALENDAR WRITE_CALENDAR BODY_SENSORS "
        "ACTIVITY_RECOGNITION READ_MEDIA_IMAGES READ_MEDIA_VIDEO READ_MEDIA_AUDIO POST_NOTIFICATIONS "
        "NEARBY_WIFI_DEVICES BLUETOOTH_CONNECT BLUETOOTH_SCAN BLUETOOTH_ADVERTISE UWB_RANGING "
        "READ_MEDIA_VISUAL_USER_SELECTED"
    ).split()
)

# Special-access / high-impact permissions that need dedicated user or system gestures.
SPECIAL = frozenset(
    "android.permission." + p
    for p in (
        "SYSTEM_ALERT_WINDOW REQUEST_INSTALL_PACKAGES WRITE_SETTINGS MANAGE_EXTERNAL_STORAGE "
        "BIND_ACCESSIBILITY_SERVICE BIND_DEVICE_ADMIN BIND_NOTIFICATION_LISTENER_SERVICE "
        "PACKAGE_USAGE_STATS QUERY_ALL_PACKAGES USE_FULL_SCREEN_INTENT SCHEDULE_EXACT_ALARM "
        "USE_EXACT_ALARM REQUEST_IGNORE_BATTERY_OPTIMIZATIONS BIND_INPUT_METHOD "
        "BIND_VPN_SERVICE READ_LOGS WRITE_SECURE_SETTINGS INSTALL_PACKAGES DELETE_PACKAGES "
        "MANAGE_ACCOUNTS CHANGE_COMPONENT_ENABLED_STATE"
    ).split()
)

_COMPONENT_TAGS = (
    ("activity", "activity"),
    ("activity-alias", "activity"),
    ("service", "service"),
    ("receiver", "receiver"),
    ("provider", "provider"),
)


def _a(el: Any, name: str) -> str | None:
    val = el.get(NS + name)
    return None if val is None else str(val)


def _bool(val: str | None) -> bool | None:
    if val is None:
        return None
    v = val.strip().lower()
    if v in ("true", "0xffffffff", "-1", "1"):
        return True
    if v in ("false", "0", "0x0", "0x00000000"):
        return False
    return None


def _int(val: str | None) -> int | None:
    if val is None:
        return None
    try:
        return int(val, 0)
    except ValueError:
        return None


def _sensitivity(name: str) -> str:
    if name in DANGEROUS:
        return "dangerous"
    if name in SPECIAL:
        return "special"
    return "normal"


def _normalise_component_name(name: str, package: str) -> str:
    if name.startswith("."):
        return package + name
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def _intent_filters(el: Any) -> list[IntentFilterInfo]:
    out = []
    for f in el.findall("intent-filter"):
        out.append(
            IntentFilterInfo(
                actions=[x for x in (_a(n, "name") for n in f.findall("action")) if x],
                categories=[x for x in (_a(n, "name") for n in f.findall("category")) if x],
                data_schemes=[x for x in (_a(n, "scheme") for n in f.findall("data")) if x],
                priority=_int(_a(f, "priority")),
            )
        )
    return out


def parse_manifest_element(root: Any) -> ManifestInfo:
    warnings: list[str] = []
    package = root.get("package") or ""
    if not package:
        warnings.append("manifest has no package attribute")

    sdk = root.find("uses-sdk")
    min_sdk = target_sdk = max_sdk = None
    if sdk is not None:
        min_sdk, target_sdk, max_sdk = (
            _int(_a(sdk, "minSdkVersion")),
            _int(_a(sdk, "targetSdkVersion")),
            _int(_a(sdk, "maxSdkVersion")),
        )
    eff_target = target_sdk if target_sdk is not None else min_sdk

    permissions: list[PermissionUse] = []
    seen: set[str] = set()
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for el in root.findall(tag):
            name = _a(el, "name")
            if name and name not in seen:
                seen.add(name)
                permissions.append(
                    PermissionUse(
                        name=name,
                        is_platform=name.startswith("android.permission."),
                        sensitivity=_sensitivity(name),
                    )
                )

    custom = [
        CustomPermission(name=n, protection_level=_a(el, "protectionLevel"))
        for el in root.findall("permission")
        if (n := _a(el, "name"))
    ]

    app = root.find("application")
    components: list[ComponentInfo] = []
    accessibility: list[str] = []
    admin: list[str] = []
    debuggable = allow_backup = cleartext = test_only = None
    nsc = app_class = None
    if app is not None:
        debuggable = _bool(_a(app, "debuggable"))
        allow_backup = _bool(_a(app, "allowBackup"))
        cleartext = _bool(_a(app, "usesCleartextTraffic"))
        test_only = _bool(_a(app, "testOnly"))
        nsc = _a(app, "networkSecurityConfig")
        app_class = _a(app, "name")
        for tag, kind in _COMPONENT_TAGS:
            for el in app.findall(tag):
                raw_name = _a(el, "name") or _a(el, "targetActivity")
                if not raw_name:
                    continue
                name = _normalise_component_name(raw_name, package)
                filters = _intent_filters(el)
                explicit = _bool(_a(el, "exported"))
                if explicit is not None:
                    exported = explicit
                elif kind == "provider":
                    exported = eff_target is not None and eff_target < 17
                else:
                    exported = bool(filters)
                permission = _a(el, "permission")
                meta = [m for m in (_a(x, "name") for x in el.findall("meta-data")) if m]
                comp = ComponentInfo(
                    kind=kind,
                    name=name,
                    exported=exported,
                    exported_explicit=explicit,
                    permission=permission,
                    enabled=_bool(_a(el, "enabled")) is not False,
                    intent_filters=filters,
                    task_affinity=_a(el, "taskAffinity"),
                    allow_task_reparenting=_bool(_a(el, "allowTaskReparenting")),
                    extra={"meta_data": ",".join(meta)} if meta else {},
                )
                components.append(comp)
                actions = {a for f in filters for a in f.actions}
                if kind == "service" and (
                    permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
                    or "android.accessibilityservice.AccessibilityService" in actions
                ):
                    accessibility.append(name)
                if kind == "receiver" and (
                    permission == "android.permission.BIND_DEVICE_ADMIN"
                    or "android.app.device_admin" in meta
                    or "android.app.action.DEVICE_ADMIN_ENABLED" in actions
                ):
                    admin.append(name)

    return ManifestInfo(
        package=package,
        version_name=_a(root, "versionName"),
        version_code=_a(root, "versionCode"),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        max_sdk=max_sdk,
        permissions=permissions,
        custom_permissions=custom,
        components=components,
        uses_features=[n for el in root.findall("uses-feature") if (n := _a(el, "name"))],
        debuggable=debuggable,
        allow_backup=allow_backup,
        uses_cleartext_traffic=cleartext,
        network_security_config=nsc,
        test_only=test_only,
        shared_user_id=_a(root, "sharedUserId"),
        application_class=app_class,
        accessibility_services=accessibility,
        device_admin_receivers=admin,
        parse_warnings=warnings,
    )


def parse_manifest_text(xml_text: str) -> ManifestInfo:
    """Parse a decoded (text) manifest, e.g. from Apktool. Uses defusedxml against XXE/bombs."""
    return parse_manifest_element(SafeET.fromstring(xml_text))
