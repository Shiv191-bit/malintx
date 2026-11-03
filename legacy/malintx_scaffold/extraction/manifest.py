"""
MALINT-X Manifest Parser.

Parses ``AndroidManifest.xml`` and extracts package metadata, permissions,
components (activities, services, receivers, providers) with their exported
status and intent-filter actions.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence

from malintx.config import DANGEROUS_PERMISSIONS
from malintx.core.models import AndroidComponent, ManifestData

logger = logging.getLogger(__name__)

# Android XML namespace
_NS = "http://schemas.android.com/apk/res/android"
_NS_MAP = {"android": _NS}


def _attr(element: ET.Element, name: str) -> str | None:
    """Return an android-namespaced attribute value, or ``None``."""
    return element.get(f"{{{_NS}}}{name}")


class ManifestParser:
    """Parser for ``AndroidManifest.xml``.

    Usage::

        parser = ManifestParser()
        data = parser.parse(Path("path/to/AndroidManifest.xml"))
        print(data.package_name, data.dangerous_permissions)
    """

    def parse(self, manifest_path: Path) -> ManifestData:
        """Parse an AndroidManifest.xml file into structured data.

        Parameters
        ----------
        manifest_path:
            Path to the ``AndroidManifest.xml`` file.

        Returns
        -------
        ManifestData
            A populated data model.  On parse failure an empty
            :class:`ManifestData` with ``package_name`` set to ``"<parse-error>"``
            is returned.
        """
        manifest_path = Path(manifest_path)
        if not manifest_path.is_file():
            logger.error("Manifest file not found: %s", manifest_path)
            return ManifestData(package_name="<file-not-found>")

        try:
            tree = ET.parse(manifest_path)  # noqa: S314 – trusted local file
        except ET.ParseError as exc:
            logger.error("Malformed XML in manifest %s: %s", manifest_path, exc)
            return ManifestData(package_name="<parse-error>")
        except OSError as exc:
            logger.error("Cannot read manifest %s: %s", manifest_path, exc)
            return ManifestData(package_name="<read-error>")

        root = tree.getroot()

        # ---- Top-level manifest attributes ----
        package_name = root.get("package", "")
        version_code = _attr(root, "versionCode")
        version_name = _attr(root, "versionName")

        # ---- SDK versions ----
        min_sdk: int | None = None
        target_sdk: int | None = None
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            min_sdk = self._safe_int(_attr(uses_sdk, "minSdkVersion"))
            target_sdk = self._safe_int(_attr(uses_sdk, "targetSdkVersion"))

        # ---- Permissions ----
        permissions = self._extract_permissions(root)
        dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]

        # ---- Components ----
        application = root.find("application")
        activities: list[AndroidComponent] = []
        services: list[AndroidComponent] = []
        receivers: list[AndroidComponent] = []
        providers: list[AndroidComponent] = []

        if application is not None:
            activities = self._extract_components(application, "activity", "activity")
            # Also handle activity-alias
            activities += self._extract_components(application, "activity-alias", "activity")
            services = self._extract_components(application, "service", "service")
            receivers = self._extract_components(application, "receiver", "receiver")
            providers = self._extract_components(application, "provider", "provider")

        # Collect all unique intent-filter actions across every component
        all_intent_filters = self._collect_all_intent_filter_actions(root)

        # ---- uses-feature ----
        uses_features: list[str] = []
        for feat in root.findall("uses-feature"):
            name = _attr(feat, "name")
            if name:
                uses_features.append(name)

        return ManifestData(
            package_name=package_name,
            version_code=version_code,
            version_name=version_name,
            min_sdk_version=min_sdk,
            target_sdk_version=target_sdk,
            permissions=permissions,
            dangerous_permissions=dangerous,
            activities=activities,
            services=services,
            receivers=receivers,
            providers=providers,
            intent_filters=all_intent_filters,
            uses_features=uses_features,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_int(value: str | None) -> int | None:
        """Parse an integer attribute that may be ``None`` or non-numeric."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _extract_permissions(root: ET.Element) -> list[str]:
        """Extract all ``<uses-permission>`` names."""
        perms: list[str] = []
        for tag_name in ("uses-permission", "uses-permission-sdk-23"):
            for elem in root.findall(tag_name):
                name = _attr(elem, "name")
                if name:
                    perms.append(name)
        return perms

    @staticmethod
    def _extract_components(
        application: ET.Element,
        tag: str,
        component_type: str,
    ) -> list[AndroidComponent]:
        """Extract components of a given *tag* from the ``<application>``."""
        components: list[AndroidComponent] = []
        for elem in application.findall(tag):
            name = _attr(elem, "name") or elem.get("name", "")
            if not name:
                continue

            # Exported attribute (may be absent — Android infers it)
            exported_str = _attr(elem, "exported")
            if exported_str is not None:
                exported: bool | None = exported_str.lower() == "true"
            else:
                # If any intent-filter is declared, Android treats the component
                # as implicitly exported (prior to API 31).
                has_filter = elem.find("intent-filter") is not None
                exported = True if has_filter else None

            # Gather intent-filter action names
            intent_filters: list[str] = []
            for intent_filter in elem.findall("intent-filter"):
                for action in intent_filter.findall("action"):
                    action_name = _attr(action, "name")
                    if action_name:
                        intent_filters.append(action_name)

            components.append(
                AndroidComponent(
                    name=name,
                    component_type=component_type,
                    exported=exported,
                    intent_filters=intent_filters,
                )
            )
        return components

    @staticmethod
    def _collect_all_intent_filter_actions(root: ET.Element) -> list[str]:
        """Return a deduplicated list of every intent-filter action in the manifest."""
        seen: set[str] = set()
        actions: list[str] = []
        for action_elem in root.iter("action"):
            name = _attr(action_elem, "name")
            if name and name not in seen:
                seen.add(name)
                actions.append(name)
        return actions
