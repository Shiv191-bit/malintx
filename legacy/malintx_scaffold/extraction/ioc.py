"""
MALINT-X Indicator of Compromise (IoC) Extractor.

Scans decompiled source, XML, and JSON files for network-based indicators
(IPv4 addresses, URLs, domain names), filters out benign/private-range
entries, and returns a deduplicated list of :class:`IoC` objects.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from malintx.core.models import IoC, IoCType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# IPv4 — four dot-separated octets (must NOT be preceded/followed by a digit
# to avoid matching inside version strings like "1.2.3.4.5").
_IPV4_RE = re.compile(
    r"(?<![0-9.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?![0-9.])"
)

# Full URL with scheme
_URL_RE = re.compile(
    r"https?://"
    r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"
)

# Domain name (must have at least two labels and a valid TLD)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|gq|cc|pw|"
    r"de|uk|fr|br|in|jp|au|ca|nl|eu|se|no|fi|dk|ch|at|za|co|me|tv|ws|"
    r"pro|mobi|tel|asia|name|aero|coop|museum|onion|app|dev|cloud)\b"
)

# ---------------------------------------------------------------------------
# Benign allow-lists
# ---------------------------------------------------------------------------

_BENIGN_DOMAINS: frozenset[str] = frozenset({
    "localhost",
    "google.com",
    "www.google.com",
    "android.com",
    "www.android.com",
    "developer.android.com",
    "googleapis.com",
    "www.googleapis.com",
    "gstatic.com",
    "www.gstatic.com",
    "schema.org",
    "www.w3.org",
    "w3.org",
    "xmlpull.org",
    "xml.org",
    "apache.org",
    "www.apache.org",
    "schemas.android.com",
    "ns.adobe.com",
    "play.google.com",
    "dl.google.com",
    "fonts.googleapis.com",
    "maps.googleapis.com",
    "firebase.google.com",
    "crashlytics.com",
    "firebaseio.com",
    "googlesyndication.com",
    "googleadservices.com",
    "doubleclick.net",
    "goo.gl",
    "github.com",
    "raw.githubusercontent.com",
    "stackoverflow.com",
    "example.com",
    "example.org",
    "example.net",
    "mozilla.org",
    "www.mozilla.org",
    "gradle.org",
    "maven.org",
    "jitpack.io",
    "bintray.com",
    "kotlin.org",
    "jetbrains.com",
})

_BENIGN_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".google.com",
    ".googleapis.com",
    ".gstatic.com",
    ".android.com",
    ".googlesyndication.com",
    ".googleadservices.com",
    ".doubleclick.net",
    ".firebase.com",
    ".firebaseio.com",
    ".crashlytics.com",
    ".apple.com",
    ".mozilla.org",
    ".w3.org",
    ".apache.org",
    ".gradle.org",
    ".github.com",
    ".github.io",
    ".githubusercontent.com",
)

# File extensions to scan
_SCAN_EXTENSIONS: frozenset[str] = frozenset({".java", ".xml", ".json"})


class IoCExtractor:
    """Extract network-based Indicators of Compromise from source files.

    Usage::

        extractor = IoCExtractor()
        iocs = extractor.extract(Path("workdir/jadx_xyz/sources"))
    """

    def extract(self, source_root: Path) -> list[IoC]:
        """Scan all relevant files under *source_root* for IoCs.

        Parameters
        ----------
        source_root:
            Root directory of decompiled source files.

        Returns
        -------
        list[IoC]
            Deduplicated list of extracted indicators.
        """
        source_root = Path(source_root)
        if not source_root.is_dir():
            logger.error("Source root does not exist: %s", source_root)
            return []

        seen: dict[str, IoC] = {}  # value -> first occurrence

        scan_files = [
            f for f in source_root.rglob("*")
            if f.is_file() and f.suffix.lower() in _SCAN_EXTENSIONS
        ]
        logger.info("IoC extractor scanning %d files in %s", len(scan_files), source_root)

        for file_path in scan_files:
            try:
                self._scan_file(file_path, seen)
            except Exception:
                logger.warning("Error scanning %s for IoCs", file_path, exc_info=True)

        result = list(seen.values())
        logger.info("IoC extractor found %d unique indicators", len(result))
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_file(self, file_path: Path, seen: dict[str, IoC]) -> None:
        """Scan a single file and add unique IoCs to *seen*."""
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return

        lines = text.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            # --- URLs (check first, as they contain domains and possibly IPs) ---
            for match in _URL_RE.finditer(line):
                url = match.group(0).rstrip(".,;:)\"'>")
                if self._is_benign_url(url):
                    continue
                if url not in seen:
                    seen[url] = IoC(
                        value=url,
                        ioc_type=IoCType.URL,
                        source_file=str(file_path),
                        line_number=line_idx,
                        context=line.strip()[:200],
                    )

            # --- IPv4 addresses ---
            for match in _IPV4_RE.finditer(line):
                ip = match.group(0)
                if self._is_benign_ip(ip):
                    continue
                if ip not in seen:
                    seen[ip] = IoC(
                        value=ip,
                        ioc_type=IoCType.IPV4,
                        source_file=str(file_path),
                        line_number=line_idx,
                        context=line.strip()[:200],
                    )

            # --- Domain names ---
            for match in _DOMAIN_RE.finditer(line):
                domain = match.group(0).lower().rstrip(".")
                if self._is_benign_domain(domain):
                    continue
                # Skip if this domain is already part of a captured URL
                if any(domain in url_val for url_val in seen if seen[url_val].ioc_type == IoCType.URL):
                    continue
                if domain not in seen:
                    seen[domain] = IoC(
                        value=domain,
                        ioc_type=IoCType.DOMAIN,
                        source_file=str(file_path),
                        line_number=line_idx,
                        context=line.strip()[:200],
                    )

    # ------------------------------------------------------------------
    # Filtering helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_benign_ip(ip: str) -> bool:
        """Return True if the IP is a private, loopback, or link-local address."""
        parts = ip.split(".")
        if len(parts) != 4:
            return True  # not a valid IPv4

        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return True

        first = octets[0]

        # Loopback 127.x.x.x
        if first == 127:
            return True
        # Private 10.x.x.x
        if first == 10:
            return True
        # Private 172.16.0.0 – 172.31.255.255
        if first == 172 and 16 <= octets[1] <= 31:
            return True
        # Private 192.168.x.x
        if first == 192 and octets[1] == 168:
            return True
        # Link-local 169.254.x.x
        if first == 169 and octets[1] == 254:
            return True
        # APIPA / self-assigned 0.x.x.x
        if first == 0:
            return True
        # Broadcast 255.255.255.255
        if all(o == 255 for o in octets):
            return True

        return False

    @staticmethod
    def _is_benign_domain(domain: str) -> bool:
        """Return True if the domain is known-benign."""
        domain = domain.lower()
        if domain in _BENIGN_DOMAINS:
            return True
        for suffix in _BENIGN_DOMAIN_SUFFIXES:
            if domain.endswith(suffix):
                return True
        return False

    @staticmethod
    def _is_benign_url(url: str) -> bool:
        """Return True if the URL points to a known-benign domain."""
        # Extract the host part from the URL
        try:
            # Strip scheme
            after_scheme = url.split("://", 1)[1] if "://" in url else url
            # Extract host (before first / or : for port)
            host = after_scheme.split("/", 1)[0].split(":", 1)[0].lower()
        except (IndexError, ValueError):
            return False

        if host in _BENIGN_DOMAINS:
            return True
        for suffix in _BENIGN_DOMAIN_SUFFIXES:
            if host.endswith(suffix):
                return True

        # Also filter out benign IPs in URLs
        if _IPV4_RE.fullmatch(host):
            return IoCExtractor._is_benign_ip(host)

        return False
