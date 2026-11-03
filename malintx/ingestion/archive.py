"""APK container validation and ZIP structure inspection.

Nothing is ever extracted to disk by archive entry name, so path-traversal entries cannot write
anywhere; they are recorded as suspicious structure instead.
"""

from __future__ import annotations

import re
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath

from malintx.config import Settings
from malintx.errors import CorruptArchiveError, NotAnApkError, UnsafeArchiveError
from malintx.schemas.sample import ZipInspection

ZIP_MAGIC = b"PK\x03\x04"
_DEX_RE = re.compile(r"^classes\d*\.dex$")
_WIN_DRIVE = re.compile(r"^[A-Za-z]:")


def check_magic(path: Path) -> None:
    with path.open("rb") as fh:
        head = fh.read(4)
    if head != ZIP_MAGIC:
        raise NotAnApkError("File is not a ZIP/APK container (bad magic bytes)")


def _suspicious_name(name: str) -> str | None:
    if "\x00" in name:
        return f"NUL byte in entry name: {name!r}"
    if name.startswith(("/", "\\")) or _WIN_DRIVE.match(name):
        return f"absolute path entry: {name!r}"
    parts = PurePosixPath(name.replace("\\", "/")).parts
    if ".." in parts:
        return f"path traversal entry: {name!r}"
    if len(name) > 512:
        return "entry name longer than 512 characters"
    return None


def inspect_archive(path: Path, settings: Settings) -> ZipInspection:
    """Validate the ZIP structure against resource limits and summarise it.

    Raises NotAnApkError / CorruptArchiveError / UnsafeArchiveError on rejection.
    """
    check_magic(path)
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise CorruptArchiveError(f"Malformed ZIP archive: {exc}") from exc
    except (OSError, NotImplementedError, RuntimeError) as exc:
        raise CorruptArchiveError(f"Cannot open archive: {exc}") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > settings.max_zip_entries:
            raise UnsafeArchiveError(
                f"Archive has {len(infos)} entries (limit {settings.max_zip_entries})"
            )
        if not infos:
            raise NotAnApkError("Archive is empty")

        total = 0
        max_ratio = 0.0
        names: dict[str, int] = {}
        dex: list[str] = []
        abis: set[str] = set()
        assets = 0
        encrypted = 0
        suspicious: list[str] = []
        times: list[datetime] = []

        for info in infos:
            name = info.filename
            names[name] = names.get(name, 0) + 1
            total += info.file_size
            if info.compress_size > 0:
                max_ratio = max(max_ratio, info.file_size / info.compress_size)
            elif info.file_size > 1_000_000:
                max_ratio = max(max_ratio, float(info.file_size))
            if info.flag_bits & 0x1:
                encrypted += 1
            reason = _suspicious_name(name)
            if reason:
                suspicious.append(reason)
            if _DEX_RE.match(name):
                dex.append(name)
            if name.startswith("lib/") and name.count("/") >= 2:
                abis.add(name.split("/")[1])
            if name.startswith("assets/") and not name.endswith("/"):
                assets += 1
            try:
                times.append(datetime(*info.date_time))
            except ValueError:
                suspicious.append(f"invalid timestamp on entry {name!r}")

        if total > settings.max_uncompressed_mb * 1024 * 1024:
            raise UnsafeArchiveError(
                f"Declared uncompressed size {total / 2**20:.0f} MiB exceeds "
                f"{settings.max_uncompressed_mb} MiB limit"
            )
        if max_ratio > settings.max_compression_ratio:
            raise UnsafeArchiveError(
                f"Compression ratio {max_ratio:.0f}:1 exceeds limit "
                f"{settings.max_compression_ratio}:1 (possible zip bomb)"
            )
        if "AndroidManifest.xml" not in names:
            raise NotAnApkError("Archive has no AndroidManifest.xml; not an Android package")

        duplicates = sorted(n for n, c in names.items() if c > 1)
        if duplicates:
            suspicious.append(
                "duplicate entry names (known archive-parser evasion): " + ", ".join(duplicates[:5])
            )

    return ZipInspection(
        entry_count=len(infos),
        total_uncompressed_bytes=total,
        max_compression_ratio=round(max_ratio, 2),
        dex_files=sorted(dex),
        native_abis=sorted(abis),
        asset_count=assets,
        encrypted_entries=encrypted,
        duplicate_entry_names=duplicates,
        suspicious_entries=suspicious[:50],
        earliest_entry_time=min(times).isoformat() if times else None,
        latest_entry_time=max(times).isoformat() if times else None,
    )
