"""Upload ingestion: bounded streaming, hashing, validation and content-addressed storage."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from malintx.config import Settings
from malintx.errors import InvalidSampleError, OversizedUploadError
from malintx.ingestion.archive import inspect_archive
from malintx.ingestion.workspace import workspace
from malintx.schemas.sample import ZipInspection

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ \-()]")
_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class IngestedSample:
    sha256: str
    sha1: str
    md5: str
    size_bytes: int
    display_name: str
    stored_path: Path
    archive: ZipInspection
    first_seen: str
    already_stored: bool


def sanitize_display_name(name: str | None) -> str:
    """The uploaded filename is untrusted: keep only a harmless basename for display."""
    base = (name or "sample.apk").replace("\\", "/").rsplit("/", 1)[-1]
    base = _SAFE_NAME.sub("_", base).strip(" .") or "sample.apk"
    return base[:120]


def sample_path(settings: Settings, sha256: str) -> Path:
    return settings.samples_dir / sha256[:2] / f"{sha256}.sample"


def _stream_to_file(chunks: Iterable[bytes], dest: Path, limit: int) -> tuple[str, str, str, int]:
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()  # noqa: S324 - fingerprints only
    size = 0
    with dest.open("wb") as out:
        for chunk in chunks:
            size += len(chunk)
            if size > limit:
                raise OversizedUploadError(f"Upload exceeds the {limit // 2**20} MiB limit")
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            out.write(chunk)
    if size == 0:
        raise InvalidSampleError("Uploaded file is empty")
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), size


def read_chunks(fh: BinaryIO) -> Iterable[bytes]:
    while True:
        chunk = fh.read(_CHUNK)
        if not chunk:
            return
        yield chunk


def ingest(chunks: Iterable[bytes], filename: str | None, settings: Settings) -> IngestedSample:
    """Validate and register an uploaded sample.

    The upload is counted as it streams (Content-Length is never trusted), validated as a
    well-formed APK container, hashed, and stored under its SHA-256. Re-uploading identical
    bytes is detected as a duplicate and reuses the stored copy.
    """
    settings.ensure_dirs()
    limit = settings.max_upload_mb * 1024 * 1024
    with workspace(settings.workspaces_dir, "ingest-") as ws:
        tmp = ws / "upload.bin"
        sha256, sha1, md5, size = _stream_to_file(chunks, tmp, limit)
        archive = inspect_archive(tmp, settings)
        dest = sample_path(settings, sha256)
        already = dest.exists()
        if not already:
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.move(str(tmp), dest)
            except (FileExistsError, PermissionError):
                if not dest.exists():  # a genuine failure, not a concurrent identical upload
                    raise
                already = True  # another request stored identical content between our check and the move
            else:
                try:
                    os.chmod(dest, 0o444)
                except OSError:
                    pass
    return IngestedSample(
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        size_bytes=size,
        display_name=sanitize_display_name(filename),
        stored_path=dest,
        archive=archive,
        first_seen=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        already_stored=already,
    )


def ingest_path(path: Path, settings: Settings, filename: str | None = None) -> IngestedSample:
    with path.open("rb") as fh:
        return ingest(read_chunks(fh), filename or path.name, settings)
