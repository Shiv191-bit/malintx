from __future__ import annotations

import io
import zipfile

import pytest
from scenarios import banking_trojan

from malintx.errors import (
    CorruptArchiveError,
    InvalidSampleError,
    NotAnApkError,
    OversizedUploadError,
    UnsafeArchiveError,
)
from malintx.ingestion import ingest, ingest_path, sanitize_display_name, sweep_stale, workspace


def _zip(entries: dict[str, bytes], compress=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as z:
        for k, v in entries.items():
            z.writestr(k, v)
    return buf.getvalue()


def test_valid_apk_hashed_and_stored_content_addressed(settings, tmp_path):
    f = tmp_path / "x.apk"
    data = banking_trojan()
    f.write_bytes(data)
    s = ingest_path(f, settings)
    import hashlib
    assert s.sha256 == hashlib.sha256(data).hexdigest() and s.sha1 == hashlib.sha1(data).hexdigest()
    assert s.stored_path.name == f"{s.sha256}.sample" and s.stored_path.read_bytes() == data
    assert s.archive.dex_files == ["classes.dex"] and not s.already_stored


def test_duplicate_upload_detected(settings, tmp_path):
    f = tmp_path / "x.apk"
    f.write_bytes(banking_trojan())
    a, b = ingest_path(f, settings), ingest_path(f, settings, "other-name.apk")
    assert a.sha256 == b.sha256 and b.already_stored and not a.already_stored


@pytest.mark.parametrize("data,exc", [
    (b"", InvalidSampleError),
    (b"MZ\x90\x00" + b"\x00" * 100, NotAnApkError),
    (b"not an apk at all", NotAnApkError),
    (b"PK\x03\x04" + b"\x00" * 50, CorruptArchiveError),
    (_zip({"hello.txt": b"hi"}), NotAnApkError),  # zip without AndroidManifest.xml
])
def test_rejects_non_apk_inputs(settings, data, exc):
    with pytest.raises(exc):
        ingest([data] if data else [], "evil.apk", settings)


def test_truncated_apk_rejected(settings):
    with pytest.raises(CorruptArchiveError):
        ingest([banking_trojan()[:-40]], "t.apk", settings)


def test_zip_bomb_rejected_by_ratio(settings):
    bomb = _zip({"AndroidManifest.xml": b"x", "classes.dex": b"\x00" * (60 * 1024 * 1024)})
    s = settings.model_copy(update={"max_compression_ratio": 100})
    with pytest.raises(UnsafeArchiveError, match="zip bomb"):
        ingest([bomb], "bomb.apk", s)


def test_total_uncompressed_limit(settings):
    data = _zip({"AndroidManifest.xml": b"x", "big.bin": b"\x01" * (3 * 1024 * 1024)}, zipfile.ZIP_STORED)
    s = settings.model_copy(update={"max_uncompressed_mb": 1})
    with pytest.raises(UnsafeArchiveError, match="uncompressed"):
        ingest([data], "big.apk", s)


def test_entry_count_limit(settings):
    data = _zip({"AndroidManifest.xml": b"x", **{f"f{i}": b"" for i in range(20)}})
    s = settings.model_copy(update={"max_zip_entries": 10})
    with pytest.raises(UnsafeArchiveError, match="entries"):
        ingest([data], "many.apk", s)


def test_upload_size_enforced_while_streaming(settings):
    s = settings.model_copy(update={"max_upload_mb": 1})
    consumed = []

    def chunks():
        for i in range(10):
            consumed.append(i)
            yield b"A" * (512 * 1024)

    with pytest.raises(OversizedUploadError):
        ingest(chunks(), "huge.apk", s)
    assert len(consumed) <= 3, "must stop reading soon after the limit, not buffer everything"
    assert not list(s.samples_dir.rglob("*.sample"))


def test_path_traversal_and_duplicate_entries_flagged_not_extracted(settings, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"x")
        z.writestr("../../evil.txt", b"x")
        z.writestr("/abs/path.txt", b"x")
        z.writestr("dup.txt", b"1")
        z.writestr("dup.txt", b"2")
    s = ingest([buf.getvalue()], "t.apk", settings)
    joined = " ".join(s.archive.suspicious_entries)
    assert "path traversal" in joined and "absolute path" in joined and "duplicate" in joined
    assert s.archive.duplicate_entry_names == ["dup.txt"]
    assert not (tmp_path.parent / "evil.txt").exists()


@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd", "passwd"), ("C:\\Users\\x\\evil<>.apk", "evil__.apk"), ("", "sample.apk"),
    ("a" * 300 + ".apk", ("a" * 120)),
])
def test_filename_never_trusted(raw, expected):
    out = sanitize_display_name(raw)
    assert out == expected[:120] and "/" not in out and "\\" not in out


def test_workspace_is_removed_even_on_error(tmp_path):
    seen = None
    with pytest.raises(RuntimeError):
        with workspace(tmp_path / "w") as ws:
            seen = ws
            (ws / "a.txt").write_text("x")
            raise RuntimeError("boom")
    assert seen is not None and not seen.exists()


def test_sweep_stale(tmp_path):
    import os
    import time
    root = tmp_path / "w"
    old, new = root / "old", root / "new"
    old.mkdir(parents=True)
    new.mkdir()
    past = time.time() - 10 * 3600
    os.utime(old, (past, past))
    assert sweep_stale(root, max_age_s=3600) == 1
    assert not old.exists() and new.exists()


def test_concurrent_identical_uploads_are_safe(settings):
    from concurrent.futures import ThreadPoolExecutor

    data = banking_trojan()
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda _: ingest([data], "same.apk", settings), range(8)))
    assert len({r.sha256 for r in results}) == 1
    assert len(list(settings.samples_dir.rglob("*.sample"))) == 1
    assert sum(1 for r in results if not r.already_stored) >= 1
