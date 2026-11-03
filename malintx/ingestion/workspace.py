"""Isolated, self-cleaning temporary workspaces for untrusted-sample processing."""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

log = logging.getLogger(__name__)


@contextlib.contextmanager
def workspace(root: Path, prefix: str = "ws-") -> Iterator[Path]:
    """Create a private directory under *root* and always remove it afterwards."""
    root.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    with contextlib.suppress(OSError):  # no-op semantics on Windows
        os.chmod(path, 0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
        if path.exists():
            log.warning("workspace %s could not be fully removed", path.name)


def sweep_stale(root: Path, max_age_s: int = 6 * 3600) -> int:
    """Remove workspaces left behind by crashed workers. Returns the number removed."""
    if not root.is_dir():
        return 0
    cutoff = time.time() - max_age_s
    removed = 0
    for child in root.iterdir():
        try:
            if child.is_dir() and child.stat().st_mtime < cutoff:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed
