from __future__ import annotations

import sys
import warnings
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
warnings.filterwarnings("ignore")

from scenarios import SCENARIOS  # noqa: E402

from malintx.analysis.static import analyze_apk  # noqa: E402
from malintx.config import Settings  # noqa: E402
from malintx.ingestion import ingest_path  # noqa: E402


@pytest.fixture()
def settings(tmp_path) -> Settings:
    s = Settings(data_dir=tmp_path / "var", _env_file=None)
    s.ensure_dirs()
    return s


def run_static(apk_bytes: bytes, tmp: Path, settings: Settings):
    f = tmp / "sample.apk"
    f.write_bytes(apk_bytes)
    ing = ingest_path(f, settings)
    d = dict(sha256=ing.sha256, sha1=ing.sha1, md5=ing.md5, size_bytes=ing.size_bytes, display_name=ing.display_name,
             first_seen=ing.first_seen, archive=ing.archive.model_dump(mode="json"))
    return analyze_apk(ing.stored_path, d, settings), ing


@pytest.fixture(scope="session")
def analyzed(tmp_path_factory):
    """Static analysis of every synthetic scenario, computed once per test session."""
    base = tmp_path_factory.mktemp("scen")
    s = Settings(data_dir=base / "var", _env_file=None)
    s.ensure_dirs()
    out = {}
    for name, build in SCENARIOS.items():
        d = base / name
        d.mkdir()
        out[name] = run_static(build(), d, s)[0]
    return out
