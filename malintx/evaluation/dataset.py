"""Evaluation dataset manifests with enforced provenance and train/calibration/test hygiene."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

ALLOWED_SPLITS = ("calibration", "test")
PROVENANCE_KINDS = ("wild_caught", "curated_benign", "open_source_build", "synthetic", "unknown")
# Sources whose samples may legitimately be described as wild-caught / store-sourced.
WILD_SOURCES = {"MalwareBazaar", "Koodous", "AndroZoo", "F-Droid", "VirusShare", "Other-Documented"}


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    provenance: str = "unknown"
    retrieved_at: str | None = None
    url: str | None = None
    license_note: str | None = None

    @model_validator(mode="after")
    def _check(self) -> Source:
        if self.provenance not in PROVENANCE_KINDS:
            raise ValueError(f"provenance must be one of {PROVENANCE_KINDS}")
        if self.provenance in ("wild_caught", "curated_benign", "open_source_build"):
            if self.name not in WILD_SOURCES:
                raise ValueError(f"'{self.provenance}' requires a documented source in {sorted(WILD_SOURCES)}; "
                                 "use provenance 'unknown' when the origin is not known")
            if not self.retrieved_at:
                raise ValueError(f"'{self.provenance}' samples need retrieved_at (when and from where they were obtained)")
        return self


class SampleEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    sha256: str
    label: str  # malicious | benign
    split: str
    source: Source
    family: str | None = None
    expected_techniques: list[str] = Field(default_factory=list)
    notes: str = ""

    @model_validator(mode="after")
    def _check(self) -> SampleEntry:
        if self.label not in ("malicious", "benign"):
            raise ValueError("label must be 'malicious' or 'benign'")
        if self.split not in ALLOWED_SPLITS:
            raise ValueError(f"split must be one of {ALLOWED_SPLITS}")
        return self


class DatasetManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    version: str
    description: str = ""
    samples: list[SampleEntry]

    @model_validator(mode="after")
    def _no_leakage(self) -> DatasetManifest:
        seen: dict[str, str] = {}
        for s in self.samples:
            prev = seen.get(s.sha256)
            if prev is not None and prev != s.split:
                raise ValueError(f"sample {s.sha256[:12]} appears in both '{prev}' and '{s.split}' (split leakage)")
            if prev is not None:
                raise ValueError(f"duplicate sample {s.sha256[:12]} listed twice")
            seen[s.sha256] = s.split
        return self


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: Path, verify_hashes: bool = True) -> tuple[DatasetManifest, Path]:
    manifest = DatasetManifest.model_validate(json.loads(path.read_text(encoding="utf-8")))
    root = path.parent
    if verify_hashes:
        for s in manifest.samples:
            f = (root / s.path).resolve()
            if root.resolve() not in f.parents:
                raise ValueError(f"sample path escapes the dataset directory: {s.path}")
            if not f.is_file():
                raise FileNotFoundError(f"sample file missing: {s.path}")
            if sha256_file(f) != s.sha256.lower():
                raise ValueError(f"sha256 mismatch for {s.path}: manifest does not describe this file")
    return manifest, root


def init_manifest(directory: Path, name: str, version: str) -> dict:
    """Create a manifest skeleton from `directory/{malicious,benign}/*`.

    Everything defaults to provenance 'unknown' and split 'test': the operator must document real
    origins before any result can be described as measured on wild-caught data.
    """
    samples = []
    for label in ("malicious", "benign"):
        for f in sorted((directory / label).glob("*")):
            if f.is_file():
                samples.append({"path": f"{label}/{f.name}", "sha256": sha256_file(f), "label": label, "split": "test",
                                "source": {"name": "unknown", "provenance": "unknown"}, "notes": "FILL IN: origin, retrieval date, licence"})
    return {"name": name, "version": version, "description": "generated skeleton: provenance not yet documented", "samples": samples}
