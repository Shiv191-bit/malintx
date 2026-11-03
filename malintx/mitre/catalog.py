"""MITRE ATT&CK for Mobile catalog loaded from the vendored official STIX bundle.

Technique IDs are never hand-typed into results: every ID that reaches a finding, a mapping or an
AI claim must exist in this catalog (`require`/`is_valid`).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from malintx.config import Settings, get_settings


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    description: str
    url: str
    is_subtechnique: bool


@dataclass(frozen=True)
class MitreCatalog:
    version: str
    dataset_file: str
    dataset_sha256: str
    techniques: dict[str, Technique]

    @property
    def source(self) -> str:
        return f"MITRE ATT&CK for Mobile v{self.version}"

    def is_valid(self, technique_id: str) -> bool:
        return technique_id in self.techniques

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id)

    def require(self, technique_id: str) -> Technique:
        tech = self.techniques.get(technique_id)
        if tech is None:
            raise KeyError(f"Unknown ATT&CK for Mobile technique id: {technique_id}")
        return tech


def _first_paragraph(text: str, limit: int = 400) -> str:
    para = text.strip().split("\n\n", 1)[0].replace("\n", " ")
    return para if len(para) <= limit else para[: limit - 1].rstrip() + "…"


def load_catalog(path: Path) -> MitreCatalog:
    raw = path.read_bytes()
    bundle = json.loads(raw)
    version = "unknown"
    techniques: dict[str, Technique] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", version)
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ref or not ref.get("external_id", "").startswith("T"):
            continue
        tactics = tuple(
            p["phase_name"].replace("-", " ").title()
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-mobile-attack"
        )
        tid = ref["external_id"]
        techniques[tid] = Technique(
            id=tid,
            name=obj["name"],
            tactics=tactics,
            description=_first_paragraph(obj.get("description", "")),
            url=ref.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
            is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
        )
    return MitreCatalog(
        version=version,
        dataset_file=path.name,
        dataset_sha256=hashlib.sha256(raw).hexdigest(),
        techniques=techniques,
    )


@lru_cache(maxsize=2)
def _cached(path_str: str) -> MitreCatalog:
    return load_catalog(Path(path_str))


def get_catalog(settings: Settings | None = None) -> MitreCatalog:
    settings = settings or get_settings()
    return _cached(str(settings.mitre_dataset))
