"""Deterministic evidence registry. Evidence IDs are derived from the observation's identity,
so re-analysing the same sample always yields the same IDs."""

from __future__ import annotations

import hashlib

from malintx.schemas.analysis import Evidence
from malintx.schemas.common import Confidence, EvidenceKind

MAX_SNIPPET_CHARS = 3500
MAX_EVIDENCE = 800


class EvidenceStore:
    def __init__(self, max_items: int = MAX_EVIDENCE) -> None:
        self._items: dict[str, Evidence] = {}
        self._max = max_items
        self.dropped = 0

    def add(
        self,
        *,
        kind: EvidenceKind,
        rule_id: str | None,
        source_file: str,
        extraction_method: str,
        class_name: str | None = None,
        method_name: str | None = None,
        bytecode_offset: int | None = None,
        line_number: int | None = None,
        api: str | None = None,
        artifact: str | None = None,
        snippet: str | None = None,
        confidence: Confidence = Confidence.HIGH,
        limitations: str | None = None,
    ) -> Evidence | None:
        identity = "|".join(
            str(x)
            for x in (kind.value, rule_id, source_file, class_name, method_name, bytecode_offset, api, artifact)
        )
        eid = "EV-" + hashlib.sha1(identity.encode("utf-8")).hexdigest()[:10]  # noqa: S324 - id only
        existing = self._items.get(eid)
        if existing is not None:
            return existing
        if len(self._items) >= self._max:
            self.dropped += 1
            return None
        if snippet and len(snippet) > MAX_SNIPPET_CHARS:
            snippet = snippet[:MAX_SNIPPET_CHARS] + "\n… (truncated)"
        ev = Evidence(
            id=eid,
            kind=kind,
            rule_id=rule_id,
            source_file=source_file,
            class_name=class_name,
            method_name=method_name,
            line_number=line_number,
            bytecode_offset=bytecode_offset,
            api=api,
            artifact=artifact,
            snippet=snippet,
            extraction_method=extraction_method,
            confidence=confidence,
            limitations=limitations,
        )
        self._items[eid] = ev
        return ev

    def all(self) -> list[Evidence]:
        return sorted(self._items.values(), key=lambda e: e.id)

    def get(self, eid: str) -> Evidence | None:
        return self._items.get(eid)
