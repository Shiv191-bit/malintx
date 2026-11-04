"""Similarity search over stored behavioural fingerprints."""

from __future__ import annotations

from typing import Any

from malintx.lineage.fingerprint import set_similarity, similarity
from malintx.schemas.analysis import LineageFingerprint


def compare(a: LineageFingerprint, b: LineageFingerprint) -> dict[str, Any]:
    api = similarity(a.minhash, b.minhash)
    return {
        "api_similarity": api,
        "permission_similarity": set_similarity(a.permissions, b.permissions),
        "behaviour_similarity": set_similarity(a.rule_ids, b.rule_ids),
        "same_signer": bool(set(a.signer_sha256) & set(b.signer_sha256)) if a.signer_sha256 and b.signer_sha256 else None,
        "relation": relation(api),
    }


def relation(api_similarity: float | None) -> str:
    """Interpretation bands. Calibrated on 74 real F-Droid apps (docs/LINEAGE.md): unrelated p95=0.53, p99=0.64; related-family median 0.78."""
    if api_similarity is None:
        return "not comparable (no analysable code)"
    if api_similarity >= 0.85:
        return "near-identical code surface: same codebase, repack or version drift"
    if api_similarity >= 0.65:  # above the 99th percentile of unrelated real app pairs (0.64)
        return "closely related: shared codebase lineage or shared framework"
    if api_similarity >= 0.50:  # ~95th percentile of unrelated pairs: weak evidence only
        return "loosely related: common platform usage"
    return "unrelated"


def rank(target: LineageFingerprint, others: list[tuple[str, dict[str, Any], LineageFingerprint]], limit: int, min_similarity: float) -> list[dict[str, Any]]:
    out = []
    for job_id, meta, fp in others:
        c = compare(target, fp)
        if c["api_similarity"] is not None and c["api_similarity"] >= min_similarity:
            out.append({"job_id": job_id, **meta, **c})
    out.sort(key=lambda r: (-r["api_similarity"], r["job_id"]))
    return out[:limit]
