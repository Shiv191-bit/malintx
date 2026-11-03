"""
MALINT-X Risk Scorer.

Deterministic scoring engine that computes a 0–100 risk score from
LLM-detected MITRE techniques, enriched IoCs, and manifest permissions.
Same inputs always produce exactly the same score.
"""

from __future__ import annotations

import logging
from typing import Any

from malintx.config import (
    CONFIDENCE_MULTIPLIERS,
    DANGEROUS_PERMISSIONS,
    MITRE_TECHNIQUE_WEIGHTS,
    get_score_label,
)
from malintx.core.models import (
    EnrichedIoC,
    LLMVerdict,
    ManifestData,
    RiskScore,
)

logger = logging.getLogger(__name__)

# Per-category caps defined inline so scoring is self-contained
_IOC_POINTS_PER_MALICIOUS = 5
_IOC_CAP = 15
_PERMISSION_CAP = 15
_PERMISSION_RISK_POINTS: dict[str, int] = {
    "critical": 5,
    "high": 3,
    "medium": 1,
}


class RiskScorer:
    """Deterministic scoring engine for MALINT-X analysis results.

    Scoring algorithm
    -----------------
    1. **technique_score** — weighted sum over each MITRE technique detected
       by the LLM, scaled by the technique weight from config and the
       confidence multiplier.
    2. **ioc_score** — 5 points per malicious-flagged IoC, capped at 15.
    3. **permission_score** — points from dangerous permissions
       (critical=5, high=3, medium=1), capped at 15.
    4. **raw_score** = technique_score + ioc_score + permission_score
    5. **final_score** = min(raw_score, 100)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def score(
        self,
        llm_verdict: LLMVerdict,
        enriched_iocs: list[EnrichedIoC],
        manifest_data: ManifestData,
    ) -> RiskScore:
        """Compute a deterministic risk score.

        Parameters
        ----------
        llm_verdict:
            Structured LLM output containing detected techniques.
        enriched_iocs:
            IoCs enriched with VirusTotal (or other) data.
        manifest_data:
            Parsed ``AndroidManifest.xml`` data including permissions.

        Returns
        -------
        RiskScore
            Fully populated score with human-readable breakdown.
        """
        breakdown: list[dict[str, Any]] = []

        # 1. Technique score --------------------------------------------------
        technique_score, technique_details = self._score_techniques(llm_verdict)
        breakdown.extend(technique_details)

        # 2. IoC score --------------------------------------------------------
        ioc_score, ioc_details = self._score_iocs(enriched_iocs)
        breakdown.extend(ioc_details)

        # 3. Permission score -------------------------------------------------
        permission_score, perm_details = self._score_permissions(manifest_data)
        breakdown.extend(perm_details)

        # 4 & 5. Aggregate ----------------------------------------------------
        raw_score = technique_score + ioc_score + permission_score
        final_score = min(raw_score, 100)

        breakdown.append(
            {
                "component": "total",
                "description": (
                    f"technique({technique_score}) + ioc({ioc_score}) "
                    f"+ permission({permission_score}) = {raw_score} → "
                    f"capped at {final_score}"
                ),
                "points": final_score,
            }
        )

        label, color = get_score_label(final_score)

        logger.info(
            "Risk score computed: %d (%s) — techniques=%d, iocs=%d, perms=%d",
            final_score,
            label,
            technique_score,
            ioc_score,
            permission_score,
        )

        return RiskScore(
            score=final_score,
            label=label,
            color=color,
            technique_score=technique_score,
            ioc_score=ioc_score,
            permission_score=permission_score,
            breakdown=breakdown,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _score_techniques(
        self, llm_verdict: LLMVerdict
    ) -> tuple[int, list[dict[str, Any]]]:
        """Score detected MITRE techniques.

        Each technique contributes
        ``MITRE_TECHNIQUE_WEIGHTS[id].weight * CONFIDENCE_MULTIPLIERS[confidence]``
        rounded to the nearest integer.  Unknown technique IDs are logged and
        skipped.
        """
        total = 0
        details: list[dict[str, Any]] = []

        for tech in llm_verdict.detected_techniques:
            weight_entry = MITRE_TECHNIQUE_WEIGHTS.get(tech.technique_id)
            if weight_entry is None:
                logger.warning(
                    "Unknown technique ID %s — skipping for scoring",
                    tech.technique_id,
                )
                continue

            weight = weight_entry["weight"]
            confidence_key = tech.confidence.value.lower()
            multiplier = CONFIDENCE_MULTIPLIERS.get(confidence_key, 0.3)
            points = round(weight * multiplier)
            total += points

            details.append(
                {
                    "component": "technique",
                    "technique_id": tech.technique_id,
                    "technique_name": tech.technique_name,
                    "confidence": confidence_key,
                    "weight": weight,
                    "multiplier": multiplier,
                    "points": points,
                    "description": (
                        f"{tech.technique_id} {tech.technique_name} "
                        f"({confidence_key}) — {weight}×{multiplier}={points}"
                    ),
                }
            )

        return total, details

    def _score_iocs(
        self, enriched_iocs: list[EnrichedIoC]
    ) -> tuple[int, list[dict[str, Any]]]:
        """Score IoCs: 5 points per malicious-flagged IoC, capped at 15."""
        details: list[dict[str, Any]] = []
        malicious_count = 0

        for eioc in enriched_iocs:
            if (
                eioc.enriched
                and eioc.enrichment is not None
                and eioc.enrichment.is_malicious
            ):
                malicious_count += 1

        uncapped = malicious_count * _IOC_POINTS_PER_MALICIOUS
        capped = min(uncapped, _IOC_CAP)

        details.append(
            {
                "component": "ioc",
                "malicious_count": malicious_count,
                "points_per_ioc": _IOC_POINTS_PER_MALICIOUS,
                "uncapped": uncapped,
                "cap": _IOC_CAP,
                "points": capped,
                "description": (
                    f"{malicious_count} malicious IoC(s) × "
                    f"{_IOC_POINTS_PER_MALICIOUS} = {uncapped}, "
                    f"capped at {capped}"
                ),
            }
        )

        return capped, details

    def _score_permissions(
        self, manifest_data: ManifestData
    ) -> tuple[int, list[dict[str, Any]]]:
        """Score dangerous permissions: critical=5, high=3, medium=1; capped at 15."""
        details: list[dict[str, Any]] = []
        total = 0
        scored_perms: list[dict[str, Any]] = []

        for perm in manifest_data.permissions:
            entry = DANGEROUS_PERMISSIONS.get(perm)
            if entry is None:
                continue
            risk = entry["risk"]
            points = _PERMISSION_RISK_POINTS.get(risk, 0)
            if points == 0:
                continue
            total += points
            scored_perms.append(
                {
                    "permission": perm,
                    "risk": risk,
                    "points": points,
                }
            )

        capped = min(total, _PERMISSION_CAP)

        details.append(
            {
                "component": "permission",
                "scored_permissions": scored_perms,
                "uncapped": total,
                "cap": _PERMISSION_CAP,
                "points": capped,
                "description": (
                    f"{len(scored_perms)} dangerous permission(s) totalling "
                    f"{total}, capped at {capped}"
                ),
            }
        )

        return capped, details
