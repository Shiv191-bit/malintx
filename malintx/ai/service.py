"""Evidence-grounded AI assessment with schema enforcement, retries and graceful fallback.

The AI is optional and advisory: a failure here never changes deterministic findings or the score.
"""

from __future__ import annotations

import json
import logging

import httpx
from pydantic import ValidationError

from malintx.ai.context import build_context
from malintx.ai.prompts import RESPONSE_SCHEMA, SYSTEM_PROMPT, user_message
from malintx.ai.providers import LLMProvider, get_provider
from malintx.config import Settings
from malintx.errors import AIOutputInvalidError, ProviderError, ProviderUnconfiguredError
from malintx.mitre import get_catalog
from malintx.schemas.analysis import StaticAnalysisResult
from malintx.schemas.results import AIAssessment, AIClaim, AIResult, IntelReport

log = logging.getLogger(__name__)

_ASSESS = {"malicious_intent", "suspicious", "legitimate_functionality", "inconclusive"}
_OVERALL = {"likely_malicious", "suspicious", "likely_legitimate", "inconclusive"}


def not_requested() -> AIResult:
    return AIResult(status="not_requested")


def _parse(raw: str) -> AIAssessment:
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AIOutputInvalidError(f"reply was not valid JSON ({exc.msg})") from exc
    if not isinstance(data, dict):
        raise AIOutputInvalidError("reply JSON was not an object")
    for claim in data.get("claims", []) or []:
        if isinstance(claim, dict):
            claim.setdefault("mitre_ids", [])
            claim.setdefault("uncertainty", "")
    try:
        parsed = AIAssessment.model_validate(data)
    except ValidationError as exc:
        raise AIOutputInvalidError("reply did not match the schema: " + "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:4])) from exc
    if parsed.overall not in _OVERALL:
        raise AIOutputInvalidError(f"overall must be one of {sorted(_OVERALL)}")
    for c in parsed.claims:
        if c.assessment not in _ASSESS:
            raise AIOutputInvalidError(f"claim assessment must be one of {sorted(_ASSESS)}")
    return parsed


def ground(assessment: AIAssessment, valid_evidence: set[str], catalog_ids: set[str]) -> tuple[AIAssessment, list[str], list[str]]:
    """Drop claims that cite no real evidence; drop invalid ATT&CK ids; keep the verdict honest."""
    kept: list[AIClaim] = []
    dropped: list[str] = []
    for c in assessment.claims:
        good = [e for e in c.evidence_ids if e in valid_evidence]
        bad = [e for e in c.evidence_ids if e not in valid_evidence]
        if not good:
            dropped.append(f"'{c.title[:80]}': cites no valid evidence id" + (f" (unknown: {', '.join(bad[:3])})" if bad else ""))
            continue
        bad_m = [m for m in c.mitre_ids if m not in catalog_ids]
        if bad_m:
            dropped.append(f"'{c.title[:80]}': removed unknown ATT&CK id(s) {', '.join(bad_m[:3])}")
        kept.append(c.model_copy(update={"evidence_ids": good, "mitre_ids": [m for m in c.mitre_ids if m in catalog_ids]}))
    overall = assessment.overall
    note = list(assessment.limitations)
    if overall in ("likely_malicious", "suspicious") and not any(c.assessment in ("malicious_intent", "suspicious") for c in kept):
        overall = "inconclusive"
        note.append("Overall verdict downgraded to inconclusive: no surviving claim with valid evidence supports it.")
    if not kept and overall != "inconclusive":
        overall = "inconclusive"
        note.append("All claims were discarded because they were not grounded in extracted evidence.")
    out = assessment.model_copy(update={"claims": kept, "overall": overall, "limitations": note})
    accepted = sorted({m for c in kept if c.assessment in ("malicious_intent", "suspicious") for m in c.mitre_ids})
    return out, dropped, accepted


def run_ai(static: StaticAnalysisResult, intel: IntelReport | None, settings: Settings, *,
           provider: LLMProvider | None = None, transport: httpx.BaseTransport | None = None, sleep=None) -> AIResult:
    try:
        prov = provider or get_provider(settings, transport, sleep)
    except ProviderUnconfiguredError as exc:
        return AIResult(status="unconfigured", error=str(exc))
    if not prov.configured():
        return AIResult(status="unconfigured", provider=prov.name, error=f"no API key configured for {prov.name}")

    ctx = build_context(static, intel, settings.ai_max_context_chars)
    if not ctx.payload["findings"]:
        return AIResult(status="completed", provider=prov.name, model=prov.model,
                        assessment=AIAssessment(overall="inconclusive", summary="No findings with evidence were available to interpret.",
                                                claims=[], limitations=["Nothing to assess."]),
                        context_evidence_count=0)
    catalog_ids = set(get_catalog(settings).techniques)
    retry_error: str | None = None
    attempts = settings.ai_max_retries + 1
    last_error = "unknown error"
    for attempt in range(1, attempts + 1):
        try:
            raw = prov.complete(SYSTEM_PROMPT, user_message(ctx.payload, ctx.injection_markers, retry_error), RESPONSE_SCHEMA)
            parsed = _parse(raw)
        except AIOutputInvalidError as exc:
            retry_error = last_error = str(exc)
            log.warning("AI output rejected (attempt %d/%d): %s", attempt, attempts, exc)
            continue
        except ProviderError as exc:
            return AIResult(status="failed", provider=prov.name, model=prov.model, attempts=attempt,
                            error=str(exc)[:300], context_evidence_count=len(ctx.evidence_ids),
                            context_truncated=ctx.truncated)
        grounded, dropped, accepted = ground(parsed, ctx.evidence_ids, catalog_ids)
        if ctx.injection_markers:
            grounded.limitations.append("Instruction-like text was found inside the sample data and was treated as untrusted evidence.")
        if ctx.truncated:
            grounded.limitations.append("The evidence context was truncated to fit the size budget.")
        return AIResult(status="completed", provider=prov.name, model=prov.model, assessment=grounded,
                        dropped_claims=dropped, accepted_mitre=accepted, attempts=attempt,
                        context_evidence_count=len(ctx.evidence_ids), context_truncated=ctx.truncated)
    return AIResult(status="invalid_output", provider=prov.name, model=prov.model, attempts=attempts,
                    error=f"model did not return a valid structured assessment: {last_error}"[:300],
                    context_evidence_count=len(ctx.evidence_ids), context_truncated=ctx.truncated)
