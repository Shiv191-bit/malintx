"""Indicator enrichment orchestration, caching, graceful degradation and verdict aggregation."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

from malintx.config import Settings
from malintx.errors import ProviderError, ProviderRateLimitedError, ProviderUnavailableError
from malintx.intel.providers import ALL_PROVIDERS, Provider, now_iso
from malintx.schemas.analysis import Indicator, StaticAnalysisResult
from malintx.schemas.common import IndicatorType, IntelVerdict, ProviderStatus
from malintx.schemas.results import IndicatorIntel, IntelLookup, IntelReport
from malintx.storage.repository import Repository

log = logging.getLogger(__name__)

_LOOKUP_ORDER = {IndicatorType.URL: 0, IndicatorType.IPV4: 1, IndicatorType.DOMAIN: 2}
_CACHEABLE = (ProviderStatus.OK, ProviderStatus.NOT_FOUND)


def aggregate(lookups: list[IntelLookup]) -> IntelVerdict:
    verdicts = [lk.verdict for lk in lookups if lk.status == ProviderStatus.OK]
    if IntelVerdict.KNOWN_MALICIOUS in verdicts:
        return IntelVerdict.KNOWN_MALICIOUS
    if IntelVerdict.SUSPICIOUS in verdicts:
        return IntelVerdict.SUSPICIOUS
    if IntelVerdict.BENIGN_OBSERVED in verdicts:
        return IntelVerdict.BENIGN_OBSERVED
    return IntelVerdict.UNKNOWN  # no data, errors and not-found all land here, never "safe"


def explain(v: IntelVerdict, lookups: list[IntelLookup]) -> str:
    ok = [lk for lk in lookups if lk.status == ProviderStatus.OK]
    if v == IntelVerdict.KNOWN_MALICIOUS:
        return "Flagged malicious by: " + ", ".join(f"{lk.provider}" for lk in ok if lk.verdict == v) + "."
    if v == IntelVerdict.SUSPICIOUS:
        return "Flagged suspicious by: " + ", ".join(f"{lk.provider}" for lk in ok if lk.verdict == v) + "."
    if v == IntelVerdict.BENIGN_OBSERVED:
        return "Observed by providers without detections. This does not prove the indicator is safe."
    return "No provider returned a verdict. Unknown is NOT the same as safe."


class IntelService:
    def __init__(self, settings: Settings, repo: Repository | None = None, *,
                 transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] | None = None,
                 providers: list[Provider] | None = None, time_budget_s: float = 150.0) -> None:
        self.settings = settings
        self.repo = repo
        self.time_budget_s = time_budget_s
        self.providers = providers if providers is not None else [p(settings, transport, sleep) for p in ALL_PROVIDERS]

    def provider_status(self) -> dict[str, dict[str, Any]]:
        return {p.name: {"configured": p.configured(), "experimental": p.experimental,
                         "supports": [t.value for t in p.supports] + (["sha256"] if p.supports_hash else [])}
                for p in self.providers}

    # ----------------------------------------------------------------------------------------
    def _cached_lookup(self, p: Provider, kind: str, subject: str, fn: Callable[[], IntelLookup]) -> IntelLookup:
        key = f"{p.name}:{kind}:{subject}"
        if self.repo:
            hit = self.repo.cache_get(key)
            if hit:
                lk = IntelLookup.model_validate_json(hit)
                return lk.model_copy(update={"cached": True})
        lk = fn()
        if self.repo and lk.status in _CACHEABLE:
            self.repo.cache_put(key, p.name, subject, lk.model_dump_json(), self.settings.intel_cache_ttl_s)
        return lk

    def _safe(self, p: Provider, subject: str, stype: str, fn: Callable[[], IntelLookup]) -> IntelLookup:
        try:
            return fn()
        except ProviderRateLimitedError as exc:
            return IntelLookup(provider=p.name, subject=subject, subject_type=stype, status=ProviderStatus.RATE_LIMITED,
                               retrieved_at=now_iso(), detail=str(exc)[:200])
        except ProviderUnavailableError as exc:
            return IntelLookup(provider=p.name, subject=subject, subject_type=stype, status=ProviderStatus.UNAVAILABLE,
                               retrieved_at=now_iso(), detail=str(exc)[:200])
        except ProviderError as exc:
            return IntelLookup(provider=p.name, subject=subject, subject_type=stype, status=ProviderStatus.ERROR,
                               retrieved_at=now_iso(), detail=str(exc)[:200])

    def select_indicators(self, indicators: list[Indicator]) -> tuple[list[Indicator], int]:
        cand = [i for i in indicators if i.type in _LOOKUP_ORDER and not (i.note and "library" in i.note)
                and not (i.note and "resolver" in i.note)]
        cand.sort(key=lambda i: (_LOOKUP_ORDER[i.type], -i.occurrences, i.value))
        limit = self.settings.intel_max_indicators
        return cand[:limit], max(0, len(cand) - limit)

    def enrich(self, static: StaticAnalysisResult, progress: Callable[[str], None] | None = None) -> IntelReport:
        active = [p for p in self.providers if p.configured()]
        statuses = {p.name: (ProviderStatus.OK if p.configured() else ProviderStatus.UNCONFIGURED) for p in self.providers}
        report = IntelReport(requested=True, providers=statuses)
        if not active:
            report.notes.append("No threat-intelligence provider is configured; indicators were not enriched. "
                                "Unenriched indicators are UNKNOWN, not safe.")
            return report
        start = time.monotonic()

        for p in active:
            if p.supports_hash:
                lk = self._safe(p, static.sample.sha256, "sha256", lambda p=p: self._cached_lookup(
                    p, "sha256", static.sample.sha256, lambda: p.lookup_hash(static.sample.sha256)))
                report.sample_lookups.append(lk)
                if lk.status in (ProviderStatus.UNAVAILABLE, ProviderStatus.RATE_LIMITED, ProviderStatus.ERROR):
                    statuses[p.name] = lk.status
        report.sample_verdict = aggregate(report.sample_lookups)

        chosen, skipped = self.select_indicators(static.indicators)
        report.skipped_indicators = skipped
        degraded: set[str] = set()
        for n, ind in enumerate(chosen):
            if time.monotonic() - start > self.time_budget_s:
                report.skipped_indicators += len(chosen) - n
                report.notes.append(f"time budget of {self.time_budget_s:.0f}s reached; remaining indicators were not looked up")
                break
            if progress:
                progress(f"{n + 1}/{len(chosen)} {ind.type.value}")
            lookups: list[IntelLookup] = []
            for p in active:
                if ind.type not in p.supports or p.name in degraded:
                    continue
                lk = self._safe(p, ind.value, ind.type.value, lambda p=p, ind=ind: self._cached_lookup(
                    p, ind.type.value, ind.value, lambda: p.lookup_indicator(ind.type, ind.value)))
                lookups.append(lk)
                if lk.status in (ProviderStatus.UNAVAILABLE, ProviderStatus.RATE_LIMITED):
                    degraded.add(p.name)  # stop hammering a provider that is down or throttling
                    statuses[p.name] = lk.status
            verdict = aggregate(lookups)
            report.indicators.append(IndicatorIntel(indicator_id=ind.id, value=ind.value, type=ind.type, verdict=verdict,
                                                    lookups=lookups, explanation=explain(verdict, lookups)))
        for name in degraded:
            report.notes.append(f"{name} became unavailable or rate-limited; later lookups for it were skipped")
        report.providers = statuses
        report.notes.append("Lookups are passive: only provider APIs were contacted, never the extracted infrastructure. "
                            "Sample hashes and indicator values were shared with the providers listed above.")
        return report
