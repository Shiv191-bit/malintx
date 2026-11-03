"""
MALINT-X Threat Intelligence Client.

Async VirusTotal API v3 client for IoC enrichment.  Provides batch
enrichment with per-minute rate-limiting, in-memory caching, and
graceful degradation when the API key is missing or the service is
unreachable.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Any

import aiohttp

from malintx.config import settings
from malintx.core.models import EnrichedIoC, IoC, IoCType, VTEnrichment

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"


class ThreatIntelClient:
    """Async VirusTotal v3 client with rate-limiting and caching."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key: str = api_key or settings.vt_api_key
        self._rate_limit: int = settings.vt_rate_limit_per_minute
        # Semaphore bounds concurrent in-flight requests to the rate limit.
        self._semaphore = asyncio.Semaphore(max(self._rate_limit, 1))
        # Simple time-based throttle tracking (wall-clock seconds).
        self._request_times: list[float] = []
        # In-memory cache keyed by (ioc_type, value).
        self._cache: dict[tuple[str, str], VTEnrichment] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enrich_iocs(self, iocs: list[IoC]) -> list[EnrichedIoC]:
        """Batch-enrich a list of IoCs via VirusTotal.

        Returns one ``EnrichedIoC`` per input IoC, preserving order.
        If the API key is missing the items are returned un-enriched with
        a descriptive error string.
        """
        if not self._api_key:
            logger.warning("VirusTotal API key not configured – skipping enrichment")
            return [
                EnrichedIoC(
                    ioc=ioc,
                    enriched=False,
                    error="VirusTotal API key not configured",
                )
                for ioc in iocs
            ]

        # Deduplicate IoCs so we don't waste API quota.
        unique: dict[tuple[str, str], IoC] = {}
        for ioc in iocs:
            key = (ioc.ioc_type.value, ioc.value)
            if key not in unique:
                unique[key] = ioc

        # Fire enrichment tasks concurrently (bounded by semaphore).
        tasks = {
            key: asyncio.create_task(self._enrich_single(ioc))
            for key, ioc in unique.items()
        }
        await asyncio.gather(*tasks.values(), return_exceptions=True)

        # Build result list in original order.
        results: list[EnrichedIoC] = []
        for ioc in iocs:
            key = (ioc.ioc_type.value, ioc.value)
            task = tasks[key]
            if task.done() and task.exception() is None:
                results.append(task.result())
            else:
                exc = task.exception() if task.done() else None
                results.append(
                    EnrichedIoC(
                        ioc=ioc,
                        enriched=False,
                        error=f"Enrichment failed: {exc}" if exc else "Unknown error",
                    )
                )
        return results

    # ------------------------------------------------------------------
    # Per-type VT queries
    # ------------------------------------------------------------------

    async def _check_ip(self, ip: str) -> VTEnrichment:
        """Query ``/api/v3/ip_addresses/{ip}``."""
        data = await self._vt_get(f"{_VT_BASE}/ip_addresses/{ip}")
        return self._parse_response(data, ioc_type="ip")

    async def _check_domain(self, domain: str) -> VTEnrichment:
        """Query ``/api/v3/domains/{domain}``."""
        data = await self._vt_get(f"{_VT_BASE}/domains/{domain}")
        return self._parse_response(data, ioc_type="domain")

    async def _check_url(self, url: str) -> VTEnrichment:
        """Submit a URL for scanning, then fetch the analysis result.

        VirusTotal requires URL submission via POST to ``/api/v3/urls``
        followed by a GET to retrieve the analysis.
        """
        # VT accepts base64url-encoded URL identifiers.
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        # Try fetching an existing report first.
        try:
            data = await self._vt_get(f"{_VT_BASE}/urls/{url_id}")
            return self._parse_response(data, ioc_type="url")
        except VTApiError:
            pass  # Fall through to submit the URL.

        # Submit for scanning.
        submit_data = await self._vt_post(f"{_VT_BASE}/urls", form_data={"url": url})

        # The response contains an analysis link we can poll, but for a
        # triage pipeline we simply wait briefly and re-fetch once.
        analysis_link = (
            submit_data.get("data", {}).get("links", {}).get("self", "")
        )
        if analysis_link:
            await asyncio.sleep(2)
            try:
                data = await self._vt_get(analysis_link)
                return self._parse_response(data, ioc_type="url")
            except VTApiError:
                pass

        # Final attempt: re-fetch using the url_id.
        await asyncio.sleep(3)
        data = await self._vt_get(f"{_VT_BASE}/urls/{url_id}")
        return self._parse_response(data, ioc_type="url")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _enrich_single(self, ioc: IoC) -> EnrichedIoC:
        """Enrich a single IoC, using cache when possible."""
        cache_key = (ioc.ioc_type.value, ioc.value)

        if cache_key in self._cache:
            logger.debug("Cache hit for %s %s", ioc.ioc_type.value, ioc.value)
            return EnrichedIoC(
                ioc=ioc,
                enrichment=self._cache[cache_key],
                enriched=True,
            )

        try:
            async with self._semaphore:
                await self._throttle()
                if ioc.ioc_type == IoCType.IPV4:
                    enrichment = await self._check_ip(ioc.value)
                elif ioc.ioc_type == IoCType.DOMAIN:
                    enrichment = await self._check_domain(ioc.value)
                elif ioc.ioc_type == IoCType.URL:
                    enrichment = await self._check_url(ioc.value)
                else:
                    return EnrichedIoC(
                        ioc=ioc,
                        enriched=False,
                        error=f"Unsupported IoC type: {ioc.ioc_type}",
                    )

            self._cache[cache_key] = enrichment
            return EnrichedIoC(ioc=ioc, enrichment=enrichment, enriched=True)

        except VTApiError as exc:
            logger.warning("VT API error for %s: %s", ioc.value, exc)
            return EnrichedIoC(ioc=ioc, enriched=False, error=str(exc))
        except aiohttp.ClientError as exc:
            logger.warning("Network error for %s: %s", ioc.value, exc)
            return EnrichedIoC(
                ioc=ioc,
                enriched=False,
                error=f"Network error: {exc}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error enriching %s", ioc.value)
            return EnrichedIoC(
                ioc=ioc,
                enriched=False,
                error=f"Unexpected error: {exc}",
            )

    async def _throttle(self) -> None:
        """Enforce per-minute rate limit using a sliding window."""
        now = time.monotonic()
        window = 60.0
        # Purge timestamps older than the window.
        self._request_times = [
            t for t in self._request_times if now - t < window
        ]
        if len(self._request_times) >= self._rate_limit:
            oldest = self._request_times[0]
            sleep_for = window - (now - oldest) + 0.1
            if sleep_for > 0:
                logger.debug("Rate-limit reached, sleeping %.1fs", sleep_for)
                await asyncio.sleep(sleep_for)
        self._request_times.append(time.monotonic())

    async def _vt_get(self, url: str) -> dict[str, Any]:
        """Perform an authenticated GET request to VirusTotal."""
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 404:
                    raise VTApiError(f"Resource not found (404): {url}")
                if resp.status == 429:
                    raise VTApiError("Rate limit exceeded (429)")
                if resp.status != 200:
                    body = await resp.text()
                    raise VTApiError(
                        f"VT API error {resp.status}: {body[:300]}"
                    )
                return await resp.json()  # type: ignore[no-any-return]

    async def _vt_post(
        self,
        url: str,
        *,
        form_data: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Perform an authenticated POST request to VirusTotal."""
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers=headers,
                data=form_data,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status not in (200, 201):
                    body = await resp.text()
                    raise VTApiError(
                        f"VT API POST error {resp.status}: {body[:300]}"
                    )
                return await resp.json()  # type: ignore[no-any-return]

    @staticmethod
    def _parse_response(
        data: dict[str, Any],
        *,
        ioc_type: str = "",
    ) -> VTEnrichment:
        """Parse a VirusTotal JSON response into a ``VTEnrichment``."""
        attrs: dict[str, Any] = data.get("data", {}).get("attributes", {})
        stats: dict[str, int] = attrs.get("last_analysis_stats", {})

        last_analysis_epoch = attrs.get("last_analysis_date")
        last_analysis_str: str | None = None
        if isinstance(last_analysis_epoch, (int, float)):
            from datetime import datetime, timezone

            last_analysis_str = (
                datetime.fromtimestamp(last_analysis_epoch, tz=timezone.utc)
                .isoformat()
            )

        tags: list[str] = attrs.get("tags", []) or []
        if not isinstance(tags, list):
            tags = []

        return VTEnrichment(
            malicious_count=stats.get("malicious", 0),
            suspicious_count=stats.get("suspicious", 0),
            harmless_count=stats.get("harmless", 0),
            undetected_count=stats.get("undetected", 0),
            community_score=attrs.get("reputation", 0),
            last_analysis_date=last_analysis_str,
            tags=tags,
            country=attrs.get("country") if ioc_type == "ip" else None,
            asn=attrs.get("asn") if ioc_type == "ip" else None,
            as_owner=attrs.get("as_owner") if ioc_type == "ip" else None,
        )


class VTApiError(Exception):
    """Custom exception for VirusTotal API errors."""
