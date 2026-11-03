"""Passive, host-pinned HTTP client for threat-intelligence providers.

Guarantees:
* requests only ever go to the provider's own host (extracted/C2 infrastructure is never contacted);
* timeouts, bounded retries with exponential backoff, `Retry-After` honoured on 429;
* a per-provider token-bucket rate limiter with a wait budget;
* error text never includes URLs, headers or credentials.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from malintx.errors import ProviderRateLimitedError, ProviderUnavailableError

log = logging.getLogger(__name__)

USER_AGENT = "MALINT-X/0.2 (passive-lookup)"


class RateLimiter:
    """Allows `per_minute` requests per rolling minute."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.per_minute = max(1, per_minute)
        self._clock, self._sleep = clock, sleep
        self._stamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self, max_wait_s: float) -> None:
        with self._lock:
            now = self._clock()
            self._stamps = [t for t in self._stamps if now - t < 60.0]
            if len(self._stamps) >= self.per_minute:
                wait = 60.0 - (now - self._stamps[0]) + 0.05
                if wait > max_wait_s:
                    raise ProviderRateLimitedError(f"rate limit would require waiting {wait:.0f}s (budget {max_wait_s:.0f}s)")
                self._sleep(wait)
                now = self._clock()
                self._stamps = [t for t in self._stamps if now - t < 60.0]
            self._stamps.append(self._clock())


class PassiveHTTP:
    def __init__(
        self, provider: str, base_url: str, *, timeout_s: float, max_retries: int,
        limiter: RateLimiter | None = None, transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep, wait_budget_s: float = 90.0,
    ) -> None:
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self._host = urlsplit(self.base_url).hostname or ""
        self._retries = max(0, max_retries)
        self._limiter = limiter
        self._sleep = sleep
        self._budget = wait_budget_s
        self._client = httpx.Client(
            timeout=timeout_s, transport=transport, follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, path: str, *, headers: dict[str, str] | None = None,
                params: dict[str, str] | None = None, data: dict[str, str] | None = None,
                json_body: dict[str, Any] | None = None) -> httpx.Response:
        url = self.base_url + path
        if (urlsplit(url).hostname or "") != self._host:  # defence in depth against path-injection tricks
            raise ProviderUnavailableError(f"{self.provider}: refused request to unexpected host")
        last = "unknown error"
        for attempt in range(self._retries + 1):
            if self._limiter:
                self._limiter.acquire(self._budget)
            try:
                resp = self._client.request(method, url, headers=headers, params=params, data=data, json=json_body)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = f"network error ({type(exc).__name__})"
            else:
                if resp.status_code == 429:
                    retry_after = _retry_after(resp)
                    last = "rate limited by provider"
                    if attempt >= self._retries or retry_after > self._budget:
                        raise ProviderRateLimitedError(f"{self.provider}: rate limited (HTTP 429)")
                    self._sleep(retry_after)
                    continue
                if resp.status_code >= 500:
                    last = f"provider error (HTTP {resp.status_code})"
                else:
                    return resp
            if attempt < self._retries:
                self._sleep(min(30.0, 1.0 * (2 ** attempt)))
        raise ProviderUnavailableError(f"{self.provider}: {last} after {self._retries + 1} attempt(s)")


def _retry_after(resp: httpx.Response) -> float:
    try:
        return max(1.0, min(120.0, float(resp.headers.get("Retry-After", "5"))))
    except ValueError:
        return 5.0
