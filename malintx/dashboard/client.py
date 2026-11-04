"""Thin API client for the dashboard. The dashboard shows only what the backend returns."""

from __future__ import annotations

import os
from typing import Any

import httpx


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{message} ({code})")
        self.status, self.code, self.message = status, code, message


class ApiUnreachable(Exception):
    pass


class ApiClient:
    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: float = 30.0) -> None:
        self.base = (base_url or os.environ.get("MALINTX_API_URL") or "http://127.0.0.1:8750").rstrip("/")
        tok = token if token is not None else os.environ.get("MALINTX_API_TOKEN", "")
        headers = {"Authorization": f"Bearer {tok}"} if tok else {}
        self._c = httpx.Client(base_url=self.base + "/api/v1", headers=headers, timeout=timeout)

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            resp = self._c.request(method, path, **kw)
        except httpx.TransportError as exc:
            raise ApiUnreachable(f"Cannot reach the MALINT-X API at {self.base}: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            try:
                err = resp.json().get("error", {})
            except ValueError:
                err = {}
            raise ApiError(resp.status_code, err.get("code", "http_error"), err.get("message", f"HTTP {resp.status_code}"))
        return resp

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health").json()

    def config(self) -> dict[str, Any]:
        return self._request("GET", "/config").json()

    def overview(self) -> dict[str, Any]:
        return self._request("GET", "/overview").json()

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._request("GET", "/analyses", params={"limit": limit}).json()

    def job(self, job_id: str) -> dict[str, Any]:
        return self._request("GET", f"/analyses/{job_id}").json()

    def result(self, job_id: str) -> dict[str, Any] | None:
        resp = self._request("GET", f"/analyses/{job_id}/result")
        return resp.json() if resp.status_code == 200 else None

    def similar(self, job_id: str, limit: int = 8, min_similarity: float = 0.3) -> dict[str, Any]:
        return self._request("GET", f"/analyses/{job_id}/similar", params={"limit": limit, "min_similarity": min_similarity}).json()

    def infrastructure(self) -> dict[str, Any]:
        return self._request("GET", "/infrastructure").json()

    def diff(self, base: str, other: str) -> dict[str, Any]:
        return self._request("GET", "/diff", params={"base": base, "other": other}).json()

    def report(self, job_id: str) -> bytes | None:
        try:
            return self._request("GET", f"/analyses/{job_id}/report").content
        except ApiError as exc:
            if exc.status == 404:
                return None
            raise

    def submit(self, filename: str, data: bytes, *, enrich: bool, ai: bool, force: bool) -> dict[str, Any]:
        return self._request(
            "POST", "/analyses", files={"file": (filename, data, "application/octet-stream")},
            data={"enrich": str(enrich).lower(), "ai": str(ai).lower(), "force": str(force).lower()}, timeout=300,
        ).json()
