"""API hardening: bearer auth, rate limiting, streaming upload cap."""

from __future__ import annotations

import hmac
import json
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from malintx.config import Settings


def require_auth(settings: Settings):
    token = settings.api_token.get_secret_value()

    async def dependency(request: Request) -> None:
        if not token:
            return
        supplied = request.headers.get("authorization", "")
        if not supplied.lower().startswith("bearer ") or not hmac.compare_digest(supplied[7:].strip(), token):
            raise HTTPException(status_code=401, detail={"code": "unauthorized", "message": "missing or invalid bearer token"})

    return dependency


class SlidingWindowLimiter:
    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return False
        q.append(now)
        return True


class BodyLimitMiddleware:
    """Pure-ASGI middleware that aborts oversized uploads while they stream, before any buffering."""

    def __init__(self, app, max_bytes: int, path_suffix: str = "/analyses") -> None:
        self.app, self.max_bytes, self.suffix = app, max_bytes, path_suffix

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST" or not scope["path"].endswith(self.suffix):
            return await self.app(scope, receive, send)
        headers = {k.lower(): v for k, v in scope["headers"]}
        declared = headers.get(b"content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            return await self._reject(send)
        seen = 0
        exceeded = False

        async def limited_receive():
            nonlocal seen, exceeded
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        started = False

        async def guarded_send(message):
            nonlocal started
            if exceeded and not started:
                started = True
                return await self._reject(send)
            if not exceeded:
                started = True
                await send(message)

        await self.app(scope, limited_receive, guarded_send)
        if exceeded and not started:
            await self._reject(send)

    @staticmethod
    async def _reject(send) -> None:
        body = json.dumps({"error": {"code": "oversized_upload", "message": "upload exceeds the configured size limit"}}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def configured_limit(settings: Settings) -> int:
    return settings.max_upload_mb * 1024 * 1024 + 64 * 1024  # multipart overhead allowance
