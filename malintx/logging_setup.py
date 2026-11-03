"""Structured, secret-safe logging."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone

from malintx.config import Settings

_PATTERNS = [
    re.compile(r"(?i)(x-api-key|x-goog-api-key|authorization|auth-key|apikey|api_key|token|key)(\s*[=:]\s*)([^\s,&;\"']{6,})"),
    re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{20,}|[a-f0-9]{64})\b"),
]


class RedactingFilter(logging.Filter):
    def __init__(self, secrets: list[str]) -> None:
        super().__init__()
        self._secrets = [s for s in secrets if s and len(s) >= 6]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for s in self._secrets:
            msg = msg.replace(s, "[REDACTED]")
        # sha256 hashes are legitimate log content for this product; only redact key-like pairs
        msg = _PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", msg)
        msg = re.sub(r"\b(sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{20,})\b", "[REDACTED]", msg)
        record.msg, record.args = msg, ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "level": record.levelname,
                "logger": record.name, "msg": record.getMessage()}
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)[-1500:]
        return json.dumps(data)


def configure_logging(settings: Settings) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    secrets = [s.get_secret_value() for s in (
        settings.vt_api_key, settings.shodan_api_key, settings.abusech_auth_key, settings.koodous_token,
        settings.anthropic_api_key, settings.gemini_api_key, settings.openai_api_key, settings.api_token)]
    handler.addFilter(RedactingFilter(secrets))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.log_level.upper())
    for noisy in ("httpx", "httpcore", "androguard", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
