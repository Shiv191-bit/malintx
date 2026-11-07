"""LLM provider adapters. Each returns the raw JSON text of a schema-constrained reply.

Adapters are unit-tested against mocked transports; they have not been run against the live vendor
APIs in this repository (no credentials provisioned).
"""

from __future__ import annotations

import copy
import json
from typing import Any

import httpx

from malintx.config import Settings
from malintx.errors import AIOutputInvalidError, ProviderError, ProviderUnconfiguredError
from malintx.intel.http import PassiveHTTP


class LLMProvider:
    name = ""

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None, sleep=None) -> None:
        self.settings = settings
        self._transport = transport
        self._sleep = sleep

    @property
    def model(self) -> str:
        raise NotImplementedError

    def configured(self) -> bool:
        raise NotImplementedError

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        raise NotImplementedError

    def _http(self, base: str) -> PassiveHTTP:
        kw: dict[str, Any] = {"sleep": self._sleep} if self._sleep else {}
        return PassiveHTTP(self.name, base, timeout_s=self.settings.ai_timeout_s, max_retries=2,
                           transport=self._transport, **kw)

    def _post(self, base: str, path: str, *, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        http = self._http(base)
        try:
            resp = http.request("POST", path, headers=headers, json_body=body)
        finally:
            http.close()
        if resp.status_code in (401, 403):
            raise ProviderError(f"{self.name}: authentication rejected (check API key)")
        if resp.status_code >= 400:
            raise ProviderError(f"{self.name}: HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise ProviderError(f"{self.name}: non-JSON response") from exc
        if not isinstance(data, dict):
            raise ProviderError(f"{self.name}: unexpected response shape")
        return data


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    @property
    def model(self) -> str:
        return self.settings.anthropic_model

    def configured(self) -> bool:
        return bool(self.settings.anthropic_api_key.get_secret_value())

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        body = {
            "model": self.model, "max_tokens": 4096, "temperature": 0, "system": system,
            "messages": [{"role": "user", "content": user}],
            "tools": [{"name": "report_assessment", "description": "Report the structured evidence-grounded assessment.",
                       "input_schema": schema}],
            "tool_choice": {"type": "tool", "name": "report_assessment"},
        }
        data = self._post("https://api.anthropic.com", "/v1/messages",
                          headers={"x-api-key": self.settings.anthropic_api_key.get_secret_value(),
                                   "anthropic-version": "2023-06-01"}, body=body)
        for block in data.get("content", []):
            if block.get("type") == "tool_use":
                return json.dumps(block.get("input", {}))
        raise AIOutputInvalidError("anthropic: reply contained no structured tool output")


def _gemini_schema(schema: dict[str, Any]) -> dict[str, Any]:
    s = copy.deepcopy(schema)

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            node.pop("additionalProperties", None)
            if "type" in node and isinstance(node["type"], str):
                node["type"] = node["type"].upper()
            for k, v in list(node.items()):
                node[k] = walk(v)
        elif isinstance(node, list):
            return [walk(x) for x in node]
        return node

    return walk(s)


class GeminiProvider(LLMProvider):
    name = "gemini"

    @property
    def model(self) -> str:
        return self.settings.gemini_model

    def configured(self) -> bool:
        return bool(self.settings.gemini_api_key.get_secret_value())

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0, "responseMimeType": "application/json",
                                 "responseSchema": _gemini_schema(schema)},
        }
        data = self._post("https://generativelanguage.googleapis.com", f"/v1beta/models/{self.model}:generateContent",
                          headers={"x-goog-api-key": self.settings.gemini_api_key.get_secret_value()}, body=body)
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIOutputInvalidError("gemini: reply contained no text candidate") from exc


class OpenAICompatibleProvider(LLMProvider):
    name = "openai_compatible"

    @property
    def model(self) -> str:
        return self.settings.openai_model

    def configured(self) -> bool:
        return bool(self.settings.openai_api_key.get_secret_value())

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        body = {
            "model": self.model, "temperature": 0, "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system + "\n\nReply with a single JSON object matching this JSON Schema:\n" + json.dumps(schema)},
                {"role": "user", "content": user},
            ],
        }
        base = self.settings.openai_base_url.rstrip("/")
        from urllib.parse import urlsplit

        parts = urlsplit(base)
        origin, prefix = f"{parts.scheme}://{parts.netloc}", parts.path
        data = self._post(origin, prefix + "/chat/completions",
                          headers={"Authorization": f"Bearer {self.settings.openai_api_key.get_secret_value()}"}, body=body)
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIOutputInvalidError("openai_compatible: reply contained no message content") from exc


PROVIDERS: dict[str, type[LLMProvider]] = {
    "anthropic": AnthropicProvider, "gemini": GeminiProvider, "openai_compatible": OpenAICompatibleProvider,
    "openai": OpenAICompatibleProvider,
}


def get_provider(settings: Settings, transport: httpx.BaseTransport | None = None, sleep=None) -> LLMProvider:
    key = settings.ai_provider.lower()
    if key not in PROVIDERS:
        raise ProviderUnconfiguredError(f"AI provider '{settings.ai_provider}' is not enabled")
    return PROVIDERS[key](settings, transport, sleep)
