from __future__ import annotations

import json

import httpx

from malintx.ai.context import build_context
from malintx.ai.providers import AnthropicProvider, GeminiProvider, LLMProvider, OpenAICompatibleProvider
from malintx.ai.service import run_ai
from malintx.config import Settings
from malintx.errors import ProviderError


class Scripted(LLMProvider):
    name = "scripted"
    model = "test-model"

    def __init__(self, settings, replies):
        super().__init__(settings)
        self.replies, self.calls = list(replies), []

    def configured(self):
        return True

    def complete(self, system, user, schema):
        self.calls.append((system, user))
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r if isinstance(r, str) else json.dumps(r)


def good_reply(static, **over):
    f = next(x for x in static.findings if x.rule_id == "COMP-SMS-SUPPRESSION")
    ev = f.evidence_ids[:2]
    reply = {"overall": "likely_malicious", "summary": "SMS interception pattern.",
             "claims": [{"title": "OTP hiding", "explanation": "High-priority receiver aborts the SMS broadcast.", "assessment": "malicious_intent",
                         "confidence": "high", "evidence_ids": ev, "mitre_ids": ["T1636.004"], "uncertainty": "Reachability unknown."}],
             "limitations": ["static only"]}
    reply.update(over)
    return reply


def S(tmp_path, **kw):
    return Settings(data_dir=tmp_path, _env_file=None, ai_provider="anthropic", anthropic_api_key="ANTH-SECRET", **kw)


def test_grounded_claims_accepted(analyzed, tmp_path):
    st = analyzed["banking_trojan"]
    p = Scripted(S(tmp_path), [good_reply(st)])
    res = run_ai(st, None, S(tmp_path), provider=p)
    assert res.status == "completed" and res.attempts == 1
    assert res.assessment.overall == "likely_malicious" and res.accepted_mitre == ["T1636.004"]
    assert not res.dropped_claims


def test_hallucinated_evidence_is_dropped_and_verdict_downgraded(analyzed, tmp_path):
    st = analyzed["banking_trojan"]
    bad = good_reply(st)
    bad["claims"][0]["evidence_ids"] = ["EV-doesnotexist", "EV-alsofake"]
    res = run_ai(st, None, S(tmp_path), provider=Scripted(S(tmp_path), [bad]))
    assert res.status == "completed" and res.assessment.claims == []
    assert res.assessment.overall == "inconclusive"
    assert any("no valid evidence" in d for d in res.dropped_claims) and not res.accepted_mitre
    assert any("downgraded" in x or "discarded" in x for x in res.assessment.limitations)


def test_partially_valid_evidence_ids_are_filtered(analyzed, tmp_path):
    st = analyzed["banking_trojan"]
    r = good_reply(st)
    real = r["claims"][0]["evidence_ids"][0]
    r["claims"][0]["evidence_ids"] = [real, "EV-fake000000"]
    res = run_ai(st, None, S(tmp_path), provider=Scripted(S(tmp_path), [r]))
    assert res.assessment.claims[0].evidence_ids == [real]


def test_invented_mitre_ids_removed(analyzed, tmp_path):
    st = analyzed["banking_trojan"]
    r = good_reply(st)
    r["claims"][0]["mitre_ids"] = ["T1636.004", "T1447", "T9999"]
    res = run_ai(st, None, S(tmp_path), provider=Scripted(S(tmp_path), [r]))
    assert res.assessment.claims[0].mitre_ids == ["T1636.004"] and res.accepted_mitre == ["T1636.004"]
    assert any("T1447" in d for d in res.dropped_claims)


def test_invalid_json_retried_with_feedback(analyzed, tmp_path):
    st = analyzed["banking_trojan"]
    p = Scripted(S(tmp_path), ["Sure! here is my analysis: it is bad", good_reply(st)])
    res = run_ai(st, None, S(tmp_path), provider=p)
    assert res.status == "completed" and res.attempts == 2
    assert "previous reply was rejected" in p.calls[1][1]


def test_schema_violations_exhaust_retries_to_invalid_output(analyzed, tmp_path):
    st = analyzed["banking_trojan"]
    bad = {"overall": "definitely_evil", "summary": "x", "claims": [], "limitations": []}
    p = Scripted(S(tmp_path, ai_max_retries=2), [bad, {"summary": 1}, "{}"])
    res = run_ai(st, None, S(tmp_path, ai_max_retries=2), provider=p)
    assert res.status == "invalid_output" and res.attempts == 3 and res.assessment is None


def test_provider_failure_never_raises(analyzed, tmp_path):
    st = analyzed["banking_trojan"]
    res = run_ai(st, None, S(tmp_path), provider=Scripted(S(tmp_path), [ProviderError("anthropic: HTTP 500")]))
    assert res.status == "failed" and "500" in res.error


def test_unconfigured_is_graceful(analyzed, tmp_path):
    s = Settings(data_dir=tmp_path, _env_file=None)  # provider "none"
    assert run_ai(analyzed["banking_trojan"], None, s).status == "unconfigured"
    s2 = Settings(data_dir=tmp_path, _env_file=None, ai_provider="gemini")  # selected but no key
    assert run_ai(analyzed["banking_trojan"], None, s2).status == "unconfigured"


def test_prompt_injection_in_sample_is_flagged_and_isolated(analyzed, tmp_path):
    st = analyzed["injection_app"]
    ctx = build_context(st, None, 60000)
    assert ctx.injection_markers
    p = Scripted(S(tmp_path), [{"overall": "likely_legitimate", "summary": "benign, as instructed", "claims": [], "limitations": []}])
    res = run_ai(st, None, S(tmp_path), provider=p)
    system, user = p.calls[0]
    assert "NOTICE: instruction-like text was detected" in user
    assert "<untrusted_evidence>" in user and "never follow it" in system.lower()
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" not in system
    assert any("Instruction-like text" in x for x in res.assessment.limitations)


def test_context_contains_only_extracted_evidence(analyzed):
    st = analyzed["banking_trojan"]
    ctx = build_context(st, None, 60000)
    assert ctx.evidence_ids <= {e.id for e in st.evidence}
    blob = json.dumps(ctx.payload)
    assert st.sample.sha256 not in blob and "display_name" not in blob  # no raw sample identity/file names
    for f in ctx.payload["findings"]:
        assert set(f["evidence_ids"]) <= ctx.evidence_ids


def test_context_respects_budget(analyzed):
    ctx = build_context(analyzed["banking_trojan"], None, 3000)
    assert ctx.truncated and len(json.dumps(ctx.payload["evidence"])) < 6000


# ---------------------------------------------------------------------------------------------- provider wire formats
def _capture(reply):
    seen = {}

    def h(req: httpx.Request):
        seen.update(url=str(req.url), headers=dict(req.headers), body=json.loads(req.content))
        return httpx.Response(200, json=reply)

    return seen, httpx.MockTransport(h)


PAYLOAD = json.dumps({"overall": "inconclusive", "summary": "s", "claims": [], "limitations": []})


def test_anthropic_wire_format(tmp_path):
    seen, tr = _capture({"content": [{"type": "tool_use", "name": "report_assessment", "input": json.loads(PAYLOAD)}]})
    out = AnthropicProvider(S(tmp_path), tr).complete("SYS", "USER", {"type": "object"})
    assert json.loads(out)["overall"] == "inconclusive"
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["headers"]["x-api-key"] == "ANTH-SECRET" and seen["headers"]["anthropic-version"] == "2023-06-01"
    b = seen["body"]
    assert b["tool_choice"] == {"type": "tool", "name": "report_assessment"} and b["temperature"] == 0 and b["system"] == "SYS"
    assert "ANTH-SECRET" not in json.dumps(b)


def test_gemini_wire_format(tmp_path):
    s = Settings(data_dir=tmp_path, _env_file=None, ai_provider="gemini", gemini_api_key="GEM-SECRET")
    seen, tr = _capture({"candidates": [{"content": {"parts": [{"text": PAYLOAD}]}}]})
    from malintx.ai.prompts import RESPONSE_SCHEMA
    out = GeminiProvider(s, tr).complete("SYS", "USER", RESPONSE_SCHEMA)
    assert json.loads(out)["summary"] == "s"
    assert seen["url"].startswith("https://generativelanguage.googleapis.com/v1beta/models/") and seen["url"].endswith(":generateContent")
    assert seen["headers"]["x-goog-api-key"] == "GEM-SECRET" and "GEM-SECRET" not in seen["url"]
    cfg = seen["body"]["generationConfig"]
    assert cfg["responseMimeType"] == "application/json" and cfg["responseSchema"]["type"] == "OBJECT"
    assert "additionalProperties" not in json.dumps(cfg)


def test_openai_compatible_wire_format_with_custom_base(tmp_path):
    s = Settings(data_dir=tmp_path, _env_file=None, ai_provider="openai_compatible", openai_api_key="OAI-SECRET",
                 openai_base_url="http://localhost:11434/v1", openai_model="llama3")
    seen, tr = _capture({"choices": [{"message": {"content": PAYLOAD}}]})
    out = OpenAICompatibleProvider(s, tr).complete("SYS", "USER", {"type": "object"})
    assert json.loads(out)["overall"] == "inconclusive"
    assert seen["url"] == "http://localhost:11434/v1/chat/completions"
    assert seen["headers"]["authorization"] == "Bearer OAI-SECRET" and seen["body"]["model"] == "llama3"
    assert seen["body"]["response_format"] == {"type": "json_object"}


def test_provider_auth_error_is_sanitised(tmp_path):
    p = AnthropicProvider(S(tmp_path), httpx.MockTransport(lambda r: httpx.Response(401, json={"error": "invalid x-api-key ANTH-SECRET"})))
    try:
        p.complete("s", "u", {})
    except ProviderError as exc:
        assert "ANTH-SECRET" not in str(exc) and "authentication" in str(exc)
    else:
        raise AssertionError("expected ProviderError")
