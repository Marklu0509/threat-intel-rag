from types import SimpleNamespace
from typing import Any

import httpx
import openai
import pytest

from attack_qa.answer import AnswerDraft, Claim, ModelRefusalError
from attack_qa.openai_compat_model import (
    GROQ,
    MissingApiKeyError,
    OpenAICompatibleAnswerModel,
    draft_from_prose,
)

DRAFT = AnswerDraft(answerable=True, refusal_reason="",
                    claims=[Claim(text="x", passage_ids=["T1059:overview"])])


def _completion(content: str = DRAFT.model_dump_json(), finish: str = "stop") -> Any:
    return SimpleNamespace(choices=[SimpleNamespace(
        finish_reason=finish, message=SimpleNamespace(content=content))])


def _rate_limited() -> openai.RateLimitError:
    response = httpx.Response(429, request=httpx.Request("POST", "https://api.groq.com"))
    return openai.RateLimitError("tokens per minute", response=response, body=None)


class _StubCompletions:
    def __init__(self, *outcomes: Any) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _model(*outcomes: Any) -> tuple[OpenAICompatibleAnswerModel, _StubCompletions]:
    completions = _StubCompletions(*outcomes)
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    return OpenAICompatibleAnswerModel(client=client, wait_s=0), completions


def test_parses_the_draft_and_asks_for_strict_json() -> None:
    model, completions = _model(_completion())
    assert model.draft("system", "user") == DRAFT
    call = completions.calls[0]
    assert call["model"] == GROQ.default_model
    assert call["response_format"]["json_schema"]["strict"] is True
    assert call["messages"][0] == {"role": "system", "content": "system"}


def test_content_filter_becomes_a_model_refusal() -> None:
    model, _ = _model(_completion(finish="content_filter"))
    with pytest.raises(ModelRefusalError):
        model.draft("s", "u")


def test_retries_rate_limits() -> None:
    model, completions = _model(_rate_limited(), _completion())
    assert model.draft("s", "u") == DRAFT
    assert len(completions.calls) == 2


def test_request_too_large_is_not_retried() -> None:
    response = httpx.Response(429, request=httpx.Request("POST", "https://api.groq.com"))
    too_large = openai.RateLimitError("Request too large for model", response=response, body=None)
    model, completions = _model(too_large, _completion())
    with pytest.raises(openai.RateLimitError):
        model.draft("s", "u")
    assert len(completions.calls) == 1


def test_malformed_json_is_reported_clearly() -> None:
    model, _ = _model(_completion(content='{"answerable": true}'))
    with pytest.raises(ValueError, match="does not match the schema"):
        model.draft("s", "u")


def test_name_includes_the_provider() -> None:
    model, _ = _model()
    assert model.name == f"groq/{GROQ.default_model}"


def test_missing_key_fails_with_instructions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(MissingApiKeyError, match="GROQ_API_KEY"):
        OpenAICompatibleAnswerModel()


def test_free_text_mode_sends_no_response_format_and_parses_citations() -> None:
    prose = "Monitor encoded commands [T1059.001:detection]. Deploy it [T1059.001:mitigation#poison-plain]."
    completions = _StubCompletions(_completion(content=prose))
    model = OpenAICompatibleAnswerModel(client=SimpleNamespace(chat=SimpleNamespace(completions=completions)),
                                        wait_s=0, structured=False)
    draft = model.draft("s", "u")
    assert "response_format" not in completions.calls[0]
    assert draft.claims[0].passage_ids == ["T1059.001:detection", "T1059.001:mitigation#poison-plain"]


def test_empty_prose_is_not_answerable() -> None:
    assert not draft_from_prose("   ").answerable


def test_daily_token_quota_fails_fast_without_retrying() -> None:
    from attack_qa.answer import DailyQuotaExceededError
    response = httpx.Response(429, request=httpx.Request("POST", "https://api.groq.com"))
    daily = openai.RateLimitError(
        "Rate limit reached for model on tokens per day (TPD): Limit 200000, Used 199671",
        response=response, body=None)
    model, completions = _model(daily, _completion())
    with pytest.raises(DailyQuotaExceededError):
        model.draft("s", "u")
    assert len(completions.calls) == 1


def test_truncated_output_is_reported_as_truncation_not_bad_json() -> None:
    model, _ = _model(_completion(content='{"answerable": true, "claims": [', finish="length"))
    with pytest.raises(ValueError, match="max_tokens"):
        model.draft("s", "u")


def test_output_cap_is_per_provider() -> None:
    from attack_qa.openai_compat_model import OPENROUTER
    completions = _StubCompletions(_completion())
    model = OpenAICompatibleAnswerModel(provider=OPENROUTER, wait_s=0,
                                        client=SimpleNamespace(chat=SimpleNamespace(completions=completions)))
    model.draft("s", "u")
    assert completions.calls[0]["max_tokens"] == OPENROUTER.max_output_tokens > GROQ.max_output_tokens == 900
