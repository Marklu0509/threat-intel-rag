from types import SimpleNamespace
from typing import Any

import httpx
import openai
import pytest

from attack_qa.answer import AnswerDraft, Claim, ModelRefusalError
from attack_qa.openai_compat_model import GROQ, MissingApiKeyError, OpenAICompatibleAnswerModel

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
