from types import SimpleNamespace
from typing import Any

import pytest
from google.genai import errors, types

from attack_qa.answer import AnswerDraft, Claim, ModelRefusalError
from attack_qa.gemini_model import GeminiAnswerModel, MissingApiKeyError

DRAFT = AnswerDraft(answerable=True, refusal_reason="",
                    claims=[Claim(text="x", passage_ids=["T1059:overview"])])


def _response(parsed: Any = DRAFT, finish: Any = types.FinishReason.STOP,
              block_reason: Any = None, text: str = "") -> Any:
    return SimpleNamespace(
        parsed=parsed, text=text,
        candidates=[SimpleNamespace(finish_reason=finish)],
        prompt_feedback=SimpleNamespace(block_reason=block_reason) if block_reason else None,
    )


class _StubModels:
    def __init__(self, *outcomes: Any) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def generate_content(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _model(*outcomes: Any) -> tuple[GeminiAnswerModel, _StubModels]:
    models = _StubModels(*outcomes)
    return GeminiAnswerModel(client=SimpleNamespace(models=models), rate_limit_wait_s=0), models


def test_returns_the_parsed_draft_and_requests_json() -> None:
    model, models = _model(_response())
    assert model.draft("system", "user") == DRAFT
    config = models.calls[0]["config"]
    assert config.response_mime_type == "application/json"
    assert config.system_instruction == "system"


def test_falls_back_to_parsing_text() -> None:
    model, _ = _model(_response(parsed=None, text=DRAFT.model_dump_json()))
    assert model.draft("s", "u") == DRAFT


def test_safety_block_becomes_a_model_refusal() -> None:
    model, _ = _model(_response(finish=types.FinishReason.SAFETY))
    with pytest.raises(ModelRefusalError):
        model.draft("s", "u")


def test_blocked_prompt_becomes_a_model_refusal() -> None:
    model, _ = _model(_response(block_reason="SAFETY"))
    with pytest.raises(ModelRefusalError, match="blocked"):
        model.draft("s", "u")


def test_retries_after_rate_limit() -> None:
    rate_limited = errors.ClientError(429, {"error": {"message": "quota", "status": "RESOURCE_EXHAUSTED"}})
    model, models = _model(rate_limited, _response())
    assert model.draft("s", "u") == DRAFT
    assert len(models.calls) == 2


def test_retries_when_the_model_is_overloaded() -> None:
    overloaded = errors.ServerError(503, {"error": {"message": "high demand", "status": "UNAVAILABLE"}})
    model, models = _model(overloaded, _response())
    assert model.draft("s", "u") == DRAFT
    assert len(models.calls) == 2


def test_falls_back_when_the_main_model_stays_overloaded() -> None:
    overloaded = errors.ServerError(503, {"error": {"message": "high demand", "status": "UNAVAILABLE"}})
    model, models = _model(overloaded, overloaded, overloaded, _response())
    assert model.draft("s", "u") == DRAFT
    assert [c["model"] for c in models.calls] == ["gemini-3.8-flash"] * 3 + ["gemini-3.1-flash-lite"]


def test_other_client_errors_are_not_retried() -> None:
    bad = errors.ClientError(400, {"error": {"message": "bad", "status": "INVALID_ARGUMENT"}})
    model, models = _model(bad)
    with pytest.raises(errors.ClientError):
        model.draft("s", "u")
    assert len(models.calls) == 1


def test_missing_key_fails_with_instructions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(MissingApiKeyError, match="keychain"):
        GeminiAnswerModel()
