from types import SimpleNamespace
from typing import Any

import httpx
import openai
import pytest

from attack_qa.faithfulness import ClaimVerdict, CompletenessVerdict, Judgement
from attack_qa.judge_model import DEFAULT_JUDGE, OpenRouterJudge

JUDGEMENT = Judgement(claims=[ClaimVerdict(index=0, verdict="supported", reason="quoted")],
                      completeness=CompletenessVerdict(verdict="complete", reason="all"))


def _completion(content: str, finish: str = "stop") -> Any:
    return SimpleNamespace(choices=[SimpleNamespace(
        finish_reason=finish, message=SimpleNamespace(content=content))])


class _Stub:
    def __init__(self, *outcomes: Any) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _judge(*outcomes: Any) -> tuple[OpenRouterJudge, _Stub]:
    stub = _Stub(*outcomes)
    return OpenRouterJudge(client=SimpleNamespace(chat=SimpleNamespace(completions=stub)),
                           wait_s=0), stub


def test_parses_judgement_with_strict_schema_and_pinned_provider():
    judge, stub = _judge(_completion(JUDGEMENT.model_dump_json()))

    assert judge.judge("sys", "user") == JUDGEMENT
    call = stub.calls[0]
    assert call["model"] == DEFAULT_JUDGE
    assert "temperature" not in call  # unsupported by the pinned host
    assert call["response_format"]["json_schema"]["strict"] is True
    assert call["extra_body"]["provider"]["data_collection"] == "deny"
    assert call["extra_body"]["provider"]["require_parameters"] is True
    assert judge.name == f"openrouter/{DEFAULT_JUDGE}"


def test_truncated_output_is_an_error_not_a_bad_parse():
    judge, _ = _judge(_completion('{"claims": [', finish="length"))
    with pytest.raises(ValueError, match="max_tokens"):
        judge.judge("sys", "user")


def test_retries_server_errors_then_succeeds():
    response = httpx.Response(503, request=httpx.Request("POST", "https://openrouter.ai"))
    busy = openai.InternalServerError("busy", response=response, body=None)
    judge, stub = _judge(busy, _completion(JUDGEMENT.model_dump_json()))
    assert judge.judge("sys", "user") == JUDGEMENT
    assert len(stub.calls) == 2
