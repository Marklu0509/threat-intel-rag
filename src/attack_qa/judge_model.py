"""Faithfulness judge on OpenRouter (grill-decisions Q33).

A different model family from the Qwen answerer, to avoid a judge favouring its own family's
answers. Reuses the OpenRouter key; pinned to Anthropic as the host so every call runs on the
same model build, with prompt retention refused.
"""

import logging
import time
from typing import Any

import openai
from pydantic import ValidationError

from attack_qa.faithfulness import JUDGE_SCHEMA, Judgement
from attack_qa.openai_compat_model import OPENROUTER, _client_for

logger = logging.getLogger(__name__)

DEFAULT_JUDGE = "anthropic/claude-sonnet-5.5"
_EXTRA_BODY = {"provider": {"order": ["Anthropic"], "allow_fallbacks": False,
                            "require_parameters": True, "data_collection": "deny"}}
# A reason of one or two sentences per claim; the longest answers have about ten claims.
_MAX_OUTPUT_TOKENS = 3000
_RETRIES = 4
_WAIT_S = 10.0


class OpenRouterJudge:
    def __init__(self, model: str = DEFAULT_JUDGE, client: Any = None,
                 wait_s: float = _WAIT_S) -> None:
        self._model = model
        self._client = client or _client_for(OPENROUTER)
        self._wait = wait_s

    @property
    def name(self) -> str:
        return f"openrouter/{self._model}"

    def judge(self, system: str, user: str) -> Judgement:
        choice = self._create(system, user).choices[0]
        if choice.finish_reason == "length":
            raise ValueError(f"{self.name} hit max_tokens={_MAX_OUTPUT_TOKENS}; output truncated")
        try:
            return Judgement.model_validate_json(choice.message.content or "")
        except ValidationError as exc:
            raise ValueError(f"{self.name} returned JSON that does not match the schema") from exc

    def _create(self, system: str, user: str) -> Any:
        """Retry rate limits and server errors; give up on other errors at once."""
        for attempt in range(1, _RETRIES + 1):
            try:
                return self._client.chat.completions.create(
                    model=self._model,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}],
                    # No temperature: the Anthropic host doesn't accept it for this model, and
                    # require_parameters would then find no host at all.
                    max_tokens=_MAX_OUTPUT_TOKENS,
                    response_format={"type": "json_schema", "json_schema": {
                        "name": "judgement", "schema": JUDGE_SCHEMA, "strict": True}},
                    extra_body=_EXTRA_BODY,
                )
            except (openai.RateLimitError, openai.InternalServerError) as exc:
                if attempt == _RETRIES:
                    raise
                logger.warning("%s: %s; waiting %.0fs (attempt %d)",
                               self.name, type(exc).__name__, self._wait * attempt, attempt)
                time.sleep(self._wait * attempt)
        raise RuntimeError("unreachable")
