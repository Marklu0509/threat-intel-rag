"""AnswerModel for any OpenAI-compatible endpoint (Groq, Cerebras, OpenRouter, Ollama).

Default: Groq's free tier, which allows 1,000 requests per day per model but only
8,000 tokens per minute (read from its x-ratelimit headers, 2026-10-05). One answer
request is about 2,500-3,000 tokens, so rate-limit retries wait long enough for the
per-minute token budget to refill.
"""

import logging
import os
import time
from dataclasses import dataclass
from typing import Any

import openai
from pydantic import ValidationError

from attack_qa.answer import AnswerDraft, ModelRefusalError
from attack_qa.claude_model import _ANSWER_SCHEMA

logger = logging.getLogger(__name__)

_RETRIES = 4
_WAIT_S = 20.0


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    key_env: str
    default_model: str


GROQ = Provider("groq", "https://api.groq.com/openai/v1", "GROQ_API_KEY", "qwen/qwen3.8-27b")
CEREBRAS = Provider("cerebras", "https://api.cerebras.ai/v1", "CEREBRAS_API_KEY", "llama-3.3-70b")
PROVIDERS = {p.name: p for p in (GROQ, CEREBRAS)}


class MissingApiKeyError(Exception):
    """The provider's API key environment variable is not set."""


def _client_for(provider: Provider) -> openai.OpenAI:
    key = os.environ.get(provider.key_env, "")
    if not key:
        raise MissingApiKeyError(
            f"{provider.key_env} is not set. Store the key in the macOS keychain and export it "
            "from ~/.zshrc, then open a new terminal."
        )
    return openai.OpenAI(base_url=provider.base_url, api_key=key, max_retries=0)


class OpenAICompatibleAnswerModel:
    def __init__(self, provider: Provider = GROQ, model: str | None = None,
                 client: Any = None, wait_s: float = _WAIT_S) -> None:
        self._provider = provider
        self._model = model or provider.default_model
        self._client = client or _client_for(provider)
        self._wait = wait_s
        self.last_model_used = self._model

    @property
    def name(self) -> str:
        return f"{self._provider.name}/{self._model}"

    def draft(self, system: str, user: str) -> AnswerDraft:
        response = self._create(system, user)
        choice = response.choices[0]
        if choice.finish_reason == "content_filter":
            raise ModelRefusalError("response blocked by the provider's content filter")
        text = choice.message.content or ""
        try:
            return AnswerDraft.model_validate_json(text)
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
                    response_format={
                        "type": "json_schema",
                        "json_schema": {"name": "answer", "schema": _ANSWER_SCHEMA, "strict": True},
                    },
                    temperature=0.0,
                    max_tokens=4000,
                )
            except (openai.RateLimitError, openai.InternalServerError) as exc:
                if attempt == _RETRIES:
                    raise
                logger.warning("%s: %s; waiting %.0fs (attempt %d)",
                               self.name, type(exc).__name__, self._wait * attempt, attempt)
                time.sleep(self._wait * attempt)
        raise RuntimeError("unreachable")
