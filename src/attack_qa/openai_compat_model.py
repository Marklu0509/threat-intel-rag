"""AnswerModel for any OpenAI-compatible endpoint (Groq, Cerebras, OpenRouter, Ollama).

Default: Groq's free tier, which allows 1,000 requests per day per model but only
8,000 input and 1,000 output tokens per minute (read from its x-ratelimit headers and
429 errors, 2026-10-05). One answer
request is about 2,500-3,000 tokens, so rate-limit retries wait long enough for the
per-minute token budget to refill.
"""

import logging
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import openai
from pydantic import ValidationError

from attack_qa.answer import AnswerDraft, Claim, DailyQuotaExceededError, ModelRefusalError
from attack_qa.claude_model import _ANSWER_SCHEMA

logger = logging.getLogger(__name__)

_RETRIES = 4
_WAIT_S = 20.0
# Groq's free tier caps OUTPUT at 1,000 tokens/minute and rejects a single request whose
# max_tokens could exceed it, hence 900. That cut off the longest answers (a 10-mitigation list
# plus an attack's extra claims), so providers without that limit get more room.
_GROQ_FREE_TIER_MAX_OUTPUT = 900
_CITED_ID = re.compile(r"T\d{4}(?:\.\d{3})?:(?:overview|mitigation|detection)(?:#[\w-]+)?")


def draft_from_prose(text: str) -> AnswerDraft:
    """Wrap a free-prose answer (attack control group) so it can be scored like the others."""
    ids = list(dict.fromkeys(_CITED_ID.findall(text)))
    return AnswerDraft(answerable=bool(text.strip()), refusal_reason="",
                       claims=[Claim(text=text.strip(), passage_ids=ids)] if text.strip() else [])


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    key_env: str
    default_model: str
    extra_body: Mapping[str, Any] = field(default_factory=dict)
    max_output_tokens: int = 2000


GROQ = Provider("groq", "https://api.groq.com/openai/v1", "GROQ_API_KEY", "qwen/qwen3.8-27b",
                max_output_tokens=_GROQ_FREE_TIER_MAX_OUTPUT)
CEREBRAS = Provider("cerebras", "https://api.cerebras.ai/v1", "CEREBRAS_API_KEY", "llama-3.3-70b")
# Same Qwen model as Groq, pay-as-you-go. OpenRouter routes to ~18 hosts at fp4-bf16 precision,
# some with Qwen's thinking mode on. To match Groq (which answers without thinking): pin one
# full-precision host, turn thinking off, require JSON-schema support, refuse prompt retention.
OPENROUTER = Provider(
    "openrouter", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", "qwen/qwen3.8-27b",
    extra_body={
        "provider": {"order": ["DeepInfra"], "allow_fallbacks": False,
                     "require_parameters": True, "data_collection": "deny"},
        "reasoning": {"enabled": False},
    },
)
PROVIDERS = {p.name: p for p in (GROQ, CEREBRAS, OPENROUTER)}


class MissingApiKeyError(Exception):
    """The provider's API key environment variable is not set."""


def _client_for(provider: Provider) -> openai.OpenAI:
    key = os.environ.get(provider.key_env, "").strip()  # a pasted key often ends in a newline
    if not key:
        raise MissingApiKeyError(
            f"{provider.key_env} is not set (or is blank). Set it as an environment variable; in "
            "Azure, as a secret referenced by the container's environment variable."
        )
    return openai.OpenAI(base_url=provider.base_url, api_key=key, max_retries=0)


class OpenAICompatibleAnswerModel:
    def __init__(self, provider: Provider = GROQ, model: str | None = None,
                 client: Any = None, wait_s: float = _WAIT_S, structured: bool = True) -> None:
        """structured=False asks for free prose instead of JSON (attack-test control group only)."""
        self._structured = structured
        self._provider = provider
        self._model = model or provider.default_model
        self._client = client or _client_for(provider)
        self._wait = wait_s
        self.last_model_used = self._model

    @property
    def name(self) -> str:
        return f"{self._provider.name}/{self._model}"

    def ping(self) -> None:
        """Reach the provider without spending tokens (lists models); raises if that fails."""
        self._client.models.list()

    def draft(self, system: str, user: str) -> AnswerDraft:
        response = self._create(system, user)
        choice = response.choices[0]
        if choice.finish_reason == "content_filter":
            raise ModelRefusalError("response blocked by the provider's content filter")
        if choice.finish_reason == "length":
            raise ValueError(f"{self.name} hit max_tokens={self._provider.max_output_tokens}; output truncated")
        text = choice.message.content or ""
        if not self._structured:
            return draft_from_prose(text)
        try:
            return AnswerDraft.model_validate_json(text)
        except ValidationError as exc:
            raise ValueError(f"{self.name} returned JSON that does not match the schema") from exc

    def _create(self, system: str, user: str) -> Any:
        """Retry rate limits and server errors; give up on other errors at once."""
        output_format = {"response_format": {
            "type": "json_schema",
            "json_schema": {"name": "answer", "schema": _ANSWER_SCHEMA, "strict": True},
        }} if self._structured else {}
        for attempt in range(1, _RETRIES + 1):
            try:
                return self._client.chat.completions.create(
                    model=self._model,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}],
                    temperature=0.0,
                    max_tokens=self._provider.max_output_tokens,
                    extra_body=dict(self._provider.extra_body) or None,
                    **output_format,
                )
            except (openai.RateLimitError, openai.InternalServerError) as exc:
                # A per-day limit (Groq: "tokens per day (TPD)") won't clear by waiting minutes.
                if "per day" in str(exc).lower():
                    raise DailyQuotaExceededError(f"{self.name}: daily quota used up") from exc
                # A single request over the per-minute token limit never fits; don't wait for it.
                if "too large" in str(exc).lower() or attempt == _RETRIES:
                    raise
                logger.warning("%s: %s; waiting %.0fs (attempt %d)",
                               self.name, type(exc).__name__, self._wait * attempt, attempt)
                time.sleep(self._wait * attempt)
        raise RuntimeError("unreachable")
