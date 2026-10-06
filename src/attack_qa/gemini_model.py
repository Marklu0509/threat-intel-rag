"""AnswerModel backed by the Gemini API (free tier for development and evaluation)."""

import logging
import os
import time
from typing import Any

from google import genai
from google.genai import errors, types

from attack_qa.answer import AnswerDraft, DailyQuotaExceededError, ModelRefusalError

logger = logging.getLogger(__name__)

# gemini-2.5-flash is closed to new users; 3.8 Flash is on the free tier (checked 2026-10-05)
DEFAULT_MODEL = "gemini-3.8-flash"
# Used when DEFAULT_MODEL stays overloaded (503) after retries; also on the free tier
FALLBACK_MODEL = "gemini-3.1-flash-lite"
_RATE_LIMIT_RETRIES = 3
_RATE_LIMIT_WAIT_S = 15.0  # free tier allows about 10 requests per minute


class MissingApiKeyError(Exception):
    """GEMINI_API_KEY is not set in the environment."""


def _is_daily_quota(exc: errors.APIError) -> bool:
    return exc.code == 429 and "PerDay" in str(exc)


def _client_from_env() -> genai.Client:
    key = os.environ.get("GEMINI_API_KEY", "")
    if not key:
        raise MissingApiKeyError(
            "GEMINI_API_KEY is not set. Store the key in the macOS keychain and export it "
            "from ~/.zshrc (see docs), then open a new terminal."
        )
    return genai.Client(api_key=key)


class GeminiAnswerModel:
    def __init__(self, model: str = DEFAULT_MODEL, client: Any = None,
                 rate_limit_wait_s: float = _RATE_LIMIT_WAIT_S,
                 fallback_model: str | None = FALLBACK_MODEL) -> None:
        self._model = model
        self._fallback = fallback_model
        self._client = client or _client_from_env()
        self._wait = rate_limit_wait_s
        self.last_model_used = model  # which model produced the latest draft, for evaluation

    @property
    def name(self) -> str:
        return self._model

    def draft(self, system: str, user: str) -> AnswerDraft:
        config = types.GenerateContentConfig(
            system_instruction=system,
            response_mime_type="application/json",
            response_schema=AnswerDraft,
            temperature=0.0,  # repeatable evaluation runs
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        try:
            response = self._generate(self._model, user, config)
            self.last_model_used = self._model
        except (errors.ServerError, DailyQuotaExceededError) as exc:
            if not self._fallback:
                raise
            logger.warning("%s unavailable (%s); falling back to %s",
                           self._model, type(exc).__name__, self._fallback)
            response = self._generate(self._fallback, user, config)
            self.last_model_used = self._fallback
        if response.prompt_feedback and response.prompt_feedback.block_reason:
            raise ModelRefusalError(f"prompt blocked: {response.prompt_feedback.block_reason}")
        candidate = response.candidates[0] if response.candidates else None
        if candidate is None or candidate.finish_reason == types.FinishReason.SAFETY:
            raise ModelRefusalError("response blocked by safety filters")
        if isinstance(response.parsed, AnswerDraft):
            return response.parsed
        return AnswerDraft.model_validate_json(response.text or "")

    def _generate(self, model: str, user: str, config: types.GenerateContentConfig) -> Any:
        """Retry per-minute rate limits (429) and overload (5xx); a per-day quota fails fast."""
        for attempt in range(1, _RATE_LIMIT_RETRIES + 1):
            try:
                return self._client.models.generate_content(
                    model=model, contents=user, config=config
                )
            except (errors.ClientError, errors.ServerError) as exc:
                if _is_daily_quota(exc):
                    raise DailyQuotaExceededError(f"{model}: daily free-tier quota used up") from exc
                retryable = exc.code == 429 or exc.code >= 500
                if not retryable or attempt == _RATE_LIMIT_RETRIES:
                    raise
                logger.warning("Gemini %s; waiting %.0fs (attempt %d)", exc.code, self._wait * attempt, attempt)
                time.sleep(self._wait * attempt)
        raise RuntimeError("unreachable")
