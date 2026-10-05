"""AnswerModel backed by the Claude API."""

import anthropic

from attack_qa.answer import AnswerDraft, ModelRefusalError

DEFAULT_MODEL = "claude-opus-5-5"

# Raw JSON schema for structured output; mirrors AnswerDraft.
_ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "answerable": {"type": "boolean"},
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "passage_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["text", "passage_ids"],
                "additionalProperties": False,
            },
        },
        "refusal_reason": {"type": "string"},
    },
    "required": ["answerable", "claims", "refusal_reason"],
    "additionalProperties": False,
}


class ClaudeAnswerModel:
    """Structured answer from Claude.

    Security questions can trip Claude's cyber safety classifier, so requests opt into
    server-side fallback: a declined request is re-run on Anthropic's recommended
    fallback model inside the same call. A refusal that survives the fallback raises
    ModelRefusalError.
    """

    def __init__(self, model: str = DEFAULT_MODEL, effort: str = "medium",
                 client: anthropic.Anthropic | None = None) -> None:
        self._model = model
        self._effort = effort
        self._client = client or anthropic.Anthropic()  # credentials from the environment

    @property
    def name(self) -> str:
        return self._model

    def draft(self, system: str, user: str) -> AnswerDraft:
        response = self._client.beta.messages.create(
            model=self._model,
            max_tokens=16000,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={
                "effort": self._effort,
                "format": {"type": "json_schema", "schema": _ANSWER_SCHEMA},
            },
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        if response.stop_reason == "refusal":
            category = response.stop_details.category if response.stop_details else None
            raise ModelRefusalError(f"category={category}")
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise ValueError(f"No text block in response (stop_reason={response.stop_reason})")
        return AnswerDraft.model_validate_json(text)
