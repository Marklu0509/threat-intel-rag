"""Pick an AnswerModel by name, importing each provider's SDK only when it is used."""

from typing import Any

# Seconds to wait between LLM calls during evaluation, to stay under each free tier's
# per-minute limit: Groq allows 8,000 tokens/minute and one request is ~2,500-3,000 tokens.
PACING_S = {"groq": 22.0, "openrouter": 0.5, "gemini": 7.0, "claude": 0.0}
CHOICES = tuple(PACING_S)


def make_answer_model(name: str) -> Any:
    if name == "groq":
        from attack_qa.openai_compat_model import OpenAICompatibleAnswerModel
        return OpenAICompatibleAnswerModel()
    if name == "openrouter":
        from attack_qa.openai_compat_model import OPENROUTER, OpenAICompatibleAnswerModel
        return OpenAICompatibleAnswerModel(provider=OPENROUTER)
    if name == "gemini":
        from attack_qa.gemini_model import GeminiAnswerModel
        return GeminiAnswerModel()
    if name == "claude":
        from attack_qa.claude_model import ClaudeAnswerModel
        return ClaudeAnswerModel()
    raise ValueError(f"Unknown LLM {name!r}; choose from {CHOICES}")
