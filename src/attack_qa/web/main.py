"""Serve the demo API with the real index, embedding model and LLM.

Run: uvicorn attack_qa.web.main:app --host 0.0.0.0 --port 8000
Environment: GROQ_API_KEY (secret), ALLOWED_ORIGINS (comma-separated, default the demo site),
DEMO_LLM (default groq). Everything is loaded before the server accepts requests, so /health
answering means the API is ready.
"""

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass

DEFAULT_ORIGIN = "https://rag.marklu.page"


@dataclass(frozen=True)
class Settings:
    allowed_origins: tuple[str, ...]
    llm: str


def settings_from_env(env: Mapping[str, str]) -> Settings:
    origins = tuple(o.strip() for o in env.get("ALLOWED_ORIGINS", DEFAULT_ORIGIN).split(",") if o.strip())
    if "*" in origins:  # any site could then spend the demo's Groq quota (Q41)
        raise ValueError("ALLOWED_ORIGINS must list sites explicitly; a wildcard is not allowed")
    return Settings(allowed_origins=origins, llm=env.get("DEMO_LLM", "groq"))


def _build_app():  # type: ignore[no-untyped-def]
    from attack_qa.bm25_index import Bm25Index
    from attack_qa.config import INDEX_DIR, PROCESSED_DIR
    from attack_qa.dense_index import DenseIndex
    from attack_qa.embedding import SentenceTransformerEmbedder
    from attack_qa.intent import IntentClassifier
    from attack_qa.llms import make_answer_model
    from attack_qa.lookups import load_revoked_ids
    from attack_qa.passage_io import load_passages
    from attack_qa.retrieval import HybridRetriever
    from attack_qa.web.app import create_app
    from attack_qa.web.limits import RateLimiter

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    settings = settings_from_env(os.environ)
    passages = load_passages(PROCESSED_DIR / "passages.jsonl")
    embedder = SentenceTransformerEmbedder()
    retriever = HybridRetriever(passages, DenseIndex.open(INDEX_DIR, embedder), Bm25Index(passages),
                                load_revoked_ids(PROCESSED_DIR / "revoked_ids.json"),
                                intent_classifier=IntentClassifier(embedder))
    retriever.retrieve("warm up")  # first query pays one-off costs; do it before /health says ready
    return create_app(retriever, make_answer_model(settings.llm), RateLimiter(),
                      allowed_origins=settings.allowed_origins)


app = _build_app() if os.environ.get("ATTACK_QA_SERVE") == "1" else None
