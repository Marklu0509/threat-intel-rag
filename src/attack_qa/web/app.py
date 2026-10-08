"""The demo API: one question in, a cited answer (or refusal) and its retrieval trace out.

Built by create_app() from already-loaded parts, so tests pass a tiny index and a fake model;
attack_qa.web.main loads the real ones. Nothing here calls a paid service (grill-decisions Q42).
"""

import json
import logging
import time
from collections.abc import Sequence
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from attack_qa.answer import RELEVANCE_THRESHOLD, AnswerModel, DailyQuotaExceededError, answer_question
from attack_qa.answer_eval import error_text
from attack_qa.config import ATTACK_VERSION
from attack_qa.retrieval import HybridRetriever, RetrievalResult
from attack_qa.web.limits import RateLimiter

logger = logging.getLogger("attack_qa.web")


class AskRequest(BaseModel):
    question: str


class _RecordingRetriever:
    """Hands answer_question the real retriever and keeps the result for the response trace."""

    def __init__(self, inner: HybridRetriever) -> None:
        self._inner = inner
        self.result: RetrievalResult | None = None

    def retrieve(self, question: str, **kwargs: Any) -> RetrievalResult:
        self.result = self._inner.retrieve(question, **kwargs)
        return self.result


def client_ip(forwarded_for: str | None, peer: str | None) -> str:
    """The visitor's address: the last X-Forwarded-For entry, which Azure's ingress appended.

    Entries to its left were sent by the client and can be forged to dodge the rate limit.
    """
    if forwarded_for:
        return forwarded_for.split(",")[-1].strip()
    return peer or "unknown"


def _error(status: int, code: str, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": code, "message": message}, status_code=status, headers=headers)


def _trace(result: RetrievalResult) -> list[dict[str, Any]]:
    return [{"id": h.passage.passage_id, "rank": h.rank, "kind": h.passage.kind.value,
             "dense_rank": h.dense_rank, "bm25_rank": h.bm25_rank, "cosine": h.dense_cosine,
             "text": h.passage.text} for h in result.hits]


LLM_CHECK_CACHE_S = 60.0


def _llm_status(model: AnswerModel, cache: dict[str, Any]) -> dict[str, Any]:
    """Can the server reach the LLM provider? Error types and status only, never messages:
    a malformed key, for one, appears verbatim in the underlying error. Cached so the public
    endpoint can't be used to hammer the provider."""
    if cache and time.monotonic() - cache["at"] < LLM_CHECK_CACHE_S:
        return cache["result"]
    ping = getattr(model, "ping", None)
    if ping is None:
        result: dict[str, Any] = {"ok": None, "detail": "model has no ping"}
    else:
        try:
            ping()
            result = {"ok": True}
        except Exception as exc:  # report the kind of failure, not its text
            cause = exc.__cause__ or exc.__context__
            result = {"ok": False, "error_type": type(exc).__name__,
                      "cause_type": type(cause).__name__ if cause else None,
                      "status": getattr(exc, "status_code", None)}
            logger.warning(json.dumps({"event": "llm_check", **result}))
    cache.update(at=time.monotonic(), result=result)
    return result


def create_app(retriever: HybridRetriever, model: AnswerModel, limiter: RateLimiter, *,
               allowed_origins: Sequence[str],
               relevance_threshold: float = RELEVANCE_THRESHOLD, version: str = "dev") -> FastAPI:
    app = FastAPI(title="threat-intel-rag demo API", docs_url=None, redoc_url=None)
    app.add_middleware(CORSMiddleware, allow_origins=list(allowed_origins),
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

    llm_check: dict[str, Any] = {}  # last result and when it was taken

    @app.get("/health")
    def health(check: str = "") -> dict[str, Any]:
        body: dict[str, Any] = {"status": "ok", "model": model.name, "attack_version": ATTACK_VERSION,
                                "version": version}
        if check == "llm":
            body["llm"] = _llm_status(model, llm_check)
        return body

    @app.post("/ask")
    def ask(body: AskRequest, request: Request) -> JSONResponse:
        question = body.question.strip()
        limit = limiter.limits.max_question_chars
        if not question or len(question) > limit:
            return _error(400, "invalid_question", f"Ask a question of 1 to {limit} characters.")
        decision = limiter.check(client_ip(request.headers.get("x-forwarded-for"),
                                           request.client.host if request.client else None))
        if decision.reason == "daily":
            return _error(503, "daily_limit", "Today's live questions are used up. "
                          "The recorded examples below still work.")
        if not decision.allowed:
            return _error(429, "rate_limited", "That's the hourly limit for live questions. "
                          "Try again later.", {"Retry-After": str(decision.retry_after_s)})

        started = time.monotonic()
        recorder = _RecordingRetriever(retriever)
        log: dict[str, Any] = {"event": "ask", "question": question}  # never the visitor's IP (Q50)
        try:
            answer = answer_question(question, recorder, model, relevance_threshold=relevance_threshold)
        except DailyQuotaExceededError:
            logger.info(json.dumps({**log, "status": "llm_quota"}, ensure_ascii=False))
            return _error(503, "daily_limit", "Today's live questions are used up. "
                          "The recorded examples below still work.")
        except Exception as exc:  # the model is an outside service; report, don't crash
            logger.warning(json.dumps({**log, "status": "error", "error": error_text(exc)},
                                      ensure_ascii=False))
            return _error(502, "upstream", "The language model didn't respond. Try again in a minute.")

        elapsed_ms = round((time.monotonic() - started) * 1000)
        result = recorder.result
        logger.info(json.dumps({**log, "status": answer.status, "refused_by": answer.refused_by,
                                "retrieved": list(answer.retrieved), "elapsed_ms": elapsed_ms},
                               ensure_ascii=False))
        return JSONResponse({
            "status": answer.status, "refused_by": answer.refused_by,
            "refusal_reason": answer.refusal_reason,
            "claims": [{"text": c.text, "passage_ids": list(c.passage_ids)} for c in answer.claims],
            "substitutions": answer.substitutions,
            "top_cosine": result.top_dense_cosine if result else None,
            "relevance_threshold": relevance_threshold,
            "hits": _trace(result) if result else [],
            "model": model.name, "attack_version": ATTACK_VERSION,
            "elapsed_ms": elapsed_ms, "remaining_today": decision.remaining_today,
        })

    return app
