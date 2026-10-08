import json
import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from attack_qa.answer import AnswerDraft, Claim, DailyQuotaExceededError
from attack_qa.bm25_index import Bm25Index
from attack_qa.dense_index import DenseIndex
from attack_qa.passages import Passage, PassageKind
from attack_qa.retrieval import HybridRetriever
from attack_qa.web.app import client_ip, create_app
from attack_qa.web.limits import Limits, RateLimiter
from tests.conftest import FakeEmbedder

ORIGIN = "https://rag.marklu.page"


def _passage(tid: str, kind: PassageKind, text: str) -> Passage:
    return Passage(tid, tid, None, None, kind, f"{tid} — {kind.value}\n{text}", "", "19.2")


PASSAGES = (
    _passage("T1056.001", PassageKind.OVERVIEW, "adversaries record user keystrokes"),
    _passage("T1059.001", PassageKind.DETECTION, "monitor encoded powershell commands"),
)


class FakeModel:
    name = "fake/model"

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls = 0

    def draft(self, system: str, user: str) -> AnswerDraft:
        self.calls += 1
        if self.error:
            raise self.error
        return AnswerDraft(answerable=True, refusal_reason="",
                           claims=[Claim(text="Keylogging records keystrokes.",
                                         passage_ids=["T1056.001:overview"])])


@pytest.fixture
def retriever(tmp_path: Path) -> HybridRetriever:
    dense = DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    return HybridRetriever(PASSAGES, dense, Bm25Index(PASSAGES), revoked={"T1086": "T1059.001"})


def _client(retriever: HybridRetriever, model: FakeModel | None = None,
            limits: Limits = Limits(), relevance_threshold: float = 0.0) -> TestClient:
    app = create_app(retriever, model or FakeModel(), RateLimiter(limits),
                     allowed_origins=[ORIGIN], relevance_threshold=relevance_threshold)
    return TestClient(app)


def test_health_reports_ready_and_versions(retriever):
    body = _client(retriever).get("/health").json()
    assert body["status"] == "ok" and body["model"] == "fake/model"
    assert body["attack_version"] == "19.2"


def test_ask_returns_claims_and_the_retrieval_trace(retriever):
    r = _client(retriever).post("/ask", json={"question": "what records user keystrokes"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "answered"
    assert body["claims"] == [{"text": "Keylogging records keystrokes.", "passage_ids": ["T1056.001:overview"]}]
    hit = body["hits"][0]
    assert {"id", "rank", "kind", "dense_rank", "bm25_rank", "cosine", "text"} <= hit.keys()
    assert "T1056.001" in hit["text"] or "T1059.001" in hit["text"]
    assert body["remaining_today"] == Limits().per_day - 1


def test_revoked_id_replacement_is_returned_for_the_page_to_show(retriever):
    body = _client(retriever).post("/ask", json={"question": "How do I detect T1086?"}).json()
    assert body["substitutions"] == {"T1086": "T1059.001"}


def test_relevance_gate_refusal_is_reported_without_calling_the_model(retriever):
    model = FakeModel()
    body = _client(retriever, model, relevance_threshold=1.01).post(
        "/ask", json={"question": "how do I bake bread"}).json()
    assert body["status"] == "refused" and body["refused_by"] == "relevance"
    assert model.calls == 0


@pytest.mark.parametrize("question", ["", "   ", "x" * 301])
def test_rejects_empty_or_overlong_questions(retriever, question):
    r = _client(retriever).post("/ask", json={"question": question})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_question"


def test_per_ip_limit_returns_429_with_retry_after(retriever):
    client = _client(retriever, limits=Limits(per_ip_per_hour=1))
    assert client.post("/ask", json={"question": "keystrokes"}).status_code == 200
    r = client.post("/ask", json={"question": "keystrokes"})
    assert r.status_code == 429 and r.json()["error"] == "rate_limited"
    assert int(r.headers["Retry-After"]) > 0


def test_daily_cap_returns_503_so_the_page_falls_back_to_recorded_examples(retriever):
    client = _client(retriever, limits=Limits(per_day=1))
    client.post("/ask", json={"question": "keystrokes"})
    r = client.post("/ask", json={"question": "keystrokes"})
    assert r.status_code == 503 and r.json()["error"] == "daily_limit"


def test_llm_daily_quota_also_returns_daily_limit(retriever):
    r = _client(retriever, FakeModel(DailyQuotaExceededError("groq: daily quota used up"))).post(
        "/ask", json={"question": "keystrokes"})
    assert r.status_code == 503 and r.json()["error"] == "daily_limit"


def test_other_llm_failures_return_502_without_leaking_details(retriever):
    r = _client(retriever, FakeModel(RuntimeError("secret upstream detail org_0000fakeorgid0000test"))).post(
        "/ask", json={"question": "keystrokes"})
    assert r.status_code == 502 and r.json()["error"] == "upstream"
    assert "secret" not in r.text and "org_" not in r.text


def test_cors_allows_only_the_demo_origin(retriever):
    client = _client(retriever)
    ok = client.options("/ask", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST",
                                         "Access-Control-Request-Headers": "content-type"})
    assert ok.headers.get("access-control-allow-origin") == ORIGIN
    bad = client.options("/ask", headers={"Origin": "https://evil.example",
                                          "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in bad.headers


def test_logs_the_question_and_outcome_but_never_the_ip(retriever, caplog):
    caplog.set_level(logging.INFO, logger="attack_qa.web")
    _client(retriever).post("/ask", json={"question": "what records user keystrokes"},
                            headers={"X-Forwarded-For": "203.0.113.9"})
    records = [json.loads(r.getMessage()) for r in caplog.records if r.name == "attack_qa.web"]
    assert records and records[-1]["question"] == "what records user keystrokes"
    assert records[-1]["status"] == "answered" and "elapsed_ms" in records[-1]
    assert "203.0.113.9" not in caplog.text


def test_client_ip_uses_the_address_appended_by_the_trusted_proxy():
    # Azure's ingress appends the real client address; anything to its left came from the client
    assert client_ip("198.51.100.7, 203.0.113.9", "10.0.0.5") == "203.0.113.9"
    assert client_ip(None, "10.0.0.5") == "10.0.0.5"


class PingingModel(FakeModel):
    def __init__(self, ping_error: Exception | None = None) -> None:
        super().__init__()
        self.ping_error = ping_error
        self.pings = 0

    def ping(self) -> None:
        self.pings += 1
        if self.ping_error:
            raise self.ping_error


def test_health_llm_check_reports_ok(retriever):
    model = PingingModel()
    body = _client(retriever, model).get("/health?check=llm").json()
    assert body["llm"] == {"ok": True}
    assert model.pings == 1


def test_health_llm_check_reports_the_error_type_and_cause_but_no_secrets(retriever):
    cause = ValueError("Illegal header value b'Bearer gsk_secret\\n'")
    error = RuntimeError("Connection error. org_0000fakeorgid0000test")
    error.__cause__ = cause
    r = _client(retriever, PingingModel(error)).get("/health?check=llm")
    assert r.status_code == 200
    llm = r.json()["llm"]
    assert llm["ok"] is False and llm["error_type"] == "RuntimeError" and llm["cause_type"] == "ValueError"
    assert "gsk_secret" not in r.text and "org_0000fake" not in r.text


def test_health_llm_check_is_cached_so_it_cannot_be_used_to_hammer_the_provider(retriever):
    model = PingingModel()
    client = _client(retriever, model)
    for _ in range(5):
        client.get("/health?check=llm")
    assert model.pings == 1


def test_health_reports_the_deployed_version(retriever):
    """The deploy pipeline waits until /health shows the new commit before smoke-testing it."""
    app = create_app(retriever, FakeModel(), RateLimiter(Limits()), allowed_origins=[ORIGIN],
                     relevance_threshold=0.0, version="9423a6a")
    assert TestClient(app).get("/health").json()["version"] == "9423a6a"
