from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from attack_qa.answer import (
    AnswerDraft,
    Claim,
    ModelRefusalError,
    FREE_TEXT_NO_DEFENSES,
    Defenses,
    answer_question,
    build_user_message,
    system_prompt,
)
from attack_qa.bm25_index import Bm25Index
from attack_qa.claude_model import ClaudeAnswerModel
from attack_qa.dense_index import DenseIndex
from attack_qa.passages import Passage, PassageKind
from attack_qa.retrieval import HybridRetriever
from tests.conftest import FakeEmbedder


def _passage(tid: str, kind: PassageKind, text: str) -> Passage:
    return Passage(tid, tid, None, None, kind, f"{tid} — {kind.value}\n{text}", "", "19.2")


PASSAGES = (
    _passage("T1056.001", PassageKind.OVERVIEW, "adversaries record user keystrokes"),
    _passage("T1056.001", PassageKind.MITIGATION, "no preventive mitigations for keylogging"),
    _passage("T1059.001", PassageKind.DETECTION, "monitor encoded powershell commands"),
)


class FakeModel:
    def __init__(self, draft: AnswerDraft | None = None, refuse: bool = False) -> None:
        self._draft = draft
        self._refuse = refuse
        self.calls: list[tuple[str, str]] = []

    @property
    def name(self) -> str:
        return "fake"

    def draft(self, system: str, user: str) -> AnswerDraft:
        self.calls.append((system, user))
        if self._refuse:
            raise ModelRefusalError("category=cyber")
        assert self._draft is not None
        return self._draft


NO_GATE = 0.0  # fake-embedder cosines are low; these tests are not about gate 2


@pytest.fixture
def retriever(tmp_path: Path) -> HybridRetriever:
    dense = DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    return HybridRetriever(PASSAGES, dense, Bm25Index(PASSAGES), revoked={"T1086": "T1059.001"})


def _answer(answerable: bool = True, ids: tuple[str, ...] = ("T1056.001:overview",)) -> AnswerDraft:
    claims = [Claim(text="Keylogging records keystrokes.", passage_ids=list(ids))] if answerable else []
    return AnswerDraft(answerable=answerable, claims=claims,
                       refusal_reason="" if answerable else "Not in the passages.")


def test_answers_with_verified_citations(retriever: HybridRetriever) -> None:
    answer = answer_question("what records user keystrokes", retriever, FakeModel(_answer()), relevance_threshold=NO_GATE)
    assert answer.status == "answered"
    assert answer.claims[0].passage_ids == ("T1056.001:overview",)


def test_relevance_gate_refuses_without_calling_the_model(retriever: HybridRetriever) -> None:
    model = FakeModel(_answer())
    answer = answer_question("bake sourdough bread", retriever, model, relevance_threshold=0.5)
    assert (answer.status, answer.refused_by) == ("refused", "relevance")
    assert model.calls == []


def test_named_technique_skips_the_relevance_gate(retriever: HybridRetriever) -> None:
    model = FakeModel(_answer(ids=("T1059.001:detection",)))
    answer = answer_question("T1059.001", retriever, model, relevance_threshold=0.99)
    assert answer.status == "answered"


def test_llm_gate_refusal_is_reported(retriever: HybridRetriever) -> None:
    answer = answer_question("which groups use keylogging", retriever, FakeModel(_answer(False)), relevance_threshold=NO_GATE)
    assert (answer.status, answer.refused_by) == ("refused", "llm")
    assert answer.refusal_reason == "Not in the passages."


def test_citations_to_unretrieved_passages_are_dropped(retriever: HybridRetriever) -> None:
    draft = AnswerDraft(answerable=True, refusal_reason="", claims=[
        Claim(text="Real.", passage_ids=["T1056.001:overview", "T9999:overview"]),
        Claim(text="Made up.", passage_ids=["T9999:overview"]),
    ])
    answer = answer_question("keystrokes keylogging", retriever, FakeModel(draft), relevance_threshold=NO_GATE)
    assert [c.text for c in answer.claims] == ["Real."]
    assert answer.claims[0].passage_ids == ("T1056.001:overview",)
    assert answer.dropped_claims == 1


def test_answer_with_no_valid_citation_is_refused(retriever: HybridRetriever) -> None:
    draft = _answer(ids=("T9999:overview",))
    answer = answer_question("keystrokes keylogging", retriever, FakeModel(draft), relevance_threshold=NO_GATE)
    assert answer.refused_by == "no_valid_citations"


def test_model_refusal_becomes_a_refusal(retriever: HybridRetriever) -> None:
    answer = answer_question("keystrokes keylogging", retriever, FakeModel(refuse=True), relevance_threshold=NO_GATE)
    assert answer.refused_by == "model_refusal"


def test_prompt_carries_passages_and_revoked_id_note(retriever: HybridRetriever) -> None:
    result = retriever.retrieve("What is T1086?", top_k=2)
    message = build_user_message("What is T1086?", result)
    assert '<passage id="T1059.001:detection">' in message
    assert "the user wrote T1086, which ATT&CK v19.2 revoked and replaced with T1059.001" in message
    # The system shows the replacement itself; a claim restating it would cite a passage that
    # doesn't say it (grill-decisions Q37)
    assert "mention the replacement" not in message
    assert "Do not state the replacement in a claim" in message
    # the question itself names the live ID, which the passages actually contain
    assert message.rstrip().endswith("Question: What is T1059.001?")


# --- ClaudeAnswerModel with a stub client (no network) ---

class _StubMessages:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.kwargs: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        return self.response


def _stub_client(response: Any) -> tuple[Any, _StubMessages]:
    messages = _StubMessages(response)
    return SimpleNamespace(beta=SimpleNamespace(messages=messages)), messages


def test_claude_model_parses_structured_output() -> None:
    text = '{"answerable": true, "claims": [{"text": "x", "passage_ids": ["a:overview"]}], "refusal_reason": ""}'
    response = SimpleNamespace(stop_reason="end_turn", stop_details=None, content=[
        SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text),
    ])
    client, messages = _stub_client(response)
    draft = ClaudeAnswerModel(client=client).draft("system", "user")
    assert draft.claims[0].passage_ids == ["a:overview"]
    assert messages.kwargs["fallbacks"] == "default"
    assert messages.kwargs["output_config"]["format"]["type"] == "json_schema"


def test_claude_model_raises_on_refusal() -> None:
    response = SimpleNamespace(stop_reason="refusal", content=[],
                               stop_details=SimpleNamespace(category="cyber"))
    client, _ = _stub_client(response)
    with pytest.raises(ModelRefusalError, match="cyber"):
        ClaudeAnswerModel(client=client).draft("system", "user")


def test_structured_prompt_carries_the_faithfulness_rules() -> None:
    """grill-decisions Q38: from the judge-vs-human review (C14 and C23)."""
    prompt = system_prompt(Defenses())
    assert "cite every passage it draws on" in prompt
    assert "keep the whole sequence in one claim" in prompt


def test_free_text_control_prompt_is_unchanged_by_the_faithfulness_rules() -> None:
    # The attack control group must stay comparable with runs made before Q38
    assert "keep the whole sequence" not in system_prompt(FREE_TEXT_NO_DEFENSES)
