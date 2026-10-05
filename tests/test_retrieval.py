from pathlib import Path

import pytest

from attack_qa.bm25_index import Bm25Index
from attack_qa.dense_index import DenseIndex
from attack_qa.passages import Passage, PassageKind
from attack_qa.retrieval import HybridRetriever
from tests.conftest import FakeEmbedder


def _passage(tid: str, kind: PassageKind, text: str) -> Passage:
    return Passage(tid, tid, None, None, kind, f"{tid} — {kind.value}\n{text}", "", "19.2")


PASSAGES = (
    _passage("T1543.003", PassageKind.DETECTION, "monitor new windows services"),
    _passage("T1543.001", PassageKind.DETECTION, "monitor new launch agent plist files"),
    _passage("T1543.001", PassageKind.OVERVIEW, "launch agents run at login on macos"),
    _passage("T1056.001", PassageKind.OVERVIEW, "adversaries record keystrokes"),
    _passage("T1056.001", PassageKind.DETECTION, "watch keyboard hooks recording keystrokes"),
    _passage("T1059.001", PassageKind.OVERVIEW, "powershell scripting"),
)


@pytest.fixture
def retriever(tmp_path: Path) -> HybridRetriever:
    dense = DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    return HybridRetriever(PASSAGES, dense, Bm25Index(PASSAGES), revoked={"T1086": "T1059.001"})


def _ids(result) -> list[str]:  # type: ignore[no-untyped-def]
    return [h.passage.passage_id for h in result.hits]


def test_returns_top_k_in_rank_order(retriever: HybridRetriever) -> None:
    result = retriever.retrieve("detection for T1543.001", top_k=2)
    assert [h.rank for h in result.hits] == [1, 2]
    assert _ids(result)[0] == "T1543.001:detection"


def test_named_technique_comes_first_and_intent_picks_its_kind(retriever: HybridRetriever) -> None:
    assert _ids(retriever.retrieve("What is T1543.001?", top_k=2)) == [
        "T1543.001:overview", "T1543.001:detection",
    ]


def test_named_technique_is_added_even_if_no_retriever_found_it(tmp_path: Path) -> None:
    # candidates=1 leaves room for one Passage per retriever; T1059.001 must still appear
    dense = DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    retriever = HybridRetriever(PASSAGES, dense, Bm25Index(PASSAGES))
    result = retriever.retrieve("keystrokes keyboard T1059.001", top_k=1, candidates=1)
    assert _ids(result) == ["T1059.001:overview"]


def test_revoked_id_is_rewritten_before_search(retriever: HybridRetriever) -> None:
    result = retriever.retrieve("What is T1086?", top_k=1)
    assert _ids(result) == ["T1059.001:overview"]
    assert dict(result.plan.substitutions) == {"T1086": "T1059.001"}


def test_intent_moves_matching_kind_forward(retriever: HybridRetriever) -> None:
    assert _ids(retriever.retrieve("how to detect keystroke recording", top_k=1)) == [
        "T1056.001:detection",
    ]


def test_keeps_dense_cosine_for_the_refusal_gate(retriever: HybridRetriever) -> None:
    hits = retriever.retrieve("adversaries record keystrokes", top_k=3).hits
    assert hits[0].passage.passage_id == "T1056.001:overview"
    assert hits[0].dense_cosine == max(h.dense_cosine or 0.0 for h in hits)


def test_empty_query_is_rejected(retriever: HybridRetriever) -> None:
    with pytest.raises(ValueError, match="empty"):
        retriever.retrieve("   ")
