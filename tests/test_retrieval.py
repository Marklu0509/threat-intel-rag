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
    _passage("T1056.001", PassageKind.OVERVIEW, "adversaries record keystrokes"),
)


@pytest.fixture
def retriever(tmp_path: Path) -> HybridRetriever:
    dense = DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    return HybridRetriever(PASSAGES, dense, Bm25Index(PASSAGES))


def test_returns_top_k_in_rank_order(retriever: HybridRetriever) -> None:
    results = retriever.retrieve("detection for T1543.001", top_k=2)
    assert [r.rank for r in results] == [1, 2]
    assert results[0].passage.passage_id == "T1543.001:detection"


def test_keeps_dense_cosine_for_the_refusal_gate(retriever: HybridRetriever) -> None:
    results = retriever.retrieve("adversaries record keystrokes", top_k=3)
    assert results[0].passage.passage_id == "T1056.001:overview"
    assert results[0].dense_cosine is not None
    assert results[0].dense_cosine == max(r.dense_cosine or 0.0 for r in results)


def test_empty_query_is_rejected(retriever: HybridRetriever) -> None:
    with pytest.raises(ValueError, match="empty"):
        retriever.retrieve("   ")
