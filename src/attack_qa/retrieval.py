"""Hybrid retrieval: dense + BM25 candidates, merged with RRF (Q12, Q14)."""

from collections.abc import Sequence
from dataclasses import dataclass

from attack_qa.bm25_index import Bm25Index
from attack_qa.dense_index import DenseIndex
from attack_qa.fusion import rrf_merge
from attack_qa.passages import Passage

CANDIDATES = 50
TOP_K = 5


@dataclass(frozen=True)
class Retrieved:
    passage: Passage
    rank: int
    dense_cosine: float | None  # None when dense retrieval did not return it; read by refusal gate 2


class HybridRetriever:
    def __init__(self, passages: Sequence[Passage], dense: DenseIndex, bm25: Bm25Index) -> None:
        self._by_id = {p.passage_id: p for p in passages}
        self._dense = dense
        self._bm25 = bm25

    def retrieve(
        self, query: str, top_k: int = TOP_K, candidates: int = CANDIDATES
    ) -> tuple[Retrieved, ...]:
        if not query.strip():
            raise ValueError("Query is empty")
        dense_hits = self._dense.search(query, candidates)
        sparse_hits = self._bm25.search(query, candidates)
        cosine = {hit.passage_id: hit.score for hit in dense_hits}
        merged = rrf_merge(
            dense=[hit.passage_id for hit in dense_hits],
            sparse=[hit.passage_id for hit in sparse_hits],
        )
        return tuple(
            Retrieved(self._by_id[pid], rank, cosine.get(pid))
            for rank, pid in enumerate(merged[:top_k], start=1)
        )
