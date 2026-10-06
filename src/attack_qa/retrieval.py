"""Hybrid retrieval: plan the question, fetch dense + BM25 candidates, merge, reorder.

Order of the final ranking (Q12, Q13, Q14, Q23):
  1. Passages of a Technique the question names by ID — added even if neither retriever found them
  2. Passages whose kind matches the Question intent
  3. everything else, by RRF
Ties inside each group keep RRF order, so this only moves Passages forward, never drops one.
"""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Mapping

from attack_qa.bm25_index import Bm25Index
from attack_qa.dense_index import DenseIndex
from attack_qa.fusion import rrf_merge
from attack_qa.intent import IntentClassifier
from attack_qa.passages import Passage
from attack_qa.query import QueryPlan, plan_query

CANDIDATES = 50
TOP_K = 5


@dataclass(frozen=True)
class Retrieved:
    passage: Passage
    rank: int
    dense_cosine: float | None  # None when dense retrieval did not return it; read by refusal gate 2
    dense_rank: int | None = None  # each retriever's own rank, for explaining a result;
    bm25_rank: int | None = None  # None when that retriever did not return the Passage


@dataclass(frozen=True)
class RetrievalResult:
    plan: QueryPlan
    hits: tuple[Retrieved, ...]
    top_dense_cosine: float  # best cosine anywhere in the index; read by refusal gate 2 (ADR 0004)


def reorder(merged: Sequence[str], plan: QueryPlan, passages: Mapping[str, Passage],
            by_technique: Mapping[str, Sequence[str]]) -> list[str]:
    named = [pid for tid in plan.technique_ids for pid in by_technique.get(tid, ())]
    candidates = list(dict.fromkeys([*merged, *named]))  # keep RRF order, append missing named ones
    position = {pid: i for i, pid in enumerate(candidates)}

    def priority(pid: str) -> tuple[int, int, int]:
        p = passages[pid]
        names_it = p.technique_id in plan.technique_ids
        wanted_kind = plan.intent is not None and p.kind == plan.intent
        return (0 if names_it else 1, 0 if wanted_kind else 1, position[pid])

    return sorted(candidates, key=priority)


class HybridRetriever:
    def __init__(self, passages: Sequence[Passage], dense: DenseIndex, bm25: Bm25Index,
                 revoked: Mapping[str, str] | None = None,
                 understand_query: bool = True,
                 intent_classifier: IntentClassifier | None = None) -> None:
        """understand_query=False searches the raw question and keeps plain RRF order (ablation).

        intent_classifier is consulted only when the intent rules find nothing (Q24).
        """
        self._understand_query = understand_query
        self._intent_classifier = intent_classifier
        self._by_id = {p.passage_id: p for p in passages}
        by_technique: dict[str, list[str]] = defaultdict(list)
        for p in passages:
            by_technique[p.technique_id].append(p.passage_id)
        self._by_technique = dict(by_technique)
        self._dense = dense
        self._bm25 = bm25
        self._revoked = revoked or {}

    def retrieve(self, question: str, top_k: int = TOP_K,
                 candidates: int = CANDIDATES) -> RetrievalResult:
        plan = plan_query(question, self._revoked)
        if not self._understand_query:
            plan = QueryPlan(question, question, (), None, MappingProxyType({}))
        query_vector = self._dense.embed_query(plan.search_text)  # embedded once, used twice
        if self._understand_query and plan.intent is None and self._intent_classifier:
            plan = replace(plan, intent=self._intent_classifier.classify(query_vector))
        dense_hits = self._dense.search_by_vector(query_vector, candidates)
        sparse_hits = self._bm25.search(plan.search_text, candidates)
        cosine = {hit.passage_id: hit.score for hit in dense_hits}
        dense_rank = {hit.passage_id: i for i, hit in enumerate(dense_hits, start=1)}
        bm25_rank = {hit.passage_id: i for i, hit in enumerate(sparse_hits, start=1)}
        merged = rrf_merge(
            dense=[hit.passage_id for hit in dense_hits],
            sparse=[hit.passage_id for hit in sparse_hits],
        )
        ranked = reorder(merged, plan, self._by_id, self._by_technique)
        hits = tuple(
            Retrieved(self._by_id[pid], rank, cosine.get(pid), dense_rank.get(pid), bm25_rank.get(pid))
            for rank, pid in enumerate(ranked[:top_k], start=1)
        )
        top_cosine = dense_hits[0].score if dense_hits else 0.0
        return RetrievalResult(plan, hits, top_cosine)
