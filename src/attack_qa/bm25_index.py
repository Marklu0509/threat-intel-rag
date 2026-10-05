"""Keyword retrieval over Passages (grill-decisions Q12)."""

import re
from collections.abc import Sequence
from dataclasses import dataclass

from rank_bm25 import BM25Okapi

from attack_qa.passages import Passage

# Technique IDs (t1059, t1059.001) and executables (schtasks.exe) stay whole;
# splitting T1059.001 into "t1059" and "001" would make .001 and .003 identical.
_TOKEN = re.compile(r"t\d{4}(?:\.\d{3})?|[a-z0-9_-]+\.exe|[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


@dataclass(frozen=True)
class ScoredId:
    passage_id: str
    score: float


class Bm25Index:
    def __init__(self, passages: Sequence[Passage]) -> None:
        if not passages:
            raise ValueError("Cannot build a BM25 index over zero Passages")
        self._ids = tuple(p.passage_id for p in passages)
        self._bm25 = BM25Okapi([tokenize(p.text) for p in passages])

    def search(self, query: str, k: int) -> list[ScoredId]:
        """Top-k Passages sharing at least one term with the query.

        Passages with score 0 matched no term; returning them would hand them
        an arbitrary rank that RRF then rewards.
        """
        scores = self._bm25.get_scores(tokenize(query))
        matched = [i for i in range(len(self._ids)) if scores[i] > 0]
        ranked = sorted(matched, key=lambda i: scores[i], reverse=True)
        return [ScoredId(self._ids[i], float(scores[i])) for i in ranked[:k]]
