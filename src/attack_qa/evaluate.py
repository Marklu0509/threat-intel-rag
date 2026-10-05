"""Score retrieval against the evaluation set (grill-decisions Q9, Q10, Q14)."""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import mean

from attack_qa.retrieval import Retrieved

KS = (1, 3, 5, 10)
ANSWER, REFUSE = "answer", "refuse"


@dataclass(frozen=True)
class EvalQuestion:
    id: str
    category: str
    question: str
    expected: str
    gold_technique: str | None = None
    gold_kind: str | None = None  # "overview" | "mitigation" | "detection"
    revoked_id: str | None = None

    @property
    def gold_passage_id(self) -> str | None:
        if self.gold_technique is None or self.gold_kind is None:
            return None
        return f"{self.gold_technique}:{self.gold_kind}"


def load_questions(path: Path) -> tuple[EvalQuestion, ...]:
    questions = []
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            raw = json.loads(line)
            q = EvalQuestion(
                id=raw["id"],
                category=raw["category"],
                question=raw["question"],
                expected=raw["expected"],
                gold_technique=raw.get("gold_technique"),
                gold_kind=raw.get("gold_kind"),
                revoked_id=raw.get("revoked_id"),
            )
            if q.expected not in (ANSWER, REFUSE):
                raise ValueError(f"{path}:{line_no} expected must be answer or refuse")
            if q.expected == ANSWER and q.gold_passage_id is None:
                raise ValueError(f"{path}:{line_no} answerable question {q.id} has no gold")
            questions.append(q)
    return tuple(questions)


def first_rank(items: Sequence[str], target: str) -> int | None:
    """1-based position of target in items, or None when it is absent."""
    for rank, item in enumerate(items, start=1):
        if item == target:
            return rank
    return None


@dataclass(frozen=True)
class QuestionResult:
    question: EvalQuestion
    retrieved: tuple[str, ...]  # passage IDs, best first
    passage_rank: int | None
    technique_rank: int | None
    top_cosine: float | None


def score_question(q: EvalQuestion, results: Sequence[Retrieved]) -> QuestionResult:
    passage_ids = tuple(r.passage.passage_id for r in results)
    technique_ids = [r.passage.technique_id for r in results]
    cosines = [r.dense_cosine for r in results if r.dense_cosine is not None]
    return QuestionResult(
        question=q,
        retrieved=passage_ids,
        passage_rank=first_rank(passage_ids, q.gold_passage_id) if q.gold_passage_id else None,
        technique_rank=first_rank(technique_ids, q.gold_technique) if q.gold_technique else None,
        top_cosine=max(cosines) if cosines else None,
    )


def _hit_rate(ranks: Sequence[int | None], k: int) -> float:
    return sum(1 for r in ranks if r is not None and r <= k) / len(ranks)


def _mrr(ranks: Sequence[int | None]) -> float:
    return mean(1 / r if r else 0.0 for r in ranks)


@dataclass(frozen=True)
class CategoryReport:
    category: str
    n: int
    passage_hit: dict[int, float] | None  # k -> rate; None for refuse categories
    technique_hit_at_5: float | None
    mrr: float | None
    mean_top_cosine: float | None


def summarize(category: str, results: Sequence[QuestionResult]) -> CategoryReport:
    if not results:
        raise ValueError(f"No results for category {category!r}")
    cosines = [r.top_cosine for r in results if r.top_cosine is not None]
    mean_cos = mean(cosines) if cosines else None
    if results[0].question.expected == REFUSE:
        return CategoryReport(category, len(results), None, None, None, mean_cos)
    p_ranks = [r.passage_rank for r in results]
    t_ranks = [r.technique_rank for r in results]
    return CategoryReport(
        category=category,
        n=len(results),
        passage_hit={k: _hit_rate(p_ranks, k) for k in KS},
        technique_hit_at_5=_hit_rate(t_ranks, 5),
        mrr=_mrr(p_ranks),
        mean_top_cosine=mean_cos,
    )
