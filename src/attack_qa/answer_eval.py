"""Score generated answers against the evaluation set.

Answerable questions: was it answered at all (false refusals), and does the answer cite
the gold Passage (or at least the gold Technique)? Questions that should be refused:
was it refused, and by which gate?
"""

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from attack_qa.answer import Answer
from attack_qa.evaluate import ANSWER, EvalQuestion


_ACCOUNT_ID = re.compile(r"org_[A-Za-z0-9]{10,}")


def error_text(exc: Exception) -> str:
    """An error for the results file: provider account IDs hidden, at most 300 characters."""
    return _ACCOUNT_ID.sub("org_REDACTED", f"{type(exc).__name__}: {exc}")[:300]


@dataclass(frozen=True)
class AnswerResult:
    question: EvalQuestion
    answer: Answer | None  # None when the LLM call failed outright
    model_used: str
    error: str = ""

    @property
    def cited(self) -> tuple[str, ...]:
        if self.answer is None:
            return ()
        return tuple(dict.fromkeys(pid for c in self.answer.claims for pid in c.passage_ids))

    @property
    def answered(self) -> bool:
        return self.answer is not None and self.answer.status == "answered"

    @property
    def cites_gold_passage(self) -> bool:
        return self.question.gold_passage_id in self.cited

    @property
    def cites_gold_technique(self) -> bool:
        gold = self.question.gold_technique
        return gold is not None and any(pid.split(":")[0] == gold for pid in self.cited)

    @property
    def gold_was_retrieved(self) -> bool:
        return self.answer is not None and self.question.gold_passage_id in self.answer.retrieved


def to_record(r: AnswerResult) -> dict[str, Any]:
    """One evaluated question as plain JSON; the unit saved, resumed and summarized."""
    a = r.answer
    return {
        "id": r.question.id, "category": r.question.category, "question": r.question.question,
        "expected": r.question.expected, "gold": r.question.gold_passage_id,
        "model": r.model_used, "error": r.error,
        "status": a.status if a else "error", "refused_by": a.refused_by if a else None,
        "refusal_reason": a.refusal_reason if a else "",
        "claims": [{"text": c.text, "passage_ids": list(c.passage_ids)} for c in a.claims] if a else [],
        "retrieved": list(a.retrieved) if a else [],
        "dropped_claims": a.dropped_claims if a else 0,
        "cites_gold_passage": r.cites_gold_passage, "cites_gold_technique": r.cites_gold_technique,
        "gold_retrieved": r.gold_was_retrieved,
    }


@dataclass(frozen=True)
class AnswerReport:
    category: str
    n: int
    answered: int
    refused: int
    errors: int
    cites_gold_passage: int = 0
    cites_gold_technique: int = 0
    gold_retrieved: int = 0
    refused_by: dict[str, int] = field(default_factory=dict)


def summarize_records(category: str, records: Sequence[Mapping[str, Any]]) -> AnswerReport:
    if not records:
        raise ValueError(f"No results for category {category!r}")
    refusals = Counter(str(r["refused_by"]) for r in records if r["status"] == "refused")
    expected_answer = records[0]["expected"] == ANSWER

    def count(key: str) -> int:
        return sum(bool(r[key]) for r in records) if expected_answer else 0

    return AnswerReport(
        category=category,
        n=len(records),
        answered=sum(r["status"] == "answered" for r in records),
        refused=sum(refusals.values()),
        errors=sum(r["status"] == "error" for r in records),
        cites_gold_passage=count("cites_gold_passage"),
        cites_gold_technique=count("cites_gold_technique"),
        gold_retrieved=count("gold_retrieved"),
        refused_by=dict(sorted(refusals.items())),
    )
