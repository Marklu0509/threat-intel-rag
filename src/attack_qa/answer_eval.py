"""Score generated answers against the evaluation set.

Answerable questions: was it answered at all (false refusals), and does the answer cite
the gold Passage (or at least the gold Technique)? Questions that should be refused:
was it refused, and by which gate?
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from attack_qa.answer import Answer
from attack_qa.evaluate import ANSWER, EvalQuestion


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


def summarize_answers(category: str, results: Sequence[AnswerResult]) -> AnswerReport:
    if not results:
        raise ValueError(f"No results for category {category!r}")
    refusals = Counter(r.answer.refused_by for r in results
                       if r.answer is not None and r.answer.status == "refused")
    errors = sum(r.answer is None for r in results)
    expected_answer = results[0].question.expected == ANSWER
    return AnswerReport(
        category=category,
        n=len(results),
        answered=sum(r.answered for r in results),
        refused=sum(refusals.values()),
        errors=errors,
        cites_gold_passage=sum(r.cites_gold_passage for r in results) if expected_answer else 0,
        cites_gold_technique=sum(r.cites_gold_technique for r in results) if expected_answer else 0,
        gold_retrieved=sum(r.gold_was_retrieved for r in results) if expected_answer else 0,
        refused_by={str(k): v for k, v in sorted(refusals.items(), key=lambda kv: str(kv[0]))},
    )
