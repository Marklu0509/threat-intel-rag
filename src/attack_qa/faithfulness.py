"""Judge whether each Claim is supported by the Passages it cites (grill-decisions Q32–Q35).

One judge call per answer. The judge sees the question, the Claims, the Passages those Claims
cite, and the Gold passage — the last only for rating completeness. A Claim citing nothing, or
a Passage that doesn't exist, is unsupported by rule and never sent to the judge.
"""

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from pydantic import BaseModel

from attack_qa.passages import Passage

SUPPORTED, PARTIAL, UNSUPPORTED = "supported", "partial", "unsupported"
LEVELS = (SUPPORTED, PARTIAL, UNSUPPORTED)  # ordered: weighted kappa relies on this order
NOT_JUDGED = "not judged"

Verdict = Literal["supported", "partial", "unsupported"]
Completeness = Literal["complete", "partial", "incomplete"]


class ClaimVerdict(BaseModel):
    index: int
    verdict: Verdict
    reason: str


class CompletenessVerdict(BaseModel):
    verdict: Completeness
    reason: str


class Judgement(BaseModel):
    claims: list[ClaimVerdict]
    completeness: CompletenessVerdict


class JudgeModel(Protocol):
    name: str

    def judge(self, system: str, user: str) -> Judgement: ...


JUDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "reason": {"type": "string"},
                    "verdict": {"type": "string", "enum": list(LEVELS)},
                },
                "required": ["index", "reason", "verdict"],
                "additionalProperties": False,
            },
        },
        "completeness": {
            "type": "object",
            "properties": {
                "reason": {"type": "string"},
                "verdict": {"type": "string", "enum": ["complete", "partial", "incomplete"]},
            },
            "required": ["reason", "verdict"],
            "additionalProperties": False,
        },
    },
    "required": ["claims", "completeness"],
    "additionalProperties": False,
}

# Edge cases decided in grill-decisions Q36.
RUBRIC = """\
Verdicts:
- "supported": everything the claim asserts is in its cited passages. Allowed: rewording
  with the same meaning; summarising or generalising what the passages say (e.g. calling
  the methods they list "the main ways"); technique names and IDs from a passage heading.
- "partial": the claim's main point is in its cited passages, but it adds or changes a
  detail they don't support — a new fact, tool, step or number, or a stronger certainty
  than the passage expresses ("may indicate" stated as "indicates").
- "unsupported": the claim's main point is not in its cited passages, even if some words
  overlap, or the passages contradict it.
"""

JUDGE_SYSTEM = f"""\
You check answers produced by a question-answering system over MITRE ATT&CK.

Task 1 — faithfulness. For every numbered claim, decide whether the EVIDENCE passages it
cites support it. Judge only against the passages that claim cites; ignore your own
knowledge of ATT&CK, and ignore the REFERENCE PASSAGE. A claim can be true and still be
unsupported if its cited passages do not say it.

{RUBRIC}
Task 2 — completeness. Compare the whole answer with the REFERENCE PASSAGE: does it cover
what the reference says in answer to the question? "complete" = all the main points,
"partial" = some, "incomplete" = few or none. Faithfulness and completeness are separate:
an answer can be fully faithful and incomplete.

Write the reason before the verdict, in one or two sentences, quoting the words that decide it.
Return one entry per numbered claim, using the claim's number as its index.
"""


@dataclass(frozen=True)
class ClaimJudgement:
    text: str
    passage_ids: tuple[str, ...]
    verdict: str
    reason: str
    judged_by: str  # "judge" or "rule"


@dataclass(frozen=True)
class AnswerJudgement:
    id: str
    category: str
    question: str
    gold: str
    gold_retrieved: bool
    judge_model: str
    claims: tuple[ClaimJudgement, ...]
    completeness: str
    completeness_reason: str


def _citations_exist(claim: Mapping[str, Any], passages: Mapping[str, Passage]) -> bool:
    ids = claim["passage_ids"]
    return bool(ids) and all(pid in passages for pid in ids)


def build_judge_message(record: Mapping[str, Any], passages: Mapping[str, Passage],
                        judged: Sequence[int]) -> str:
    """The judge's input: claims `judged` (by index), their cited passages, and the gold passage."""
    claims = record["claims"]
    cited = list(dict.fromkeys(pid for i in judged for pid in claims[i]["passage_ids"]))
    evidence = "\n\n".join(f"<passage id=\"{pid}\">\n{passages[pid].text}\n</passage>"
                           for pid in cited)
    numbered = "\n".join(f"[{i}] {claims[i]['text']}\n    cites: {', '.join(claims[i]['passage_ids'])}"
                         for i in judged)
    gold = passages.get(record["gold"])
    reference = gold.text if gold else "(no reference passage)"
    return (f"QUESTION\n{record['question']}\n\nEVIDENCE PASSAGES\n{evidence}\n\n"
            f"CLAIMS\n{numbered}\n\nREFERENCE PASSAGE (completeness only)\n{reference}\n")


def judge_answer(record: Mapping[str, Any], passages: Mapping[str, Passage],
                 judge: JudgeModel) -> AnswerJudgement:
    if record["status"] != "answered":
        raise ValueError(f"{record['id']}: only answered records can be judged")
    claims = record["claims"]
    judged = [i for i, c in enumerate(claims) if _citations_exist(c, passages)]
    verdicts: dict[int, ClaimVerdict] = {}
    completeness = CompletenessVerdict(verdict="incomplete", reason="")
    completeness_label = NOT_JUDGED
    if judged:
        result = judge.judge(JUDGE_SYSTEM, build_judge_message(record, passages, judged))
        verdicts = {v.index: v for v in result.claims}
        if sorted(verdicts) != judged or len(result.claims) != len(judged):
            raise ValueError(f"{record['id']}: judge returned indexes {sorted(verdicts)}, "
                             f"expected {judged}")
        completeness, completeness_label = result.completeness, result.completeness.verdict

    def one(i: int, claim: Mapping[str, Any]) -> ClaimJudgement:
        ids = tuple(claim["passage_ids"])
        if i in verdicts:
            return ClaimJudgement(claim["text"], ids, verdicts[i].verdict, verdicts[i].reason, "judge")
        return ClaimJudgement(claim["text"], ids, UNSUPPORTED,
                              "cites no passage, or a passage that does not exist", "rule")

    return AnswerJudgement(
        id=record["id"], category=record["category"], question=record["question"],
        gold=record["gold"], gold_retrieved=bool(record.get("gold_retrieved")),
        judge_model=judge.name, claims=tuple(one(i, c) for i, c in enumerate(claims)),
        completeness=completeness_label, completeness_reason=completeness.reason,
    )


@dataclass(frozen=True)
class FaithfulnessSummary:
    group: str
    answers: int
    claims: int
    supported: int
    partial: int
    unsupported: int
    completeness: dict[str, int]

    @property
    def supported_rate(self) -> float:
        return self.supported / self.claims if self.claims else 0.0


def _summary(group: str, answers: Sequence[AnswerJudgement]) -> FaithfulnessSummary:
    verdicts = Counter(c.verdict for a in answers for c in a.claims)
    return FaithfulnessSummary(
        group=group, answers=len(answers), claims=sum(verdicts.values()),
        supported=verdicts[SUPPORTED], partial=verdicts[PARTIAL], unsupported=verdicts[UNSUPPORTED],
        completeness=dict(Counter(a.completeness for a in answers)),
    )


def summarize_judgements(answers: Iterable[AnswerJudgement]) -> list[FaithfulnessSummary]:
    answers = list(answers)
    return [
        _summary("all", answers),
        _summary("gold retrieved", [a for a in answers if a.gold_retrieved]),
        _summary("gold not retrieved", [a for a in answers if not a.gold_retrieved]),
    ]
