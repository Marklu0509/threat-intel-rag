"""Check the faithfulness judge against a human (grill-decisions Q34).

A stratified sample — every Claim the judge flagged, topped up with randomly chosen supported
ones — goes into a Markdown sheet that hides the judge's verdicts. The filled sheet is scored
with linear-weighted Cohen's kappa, since the three levels are ordered.
"""

import random
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from sklearn.metrics import cohen_kappa_score

from attack_qa.faithfulness import RUBRIC, LEVELS, SUPPORTED, AnswerJudgement

_ITEM = re.compile(r"^## (C\d+)\s*$")
_VERDICT = re.compile(r"^\*\*Your verdict\*\*:[ \t]*(\S*)")


@dataclass(frozen=True)
class SheetItem:
    item_id: str
    answer_id: str
    claim_index: int


def sample_claims(answers: Sequence[AnswerJudgement], size: int, seed: int) -> list[SheetItem]:
    """All judge-flagged Claims plus random supported ones up to `size`, in shuffled order."""
    refs = [(a.id, i, c.verdict) for a in answers for i, c in enumerate(a.claims)
            if c.judged_by == "judge"]
    flagged = [(a, i) for a, i, v in refs if v != SUPPORTED]
    supported = [(a, i) for a, i, v in refs if v == SUPPORTED]
    rng = random.Random(seed)
    chosen = flagged + rng.sample(supported, max(0, min(len(supported), size - len(flagged))))
    rng.shuffle(chosen)  # so flagged Claims don't cluster where the labeller might notice
    return [SheetItem(f"C{n:02d}", a, i) for n, (a, i) in enumerate(chosen, start=1)]


def render_sheet(sample: Sequence[SheetItem], answers: Sequence[AnswerJudgement],
                 passage_texts: Mapping[str, str]) -> str:
    by_id = {a.id: a for a in answers}
    parts = [
        "# Faithfulness labelling sheet\n\n"
        "For each claim, decide whether the cited passages support it — using only those "
        "passages, not your own knowledge. Write one of `supported / partial / unsupported` "
        "after **Your verdict**. Do not open the judge's results until you have finished.\n\n"
        "The judge's rubric, which applies to you too (grill-decisions Q36):\n\n"
        f"```text\n{RUBRIC}```\n\n---\n"
    ]
    for item in sample:
        answer = by_id[item.answer_id]
        claim = answer.claims[item.claim_index]
        evidence = "\n\n".join(f"**[{pid}]**\n\n" + passage_texts.get(pid, "(missing)")
                               for pid in claim.passage_ids)
        parts.append(f"\n## {item.item_id}\n\n**Question**: {answer.question}\n\n"
                     f"**Claim**: {claim.text}\n\n{evidence}\n\n**Your verdict**: \n")
    return "".join(parts)


def parse_sheet(text: str) -> dict[str, str]:
    """Verdicts filled in so far, keyed by item id; blank verdicts are skipped."""
    labels: dict[str, str] = {}
    current = None
    for line in text.splitlines():
        if m := _ITEM.match(line):
            current = m.group(1)
        elif (m := _VERDICT.match(line)) and current and m.group(1):
            label = m.group(1).strip("`").lower()
            if label not in LEVELS:
                raise ValueError(f"{current}: {label!r} is not one of {LEVELS}")
            labels[current] = label
    return labels


@dataclass(frozen=True)
class AgreementReport:
    n: int
    raw_agreement: float
    weighted_kappa: float
    disagreements: tuple[tuple[str, str, str], ...]  # (item, judge, human)


def agreement_report(sample: Sequence[SheetItem], judge: Mapping[str, str],
                     human: Mapping[str, str]) -> AgreementReport:
    missing = [s.item_id for s in sample if s.item_id not in human]
    if missing:
        raise ValueError(f"no human verdict for {', '.join(missing)}")
    ids = [s.item_id for s in sample]
    j, h = [judge[i] for i in ids], [human[i] for i in ids]
    return AgreementReport(
        n=len(ids),
        raw_agreement=sum(a == b for a, b in zip(j, h)) / len(ids),
        weighted_kappa=float(cohen_kappa_score(j, h, labels=list(LEVELS), weights="linear")),
        disagreements=tuple((i, a, b) for i, a, b in zip(ids, j, h) if a != b),
    )
