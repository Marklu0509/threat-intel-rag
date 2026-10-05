"""Understand a question before retrieval (grill-decisions Q13, Q17, Q23).

1. Rewrite Revoked IDs to their replacements (Q17).
2. Find the Technique IDs the question names (Q23).
3. Guess the Question intent: Overview, Mitigation or Detection (Q13).
"""

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from attack_qa.passages import PassageKind

# T1059.001, t1059.001 and the URL-style T1059/001 all mean the same Technique
_TECHNIQUE_ID = re.compile(r"\b[Tt](\d{4})(?:[./](\d{3}))?\b")

# English cues need word boundaries ("log" must not fire on "login"); Chinese cues are substrings.
_INTENT_CUES: Mapping[PassageKind, tuple[str, ...]] = MappingProxyType({
    PassageKind.DETECTION: (
        r"\bdetect\w*", r"\bmonitor\w*", r"\bspot\w*", r"\bnotice\b", r"\btell if\b",
        r"\bhunt\w*", r"\balert\w*", "偵測", "監控", "察覺", "發現", "檢測",
    ),
    PassageKind.MITIGATION: (
        r"\bmitigat\w*", r"\bprevent\w*", r"\bprotect\w*", r"\bstop\b", r"\bdefend\w*",
        r"\bblock\w*", r"\bharden\w*", r"\blimit the damage\b",
        "緩解", "預防", "防止", "防禦", "怎麼防", "降低損害", "阻擋",
    ),
    PassageKind.OVERVIEW: (
        r"\bwhat is\b", r"\bwhat does\b", r"\bwhat'?s\b", r"\bexplain\w*", r"\bdescribe\w*",
        r"\bcalled\b", r"\bmean\b", "是什麼", "什麼是", "什麼手法", "什麼技巧", "介紹",
    ),
})


@dataclass(frozen=True)
class QueryPlan:
    original: str
    search_text: str  # the question with Revoked IDs replaced; what retrieval sees
    technique_ids: tuple[str, ...]  # live IDs the question names, in order of appearance
    intent: PassageKind | None
    substitutions: Mapping[str, str]  # Revoked ID -> replacement, for the answer to mention


def _normalise(match: re.Match[str]) -> str:
    base, sub = match.groups()
    return f"T{base}.{sub}" if sub else f"T{base}"


def find_technique_ids(text: str) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for match in _TECHNIQUE_ID.finditer(text):
        seen.setdefault(_normalise(match), None)
    return tuple(seen)


def detect_intent(question: str) -> PassageKind | None:
    """The single Passage kind the question asks for, or None if none or several match."""
    lowered = question.lower()
    matched = [
        kind
        for kind, cues in _INTENT_CUES.items()
        if any(re.search(cue, lowered) for cue in cues)
    ]
    return matched[0] if len(matched) == 1 else None


def plan_query(question: str, revoked: Mapping[str, str]) -> QueryPlan:
    if not question.strip():
        raise ValueError("Question is empty")
    substitutions = {tid: revoked[tid] for tid in find_technique_ids(question) if tid in revoked}
    search_text = _TECHNIQUE_ID.sub(
        lambda m: substitutions.get(_normalise(m), m.group(0)), question
    )
    return QueryPlan(
        original=question,
        search_text=search_text,
        technique_ids=find_technique_ids(search_text),
        intent=detect_intent(question),
        substitutions=MappingProxyType(substitutions),
    )
