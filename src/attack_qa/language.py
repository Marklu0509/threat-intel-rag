"""Which language an answer is written in, decided by code rather than by the model.

Left to infer it from the question, the model answered 6 of 56 English questions in Chinese,
mostly short ID questions such as "What is T1059.003?", and one of them in Simplified Chinese.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

ENGLISH = "English"
TRADITIONAL_CHINESE = "Traditional Chinese (Taiwan)"

_HAN = re.compile(r"[㐀-鿿豈-﫿]")

# Characters written only in Simplified Chinese; each Traditional form differs (这 vs 這).
# Not exhaustive: enough to catch Simplified text in answers about security, where these are
# common. Characters shared by both scripts (于, 据, 机, 并) are left out.
_SIMPLIFIED_ONLY = frozenset(
    "这们说时为会对进过发动务检测记忆录权级应关开问题击个来国学数库网络执获隐资险证让设备护规则"
    "统计复杂类别输术径链载项码签读写间认识确实环节扩浏览缓删储压缩档盘终视频报现见观觉单钥书伪"
    "装织侦拦门脚线鉴访运营监审账凭转侧户该还从样无层将属与仅软处恶内启态请败尝试点"
)


def answer_language(question: str) -> str:
    """Any Chinese character makes it a Chinese question; Chinese answers are Traditional."""
    return TRADITIONAL_CHINESE if _HAN.search(question) else ENGLISH


def in_language(text: str, language: str) -> bool:
    has_chinese = bool(_HAN.search(text))
    if language == ENGLISH:
        return not has_chinese
    return has_chinese and not any(ch in _SIMPLIFIED_ONLY for ch in text)


@dataclass(frozen=True)
class LanguageReport:
    checked: int
    matched: int
    mismatched: tuple[str, ...]  # question IDs


def language_report(records: Sequence[Mapping[str, Any]]) -> LanguageReport:
    """Answers (or refusal reasons) written in the language their question asked for."""
    mismatched: list[str] = []
    checked = 0
    for r in records:
        text = " ".join(c["text"] for c in r["claims"]) or r.get("refusal_reason") or ""
        if not text:
            continue  # refused before the model was called: no model text to check
        checked += 1
        if not in_language(text, answer_language(r["question"])):
            mismatched.append(r["id"])
    return LanguageReport(checked, checked - len(mismatched), tuple(mismatched))
