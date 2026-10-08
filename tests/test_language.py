import pytest

from attack_qa.language import (
    ENGLISH, TRADITIONAL_CHINESE, answer_language, in_language, language_report,
)


@pytest.mark.parametrize(("question", "language"), [
    ("What is T1059.003?", ENGLISH),
    ("T1218.005 mitigations", ENGLISH),           # short ID questions drifted to Chinese before
    ("T1059", ENGLISH),
    ("怎麼偵測 T1059.001？", TRADITIONAL_CHINESE),
    ("如何检测 PowerShell 滥用？", TRADITIONAL_CHINESE),  # asked in Simplified, answered in Traditional
    ("How do I detect 憑證竊取?", TRADITIONAL_CHINESE),   # any Chinese makes it a Chinese question
])
def test_answer_language_is_decided_by_code(question: str, language: str) -> None:
    assert answer_language(question) == language


@pytest.mark.parametrize(("text", "language", "expected"), [
    ("Monitor encoded PowerShell commands.", ENGLISH, True),
    ("監控經過編碼的 PowerShell 命令。", ENGLISH, False),
    ("監控經過編碼的 PowerShell 命令。", TRADITIONAL_CHINESE, True),
    ("限制软件安装，特权账户管理。", TRADITIONAL_CHINESE, False),  # Simplified (from run 4-02)
    ("Monitor encoded PowerShell commands.", TRADITIONAL_CHINESE, False),
])
def test_in_language(text: str, language: str, expected: bool) -> None:
    assert in_language(text, language) is expected


def _record(qid: str, question: str, claims: list[str], refusal: str = "") -> dict:
    return {"id": qid, "question": question, "refusal_reason": refusal,
            "claims": [{"text": t, "passage_ids": ["p"]} for t in claims]}


def test_language_report_counts_answers_and_refusal_reasons() -> None:
    report = language_report([
        _record("1", "What is T1059.003?", ["T1059.003 is Windows Command Shell."]),
        _record("2", "What is T1055.003?", ["T1055.003 是執行緒執行劫持。"]),        # wrong language
        _record("3", "Emotet 使用了哪些技巧？", [], refusal="提供的参考段落中未包含关于 Emotet 的信息。"),
        _record("4", "怎麼偵測 LSASS？", ["偵測存取 LSASS 記憶體的程序。"]),
        _record("5", "bake bread", [], refusal=""),                                     # nothing to check
    ])
    assert (report.checked, report.matched) == (4, 2)
    assert report.mismatched == ("2", "3")
