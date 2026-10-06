import pytest

from attack_qa.faithfulness import (
    ClaimVerdict,
    CompletenessVerdict,
    Judgement,
    build_judge_message,
    judge_answer,
    summarize_judgements,
)
from attack_qa.passages import Passage, PassageKind


def _passage(pid: str, text: str) -> Passage:
    tid, kind = pid.split(":")
    return Passage(technique_id=tid, technique_name="Name", parent_id=None, parent_name=None,
                   kind=PassageKind(kind.capitalize()), text=text, url="", attack_version="19.2")


PASSAGES = {
    p.passage_id: p
    for p in (
        _passage("T1003.001:detection", "Watch for handles opened to lsass.exe."),
        _passage("T1003:detection", "Monitor processes reading LSASS memory."),
        _passage("T1059.001:detection", "Look for encoded PowerShell commands."),
    )
}


def _record(claims: list[dict], gold: str = "T1003.001:detection", **extra) -> dict:
    return {"id": "2-01", "category": "paraphrase", "question": "How to spot LSASS dumping?",
            "gold": gold, "status": "answered", "claims": claims, "gold_retrieved": True, **extra}


class FakeJudge:
    name = "fake/judge"

    def __init__(self, judgement: Judgement) -> None:
        self.judgement = judgement
        self.calls: list[tuple[str, str]] = []

    def judge(self, system: str, user: str) -> Judgement:
        self.calls.append((system, user))
        return self.judgement


def _judgement(*verdicts: tuple[int, str], completeness: str = "complete") -> Judgement:
    return Judgement(
        claims=[ClaimVerdict(index=i, verdict=v, reason="r") for i, v in verdicts],
        completeness=CompletenessVerdict(verdict=completeness, reason="c"),
    )


def test_message_shows_each_cited_passage_once_and_gold_separately():
    claims = [{"text": "A", "passage_ids": ["T1003.001:detection"]},
              {"text": "B", "passage_ids": ["T1003.001:detection", "T1003:detection"]}]
    message = build_judge_message(_record(claims), PASSAGES, judged=[0, 1])

    assert message.count("Watch for handles opened to lsass.exe.") == 2  # evidence + reference
    assert message.count("Monitor processes reading LSASS memory.") == 1
    evidence, reference = message.split("REFERENCE PASSAGE")
    assert "[1] B" in evidence and "cites: T1003.001:detection, T1003:detection" in evidence
    assert "T1059.001" not in message


def test_message_omits_claims_not_sent_to_the_judge():
    claims = [{"text": "kept", "passage_ids": ["T1003:detection"]},
              {"text": "skipped", "passage_ids": ["T9999:detection"]}]
    message = build_judge_message(_record(claims), PASSAGES, judged=[0])
    assert "kept" in message and "skipped" not in message


def test_judge_answer_combines_judge_and_rule_verdicts():
    claims = [{"text": "A", "passage_ids": ["T1003.001:detection"]},
              {"text": "B", "passage_ids": ["T9999:detection"]},
              {"text": "C", "passage_ids": []},
              {"text": "D", "passage_ids": ["T1003:detection"]}]
    judge = FakeJudge(_judgement((0, "supported"), (3, "partial"), completeness="partial"))

    result = judge_answer(_record(claims), PASSAGES, judge)

    assert [c.verdict for c in result.claims] == ["supported", "unsupported", "unsupported", "partial"]
    assert [c.judged_by for c in result.claims] == ["judge", "rule", "rule", "judge"]
    assert result.completeness == "partial"
    assert result.judge_model == "fake/judge"
    assert "B" not in judge.calls[0][1].split("CLAIMS")[1].split("REFERENCE")[0].replace("[", "")


def test_judge_answer_rejects_missing_or_extra_indexes():
    claims = [{"text": "A", "passage_ids": ["T1003.001:detection"]},
              {"text": "B", "passage_ids": ["T1003:detection"]}]
    with pytest.raises(ValueError, match="indexes"):
        judge_answer(_record(claims), PASSAGES, FakeJudge(_judgement((0, "supported"))))
    with pytest.raises(ValueError, match="indexes"):
        judge_answer(_record(claims), PASSAGES,
                     FakeJudge(_judgement((0, "supported"), (1, "supported"), (2, "partial"))))


def test_judge_answer_skips_the_judge_when_every_claim_fails_the_rule():
    judge = FakeJudge(_judgement())
    result = judge_answer(_record([{"text": "A", "passage_ids": ["T9999:detection"]}]),
                          PASSAGES, judge)
    assert [c.verdict for c in result.claims] == ["unsupported"]
    assert result.completeness == "not judged"
    assert judge.calls == []


def test_judge_answer_refuses_unanswered_records():
    with pytest.raises(ValueError, match="answered"):
        judge_answer(_record([], status="refused"), PASSAGES, FakeJudge(_judgement()))


def test_summary_splits_by_whether_gold_was_retrieved():
    judge = FakeJudge(_judgement((0, "supported"), (1, "unsupported")))
    claims = [{"text": "A", "passage_ids": ["T1003.001:detection"]},
              {"text": "B", "passage_ids": ["T1003:detection"]}]
    hit = judge_answer(_record(claims), PASSAGES, judge)
    miss = judge_answer(_record(claims, id="2-02", gold_retrieved=False), PASSAGES, judge)

    summary = {s.group: s for s in summarize_judgements([hit, miss])}

    assert summary["all"].claims == 4 and summary["all"].supported == 2
    assert summary["all"].supported_rate == pytest.approx(0.5)
    assert summary["gold retrieved"].answers == 1
    assert summary["gold not retrieved"].unsupported == 1
    assert summary["all"].completeness == {"complete": 2}
