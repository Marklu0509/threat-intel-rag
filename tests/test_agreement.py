import pytest

from attack_qa.agreement import (
    SheetItem,
    agreement_report,
    parse_sheet,
    render_sheet,
    sample_claims,
)
from attack_qa.faithfulness import AnswerJudgement, ClaimJudgement


def _answer(qid: str, verdicts: list[str]) -> AnswerJudgement:
    return AnswerJudgement(
        id=qid, category="paraphrase", question=f"question {qid}", gold="T1003:detection",
        gold_retrieved=True, judge_model="fake",
        claims=tuple(ClaimJudgement(text=f"{qid} claim {i}", passage_ids=("T1003:detection",),
                                    verdict=v, reason="r", judged_by="judge")
                     for i, v in enumerate(verdicts)),
        completeness="complete", completeness_reason="c",
    )


ANSWERS = [_answer(f"q{n}", ["supported"] * 4 + (["partial"] if n % 3 == 0 else []))
           for n in range(10)]


def test_sample_keeps_every_flagged_claim_and_fills_with_supported():
    sample = sample_claims(ANSWERS, size=12, seed=1)
    flagged = [(a.id, i) for a in ANSWERS for i, c in enumerate(a.claims) if c.verdict != "supported"]

    assert len(sample) == 12
    assert set(flagged) <= {(s.answer_id, s.claim_index) for s in sample}
    assert len({(s.answer_id, s.claim_index) for s in sample}) == 12


def test_sample_is_reproducible_and_shuffled():
    first = sample_claims(ANSWERS, size=12, seed=1)
    assert first == sample_claims(ANSWERS, size=12, seed=1)
    assert [s.item_id for s in first] == [f"C{n:02d}" for n in range(1, 13)]
    flagged_positions = [i for i, s in enumerate(first) if s.answer_id in {"q0", "q3", "q6", "q9"}
                         and s.claim_index == 4]
    assert flagged_positions != list(range(len(flagged_positions)))  # not all at the top


def test_sample_never_exceeds_available_claims():
    assert len(sample_claims(ANSWERS[:1], size=40, seed=1)) == 5  # q0 has 4 supported + 1 partial


def test_rendered_sheet_hides_judge_verdicts_and_parses_back():
    sample = sample_claims(ANSWERS, size=5, seed=2)
    texts = {"T1003:detection": "LSASS evidence text"}
    sheet = render_sheet(sample, ANSWERS, texts)

    assert "LSASS evidence text" in sheet
    assert "partial" not in sheet.split("---", 1)[1].replace("supported / partial / unsupported", "")
    filled = sheet.replace("**Your verdict**: \n", "**Your verdict**: supported\n", 1)
    assert parse_sheet(filled) == {sample[0].item_id: "supported"}


def test_parse_sheet_rejects_unknown_labels():
    with pytest.raises(ValueError, match="C01"):
        parse_sheet("## C01\n**Your verdict**: maybe\n")


def test_agreement_report_uses_linear_weighted_kappa():
    sample = [SheetItem(f"C{n:02d}", "q0", n) for n in range(1, 5)]
    judge = {"C01": "supported", "C02": "partial", "C03": "unsupported", "C04": "supported"}
    human = {"C01": "supported", "C02": "partial", "C03": "unsupported", "C04": "partial"}

    report = agreement_report(sample, judge, human)

    assert report.n == 4
    assert report.raw_agreement == pytest.approx(0.75)
    assert report.weighted_kappa == pytest.approx(0.714, abs=0.001)
    assert report.disagreements == (("C04", "supported", "partial"),)


def test_agreement_report_requires_every_item_labelled():
    sample = [SheetItem("C01", "q0", 0), SheetItem("C02", "q0", 1)]
    with pytest.raises(ValueError, match="C02"):
        agreement_report(sample, {"C01": "supported", "C02": "supported"}, {"C01": "supported"})
