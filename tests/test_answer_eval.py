import pytest

from attack_qa.answer import Answer, VerifiedClaim
from attack_qa.answer_eval import AnswerResult, summarize_records, to_record
from attack_qa.evaluate import EvalQuestion

GOLD_Q = EvalQuestion("4-01", "near_id", "How do I detect T1543.001?", "answer",
                      "T1543.001", "detection")
REFUSE_Q = EvalQuestion("6-01", "unsupported", "Which techniques does APT29 use?", "refuse")


def _answered(*cited: str, retrieved: tuple[str, ...] = ("T1543.001:detection",)) -> Answer:
    return Answer("answered", (VerifiedClaim("x", cited),), "", None, {}, retrieved)


def _refused(by: str) -> Answer:
    return Answer("refused", (), "no", by, {}, ())  # type: ignore[arg-type]


def test_citing_the_gold_passage() -> None:
    result = AnswerResult(GOLD_Q, _answered("T1543.001:detection"), "m")
    assert result.answered and result.cites_gold_passage and result.cites_gold_technique


def test_citing_the_right_technique_but_wrong_kind() -> None:
    result = AnswerResult(GOLD_Q, _answered("T1543.001:overview"), "m")
    assert result.cites_gold_technique and not result.cites_gold_passage


def test_summary_for_answerable_questions() -> None:
    results = [
        AnswerResult(GOLD_Q, _answered("T1543.001:detection"), "m"),
        AnswerResult(GOLD_Q, _answered("T1543.003:detection", retrieved=()), "m"),
        AnswerResult(GOLD_Q, _refused("llm"), "m"),
        AnswerResult(GOLD_Q, None, "m", error="503"),
    ]
    report = summarize_records("near_id", [to_record(r) for r in results])
    assert (report.answered, report.refused, report.errors) == (2, 1, 1)
    assert report.cites_gold_passage == 1
    assert report.gold_retrieved == 1
    assert report.refused_by == {"llm": 1}


def test_summary_for_refuse_questions_counts_gates() -> None:
    results = [
        AnswerResult(REFUSE_Q, _refused("llm"), "m"),
        AnswerResult(REFUSE_Q, _refused("relevance"), "m"),
        AnswerResult(REFUSE_Q, _answered("T1059:overview"), "m"),
    ]
    report = summarize_records("unsupported", [to_record(r) for r in results])
    assert (report.refused, report.answered) == (2, 1)
    assert report.refused_by == {"llm": 1, "relevance": 1}
    assert report.cites_gold_passage == 0


def test_empty_category_is_an_error() -> None:
    with pytest.raises(ValueError):
        summarize_records("x", [])


def test_record_round_trips_through_json() -> None:
    import json
    record = to_record(AnswerResult(GOLD_Q, _answered("T1543.001:detection"), "m"))
    assert json.loads(json.dumps(record)) == record
    assert record["retrieved"] == ["T1543.001:detection"]


def test_error_text_hides_account_ids_and_is_truncated() -> None:
    from attack_qa.answer_eval import error_text
    exc = RuntimeError("Rate limit reached in organization `org_0000fakeorgid0000test` " + "x" * 400)
    text = error_text(exc)
    assert "org_0000fake" not in text and "org_REDACTED" in text
    assert text.startswith("RuntimeError: ") and len(text) <= 300
