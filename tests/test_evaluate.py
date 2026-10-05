import json
from pathlib import Path

import pytest

from attack_qa.evaluate import (
    EvalQuestion,
    first_rank,
    load_questions,
    score_question,
    summarize,
)
from attack_qa.passages import Passage, PassageKind
from attack_qa.retrieval import Retrieved


def _hit(tid: str, kind: PassageKind, rank: int, cosine: float | None = 0.5) -> Retrieved:
    return Retrieved(Passage(tid, tid, None, None, kind, "", "", "19.2"), rank, cosine)


GOLD = EvalQuestion("2-01", "paraphrase", "q", "answer", "T1003.001", "detection")


def test_first_rank_is_one_based() -> None:
    assert first_rank(["a", "b", "c"], "b") == 2
    assert first_rank(["a"], "z") is None


def test_passage_hit_needs_the_right_kind_too() -> None:
    result = score_question(GOLD, [
        _hit("T1003.001", PassageKind.OVERVIEW, 1),
        _hit("T1003.001", PassageKind.DETECTION, 2),
    ])
    assert result.technique_rank == 1
    assert result.passage_rank == 2


def test_wrong_kind_counts_as_technique_hit_only() -> None:
    result = score_question(GOLD, [_hit("T1003.001", PassageKind.OVERVIEW, 1)])
    assert (result.technique_rank, result.passage_rank) == (1, None)


def test_top_cosine_ignores_passages_dense_did_not_return() -> None:
    result = score_question(GOLD, [
        _hit("T1", PassageKind.OVERVIEW, 1, None),
        _hit("T2", PassageKind.OVERVIEW, 2, 0.7),
    ])
    assert result.top_cosine == 0.7


def test_summary_rates_and_mrr() -> None:
    results = [
        score_question(GOLD, [_hit("T1003.001", PassageKind.DETECTION, 1)]),  # rank 1
        score_question(GOLD, [_hit("X", PassageKind.DETECTION, 1),
                              _hit("Y", PassageKind.DETECTION, 2),
                              _hit("T1003.001", PassageKind.DETECTION, 3)]),  # rank 3
        score_question(GOLD, [_hit("X", PassageKind.DETECTION, 1)]),  # missed
    ]
    report = summarize("paraphrase", results)
    assert report.passage_hit[1] == pytest.approx(1 / 3)
    assert report.passage_hit[3] == pytest.approx(2 / 3)
    assert report.mrr == pytest.approx((1 + 1 / 3 + 0) / 3)


def test_refuse_category_reports_only_cosine() -> None:
    q = EvalQuestion("7-01", "unanswerable", "weather?", "refuse")
    report = summarize("unanswerable", [score_question(q, [_hit("T1", PassageKind.OVERVIEW, 1, 0.3)])])
    assert report.passage_hit is None
    assert report.mean_top_cosine == pytest.approx(0.3)


def test_load_rejects_answerable_question_without_gold(tmp_path: Path) -> None:
    path = tmp_path / "eval.jsonl"
    path.write_text(json.dumps({"id": "x", "category": "c", "question": "q", "expected": "answer"}))
    with pytest.raises(ValueError, match="no gold"):
        load_questions(path)


def test_load_reads_the_real_evaluation_set() -> None:
    questions = load_questions(Path(__file__).parents[1] / "eval" / "handwritten.jsonl")
    assert len(questions) == 78
    assert sum(q.expected == "refuse" for q in questions) == 25
