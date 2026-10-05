"""Generate an answer for every evaluation question and score the answers.

Run: .venv/bin/python scripts/evaluate_answers.py --label answers-gemini
Uses the Groq free tier by default; pauses between LLM calls to stay under its
per-minute token limit, so 78 questions take roughly 25 minutes.
Writes eval/results/<label>.json, appending each question as it finishes.
"""

import argparse
import json
import logging
import time
from collections import defaultdict
from dataclasses import asdict
from typing import Any

from attack_qa.answer import answer_question
from attack_qa.answer_eval import AnswerReport, AnswerResult, summarize_answers
from attack_qa.bm25_index import Bm25Index
from attack_qa.config import INDEX_DIR, PROCESSED_DIR, PROJECT_ROOT
from attack_qa.dense_index import DenseIndex
from attack_qa.embedding import SentenceTransformerEmbedder
from attack_qa.evaluate import load_questions
from attack_qa.intent import IntentClassifier
from attack_qa.llms import CHOICES, PACING_S, make_answer_model
from attack_qa.lookups import load_revoked_ids
from attack_qa.passage_io import load_passages
from attack_qa.retrieval import HybridRetriever

EVAL_PATH = PROJECT_ROOT / "eval" / "handwritten.jsonl"
RESULTS_DIR = PROJECT_ROOT / "eval" / "results"

logger = logging.getLogger("evaluate_answers")


def _record(r: AnswerResult) -> dict[str, Any]:
    a = r.answer
    return {
        "id": r.question.id, "category": r.question.category, "question": r.question.question,
        "expected": r.question.expected, "gold": r.question.gold_passage_id,
        "model": r.model_used, "error": r.error,
        "status": a.status if a else "error", "refused_by": a.refused_by if a else None,
        "refusal_reason": a.refusal_reason if a else "",
        "claims": [{"text": c.text, "passage_ids": list(c.passage_ids)} for c in a.claims] if a else [],
        "dropped_claims": a.dropped_claims if a else 0,
        "cites_gold_passage": r.cites_gold_passage, "cites_gold_technique": r.cites_gold_technique,
        "gold_retrieved": r.gold_was_retrieved,
    }


def print_table(reports: list[AnswerReport]) -> None:
    print("\n| category | n | answered | refused | errors | cites gold passage | cites gold technique "
          "| gold retrieved | refused by |\n|---|---|---|---|---|---|---|---|---|")
    for r in reports:
        by = ", ".join(f"{k} {v}" for k, v in r.refused_by.items()) or "-"
        print(f"| {r.category} | {r.n} | {r.answered} | {r.refused} | {r.errors} | "
              f"{r.cites_gold_passage} | {r.cites_gold_technique} | {r.gold_retrieved} | {by} |")


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--llm", choices=CHOICES, default="groq")
    parser.add_argument("--limit", type=int, default=0, help="only the first N questions (trial)")
    args = parser.parse_args()

    passages = load_passages(PROCESSED_DIR / "passages.jsonl")
    embedder = SentenceTransformerEmbedder()
    retriever = HybridRetriever(
        passages, DenseIndex.open(INDEX_DIR, embedder), Bm25Index(passages),
        load_revoked_ids(PROCESSED_DIR / "revoked_ids.json"),
        intent_classifier=IntentClassifier(embedder),
    )
    model = make_answer_model(args.llm)
    pacing = PACING_S[args.llm]

    questions = load_questions(EVAL_PATH)
    if args.limit:
        questions = questions[: args.limit]
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    progress = RESULTS_DIR / f"{args.label}.progress.jsonl"
    progress.write_text("", encoding="utf-8")

    by_category: dict[str, list[AnswerResult]] = defaultdict(list)
    for i, q in enumerate(questions, start=1):
        started = time.monotonic()
        try:
            answer = answer_question(q.question, retriever, model)
            result = AnswerResult(q, answer, getattr(model, "last_model_used", model.name))
        except Exception as exc:  # keep going; the error is part of the result
            logger.warning("%s failed: %s", q.id, exc)
            result = AnswerResult(q, None, model.name, error=f"{type(exc).__name__}: {exc}"[:300])
        by_category[q.category].append(result)
        with progress.open("a", encoding="utf-8") as f:
            f.write(json.dumps(_record(result), ensure_ascii=False) + "\n")
        print(f"[{i}/{len(questions)}] {q.id} {result.answer.status if result.answer else 'error'}",
              flush=True)
        called_llm = result.answer is None or result.answer.refused_by != "relevance"
        if called_llm:
            time.sleep(max(0.0, pacing - (time.monotonic() - started)))

    reports = [summarize_answers(c, rs) for c, rs in by_category.items()]
    print_table(reports)
    out = RESULTS_DIR / f"{args.label}.json"
    out.write_text(json.dumps({
        "label": args.label, "llm": args.llm,
        "summary": [asdict(r) for r in reports],
        "questions": [_record(r) for rs in by_category.values() for r in rs],
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    progress.unlink()
    print(f"\nWrote {out.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
