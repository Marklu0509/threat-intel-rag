"""Generate an answer for every evaluation question and score the answers.

Run: .venv/bin/python scripts/evaluate_answers.py --label answers-gemini
Uses the Groq free tier by default; pauses between LLM calls to stay under its
per-minute token limit, so 78 questions take roughly 25 minutes.
Writes eval/results/<label>.json; each finished question is saved as it completes, and
--resume continues an interrupted run.
"""

import argparse
import json
import logging
import time
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from attack_qa.answer import DailyQuotaExceededError, answer_question
from attack_qa.answer_eval import (
    AnswerReport, AnswerResult, error_text, summarize_records, to_record,
)
from attack_qa.bm25_index import Bm25Index
from attack_qa.config import INDEX_DIR, PROCESSED_DIR, PROJECT_ROOT
from attack_qa.dense_index import DenseIndex
from attack_qa.embedding import SentenceTransformerEmbedder
from attack_qa.evaluate import load_questions
from attack_qa.intent import IntentClassifier
from attack_qa.language import language_report
from attack_qa.llms import CHOICES, PACING_S, make_answer_model
from attack_qa.lookups import load_revoked_ids
from attack_qa.passage_io import load_passages
from attack_qa.retrieval import HybridRetriever

EVAL_PATH = PROJECT_ROOT / "eval" / "handwritten.jsonl"
RESULTS_DIR = PROJECT_ROOT / "eval" / "results"

logger = logging.getLogger("evaluate_answers")


def load_finished(progress: Path) -> dict[str, dict[str, Any]]:
    """Records already saved by an interrupted run, minus the ones that errored."""
    if not progress.exists():
        return {}
    records = [json.loads(line) for line in progress.read_text(encoding="utf-8").splitlines() if line]
    return {r["id"]: r for r in records if r["status"] != "error"}


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
    parser.add_argument("--category", default="", help="only questions of this category")
    parser.add_argument("--resume", action="store_true",
                        help="keep finished questions from <label>.progress.jsonl; rerun errors")
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
    if args.category:
        questions = [q for q in questions if q.category == args.category]
    if args.limit:
        questions = questions[: args.limit]
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    progress = RESULTS_DIR / f"{args.label}.progress.jsonl"
    done = load_finished(progress) if args.resume else {}
    progress.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in done.values()),
                        encoding="utf-8")
    records = dict(done)
    todo = [q for q in questions if q.id not in done]
    print(f"{len(done)} finished earlier, {len(todo)} to run", flush=True)

    for i, q in enumerate(todo, start=1):
        started = time.monotonic()
        try:
            answer = answer_question(q.question, retriever, model)
            result = AnswerResult(q, answer, getattr(model, "last_model_used", model.name))
        except DailyQuotaExceededError as exc:
            print(f"\nStopped: {exc}. Finished questions are saved; rerun with --resume later.")
            return
        except Exception as exc:  # keep going; the error is part of the result
            logger.warning("%s failed: %s", q.id, exc)
            result = AnswerResult(q, None, model.name, error=error_text(exc))
        records[q.id] = to_record(result)
        with progress.open("a", encoding="utf-8") as f:
            f.write(json.dumps(records[q.id], ensure_ascii=False) + "\n")
        print(f"[{i}/{len(todo)}] {q.id} {result.answer.status if result.answer else 'error'}",
              flush=True)
        called_llm = result.answer is None or result.answer.refused_by != "relevance"
        if called_llm:
            time.sleep(max(0.0, pacing - (time.monotonic() - started)))

    ordered = [records[q.id] for q in questions]
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in ordered:
        by_category[record["category"]].append(record)
    reports = [summarize_records(c, rs) for c, rs in by_category.items()]
    print_table(reports)
    language = language_report(ordered)
    print(f"\nAnswer language as asked: {language.matched}/{language.checked}"
          f" (wrong: {', '.join(language.mismatched) or 'none'})")
    out = RESULTS_DIR / f"{args.label}.json"
    out.write_text(json.dumps({
        "label": args.label, "llm": args.llm,
        "summary": [asdict(r) for r in reports],
        "language": asdict(language),
        "questions": ordered,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    progress.unlink()
    print(f"\nWrote {out.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
