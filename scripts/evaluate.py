"""Run the evaluation set through retrieval and report per-category scores.

Run: .venv/bin/python scripts/evaluate.py --label baseline
Writes eval/results/<label>.json (summary + every question's retrieved Passages).
"""

import argparse
import json
import logging
from collections import defaultdict
from dataclasses import asdict

from attack_qa.bm25_index import Bm25Index
from attack_qa.config import INDEX_DIR, PROCESSED_DIR, PROJECT_ROOT
from attack_qa.dense_index import DenseIndex
from attack_qa.embedding import DEFAULT_MODEL, SentenceTransformerEmbedder
from attack_qa.evaluate import KS, CategoryReport, QuestionResult, load_questions, score_question, summarize
from attack_qa.intent import IntentClassifier
from attack_qa.lookups import load_revoked_ids
from attack_qa.passage_io import load_passages
from attack_qa.retrieval import HybridRetriever

EVAL_PATH = PROJECT_ROOT / "eval" / "handwritten.jsonl"
RESULTS_DIR = PROJECT_ROOT / "eval" / "results"


def _pct(x: float | None) -> str:
    return "  -  " if x is None else f"{x * 100:5.1f}%"


def print_table(reports: list[CategoryReport]) -> None:
    head = " | ".join(f"P@{k}" for k in KS)
    print(f"\n| category | n | {head} | T@5 | MRR | top cos |")
    print("|" + "---|" * (len(KS) + 5))
    for r in reports:
        hits = " | ".join(_pct(r.passage_hit[k] if r.passage_hit else None) for k in KS)
        mrr = "  -  " if r.mrr is None else f"{r.mrr:.3f}"
        cos = "  -  " if r.mean_top_cosine is None else f"{r.mean_top_cosine:.3f}"
        print(f"| {r.category} | {r.n} | {hits} | {_pct(r.technique_hit_at_5)} | {mrr} | {cos} |")


def _record(result: QuestionResult) -> dict[str, object]:
    return {**asdict(result.question), "passage_rank": result.passage_rank,
            "technique_rank": result.technique_rank, "top_cosine": result.top_cosine,
            "retrieved": list(result.retrieved)}


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--no-query-understanding", action="store_true",
                        help="search the raw question with plain RRF order (ablation)")

    parser.add_argument("--no-intent-examples", action="store_true",
                        help="detect intent with keyword rules only (ablation)")
    args = parser.parse_args()

    passages = load_passages(PROCESSED_DIR / "passages.jsonl")
    embedder = SentenceTransformerEmbedder(args.model)
    retriever = HybridRetriever(
        passages, DenseIndex.open(INDEX_DIR, embedder),
        Bm25Index(passages), load_revoked_ids(PROCESSED_DIR / "revoked_ids.json"),
        understand_query=not args.no_query_understanding,
        intent_classifier=None if args.no_intent_examples else IntentClassifier(embedder),
    )
    by_category: dict[str, list[QuestionResult]] = defaultdict(list)
    for q in load_questions(EVAL_PATH):
        hits = retriever.retrieve(q.question, top_k=max(KS)).hits
        by_category[q.category].append(score_question(q, hits))

    answerable = [r for rs in by_category.values() for r in rs if r.question.expected == "answer"]
    reports = [summarize(c, rs) for c, rs in by_category.items()]
    reports.append(summarize("ALL answerable", answerable))
    print_table(reports)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"{args.label}.json"
    out.write_text(json.dumps({
        "label": args.label, "model": args.model,
        "summary": [asdict(r) for r in reports],
        "questions": [_record(r) for rs in by_category.values() for r in rs],
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nWrote {out.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
