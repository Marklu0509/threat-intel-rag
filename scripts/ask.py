"""Ask a question: show retrieved Passages, or a cited answer with --answer.

Run: .venv/bin/python scripts/ask.py "How do I detect T1543.001?"
     .venv/bin/python scripts/ask.py --answer "How do I detect T1543.001?"
--answer calls an LLM: Gemini free tier by default (GEMINI_API_KEY), or --llm claude (paid).
"""

import argparse

from attack_qa.answer import Answer, AnswerModel, answer_question
from attack_qa.bm25_index import Bm25Index
from attack_qa.config import INDEX_DIR, PROCESSED_DIR
from attack_qa.dense_index import DenseIndex
from attack_qa.embedding import DEFAULT_MODEL, SentenceTransformerEmbedder
from attack_qa.intent import IntentClassifier
from attack_qa.lookups import load_revoked_ids
from attack_qa.passage_io import load_passages
from attack_qa.retrieval import TOP_K, HybridRetriever, RetrievalResult


def print_retrieval(question: str, result: RetrievalResult) -> None:
    plan = result.plan
    print(f"\nQ: {question}")
    for old, new in plan.substitutions.items():
        print(f"   ({old} was replaced by {new} in this ATT&CK release)")
    intent = plan.intent.value if plan.intent else "-"
    print(f"   IDs: {', '.join(plan.technique_ids) or '-'} | intent: {intent} "
          f"| top cosine: {result.top_dense_cosine:.3f}\n")
    for hit in result.hits:
        cosine = f"{hit.dense_cosine:.3f}" if hit.dense_cosine is not None else "  -  "
        print(f"  {hit.rank}. [cos {cosine}] {hit.passage.text.splitlines()[0]}")


def print_answer(question: str, answer: Answer) -> None:
    print(f"\nQ: {question}\n")
    if answer.status == "refused":
        print(f"  [refused by {answer.refused_by}] {answer.refusal_reason}")
        return
    for old, new in answer.substitutions.items():
        print(f"  ({old} was replaced by {new} in this ATT&CK release)")
    for claim in answer.claims:
        print(f"  - {claim.text} [{', '.join(claim.passage_ids)}]")
    if answer.dropped_claims:
        print(f"\n  ({answer.dropped_claims} claim(s) dropped: cited passages that were not retrieved)")


def make_llm(name: str) -> AnswerModel:
    if name == "claude":
        from attack_qa.claude_model import ClaudeAnswerModel

        return ClaudeAnswerModel()
    from attack_qa.gemini_model import GeminiAnswerModel

    return GeminiAnswerModel()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question")
    parser.add_argument("--top-k", type=int, default=TOP_K)
    parser.add_argument("--model", default=DEFAULT_MODEL, help="embedding model")
    parser.add_argument("--answer", action="store_true", help="generate a cited answer")
    parser.add_argument("--llm", choices=("gemini", "claude"), default="gemini",
                        help="answer model: gemini (free tier, GEMINI_API_KEY) or claude (paid)")
    args = parser.parse_args()

    passages = load_passages(PROCESSED_DIR / "passages.jsonl")
    embedder = SentenceTransformerEmbedder(args.model)
    retriever = HybridRetriever(
        passages, DenseIndex.open(INDEX_DIR, embedder), Bm25Index(passages),
        load_revoked_ids(PROCESSED_DIR / "revoked_ids.json"),
        intent_classifier=IntentClassifier(embedder),
    )
    if args.answer:
        print_answer(args.question, answer_question(args.question, retriever, make_llm(args.llm)))
    else:
        print_retrieval(args.question, retriever.retrieve(args.question, top_k=args.top_k))


if __name__ == "__main__":
    main()
