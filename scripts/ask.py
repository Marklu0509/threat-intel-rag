"""Retrieve the top Passages for a question (no LLM answer yet).

Run: .venv/bin/python scripts/ask.py "How do I detect T1543.001?"
"""

import argparse

from attack_qa.bm25_index import Bm25Index
from attack_qa.config import INDEX_DIR, PROCESSED_DIR
from attack_qa.dense_index import DenseIndex
from attack_qa.embedding import DEFAULT_MODEL, SentenceTransformerEmbedder
from attack_qa.intent import IntentClassifier
from attack_qa.lookups import load_revoked_ids
from attack_qa.passage_io import load_passages
from attack_qa.retrieval import TOP_K, HybridRetriever


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question")
    parser.add_argument("--top-k", type=int, default=TOP_K)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()

    passages = load_passages(PROCESSED_DIR / "passages.jsonl")
    embedder = SentenceTransformerEmbedder(args.model)
    retriever = HybridRetriever(
        passages, DenseIndex.open(INDEX_DIR, embedder), Bm25Index(passages),
        load_revoked_ids(PROCESSED_DIR / "revoked_ids.json"),
        intent_classifier=IntentClassifier(embedder),
    )

    result = retriever.retrieve(args.question, top_k=args.top_k)
    plan = result.plan
    print(f"\nQ: {args.question}")
    for old, new in plan.substitutions.items():
        print(f"   ({old} was replaced by {new} in this ATT&CK release)")
    intent = plan.intent.value if plan.intent else "-"
    print(f"   IDs: {', '.join(plan.technique_ids) or '-'} | intent: {intent}\n")
    for hit in result.hits:
        cosine = f"{hit.dense_cosine:.3f}" if hit.dense_cosine is not None else "  -  "
        heading = hit.passage.text.splitlines()[0]
        print(f"  {hit.rank}. [cos {cosine}] {heading}")


if __name__ == "__main__":
    main()
