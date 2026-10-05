"""Embed every Passage into the dense Passage index (ADR 0003).

Run: .venv/bin/python scripts/build_index.py [--model BAAI/bge-m3]
Takes several minutes on a laptop for bge-m3; rerun after rebuilding Passages.
"""

import argparse
import logging
import time

from attack_qa.config import INDEX_DIR, PROCESSED_DIR
from attack_qa.dense_index import DenseIndex
from attack_qa.embedding import DEFAULT_MODEL, SentenceTransformerEmbedder
from attack_qa.passage_io import load_passages


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()

    passages = load_passages(PROCESSED_DIR / "passages.jsonl")
    started = time.perf_counter()
    DenseIndex.build(INDEX_DIR, passages, SentenceTransformerEmbedder(args.model))
    logging.info(
        "Indexed %d Passages with %s in %.0fs",
        len(passages), args.model, time.perf_counter() - started,
    )


if __name__ == "__main__":
    main()
