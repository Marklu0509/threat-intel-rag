"""Score intent detection on the intent sets: rules, examples, and both combined (Q24).

Run: .venv/bin/python scripts/evaluate_intent.py
intent_dev.jsonl was used to choose the examples and margin; intent_test.jsonl was
written afterwards and is the honest number.
"""

import json
from collections import Counter
from pathlib import Path

from attack_qa.config import PROJECT_ROOT
from attack_qa.embedding import SentenceTransformerEmbedder
from attack_qa.intent import IntentClassifier
from attack_qa.passages import PassageKind
from attack_qa.query import detect_intent

SETS = ("intent_dev.jsonl", "intent_test.jsonl")


def _outcome(got: PassageKind | None, gold: str) -> str:
    if got is None:
        return "none"
    return "right" if got.value.lower() == gold else "wrong"


def main() -> None:
    embedder = SentenceTransformerEmbedder()
    classifier = IntentClassifier(embedder)
    print("\n| set | method | right | wrong | none |\n|---|---|---|---|---|")
    for name in SETS:
        path = PROJECT_ROOT / "eval" / name
        if not path.exists():
            continue
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        vectors = embedder.embed([r["question"] for r in rows])
        tallies = {m: Counter() for m in ("rules", "examples", "combined")}
        for row, vec in zip(rows, vectors):
            rule = detect_intent(row["question"])
            example = classifier.classify(vec)
            tallies["rules"][_outcome(rule, row["intent"])] += 1
            tallies["examples"][_outcome(example, row["intent"])] += 1
            tallies["combined"][_outcome(rule or example, row["intent"])] += 1
        for method, t in tallies.items():
            print(f"| {Path(name).stem} | {method} | {t['right']} | {t['wrong']} | {t['none']} |")


if __name__ == "__main__":
    main()
