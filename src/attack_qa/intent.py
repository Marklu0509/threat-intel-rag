"""Question intent by similarity to example questions (grill-decisions Q24).

Rules in query.detect_intent are precise but only know the words they list.
When they find nothing, compare the question's vector with a few example
questions per intent and accept the best intent only if it clearly beats the
runner-up; otherwise return None so no Passage kind gets boosted.
"""

from collections.abc import Sequence
from types import MappingProxyType
from typing import Mapping

from attack_qa.embedding import Embedder
from attack_qa.passages import PassageKind

EXAMPLES: Mapping[PassageKind, tuple[str, ...]] = MappingProxyType({
    PassageKind.DETECTION: (
        "How do I detect this technique?",
        "How can I tell if this attack is happening?",
        "What should I monitor or alert on?",
        "怎麼偵測這個攻擊？",
        "怎麼知道有沒有被攻擊？",
    ),
    PassageKind.MITIGATION: (
        "How do I prevent or mitigate this technique?",
        "How can I protect against this attack?",
        "What controls reduce this risk?",
        "怎麼防禦這個攻擊？",
        "要怎麼避免這種攻擊？",
    ),
    PassageKind.OVERVIEW: (
        "What is this technique?",
        "How does this attack work?",
        "Explain this technique to me.",
        "這是什麼攻擊手法？",
        "這個技巧的原理是什麼？",
    ),
})

# Minimum gap between the best and second-best intent, tuned on eval/intent_dev.jsonl only:
# the one wrong dev question ("Can I catch ... ?") had a gap of 0.000, the smallest right one 0.023.
MIN_MARGIN = 0.015


def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


class IntentClassifier:
    def __init__(self, embedder: Embedder, min_margin: float = MIN_MARGIN,
                 examples: Mapping[PassageKind, Sequence[str]] = EXAMPLES) -> None:
        self._min_margin = min_margin
        self._examples = {kind: embedder.embed(list(texts)) for kind, texts in examples.items()}

    def scores(self, query_vector: Sequence[float]) -> dict[PassageKind, float]:
        """Best cosine between the question and each intent's examples (vectors are unit length)."""
        return {
            kind: max(_dot(query_vector, v) for v in vectors)
            for kind, vectors in self._examples.items()
        }

    def classify(self, query_vector: Sequence[float]) -> PassageKind | None:
        ranked = sorted(self.scores(query_vector).items(), key=lambda kv: kv[1], reverse=True)
        (best, best_score), (_, second_score) = ranked[0], ranked[1]
        return best if best_score - second_score >= self._min_margin else None
