from attack_qa.intent import IntentClassifier
from attack_qa.passages import PassageKind
from tests.conftest import FakeEmbedder

EXAMPLES = {
    PassageKind.DETECTION: ("spot the attack in logs",),
    PassageKind.MITIGATION: ("block the attack with controls",),
    PassageKind.OVERVIEW: ("explain how the attack works",),
}


def _classifier(min_margin: float = 0.05) -> tuple[IntentClassifier, FakeEmbedder]:
    embedder = FakeEmbedder()
    return IntentClassifier(embedder, min_margin=min_margin, examples=EXAMPLES), embedder


def test_picks_the_intent_whose_examples_are_closest() -> None:
    clf, emb = _classifier()
    assert clf.classify(emb.embed(["spot it in logs"])[0]) == PassageKind.DETECTION
    assert clf.classify(emb.embed(["block it with controls"])[0]) == PassageKind.MITIGATION


def test_returns_none_when_two_intents_are_equally_close() -> None:
    clf, emb = _classifier()
    # shares exactly one word with the Detection and one with the Mitigation example
    assert clf.classify(emb.embed(["logs controls"])[0]) is None


def test_scores_cover_every_intent() -> None:
    clf, emb = _classifier()
    assert set(clf.scores(emb.embed(["anything"])[0])) == set(EXAMPLES)


def test_zero_margin_accepts_any_winner() -> None:
    clf, emb = _classifier(min_margin=0.0)
    assert clf.classify(emb.embed(["spot"])[0]) == PassageKind.DETECTION
