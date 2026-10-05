from pathlib import Path

import pytest

from attack_qa.dense_index import DenseIndex, IndexModelMismatchError, collection_name
from attack_qa.passages import Passage, PassageKind
from tests.conftest import FakeEmbedder


def _passage(tid: str, text: str) -> Passage:
    return Passage(tid, tid, None, None, PassageKind.OVERVIEW, text, "", "19.2")


PASSAGES = (
    _passage("T1056.001", "keylogging records user keystrokes"),
    _passage("T1053.005", "scheduled task created with schtasks"),
    _passage("T1059.001", "powershell runs encoded scripts"),
)


def test_collection_name_is_safe_for_chroma() -> None:
    assert collection_name("BAAI/bge-m3") == "passages-baai-bge-m3"


def test_search_ranks_the_most_similar_passage_first(tmp_path: Path) -> None:
    index = DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    hits = index.search("keylogging keystrokes", k=2)
    assert hits[0].passage_id == "T1056.001:overview"
    assert len(hits) == 2


def test_scores_are_cosine_similarity(tmp_path: Path) -> None:
    index = DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    top = index.search("keylogging records user keystrokes", k=1)[0]
    assert top.score == pytest.approx(1.0, abs=1e-4)


def test_reopening_with_the_same_model_works(tmp_path: Path) -> None:
    DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    reopened = DenseIndex.open(tmp_path, FakeEmbedder())
    assert reopened.search("schtasks", k=1)[0].passage_id == "T1053.005:overview"


def test_querying_with_another_model_fails_loudly(tmp_path: Path) -> None:
    built = DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder("model-a"))
    with pytest.raises(IndexModelMismatchError, match="model-a"):
        DenseIndex(built._collection, FakeEmbedder("model-b"))


def test_opening_a_missing_index_explains_what_to_do(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="build_index.py"):
        DenseIndex.open(tmp_path, FakeEmbedder())


def test_rebuilding_replaces_the_old_index(tmp_path: Path) -> None:
    DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    rebuilt = DenseIndex.build(tmp_path, PASSAGES[:1], FakeEmbedder())
    assert len(rebuilt.search("anything", k=10)) == 1
