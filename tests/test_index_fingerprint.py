import hashlib
from pathlib import Path

from chromadb.api.client import SharedSystemClient

from attack_qa.dense_index import DenseIndex
from attack_qa.index_fingerprint import fingerprint
from attack_qa.passages import Passage, PassageKind
from tests.conftest import FakeEmbedder


def _passage(tid: str, text: str, variant: str = "") -> Passage:
    return Passage(tid, tid, None, None, PassageKind.OVERVIEW, text, "", "19.2", variant=variant)


PASSAGES = (_passage("T1056.001", "keylogging records keystrokes"),
            _passage("T1059.001", "powershell runs encoded scripts"))


def _raw_bytes(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest.update(path.read_bytes())
    return digest.hexdigest()


def test_fingerprint_ignores_chroma_bookkeeping_when_an_index_is_only_opened(tmp_path: Path) -> None:
    DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    SharedSystemClient.clear_system_cache()  # a fresh client, as when another process opens it
    raw_before, before = _raw_bytes(tmp_path), fingerprint(tmp_path)

    DenseIndex.open(tmp_path, FakeEmbedder())

    assert _raw_bytes(tmp_path) != raw_before  # the false alarm the raw-byte hash raised
    assert fingerprint(tmp_path) == before


def test_fingerprint_changes_when_a_passage_is_added(tmp_path: Path) -> None:
    index = DenseIndex.build(tmp_path, PASSAGES, FakeEmbedder())
    before = fingerprint(tmp_path)
    index.mark_attack_test_and_add([_passage("T1059.001", "poison", variant="poison-a")])
    assert fingerprint(tmp_path) != before
