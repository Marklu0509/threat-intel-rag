"""Dense Passage index in Chroma, one per embedding model (ADR 0003)."""

import logging
import re
from collections.abc import Sequence
from pathlib import Path

import chromadb

from attack_qa.bm25_index import ScoredId
from attack_qa.embedding import Embedder
from attack_qa.passages import Passage

logger = logging.getLogger(__name__)

_BATCH = 64


ATTACK_TEST_PURPOSE = "attack-test"


class AttackIndexError(Exception):
    """An attack-test index (with Poisoned passages) was opened for normal use, or vice versa."""


class IndexModelMismatchError(Exception):
    """The Passage index was built by a different embedding model than the one querying it."""


def collection_name(model_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", model_name.lower()).strip("-")
    return f"passages-{slug}"


class DenseIndex:
    def __init__(self, collection: chromadb.Collection, embedder: Embedder) -> None:
        built_with = (collection.metadata or {}).get("embedding_model")
        if built_with != embedder.name:
            raise IndexModelMismatchError(
                f"Index {collection.name!r} was built with {built_with!r}, "
                f"not {embedder.name!r}; rebuild it with scripts/build_index.py"
            )
        self._collection = collection
        self._embedder = embedder

    @classmethod
    def build(
        cls, path: Path, passages: Sequence[Passage], embedder: Embedder
    ) -> "DenseIndex":
        if not passages:
            raise ValueError("Cannot build a dense index over zero Passages")
        client = chromadb.PersistentClient(path=str(path))
        name = collection_name(embedder.name)
        if name in [c.name for c in client.list_collections()]:
            client.delete_collection(name)
        collection = client.create_collection(
            name,
            configuration={"hnsw": {"space": "cosine"}},
            metadata={
                "embedding_model": embedder.name,
                "attack_version": passages[0].attack_version,
            },
            embedding_function=None,
        )
        for start in range(0, len(passages), _BATCH):
            batch = passages[start : start + _BATCH]
            collection.add(
                ids=[p.passage_id for p in batch],
                embeddings=embedder.embed([p.text for p in batch]),
                metadatas=[{"technique_id": p.technique_id, "kind": p.kind.value} for p in batch],
            )
            logger.info("Embedded %d / %d Passages", start + len(batch), len(passages))
        return cls(collection, embedder)

    @classmethod
    def open(cls, path: Path, embedder: Embedder, attack_test: bool = False) -> "DenseIndex":
        """Open an index; attack_test=True is required for (and only for) attack-test copies."""
        client = chromadb.PersistentClient(path=str(path))
        name = collection_name(embedder.name)
        try:
            collection = client.get_collection(name, embedding_function=None)
        except Exception as exc:  # chromadb raises different types across versions
            raise FileNotFoundError(
                f"No index {name!r} in {path}; run scripts/build_index.py first"
            ) from exc
        is_attack = (collection.metadata or {}).get("purpose") == ATTACK_TEST_PURPOSE
        if is_attack != attack_test:
            raise AttackIndexError(
                f"{path} is {'an attack-test' if is_attack else 'a production'} index; "
                f"refusing to open it with attack_test={attack_test}"
            )
        return cls(collection, embedder)

    def mark_attack_test_and_add(self, passages: Sequence[Passage]) -> None:
        """Turn this (copied) index into an attack-test index and add Poisoned passages."""
        metadata = dict(self._collection.metadata or {})
        self._collection.modify(metadata={**metadata, "purpose": ATTACK_TEST_PURPOSE})
        if passages:
            self._collection.add(
                ids=[p.passage_id for p in passages],
                embeddings=self._embedder.embed([p.text for p in passages]),
                metadatas=[{"technique_id": p.technique_id, "kind": p.kind.value} for p in passages],
            )

    def embed_query(self, query: str) -> list[float]:
        """The query vector, from the same model that built this index."""
        return self._embedder.embed([query])[0]

    def search(self, query: str, k: int) -> list[ScoredId]:
        """Top-k Passages by cosine similarity (1.0 = same direction)."""
        return self.search_by_vector(self.embed_query(query), k)

    def search_by_vector(self, query_vector: Sequence[float], k: int) -> list[ScoredId]:
        result = self._collection.query(
            query_embeddings=[list(query_vector)],
            n_results=min(k, self._collection.count()),
            include=["distances"],
        )
        ids, distances = result["ids"][0], result["distances"][0]
        return [ScoredId(pid, 1.0 - dist) for pid, dist in zip(ids, distances)]
