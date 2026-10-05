"""Swappable embedding models (grill-decisions Q11, ADR 0003)."""

from collections.abc import Sequence
from typing import Protocol

DEFAULT_MODEL = "BAAI/bge-m3"


class Embedder(Protocol):
    """Turns text into unit-length vectors. `name` identifies the model and version."""

    @property
    def name(self) -> str: ...

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class SentenceTransformerEmbedder:
    """Local model via sentence-transformers; loads the weights on construction."""

    def __init__(
        self, model_name: str = DEFAULT_MODEL, max_seq_length: int = 2048, batch_size: int = 16
    ) -> None:
        from sentence_transformers import SentenceTransformer  # heavy import, keep it lazy

        self._model_name = model_name
        self._batch_size = batch_size
        self._model = SentenceTransformer(model_name)
        self._model.max_seq_length = max_seq_length

    @property
    def name(self) -> str:
        return self._model_name

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors = self._model.encode(
            list(texts),
            batch_size=self._batch_size,
            normalize_embeddings=True,
            show_progress_bar=len(texts) > self._batch_size,
        )
        return vectors.tolist()
