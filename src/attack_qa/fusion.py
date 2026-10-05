"""Merge dense and BM25 rankings with Reciprocal Rank Fusion (grill-decisions Q12)."""

from collections.abc import Sequence

RRF_K = 60


def rrf_merge(dense: Sequence[str], sparse: Sequence[str], k: int = RRF_K) -> list[str]:
    """Merge two rankings of passage IDs, best first.

    A passage at 1-based rank r in a ranking earns 1 / (k + r); its scores from
    both rankings are summed. Ties go to the passage ranked higher by `dense`,
    and a passage missing from `dense` loses a tie to one that is in it.
    """
    scores: dict[str, float] = {}
    for ranking in (dense, sparse):
        for rank, passage_id in enumerate(ranking, start=1):
            scores[passage_id] = scores.get(passage_id, 0.0) + 1 / (k + rank)

    dense_rank = {passage_id: rank for rank, passage_id in enumerate(dense)}
    not_in_dense = len(dense)
    return sorted(
        scores,
        key=lambda pid: (-scores[pid], dense_rank.get(pid, not_in_dense)),
    )
