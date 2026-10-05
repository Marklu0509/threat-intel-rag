from attack_qa.fusion import rrf_merge


def test_agreeing_rankings_keep_their_order() -> None:
    assert rrf_merge(["a", "b", "c"], ["a", "b", "c"]) == ["a", "b", "c"]


def test_passage_ranked_well_by_both_beats_one_favoured_by_only_one() -> None:
    # "b" is 2nd in both; "a" is 1st in dense but absent from sparse
    assert rrf_merge(["a", "b", "c"], ["b", "c", "d"])[0] == "b"


def test_exact_tie_goes_to_dense_first_choice() -> None:
    # mirrors the ch5 experiment: BM25 prefers Mitigation, dense prefers Detection
    merged = rrf_merge(dense=["detection", "mitigation"], sparse=["mitigation", "detection"])
    assert merged == ["detection", "mitigation"]


def test_tie_break_does_not_depend_on_argument_order() -> None:
    # same rankings as above, passed by keyword in the other order
    merged = rrf_merge(sparse=["mitigation", "detection"], dense=["detection", "mitigation"])
    assert merged[0] == "detection"


def test_passage_only_in_sparse_loses_a_tie_to_one_in_dense() -> None:
    # "x" (sparse rank 1) and "y" (dense rank 1) both score 1/61
    assert rrf_merge(dense=["y"], sparse=["x"]) == ["y", "x"]


def test_every_passage_from_either_ranking_appears_once() -> None:
    merged = rrf_merge(["a", "b"], ["b", "c"])
    assert sorted(merged) == ["a", "b", "c"]


def test_empty_rankings() -> None:
    assert rrf_merge([], []) == []


def test_does_not_mutate_inputs() -> None:
    dense, sparse = ["a", "b"], ["b", "a"]
    rrf_merge(dense, sparse)
    assert (dense, sparse) == (["a", "b"], ["b", "a"])
