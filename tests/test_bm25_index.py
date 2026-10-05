from attack_qa.bm25_index import Bm25Index, tokenize
from attack_qa.passages import Passage, PassageKind


def _passage(tid: str, text: str) -> Passage:
    return Passage(tid, tid, None, None, PassageKind.DETECTION, text, "", "19.2")


def test_tokenize_keeps_technique_ids_whole() -> None:
    assert tokenize("Detect T1543.001 and T1543") == ["detect", "t1543.001", "and", "t1543"]


def test_tokenize_keeps_executables_whole() -> None:
    assert "schtasks.exe" in tokenize("Monitor schtasks.exe creation")


def test_tokenize_is_case_insensitive() -> None:
    assert tokenize("PowerShell") == tokenize("powershell")


def test_exact_id_beats_a_sibling_id() -> None:
    # BM25's IDF is log((N - n + 0.5) / (n + 0.5)): with only two documents a term
    # found in one of them scores 0, so the corpus needs a third, unrelated passage.
    index = Bm25Index([
        _passage("T1543.003", "T1543.003 Windows Service — Detection\nMonitor new services."),
        _passage("T1543.001", "T1543.001 Launch Agent — Detection\nMonitor plist files."),
        _passage("T1056.001", "T1056.001 Keylogging — Overview\nRecords keystrokes."),
    ])
    assert index.search("detection for T1543.001", k=1)[0].passage_id == "T1543.001:detection"


def test_passages_matching_no_term_are_not_returned() -> None:
    index = Bm25Index([
        _passage("T1001", "alpha beta"),
        _passage("T1002", "gamma delta"),
        _passage("T1003", "epsilon zeta"),
    ])
    assert [h.passage_id for h in index.search("alpha", k=10)] == ["T1001:detection"]


def test_search_returns_at_most_k() -> None:
    index = Bm25Index([_passage(f"T100{i}", f"text {i}") for i in range(5)])
    assert len(index.search("text", k=3)) == 3
