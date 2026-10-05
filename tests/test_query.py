import pytest

from attack_qa.passages import PassageKind
from attack_qa.query import detect_intent, find_technique_ids, plan_query

REVOKED = {"T1086": "T1059.001", "T1070.001": "T1685.005"}


class TestFindTechniqueIds:
    def test_finds_ids_in_order_without_duplicates(self) -> None:
        assert find_technique_ids("T1059.001 vs T1059 and T1059.001 again") == ("T1059.001", "T1059")

    def test_normalises_case_and_url_style(self) -> None:
        assert find_technique_ids("t1059/001 and t1543.003") == ("T1059.001", "T1543.003")

    def test_ignores_numbers_that_are_not_ids(self) -> None:
        assert find_technique_ids("port 4444 in 2025, CVE-2024-3094") == ()


class TestDetectIntent:
    @pytest.mark.parametrize("question, kind", [
        ("How do I detect T1543.001?", PassageKind.DETECTION),
        ("怎麼偵測有人從 LSASS 記憶體偷密碼？", PassageKind.DETECTION),
        ("How can we mitigate T1193?", PassageKind.MITIGATION),
        ("螢幕截圖這種攻擊有辦法預防嗎？", PassageKind.MITIGATION),
        ("What is T1055.003?", PassageKind.OVERVIEW),
        ("什麼是 Kerberoasting？", PassageKind.OVERVIEW),
    ])
    def test_single_cue(self, question: str, kind: PassageKind) -> None:
        assert detect_intent(question) == kind

    def test_login_does_not_look_like_log(self) -> None:
        assert detect_intent("stolen login secrets") is None

    def test_mixed_intents_give_none(self) -> None:
        assert detect_intent("What is T1059 and how do I detect it?") is None

    def test_no_cue_gives_none(self) -> None:
        assert detect_intent("T1059.001") is None


class TestPlanQuery:
    def test_rewrites_revoked_ids_and_records_the_substitution(self) -> None:
        plan = plan_query("How do I detect T1086?", REVOKED)
        assert plan.search_text == "How do I detect T1059.001?"
        assert plan.technique_ids == ("T1059.001",)
        assert dict(plan.substitutions) == {"T1086": "T1059.001"}

    def test_rewrites_url_style_revoked_ids(self) -> None:
        assert plan_query("detect t1070/001", REVOKED).technique_ids == ("T1685.005",)

    def test_live_ids_pass_through(self) -> None:
        plan = plan_query("What is T1059?", REVOKED)
        assert plan.search_text == "What is T1059?"
        assert not plan.substitutions

    def test_empty_question_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            plan_query("  ", REVOKED)
