import pytest

from attack_qa.config import ATTACK_VERSION, RAW_PATH
from attack_qa.passages import Passage, PassageKind, build_passages
from attack_qa.stix import AttackData


def _get(passages: tuple[Passage, ...], tid: str, kind: PassageKind) -> Passage:
    return next(p for p in passages if p.technique_id == tid and p.kind == kind)


@pytest.fixture
def passages(tiny_attack: AttackData) -> tuple[Passage, ...]:
    return build_passages(tiny_attack, version="19.2")


def test_every_live_technique_gets_exactly_three_passages(passages: tuple[Passage, ...]) -> None:
    ids = sorted({p.technique_id for p in passages})
    assert ids == ["T1056", "T1056.001", "T1059", "T1059.001"]
    assert len(passages) == 3 * len(ids)


def test_revoked_technique_gets_no_passage(passages: tuple[Passage, ...]) -> None:
    assert all(p.technique_id != "T1086" for p in passages)


def test_sub_technique_heading_names_its_parent(passages: tuple[Passage, ...]) -> None:
    p = _get(passages, "T1059.001", PassageKind.DETECTION)
    assert p.text.splitlines()[0] == (
        "T1059.001 PowerShell (sub-technique of T1059 Command and Scripting Interpreter)"
        " — Detection"
    )
    assert (p.parent_id, p.parent_name) == ("T1059", "Command and Scripting Interpreter")


def test_overview_lists_tactics_platforms_and_sub_techniques(passages: tuple[Passage, ...]) -> None:
    body = _get(passages, "T1059", PassageKind.OVERVIEW).text
    assert "Tactics: Execution" in body
    assert "Platforms: Windows" in body
    assert "Sub-techniques: T1059.001 PowerShell" in body


def test_mitigation_text_is_cleaned(passages: tuple[Passage, ...]) -> None:
    p = _get(passages, "T1059.001", PassageKind.MITIGATION)
    assert "- Code Signing: Only run signed scripts." in p.text
    assert not p.no_mitigation


def test_do_not_mitigate_becomes_a_no_mitigation_statement(passages: tuple[Passage, ...]) -> None:
    p = _get(passages, "T1056.001", PassageKind.MITIGATION)
    assert p.no_mitigation
    assert "lists no preventive mitigations for T1056.001 Keylogging" in p.text
    assert "Do Not Mitigate" not in p.text


def test_technique_without_any_mitigation_also_gets_the_statement(
    passages: tuple[Passage, ...],
) -> None:
    assert _get(passages, "T1059", PassageKind.MITIGATION).no_mitigation


def test_detection_lists_analytics_with_platforms(passages: tuple[Passage, ...]) -> None:
    body = _get(passages, "T1059.001", PassageKind.DETECTION).text
    assert "- Detect PowerShell abuse" in body
    assert "[Windows] Watch for powershell.exe -enc." in body


def test_passage_id_and_version(passages: tuple[Passage, ...]) -> None:
    p = _get(passages, "T1059.001", PassageKind.OVERVIEW)
    assert p.passage_id == "T1059.001:overview"
    assert p.attack_version == "19.2"


@pytest.mark.integration
@pytest.mark.skipif(not RAW_PATH.exists(), reason="run scripts/download_attack.py first")
def test_real_release_builds_2091_passages() -> None:
    passages = build_passages(AttackData.load(RAW_PATH), ATTACK_VERSION)
    assert len(passages) == 2091
    # 111 Techniques have no mitigation at all, 90 only "Do Not Mitigate"/"Pre-compromise"
    assert sum(p.no_mitigation for p in passages) == 201
    assert all("(Citation:" not in p.text for p in passages)
    assert all("](https://attack.mitre.org" not in p.text for p in passages)
