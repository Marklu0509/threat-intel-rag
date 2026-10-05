import pytest

from attack_qa.lookups import actor_names, revoked_ids
from attack_qa.stix import AttackData
from tests.conftest import relationship, technique


def test_revoked_id_maps_to_replacement(tiny_attack: AttackData) -> None:
    assert revoked_ids(tiny_attack)["T1086"] == "T1059.001"


def test_live_ids_are_not_in_the_revoked_table(tiny_attack: AttackData) -> None:
    assert "T1059.001" not in revoked_ids(tiny_attack)


def test_chained_revocation_resolves_to_the_live_end() -> None:
    data = AttackData.from_objects([
        technique("T1000", "Old", revoked=True),
        technique("T1001", "Middle", revoked=True),
        technique("T1002", "Current"),
        relationship("revoked-by", "attack-pattern--T1000", "attack-pattern--T1001"),
        relationship("revoked-by", "attack-pattern--T1001", "attack-pattern--T1002"),
    ])
    assert revoked_ids(data) == {"T1000": "T1002", "T1001": "T1002"}


def test_revocation_with_no_live_end_is_an_error() -> None:
    data = AttackData.from_objects([
        technique("T1000", "Old", revoked=True),
        technique("T1001", "Also gone", revoked=True),
        relationship("revoked-by", "attack-pattern--T1000", "attack-pattern--T1001"),
    ])
    with pytest.raises(ValueError, match="no live replacement"):
        revoked_ids(data)


def test_actor_names_include_aliases_lower_cased(tiny_attack: AttackData) -> None:
    names = actor_names(tiny_attack)
    assert {"apt29", "noblebaron", "mimikatz"} <= names
