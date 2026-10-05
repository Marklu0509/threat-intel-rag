"""Tables used before retrieval: Revoked IDs (Q17) and actor names (Q15 gate 1)."""

from types import MappingProxyType
from typing import Mapping

from attack_qa.stix import AttackData, attack_id, is_live

_ACTOR_TYPES = ("intrusion-set", "malware", "tool")


def _direct_revocations(data: AttackData) -> dict[str, str]:
    """old Technique ID -> the ID that revoked it (may itself be revoked)."""
    pairs: dict[str, str] = {}
    for rel in data.objects:
        if rel["type"] != "relationship" or rel["relationship_type"] != "revoked-by":
            continue
        old = data.by_stix_id.get(rel["source_ref"])
        new = data.by_stix_id.get(rel["target_ref"])
        if old is None or new is None or old["type"] != "attack-pattern":
            continue
        old_id, new_id = attack_id(old), attack_id(new)
        if old_id and new_id and old_id != new_id:
            pairs[old_id] = new_id
    return pairs


def _follow(start: str, pairs: Mapping[str, str]) -> str:
    seen = {start}
    current = start
    while current in pairs:
        current = pairs[current]
        if current in seen:
            raise ValueError(f"Revocation cycle starting at {start}")
        seen.add(current)
    return current


def revoked_ids(data: AttackData) -> Mapping[str, str]:
    """Revoked ID -> its live replacement, following chained revocations."""
    pairs = _direct_revocations(data)
    live_ids = {attack_id(t) for t in data.live("attack-pattern")}
    resolved = {old: _follow(old, pairs) for old in pairs}
    dangling = sorted(old for old, new in resolved.items() if new not in live_ids)
    if dangling:
        raise ValueError(f"Revoked IDs with no live replacement: {dangling}")
    return MappingProxyType(resolved)


def actor_names(data: AttackData) -> frozenset[str]:
    """Lower-cased names and aliases of every live Group and piece of software."""
    names: set[str] = set()
    for obj in data.objects:
        if obj["type"] not in _ACTOR_TYPES or not is_live(obj):
            continue
        names.add(obj["name"])
        names.update(obj.get("aliases", ()))
        names.update(obj.get("x_mitre_aliases", ()))
    return frozenset(n.strip().lower() for n in names if n.strip())
