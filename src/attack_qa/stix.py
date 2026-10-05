"""Read an ATT&CK STIX bundle into lookups the rest of the code needs."""

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

StixObject = Mapping[str, Any]


def attack_id(obj: StixObject) -> str | None:
    """The ATT&CK ID (e.g. T1059.001) from an object's external references."""
    for ref in obj.get("external_references", ()):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def attack_url(obj: StixObject) -> str | None:
    for ref in obj.get("external_references", ()):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def is_live(obj: StixObject) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


@dataclass(frozen=True)
class AttackData:
    """Read-only view over every object in one ATT&CK release."""

    objects: tuple[StixObject, ...]
    by_stix_id: Mapping[str, StixObject]

    @classmethod
    def from_objects(cls, objects: Iterable[StixObject]) -> "AttackData":
        objs = tuple(objects)
        return cls(objs, MappingProxyType({o["id"]: o for o in objs}))

    @classmethod
    def load(cls, path: Path) -> "AttackData":
        with path.open(encoding="utf-8") as f:
            bundle = json.load(f)
        if bundle.get("type") != "bundle" or "objects" not in bundle:
            raise ValueError(f"{path} is not a STIX bundle")
        return cls.from_objects(bundle["objects"])

    def live(self, stix_type: str) -> tuple[StixObject, ...]:
        return tuple(o for o in self.objects if o["type"] == stix_type and is_live(o))

    def relationships(self, relationship_type: str) -> tuple[StixObject, ...]:
        return tuple(
            o
            for o in self.objects
            if o["type"] == "relationship"
            and o["relationship_type"] == relationship_type
            and is_live(o)
        )
