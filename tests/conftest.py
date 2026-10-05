from collections.abc import Callable
from typing import Any

import pytest

from attack_qa.stix import AttackData

Factory = Callable[..., dict[str, Any]]


def _ref(external_id: str, kind: str) -> list[dict[str, str]]:
    path = external_id.replace(".", "/")
    return [
        {
            "source_name": "mitre-attack",
            "external_id": external_id,
            "url": f"https://attack.mitre.org/{kind}/{path}",
        }
    ]


def technique(tid: str, name: str, *, revoked: bool = False, **extra: Any) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "name": name,
        "description": f"{name} description.",
        "external_references": _ref(tid, "techniques"),
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        "x_mitre_platforms": ["Windows"],
        "revoked": revoked,
        **extra,
    }


def relationship(rel_type: str, source: str, target: str, description: str = "") -> dict[str, Any]:
    return {
        "type": "relationship",
        "id": f"relationship--{source}--{rel_type}--{target}",
        "relationship_type": rel_type,
        "source_ref": source,
        "target_ref": target,
        "description": description,
    }


def mitigation(name: str) -> dict[str, Any]:
    return {"type": "course-of-action", "id": f"course-of-action--{name}", "name": name}


@pytest.fixture
def tiny_attack() -> AttackData:
    """T1059 with one sub-technique, a no-mitigation T1056.001, and a revoked T1086."""
    objects = [
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--exec", "name": "Execution",
         "x_mitre_shortname": "execution"},
        technique("T1059", "Command and Scripting Interpreter"),
        technique("T1059.001", "PowerShell", x_mitre_is_subtechnique=True),
        technique("T1056", "Input Capture"),
        technique("T1056.001", "Keylogging", x_mitre_is_subtechnique=True),
        technique("T1086", "PowerShell", revoked=True),
        mitigation("Code Signing"),
        mitigation("Do Not Mitigate"),
        relationship("mitigates", "course-of-action--Code Signing", "attack-pattern--T1059.001",
                     "Only run signed scripts.(Citation: X)"),
        relationship("mitigates", "course-of-action--Do Not Mitigate", "attack-pattern--T1056.001"),
        {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--ps",
         "name": "Detect PowerShell abuse", "x_mitre_analytic_refs": ["x-mitre-analytic--a1"]},
        {"type": "x-mitre-analytic", "id": "x-mitre-analytic--a1", "name": "Analytic 1",
         "description": "Watch for <code>powershell.exe -enc</code>.",
         "x_mitre_platforms": ["Windows"]},
        relationship("detects", "x-mitre-detection-strategy--ps", "attack-pattern--T1059.001"),
        relationship("revoked-by", "attack-pattern--T1086", "attack-pattern--T1059.001"),
        {"type": "intrusion-set", "id": "intrusion-set--apt29", "name": "APT29",
         "aliases": ["APT29", "NobleBaron"]},
        {"type": "tool", "id": "tool--mimikatz", "name": "Mimikatz",
         "x_mitre_aliases": ["Mimikatz"]},
    ]
    return AttackData.from_objects(objects)
