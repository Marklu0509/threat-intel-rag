"""Build the three Passages of every Technique (grill-decisions Q2–Q7, Q18)."""

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from attack_qa.clean import clean_text
from attack_qa.stix import AttackData, StixObject, attack_id, attack_url, is_live

NON_MITIGATIONS = frozenset({"Do Not Mitigate", "Pre-compromise"})


class PassageKind(str, Enum):
    OVERVIEW = "Overview"
    MITIGATION = "Mitigation"
    DETECTION = "Detection"


@dataclass(frozen=True)
class Passage:
    technique_id: str
    technique_name: str
    parent_id: str | None
    parent_name: str | None
    kind: PassageKind
    text: str  # Passage heading on the first line, body below
    url: str
    attack_version: str
    no_mitigation: bool = False

    @property
    def passage_id(self) -> str:
        return f"{self.technique_id}:{self.kind.value.lower()}"


def heading(tid: str, name: str, parent: tuple[str, str] | None, kind: PassageKind) -> str:
    label = f"{tid} {name}"
    if parent:
        label += f" (sub-technique of {parent[0]} {parent[1]})"
    return f"{label} — {kind.value}"


def no_mitigation_statement(tid: str, name: str, version: str) -> str:
    return (
        f"ATT&CK v{version} lists no preventive mitigations for {tid} {name}. "
        "This technique cannot be easily prevented with preventive controls; "
        "rely on its Detection guidance instead."
    )


def _targets(data: AttackData, rel_type: str) -> Mapping[str, list[tuple[StixObject, StixObject]]]:
    """technique stix id -> [(source object, relationship)] for live sources."""
    out: dict[str, list[tuple[StixObject, StixObject]]] = defaultdict(list)
    for rel in data.relationships(rel_type):
        source = data.by_stix_id.get(rel["source_ref"])
        if source is not None and is_live(source):
            out[rel["target_ref"]].append((source, rel))
    return out


def _tactic_names(data: AttackData) -> Mapping[str, str]:
    return {t["x_mitre_shortname"]: t["name"] for t in data.live("x-mitre-tactic")}


def _overview_body(tech: StixObject, tactics: Mapping[str, str], children: list[str]) -> str:
    phases = [
        tactics.get(p["phase_name"], p["phase_name"])
        for p in tech.get("kill_chain_phases", ())
        if p.get("kill_chain_name") == "mitre-attack"
    ]
    lines = [clean_text(tech.get("description", ""))]
    lines.append("Tactics: " + ", ".join(phases))
    lines.append("Platforms: " + ", ".join(tech.get("x_mitre_platforms", ())))
    if children:
        lines.append("Sub-techniques: " + "; ".join(children))
    return "\n".join(lines)


def _mitigation_lines(pairs: list[tuple[StixObject, StixObject]]) -> list[str]:
    real = [(m, r) for m, r in pairs if m["name"] not in NON_MITIGATIONS]
    return sorted(f"- {m['name']}: {clean_text(r.get('description', ''))}" for m, r in real)


def _detection_body(data: AttackData, pairs: list[tuple[StixObject, StixObject]]) -> str:
    lines: list[str] = []
    for strategy, _ in sorted(pairs, key=lambda p: p[0]["name"]):
        lines.append(f"- {strategy['name']}")
        for ref in strategy.get("x_mitre_analytic_refs", ()):
            analytic = data.by_stix_id.get(ref)
            if analytic is None or not is_live(analytic):
                continue
            platforms = ", ".join(analytic.get("x_mitre_platforms", ()))
            lines.append(f"  - [{platforms}] {clean_text(analytic.get('description', ''))}")
    return "\n".join(lines)


def build_passages(data: AttackData, version: str) -> tuple[Passage, ...]:
    techniques = {attack_id(t): t for t in data.live("attack-pattern")}
    tactics = _tactic_names(data)
    mitigations = _targets(data, "mitigates")
    detections = _targets(data, "detects")
    children: dict[str, list[str]] = defaultdict(list)
    for tid in sorted(techniques):
        if "." in tid:
            children[tid.split(".")[0]].append(f"{tid} {techniques[tid]['name']}")

    passages: list[Passage] = []
    for tid in sorted(techniques):
        tech = techniques[tid]
        parent_id = tid.split(".")[0] if "." in tid else None
        if parent_id is not None and parent_id not in techniques:
            raise ValueError(f"{tid} has no live parent {parent_id}")
        parent = (parent_id, techniques[parent_id]["name"]) if parent_id else None

        def make(kind: PassageKind, body: str, no_mit: bool = False) -> Passage:
            return Passage(
                technique_id=tid,
                technique_name=tech["name"],
                parent_id=parent_id,
                parent_name=parent[1] if parent else None,
                kind=kind,
                text=heading(tid, tech["name"], parent, kind) + "\n" + body,
                url=attack_url(tech) or "",
                attack_version=version,
                no_mitigation=no_mit,
            )

        mit_lines = _mitigation_lines(mitigations.get(tech["id"], []))
        passages.append(make(PassageKind.OVERVIEW, _overview_body(tech, tactics, children[tid])))
        passages.append(
            make(PassageKind.MITIGATION, "\n".join(mit_lines))
            if mit_lines
            else make(
                PassageKind.MITIGATION,
                no_mitigation_statement(tid, tech["name"], version),
                no_mit=True,
            )
        )
        passages.append(
            make(PassageKind.DETECTION, _detection_body(data, detections.get(tech["id"], [])))
        )
    return tuple(passages)
