"""Read and write Passages as JSON Lines."""

import json
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path

from attack_qa.passages import Passage, PassageKind


def to_record(p: Passage) -> dict[str, object]:
    return {"passage_id": p.passage_id, **asdict(p), "kind": p.kind.value}


def from_record(record: dict[str, object]) -> Passage:
    fields = {k: v for k, v in record.items() if k != "passage_id"}
    fields["kind"] = PassageKind(fields["kind"])
    return Passage(**fields)  # type: ignore[arg-type]


def write_passages(passages: Iterable[Passage], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for p in passages:
            f.write(json.dumps(to_record(p), ensure_ascii=False) + "\n")


def load_passages(path: Path) -> tuple[Passage, ...]:
    if not path.exists():
        raise FileNotFoundError(f"{path} not found; run scripts/build_passages.py first")
    with path.open(encoding="utf-8") as f:
        return tuple(from_record(json.loads(line)) for line in f if line.strip())
