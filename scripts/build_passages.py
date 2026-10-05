"""Download the pinned ATT&CK release and write Passages and lookup tables.

Run: .venv/bin/python scripts/build_passages.py
Outputs in data/processed/: passages.jsonl, revoked_ids.json, actor_names.json
"""

import json
import logging
from dataclasses import asdict
from pathlib import Path

from attack_qa.config import ATTACK_VERSION, PROCESSED_DIR, RAW_PATH
from attack_qa.download import download
from attack_qa.lookups import actor_names, revoked_ids
from attack_qa.passages import Passage, build_passages
from attack_qa.stix import AttackData

logger = logging.getLogger("build_passages")


def _passage_record(p: Passage) -> dict[str, object]:
    return {"passage_id": p.passage_id, **asdict(p), "kind": p.kind.value}


def write_outputs(data: AttackData, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    passages = build_passages(data, ATTACK_VERSION)
    with (out_dir / "passages.jsonl").open("w", encoding="utf-8") as f:
        for p in passages:
            f.write(json.dumps(_passage_record(p), ensure_ascii=False) + "\n")
    (out_dir / "revoked_ids.json").write_text(
        json.dumps(dict(sorted(revoked_ids(data).items())), indent=2), encoding="utf-8"
    )
    (out_dir / "actor_names.json").write_text(
        json.dumps(sorted(actor_names(data)), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logger.info(
        "Wrote %d Passages (%d No-mitigation statements) to %s",
        len(passages),
        sum(p.no_mitigation for p in passages),
        out_dir,
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    data = AttackData.load(download(RAW_PATH))
    write_outputs(data, PROCESSED_DIR)


if __name__ == "__main__":
    main()
