"""Judge the faithfulness of every answered question in an answer-evaluation run.

Run: .venv/bin/python scripts/judge_faithfulness.py --answers answers-groq-qwen
Reads eval/results/<answers>.json, writes eval/results/faithfulness-<answers>.json. One
OpenRouter call per answered question; each finished answer is saved as it completes, and
--resume continues an interrupted run.
"""

import argparse
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

from attack_qa.config import PROCESSED_DIR, PROJECT_ROOT
from attack_qa.faithfulness import AnswerJudgement, ClaimJudgement, judge_answer, summarize_judgements
from attack_qa.judge_model import DEFAULT_JUDGE, OpenRouterJudge
from attack_qa.passage_io import load_passages

RESULTS_DIR = PROJECT_ROOT / "eval" / "results"

logger = logging.getLogger("judge_faithfulness")


def from_dict(d: dict[str, Any]) -> AnswerJudgement:
    claims = tuple(ClaimJudgement(**{**c, "passage_ids": tuple(c["passage_ids"])})
                   for c in d["claims"])
    return AnswerJudgement(**{**d, "claims": claims})


def load_finished(progress: Path) -> dict[str, AnswerJudgement]:
    if not progress.exists():
        return {}
    lines = progress.read_text(encoding="utf-8").splitlines()
    return {(j := from_dict(json.loads(line))).id: j for line in lines if line}


def print_table(judgements: list[AnswerJudgement]) -> None:
    print("\n| group | answers | claims | supported | partial | unsupported | supported rate "
          "| completeness |\n|---|---|---|---|---|---|---|---|")
    for s in summarize_judgements(judgements):
        comp = ", ".join(f"{k} {v}" for k, v in sorted(s.completeness.items())) or "-"
        print(f"| {s.group} | {s.answers} | {s.claims} | {s.supported} | {s.partial} | "
              f"{s.unsupported} | {s.supported_rate:.1%} | {comp} |")


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--answers", required=True, help="label of an answer-evaluation run")
    parser.add_argument("--judge", default=DEFAULT_JUDGE, help="OpenRouter model id")
    parser.add_argument("--limit", type=int, default=0, help="only the first N answers (trial)")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    run = json.loads((RESULTS_DIR / f"{args.answers}.json").read_text(encoding="utf-8"))
    records = [r for r in run["questions"] if r["status"] == "answered"]
    if args.limit:
        records = records[: args.limit]
    passages = {p.passage_id: p for p in load_passages(PROCESSED_DIR / "passages.jsonl")}
    judge = OpenRouterJudge(model=args.judge)

    label = f"faithfulness-{args.answers}"
    progress = RESULTS_DIR / f"{label}.progress.jsonl"
    done = load_finished(progress) if args.resume else {}
    progress.write_text("".join(json.dumps(asdict(j), ensure_ascii=False) + "\n"
                                for j in done.values()), encoding="utf-8")
    todo = [r for r in records if r["id"] not in done]
    print(f"{len(done)} finished earlier, {len(todo)} to judge", flush=True)

    failed = []
    for i, record in enumerate(todo, start=1):
        try:
            judgement = judge_answer(record, passages, judge)
        except Exception as exc:  # keep going; rerun with --resume
            logger.warning("%s failed: %s", record["id"], exc)
            failed.append(record["id"])
            continue
        done[judgement.id] = judgement
        with progress.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(judgement), ensure_ascii=False) + "\n")
        verdicts = " ".join(c.verdict[0].upper() for c in judgement.claims)
        print(f"[{i}/{len(todo)}] {record['id']} {verdicts} | {judgement.completeness}", flush=True)

    judgements = [done[r["id"]] for r in records if r["id"] in done]
    print_table(judgements)
    if failed:
        print(f"\n{len(failed)} failed ({', '.join(failed)}); rerun with --resume")
        return
    out = RESULTS_DIR / f"{label}.json"
    out.write_text(json.dumps({
        "label": label, "answers": args.answers, "judge": judge.name,
        "summary": [{**asdict(s), "supported_rate": s.supported_rate}
                    for s in summarize_judgements(judgements)],
        "answers_judged": [asdict(j) for j in judgements],
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    progress.unlink()
    print(f"\nWrote {out.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
