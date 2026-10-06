"""Check the faithfulness judge against human labels (grill-decisions Q34).

  sheet: .venv/bin/python scripts/judge_agreement.py sheet --run faithfulness-answers-groq-qwen
         writes eval/agreement/<run>.sheet.md (judge verdicts hidden) and <run>.sample.json
  score: .venv/bin/python scripts/judge_agreement.py score --run faithfulness-answers-groq-qwen
         reads the filled sheet and prints raw agreement and linear-weighted kappa
"""

import argparse
import json
from dataclasses import asdict

from attack_qa.agreement import SheetItem, agreement_report, parse_sheet, render_sheet, sample_claims
from attack_qa.config import PROCESSED_DIR, PROJECT_ROOT
from attack_qa.passage_io import load_passages
from judge_faithfulness import RESULTS_DIR, from_dict

AGREEMENT_DIR = PROJECT_ROOT / "eval" / "agreement"
SAMPLE_SIZE = 40
SEED = 34  # fixed so the sheet can be regenerated identically
KAPPA_TARGET = 0.6


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("sheet", "score"))
    parser.add_argument("--run", required=True, help="label of a faithfulness run")
    parser.add_argument("--size", type=int, default=SAMPLE_SIZE)
    args = parser.parse_args()

    run = json.loads((RESULTS_DIR / f"{args.run}.json").read_text(encoding="utf-8"))
    answers = [from_dict(a) for a in run["answers_judged"]]
    sheet_path = AGREEMENT_DIR / f"{args.run}.sheet.md"
    sample_path = AGREEMENT_DIR / f"{args.run}.sample.json"

    if args.action == "sheet":
        if sheet_path.exists():
            raise SystemExit(f"{sheet_path.name} exists; delete it first to start over")
        sample = sample_claims(answers, size=args.size, seed=SEED)
        texts = {p.passage_id: p.text for p in load_passages(PROCESSED_DIR / "passages.jsonl")}
        AGREEMENT_DIR.mkdir(parents=True, exist_ok=True)
        sheet_path.write_text(render_sheet(sample, answers, texts), encoding="utf-8")
        sample_path.write_text(json.dumps([asdict(s) for s in sample], indent=2), encoding="utf-8")
        print(f"Wrote {sheet_path.relative_to(PROJECT_ROOT)} ({len(sample)} claims)")
        return

    sample = [SheetItem(**s) for s in json.loads(sample_path.read_text(encoding="utf-8"))]
    by_id = {a.id: a for a in answers}
    judge = {s.item_id: by_id[s.answer_id].claims[s.claim_index].verdict for s in sample}
    report = agreement_report(sample, judge, parse_sheet(sheet_path.read_text(encoding="utf-8")))
    print(f"n={report.n}  raw agreement={report.raw_agreement:.1%}  "
          f"weighted kappa={report.weighted_kappa:.3f}  (target >= {KAPPA_TARGET})")
    for item, j, h in report.disagreements:
        print(f"  {item}: judge {j}, human {h}")
    (AGREEMENT_DIR / f"{args.run}.agreement.json").write_text(
        json.dumps(asdict(report), indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
