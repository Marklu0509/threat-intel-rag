"""Was each answer written in the language its question asked for? (grill-decisions Q58)

Run: .venv/bin/python scripts/check_language.py eval/results/answers-openrouter-qwen-q38.json
Reads saved runs only; no model is called.
"""

import json
import sys
from pathlib import Path

from attack_qa.language import answer_language, language_report


def main() -> None:
    for name in sys.argv[1:]:
        records = json.loads(Path(name).read_text(encoding="utf-8"))["questions"]
        report = language_report(records)
        print(f"{Path(name).name}: {report.matched}/{report.checked}")
        by_id = {r["id"]: r for r in records}
        for qid in report.mismatched:
            r = by_id[qid]
            text = " ".join(c["text"] for c in r["claims"]) or r["refusal_reason"]
            print(f"  {qid} [{answer_language(r['question'])}] {r['question'][:40]!r} -> {text[:60]!r}")


if __name__ == "__main__":
    main()
