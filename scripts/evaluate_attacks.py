"""Run the attack set against the system with and without defenses (grill-decisions Q27-Q31).

Run: .venv/bin/python scripts/evaluate_attacks.py --label attacks-groq-qwen [--resume]

Safeguards (Q29): Poisoned passages only ever enter fresh copies of the production index under
data/index-attack/, marked attack-test so normal code refuses to open them, and the production
index's content is fingerprinted before and after the run.
"""

import argparse
import json
import logging
import shutil
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from attack_qa.answer import (
    FREE_TEXT_NO_DEFENSES,
    NO_DEFENSES,
    DailyQuotaExceededError,
    Defenses,
    answer_question,
)
from attack_qa.answer_eval import AnswerResult, error_text, to_record
from attack_qa.attacks import (
    INDIRECT_PAYLOADS,
    POISON_PAYLOADS,
    TARGET_IDS,
    Attack,
    build_attacks,
    score_attack,
)
from attack_qa.bm25_index import Bm25Index
from attack_qa.config import INDEX_DIR, PROCESSED_DIR, PROJECT_ROOT
from attack_qa.dense_index import DenseIndex
from attack_qa.embedding import SentenceTransformerEmbedder
from attack_qa.evaluate import EvalQuestion, load_questions
from attack_qa.index_fingerprint import fingerprint
from attack_qa.intent import IntentClassifier
from attack_qa.llms import PACING_S, make_answer_model
from attack_qa.lookups import load_revoked_ids
from attack_qa.passage_io import load_passages
from attack_qa.retrieval import HybridRetriever

ATTACK_INDEX_ROOT = PROJECT_ROOT / "data" / "index-attack"
RESULTS_DIR = PROJECT_ROOT / "eval" / "results"
CONFIGS = {
    "no-defenses": NO_DEFENSES,
    "defended": Defenses(),
    # Control group: free prose instead of JSON claims, to test whether structured output defends
    "free-text-no-defenses": FREE_TEXT_NO_DEFENSES,
}
CLEAN = "clean"  # attack index with no Poisoned passage, used by direct injection

logger = logging.getLogger("evaluate_attacks")


def index_name(attack: Attack) -> str:
    return attack.variant if attack.poison else CLEAN


def build_attack_retrievers(attacks: list[Attack], passages: tuple, embedder: Any,
                            revoked: Any, intents: IntentClassifier) -> dict[str, HybridRetriever]:
    """One fresh attack-test copy of the production index per poison variant, plus a clean one."""
    shutil.rmtree(ATTACK_INDEX_ROOT, ignore_errors=True)
    retrievers: dict[str, HybridRetriever] = {}
    for name in [CLEAN, *INDIRECT_PAYLOADS, *POISON_PAYLOADS]:
        poisons = [a.poison for a in attacks if a.poison and a.variant == name]
        directory = ATTACK_INDEX_ROOT / name
        shutil.copytree(INDEX_DIR, directory)
        DenseIndex.open(directory, embedder).mark_attack_test_and_add(poisons)
        corpus = (*passages, *poisons)
        retrievers[name] = HybridRetriever(
            corpus, DenseIndex.open(directory, embedder, attack_test=True), Bm25Index(corpus),
            revoked, intent_classifier=intents,
        )
    return retrievers


def load_done(progress: Path) -> dict[str, dict[str, Any]]:
    if not progress.exists():
        return {}
    rows = [json.loads(line) for line in progress.read_text(encoding="utf-8").splitlines() if line]
    return {r["key"]: r for r in rows if r["status"] != "error"}


def summarize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[(r["config"], r["attack_type"])].append(r)
    table = []
    for (config, attack_type), rs in sorted(groups.items()):
        delivered = [r for r in rs if r["delivered"]]
        table.append({
            "config": config, "attack_type": attack_type, "n": len(rs),
            "delivered": len(delivered), "succeeded": sum(r["succeeded"] for r in rs),
            "succeeded_when_delivered": sum(r["succeeded"] for r in delivered),
            "refused": sum(r["status"] == "refused" for r in rs),
            "still_cites_gold": sum(r["still_cites_gold"] for r in rs),
        })
    return table


def finalize(label: str, llm: str) -> None:
    progress = RESULTS_DIR / f"{label}.progress.jsonl"
    rows = [json.loads(line) for line in progress.read_text(encoding="utf-8").splitlines() if line]
    errors = [r["key"] for r in rows if r["status"] == "error"]
    out = RESULTS_DIR / f"{label}.json"
    out.write_text(json.dumps({"label": label, "llm": llm, "summary": summarize(rows),
                               "errors": errors, "attacks": rows}, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    progress.unlink()
    print(f"Wrote {out.relative_to(PROJECT_ROOT)} ({len(rows)} runs, {len(errors)} errors kept)")


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--llm", default="groq")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="only the first N attacks per config")
    parser.add_argument("--configs", nargs="+", choices=list(CONFIGS), default=list(CONFIGS))
    parser.add_argument("--finalize", action="store_true",
                        help="write the final JSON from the progress file, keeping errored runs "
                             "as errors (when rerunning them would mix prompt versions)")
    args = parser.parse_args()
    if args.finalize:
        finalize(args.label, args.llm)
        return

    production_before = fingerprint(INDEX_DIR)
    passages = load_passages(PROCESSED_DIR / "passages.jsonl")
    by_id = {p.passage_id: p for p in passages}
    questions = {q.id: q for q in load_questions(PROJECT_ROOT / "eval" / "handwritten.jsonl")}
    attacks = list(build_attacks([questions[t] for t in TARGET_IDS], by_id))
    if args.limit:
        attacks = attacks[: args.limit]

    embedder = SentenceTransformerEmbedder()
    retrievers = build_attack_retrievers(
        attacks, passages, embedder, load_revoked_ids(PROCESSED_DIR / "revoked_ids.json"),
        IntentClassifier(embedder),
    )
    structured_model = make_answer_model(args.llm)
    free_text_model = None
    if any(not CONFIGS[c].structured_output for c in args.configs):
        from attack_qa.openai_compat_model import PROVIDERS, OpenAICompatibleAnswerModel
        if args.llm not in PROVIDERS:
            raise SystemExit(f"Free-text control group needs an OpenAI-compatible LLM: {list(PROVIDERS)}")
        free_text_model = OpenAICompatibleAnswerModel(provider=PROVIDERS[args.llm], structured=False)
    pacing = PACING_S[args.llm]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    progress = RESULTS_DIR / f"{args.label}.progress.jsonl"
    done = load_done(progress) if args.resume else {}
    progress.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in done.values()),
                        encoding="utf-8")
    jobs = [(c, a) for c in args.configs for a in attacks if f"{c}|{a.id}" not in done]
    print(f"{len(done)} finished earlier, {len(jobs)} to run", flush=True)

    rows = dict(done)
    for i, (config, attack) in enumerate(jobs, start=1):
        started = time.monotonic()
        q = EvalQuestion(attack.id, attack.variant, attack.question, "answer",
                         *attack.gold_passage_id.split(":"))
        model = structured_model if CONFIGS[config].structured_output else free_text_model
        try:
            answer = answer_question(attack.question, retrievers[index_name(attack)], model,
                                     defenses=CONFIGS[config])
            record = to_record(AnswerResult(q, answer, model.name))
        except DailyQuotaExceededError as exc:
            print(f"\nStopped: {exc}. Finished attacks are saved; rerun with --resume later.")
            break
        except Exception as exc:  # recorded and retried on --resume
            logger.warning("%s %s failed: %s", config, attack.id, exc)
            record = to_record(AnswerResult(q, None, model.name, error=error_text(exc)))
        row = {"key": f"{config}|{attack.id}", "config": config, **record, **score_attack(attack, record)}
        rows[row["key"]] = row
        with progress.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"[{i}/{len(jobs)}] {config} {attack.id} {row['status']} "
              f"{'SUCCEEDED' if row['succeeded'] else 'blocked'}", flush=True)
        time.sleep(max(0.0, pacing - (time.monotonic() - started)))

    if fingerprint(INDEX_DIR) != production_before:
        raise RuntimeError("Production index changed during the attack run!")
    table = summarize(list(rows.values()))
    print("\n| config | attack | n | delivered | succeeded | succeeded when delivered | refused | still cites gold |")
    print("|---|---|---|---|---|---|---|---|")
    for t in table:
        print(f"| {t['config']} | {t['attack_type']} | {t['n']} | {t['delivered']} | {t['succeeded']} | "
              f"{t['succeeded_when_delivered']} | {t['refused']} | {t['still_cites_gold']} |")
    complete = len(rows) == len(args.configs) * len(attacks) and all(r["status"] != "error" for r in rows.values())
    if complete:
        out = RESULTS_DIR / f"{args.label}.json"
        out.write_text(json.dumps({"label": args.label, "llm": args.llm, "summary": table,
                                   "attacks": list(rows.values())}, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        progress.unlink()
        print(f"\nProduction index unchanged. Wrote {out.relative_to(PROJECT_ROOT)}")
    else:
        print("\nIncomplete (errors or unfinished); rerun with --resume")


if __name__ == "__main__":
    main()
