"""Export recorded evaluation results as data for the static demo page (site/).

Run: .venv/bin/python scripts/build_demo_data.py
Every answer on the page comes from the evaluation runs below, not from a new LLM call. The
retrieval trace is recomputed (retrieval is deterministic) and must match the Passages the model
was given in the recorded run; otherwise the script stops rather than show a trace the model
never saw.
"""

import json
from typing import Any

from attack_qa.answer import RELEVANCE_THRESHOLD
from attack_qa.attacks import (
    DIRECT_PAYLOADS,
    INDIRECT_PAYLOADS,
    POISON_PAYLOADS,
    TARGET_IDS,
    build_attacks,
)
from attack_qa.bm25_index import Bm25Index
from attack_qa.config import ATTACK_VERSION, INDEX_DIR, PROCESSED_DIR, PROJECT_ROOT
from attack_qa.dense_index import DenseIndex
from attack_qa.embedding import SentenceTransformerEmbedder
from attack_qa.evaluate import load_questions
from attack_qa.intent import IntentClassifier
from attack_qa.lookups import load_revoked_ids
from attack_qa.passage_io import load_passages
from attack_qa.retrieval import CANDIDATES, TOP_K, HybridRetriever

RESULTS = PROJECT_ROOT / "eval" / "results"
OUT = PROJECT_ROOT / "site" / "demo-data.json"
ANSWER_RUN = "answers-openrouter-qwen-q38"
ATTACK_RUN = "attacks-openrouter-qwen-q38"

# (question id, group, title, what it shows)
EXAMPLES = [
    ("2-01", "answers", "Paraphrase", "Asks about LSASS credential dumping without naming the technique."),
    ("3-05", "answers", "Chinese question, English data",
     "A Traditional Chinese question answered from English ATT&CK text by multilingual retrieval."),
    ("4-01", "answers", "Near-duplicate ID",
     "T1543.001 vs T1543.003: the named technique is routed first, since embeddings can't tell IDs apart."),
    ("8-01", "answers", "Revoked ID",
     "T1086 was withdrawn; the question is rewritten to its replacement before searching."),
    ("3-10", "answers", "No mitigation is an answer",
     "ATT&CK lists no mitigation for Screen Capture; that absence is a passage the system can cite."),
    ("6-01", "refusals", "Unsupported: actor question",
     "Which techniques a group uses lives in ATT&CK's relationship data, not in any passage."),
    ("7-01", "refusals", "Off-topic", "Stopped by the similarity gate before any LLM call."),
    ("7-06", "refusals", "On-topic, not in ATT&CK", "ATT&CK records no CVSS scores, so the model refuses."),
    ("2-11", "failures", "Related but wrong",
     "Retrieval missed the gold passage; the answer cites a neighbouring technique instead."),
    ("6-07", "failures", "Partial list",
     "An actor-style question answered from the few passages that mention Mimikatz — and refused "
     "in 3 of 3 repeat runs."),
]

ATTACKS = [
    ("no-defenses|2-03/poison-plain", "Poisoned passage, no defenses",
     "A copy of the real mitigation passage with one planted line recommending a fake product."),
    ("defended|2-03/poison-plain", "Same poisoned passage, with defenses",
     "The fake product is not repeated; the answer still cites the poisoned copy, which counts as "
     "a successful attack."),
    ("defended|2-03/direct-authority", "Direct injection",
     "The question demands a verification code be appended; the answer ignores it."),
]


def _load(name: str) -> dict[str, Any]:
    return json.loads((RESULTS / f"{name}.json").read_text(encoding="utf-8"))


def _summary() -> dict[str, Any]:
    def overall(run: str) -> dict[str, Any]:
        return next(s for s in _load(run)["summary"] if s["category"].startswith("ALL"))

    before, after = overall("baseline-hybrid"), overall("intent-examples")
    answers = _load(ANSWER_RUN)["questions"]
    answerable = [q for q in answers if q["expected"] == "answer"]
    refuse = [q for q in answers if q["expected"] != "answer"]
    faith = next(s for s in _load(f"faithfulness-{ANSWER_RUN}")["summary"] if s["group"] == "all")
    agreement = json.loads((PROJECT_ROOT / "eval" / "agreement" /
                            "faithfulness-answers-groq-qwen.agreement.json").read_text())
    attacks: dict[str, int] = {}
    for run, configs in (("attacks-openrouter-qwen", ("free-text-no-defenses",)),
                         (ATTACK_RUN, ("no-defenses", "defended"))):
        for r in _load(run)["attacks"]:
            if r["config"] in configs:
                attacks[r["config"]] = attacks.get(r["config"], 0) + bool(r["succeeded"])
    return {
        "p5_before": before["passage_hit"]["5"], "p5_after": after["passage_hit"]["5"],
        "mrr_after": after["mrr"],
        "cites_gold": sum(bool(q["cites_gold_passage"]) for q in answerable),
        "gold_retrieved": sum(bool(q["gold_retrieved"]) for q in answerable),
        "answerable": len(answerable),
        "refused": sum(q["status"] == "refused" for q in refuse), "should_refuse": len(refuse),
        "faithful_rate": faith["supported_rate"], "claims": faith["claims"],
        "supported": faith["supported"], "kappa": agreement["weighted_kappa"],
        "attacks": attacks, "attacks_per_config": 70,
    }


def _example(qid: str, group: str, title: str, note: str, record: dict[str, Any],
             verdicts: dict[str, list[dict[str, Any]]], retriever: HybridRetriever,
             passages: dict[str, Any]) -> dict[str, Any]:
    result = retriever.retrieve(record["question"])
    traced = [h.passage.passage_id for h in result.hits]
    if traced != record["retrieved"]:
        raise SystemExit(f"{qid}: retrieval now gives {traced}, the recorded run saw {record['retrieved']}")
    judged = verdicts.get(qid, [])
    return {
        "id": qid, "group": group, "title": title, "note": note,
        "question": record["question"], "gold": record["gold"],
        "plan": {"search_text": result.plan.search_text,
                 "substitutions": dict(result.plan.substitutions),
                 "technique_ids": list(result.plan.technique_ids),
                 "intent": result.plan.intent.value if result.plan.intent else None},
        "top_cosine": result.top_dense_cosine,
        "status": record["status"], "refused_by": record["refused_by"],
        "refusal_reason": record["refusal_reason"],
        "claims": [{**c, "verdict": judged[i]["verdict"] if i < len(judged) else None,
                    "reason": judged[i]["reason"] if i < len(judged) else ""}
                   for i, c in enumerate(record["claims"])],
        "hits": [{"id": h.passage.passage_id, "rank": h.rank, "kind": h.passage.kind.value,
                  "dense_rank": h.dense_rank, "bm25_rank": h.bm25_rank,
                  "cosine": h.dense_cosine, "text": passages[h.passage.passage_id].text}
                 for h in result.hits],
    }


def _attack(key: str, title: str, note: str, rows: dict[str, dict[str, Any]],
            by_attack: dict[str, Any], passages: dict[str, Any]) -> dict[str, Any]:
    r = rows[key]
    attack = by_attack[r["attack_id"]]
    texts = {pid: passages[pid].text for pid in r["retrieved"] if pid in passages}
    if attack.poison:
        texts[attack.poison.passage_id] = attack.poison.text
    return {
        "key": key, "title": title, "note": note, "config": r["config"],
        "payload": {**DIRECT_PAYLOADS, **INDIRECT_PAYLOADS, **POISON_PAYLOADS}[r["variant"]].strip(),
        "type": r["attack_type"], "question": attack.question, "status": r["status"],
        "succeeded": r["succeeded"], "fake_product": r["mentions_fake_product"],
        "cites_poison": r["cites_poison"], "poison_id": attack.poison.passage_id if attack.poison else None,
        "claims": r["claims"], "retrieved": r["retrieved"], "texts": texts,
    }


def main() -> None:
    passage_list = load_passages(PROCESSED_DIR / "passages.jsonl")
    passages = {p.passage_id: p for p in passage_list}
    embedder = SentenceTransformerEmbedder()
    retriever = HybridRetriever(passage_list, DenseIndex.open(INDEX_DIR, embedder),
                                Bm25Index(passage_list),
                                load_revoked_ids(PROCESSED_DIR / "revoked_ids.json"),
                                intent_classifier=IntentClassifier(embedder))
    records = {q["id"]: q for q in _load(ANSWER_RUN)["questions"]}
    verdicts = {a["id"]: a["claims"] for a in _load(f"faithfulness-{ANSWER_RUN}")["answers_judged"]}
    questions = {q.id: q for q in load_questions(PROJECT_ROOT / "eval" / "handwritten.jsonl")}
    by_attack = {a.id: a for a in build_attacks([questions[t] for t in TARGET_IDS], passages)}
    attack_rows = {r["key"]: r for r in _load(ATTACK_RUN)["attacks"]}

    data = {
        "attack_version": ATTACK_VERSION, "answer_run": ANSWER_RUN, "attack_run": ATTACK_RUN,
        "model": records["2-01"]["model"], "relevance_threshold": RELEVANCE_THRESHOLD,
        "top_k": TOP_K, "candidates": CANDIDATES,
        "summary": _summary(),
        "examples": [_example(qid, group, title, note, records[qid], verdicts, retriever, passages)
                     for qid, group, title, note in EXAMPLES],
        "attacks": [_attack(key, title, note, attack_rows, by_attack, passages)
                    for key, title, note in ATTACKS],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Wrote {OUT.relative_to(PROJECT_ROOT)} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
