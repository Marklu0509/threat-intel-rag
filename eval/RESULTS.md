# Retrieval evaluation log

Evaluation set: [`handwritten.jsonl`](handwritten.jsonl) — 53 answerable questions across paraphrase,
cross-lingual (Traditional Chinese), near-ID and Revoked-ID categories, plus 25 that should be refused.
Embedding model: BAAI/bge-m3 · ATT&CK v19.2 · 2,091 Passages · top-10 retrieved per question.

**P@k** = Passage hit@k (right Technique *and* right Passage kind — the headline metric).
**T@5** = Technique hit@5 (right Technique, any kind — diagnostic only).
Per-question details are in `results/<label>.json`.

## Answerable questions (n = 53)

| Run | Change | P@1 | P@5 | P@10 | T@5 | MRR |
|---|---|---|---|---|---|---|
| `baseline-hybrid-bm25bug` | BM25 + dense, RRF (k=60) | 15.1% | 43.4% | 54.7% | 60.4% | 0.275 |
| `baseline-hybrid` | BM25 stops returning zero-score Passages | 20.8% | 47.2% | 56.6% | 66.0% | 0.319 |
| `query-understanding` | Revoked IDs rewritten, named Techniques first, intent-matching kinds next | **69.8%** | **83.0%** | **86.8%** | **83.0%** | **0.754** |

## By category, P@5

| Category | n | baseline-hybrid | query-understanding |
|---|---|---|---|
| paraphrase | 15 | 46.7% | 66.7% |
| cross-lingual | 15 | 73.3% | 73.3% |
| near-ID | 15 | 46.7% | 100.0% |
| Revoked ID | 8 | 0.0% | 100.0% |

## What each change taught us

- **Zero-score BM25 hits poisoned RRF.** BM25 returned every Passage, including ones sharing no term
  with the question; they still got a rank and RRF credited it. Chinese questions match almost no
  English terms, so their BM25 list was mostly noise. Dropping zero-score hits lifted cross-lingual
  P@5 from 60.0% to 73.3%.
- **RRF buries an exact-ID match the dense model misses.** For "T1053.003 detection", BM25 ranks the
  gold Passage 1st but dense doesn't return it in its top 50, so it scores 1/61 and loses to
  Passages both lists rank mid-way (≈ 2/70). Putting Passages of the named Technique first took
  near-ID from 46.7% to 100%.
- **Revoked IDs fail silently without a rewrite.** All 8 questions using a Revoked ID retrieved
  look-alike Techniques (T1086 → T1087 Account Discovery) until the ID was rewritten to its
  replacement.

## Intent detection (Q24)

Intent decides which Passage kind gets moved forward. Keyword rules recognise all 53 evaluation
questions — but they were written while looking at those questions, so that number is leaked.
Two separate intent sets measure it honestly: `intent_dev.jsonl` was used to choose the example
questions and the confidence margin; `intent_test.jsonl` was written afterwards in deliberately
different styles (terse keywords, typos, mixed Chinese/English, role-based, indirect) and scored once.

| Set | Method | Right | Wrong | No intent (no boost) |
|---|---|---|---|---|
| dev (20) | keyword rules | 1 | 0 | 19 |
| dev (20) | rules, then example similarity | 19 | 0 | 1 |
| **test (20)** | keyword rules | 4 | 0 | 16 |
| **test (20)** | **rules, then example similarity** | **16** | **1** | **3** |

Retrieval scores on the 53 questions are unchanged (`intent-examples` run), since the rules already
cover them; the gain is for phrasings the rules never anticipated.

## Open issues

- **Intent boost trades Technique recall for kind precision.** Ordering every intent-matching
  Passage ahead of other kinds raised P@1 sharply but lowered T@5 for paraphrase (73.3% → 66.7%) and
  cross-lingual (86.7% → 73.3%): a matching kind from the wrong Technique can now outrank the right
  Technique. A gentler boost is worth testing.
- **9 answerable questions still miss.** Most never retrieve the right Technique at all (semantic
  misses such as "recording what users type" → Keylogging). Candidates: a cross-encoder reranker
  (Q13) and comparing embedding models (Q11).
- **Refusal separation is thin.** Mean top cosine is 0.615 for answerable questions vs 0.498
  (Unsupported) and 0.461 (Unanswerable); a relevance threshold will need careful calibration.
