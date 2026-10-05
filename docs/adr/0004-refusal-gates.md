# Two refusal gates; the relevance gate reads dense cosine, not the fused score

A question can be refused at two points, because each catches a different failure. After retrieval, a relevance gate refuses when the top dense cosine similarity is below a conservative, per-model calibrated threshold, catching off-topic questions without an LLM call. Then the LLM declares whether the retrieved Passages actually answer the question, catching both on-topic questions ATT&CK doesn't answer and Actor and Aggregate questions, whose answers never appear in any Passage. The relevance gate deliberately ignores the RRF score: RRF only encodes rank, so the top result always scores 1/(k+1) however irrelevant it is, and gating on it would never refuse anything.

## Considered Options

- **A pre-retrieval gate that refuses questions naming a Group or software** — originally planned, then dropped before implementation. ATT&CK registers everyday commands as software (`cmd`, `net`, `at`, `schtasks`, `certutil`, `reg`), so name matching refused ordinary Technique questions ("How do I detect schtasks abuse?") and, with naive substring matching, almost every question ("wh**at**"). Requiring actor-style phrasing as well would still be a brittle rule. The LLM gate already refuses these questions for the right reason — the Passages hold no answer — so the evaluation set's Unsupported questions measure whether it does; a narrower rule is added only if those numbers show it is needed.
- **LLM-only refusal** — rejected because every off-topic question would cost an LLM call and hand the model irrelevant Passages it might answer from anyway.
- **Rules and threshold only** — rejected because they cannot tell when retrieved, on-topic Passages still don't contain the answer.

## Consequences

Every Actor or Aggregate question costs one LLM call. The actor-name list is kept for a later version, where it identifies which Group or software a question is about so the question can be answered from ATT&CK's relationship data instead of refused.
