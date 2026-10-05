# Three refusal gates; the relevance gate reads dense cosine, not the fused score

A question can be refused at three points, because each catches a different failure: before retrieval, a rule-based check refuses Unsupported questions by matching ATT&CK Group names and aliases and list-style phrasing; after retrieval, a relevance gate refuses when the top dense cosine similarity is below a conservative, per-model calibrated threshold (catching off-topic questions); and the LLM declares whether the retrieved Passages actually answer the question (catching on-topic questions ATT&CK doesn't answer). The relevance gate deliberately ignores the RRF score: RRF only encodes rank, so the top result always scores 1/(k+1) however irrelevant it is, and gating on it would never refuse anything.

## Considered Options

- **LLM-only refusal** — rejected because every off-topic question would cost an LLM call and hand the model irrelevant Passages it might answer from anyway.
- **Rules and threshold only** — rejected because they cannot catch an on-topic question whose answer ATT&CK simply doesn't record.
