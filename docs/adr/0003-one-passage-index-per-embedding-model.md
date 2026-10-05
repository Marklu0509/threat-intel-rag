# One Passage index per embedding model

Embedding is behind a swappable interface: bge-m3 is the MVP model, and a hosted API model and bge-small-en are compared against it on the same evaluation set before choosing what to deploy. Vectors from different models are not comparable, so each model gets its own Passage index, and every index records the model name and version that produced it. Querying an index with a different model than the one that built it must fail loudly — otherwise retrieval silently degrades with no error to point at the cause.

## Consequences

Switching or upgrading the embedding model always means re-embedding all 2,091 Passages into a new index; there is no incremental migration.
