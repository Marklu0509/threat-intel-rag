# Resolve Revoked IDs before retrieval

ATT&CK v19.2 has revoked 149 Technique IDs and replaced them (T1070.001 → T1685.005, T1562.001 → T1685, T1574.002 → T1574.001), yet older reports and analysts still use the old IDs. A Revoked ID has no Passage, so BM25 cannot match it and dense retrieval can return a look-alike Technique instead (such as T1070.004 File Deletion), producing a confident answer about the wrong Technique. Before retrieval we therefore rewrite any Revoked ID in the question to its current replacement, using ATT&CK's own `revoked-by` relationships, and the answer states the substitution ("T1070.001 was replaced by T1685.005 in ATT&CK v19.2").

## Considered Options

- **Refuse questions with a Revoked ID** — rejected: safe but unhelpful, when ATT&CK itself records the replacement.
- **Do nothing** — rejected: the look-alike answer is wrong in a way neither the user nor the refusal gates would notice.

## Consequences

The mapping is rebuilt from the data for each ATT&CK release. Three revocations are chained (an ID revoked by an ID that was itself later revoked), so resolution follows the chain to a live Technique.
