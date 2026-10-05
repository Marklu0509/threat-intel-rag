# Passages follow ATT&CK's structure, not a fixed size

We split ATT&CK into Passages along its own structure instead of fixed-size chunks: every Technique and Sub-technique gets exactly three Passages (Overview, Mitigation, Detection), each starting with a Passage heading that names its Technique. ATT&CK already separates these topics, so cutting along those lines keeps each Passage on one topic without severing a list mid-way, and the heading keeps a Passage tied to its Technique once it stands alone. A Technique with no mitigations still gets a Mitigation Passage holding a No-mitigation statement, because otherwise a mitigation question would retrieve some *other* Technique's mitigations and the LLM could answer from them.

## Considered Options

- **One Passage per Technique (all topics merged)** — rejected because one vector covering an overview, up to 11 mitigations and up to 9 analytics dilutes every topic. Kept as a baseline to compare against in evaluation.
- **One Passage per individual mitigation or analytic** — rejected because "how do I mitigate T1059?" needs all 9 items, which a top-k retrieval would return only partially.
