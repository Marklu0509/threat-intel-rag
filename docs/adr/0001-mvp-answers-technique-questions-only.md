# MVP answers Technique questions only

The MVP answers only Technique questions (what a Technique is, how to detect it, how to mitigate it) and refuses Actor questions ("Which techniques does APT29 use?", "Does FIN7 use spearphishing?", "Which groups use T1059.001?") and Aggregate questions ("Which techniques affect macOS?"). The deciding reason is where the answer lives: Actor and Aggregate answers exist only in ATT&CK's relationship data or across the whole dataset, never in any Passage's text, so retrieval cannot surface them and the LLM would answer from its own memory. That holds even for yes/no Actor questions, whose answer is short. Long list answers make it worse — APT29 alone uses 66 Techniques — because a top-k retrieval would return a partial list the LLM could present as complete.

## Consequences

Answering Actor and Aggregate questions properly needs a structured lookup the LLM calls as a tool, not retrieval. That is planned for a later version. The evaluation set includes Unsupported questions — including the easily misclassified ones that mention a Technique ID — to confirm the service refuses them.
