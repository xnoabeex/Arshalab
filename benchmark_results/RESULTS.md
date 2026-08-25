# Benchmark Results

Headline results reported in the paper, with pointers to the raw artifacts that
produce them. All numbers are over three independent runs across three cases
(KDFS 2023, Magnet CTF 2022, Hunter 4orensics).

## 1. Interactive question answering

100 reference questions per case, three runs per question, seven models
(300 questions × 3 runs × 7 models = 6,300 runs). Recall is the fraction of
reference key entities present in the answer; precision back-checks each asserted
fact against the case index; the hallucination rate is the fraction of asserted
structured facts absent from the index; consistency is the fraction of reference
entities present in all three runs; BERTScore F1 measures phrasing closeness to
the reference answer. Full methodology: [../docs/QA_BENCHMARK.md](../docs/QA_BENCHMARK.md).

| Model | KDFS | Magnet | Hunter | Mean | Halluc. | BERT F1 | Consist. |
|-------|-----:|-------:|-------:|-----:|--------:|--------:|---------:|
| DeepSeek V3        | 96.77 | 98.83 | 96.33 | 97.31 | 1.46 | 0.9113 | 94.10 |
| Claude Opus 4.1    | 96.08 | 97.92 | 96.50 | 96.83 | 1.18 | 0.8498 | 94.70 |
| Claude Sonnet 4.5  | 96.79 | 95.29 | 96.88 | 96.32 | 1.18 | 0.8481 | 93.50 |
| OpenAI GPT-5.1     | 93.24 | 87.50 | 86.89 | 89.21 | 1.68 | 0.8644 | 84.90 |
| Llama 3.1 8B + RAG | 87.56 | 69.50 | 72.58 | 76.55 | 0.00 | 0.8460 | 74.39 |
| Qwen 2.5 14B + RAG | 83.42 | 66.75 | 71.29 | 73.82 | 0.04 | 0.8558 | 71.08 |
| Phi-4 14B + RAG    | 86.42 | 70.60 | 71.33 | 76.12 | 0.35 | 0.8514 | 70.32 |

Recall and hallucination in percent, BERTScore F1 in [0,1], consistency in
percent. All seven models are scored against one common grading key. An earlier
configuration preferred a provider-specific question file where one existed, and
one existed only for OpenAI; 46 of the 300 questions carried a shorter key-entity
list there. The OpenAI row above is re-scored against the common key that the
other six models always faced.

Per-model question-answering outputs are under [`qa/`](qa/) and
[`answers/`](answers/):

| Model | Source |
|-------|--------|
| DeepSeek V3 | `qa/deepseek_{kdfs,magnet,hunter}_3run_summary.json` (per-case, three runs; 96.77 / 98.83 / 96.33), `qa/deepseek_kdfs_per_question.json` |
| Claude Opus 4.1 | `qa/claude_opus_per_question.json` (300 questions, three cases) |
| Claude Sonnet 4.5 | `qa/claude_sonnet_per_question.json` (300 questions, three cases) |
| Llama 3.1 8B / Qwen 2.5 14B / Phi-4 14B | [`local_rag_metrics.json`](local_rag_metrics.json), per-model aggregate from `eval_local_rag.py` |
| OpenAI GPT-5.1 | raw answers in `answers/OpenAI_GPT-5.1.json` (900 answers); re-score against the common key with `python benchmark.py --providers openai --case-id <case_id> --runs 3` |

## 2. Autonomous attack-chain reconstruction

Four cloud models × three cases × three runs = 36 reconstructed chains. The
composite is

```
composite = 0.30 * step + 0.30 * tactic + 0.25 * (1 - halluc) + 0.15 * ordering
```

Step coverage is milestone coverage, the share of high-level incident milestones
recovered. Full methodology: [../docs/EVALUATION.md](../docs/EVALUATION.md).

| Model | KDFS | Magnet | Hunter | Mean | Step | Tactic | Order | Halluc. | Time (s) |
|-------|-----:|-------:|-------:|-----:|-----:|-------:|------:|--------:|---------:|
| DeepSeek V3       | 90.43 | 91.62 | 88.83 | 90.29 | 97.78 | 79.82 | 80.10 | 0.00 | 13.5 |
| Claude Opus 4.1   | 92.64 | 90.53 | 92.92 | 92.03 | 98.61 | 83.27 | 83.11 | 0.00 | 57.8 |
| Claude Sonnet 4.5 | 90.33 | 91.90 | 87.59 | 89.94 | 96.67 | 79.82 | 79.97 | 0.00 | 54.2 |
| OpenAI GPT-5.1    | 95.73 | 92.41 | 95.10 | 94.41 | 96.67 | 90.43 | 88.55 | 0.00 | 47.0 |

Composite and sub-metrics in percent, time in seconds. Mean composite over the
36 chains is 91.67 percent, with 0 ungrounded events across 1,285 chain steps.

- **Raw chains and per-run scores** are in
  [`mode2_final/`](mode2_final/): `<provider>/<case>/control/chain_<case>_<provider>_run{1,2,3}.json`
  (the reconstructed chain) and `*.mode2_score.json` (its score). Each case's
  `evidence_<case>.json` in the same folder is the **98-anchor evidence pool**
  (the Stage-1 output of the anchors documented in [`../ANCHORS.md`](../ANCHORS.md)).
  The earlier `mode2_v2` run set is retained under `_superseded/` only; it
  predates the 31 July 2026 anchor fix and must not be cited.
- Reproduce one cell with `retrieve_evidence_v2.py` → `reconstruct_timeline.py`
  → `score_timeline_mode2.py` (see the main README).

## 3. Efficiency vs. the manual baseline

Manual baseline of twelve practitioners who worked the same three cases without
the platform. The comparison is drawn phase by phase, because only some phases
are comparable. Extraction and parsing followed by timeline construction is
matched against ArshaLab's ETL followed by one autonomous chain reconstruction.
ETL timing is in [`etl_timing_summary.json`](etl_timing_summary.json); detailed
per-question latency and per-run chain time are in
[`LATENCY_TIME_TABLES.md`](LATENCY_TIME_TABLES.md).

| Case | Manual, extract + timeline (h) | ArshaLab, ETL + chain (min) | Speedup |
|------|-------------------------------:|----------------------------:|--------:|
| KDFS 2023        |  6.1 | 23.1 |  16× |
| Magnet CTF 2022  |  9.6 | 18.4 |  31× |
| Hunter 4orensics | 10.8 |  2.9 | 223× |

Investigation time by phase, twelve-practitioner means given as the range over
the three cases:

| Phase | Twelve practitioners | ArshaLab |
|-------|----------------------|----------|
| Extraction and parsing       | 3.1 to 5.0 h | 2 min to 22 min |
| Timeline construction        | 3.0 to 5.8 h | 14 s to 58 s |
| Verification of every event  | 3.7 to 6.5 h | performed by the user, not measured |

Per-case total effort was 9.8 h on KDFS 2023, 14.5 h on Magnet CTF 2022, and
17.3 h on Hunter 4orensics. ETL alone is 22:18 on KDFS 2023, 17:44 on Magnet CTF
2022, and 02:15 on Hunter 4orensics. Per-question latency means: cloud 5.65 s
(OpenAI GPT-5.1) to 35.49 s (DeepSeek V3); local 2.91 s to 3.75 s.
