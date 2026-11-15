# Benchmark Results

Headline results reported in the paper, with pointers to the raw artifacts that
produce them, across three cases (KDFS 2023, Magnet CTF 2022, Hunter
4orensics). Question answering and chain reconstruction are reported over three
runs per question or chain and model; the closed-book control is a single run.

## 1. Interactive question answering (Table 5)

100 reference questions per case and seven models. The released answer set in
[`answers/`](answers/) holds 6,290 completed answers, three completed runs per
question and model, except Claude Opus KDFS40 and Claude Sonnet KDFS61 to KDFS69,
which have two because their other attempts failed at the model interface. Where
the logs held more than three completed answers to a question (GPT-5.1, Claude
Sonnet and the three local models), the set keeps the first three in time order.
For DeepSeek V3.2 the set holds the three runs per case that each answered all
100 questions in one session. Its earlier complete sessions answered earlier
versions of the question texts, and its passes over a case in separate batches
are not included.

Every column below is produced by one script, with the scorer in `benchmark.py`
and the common key in `benchmark/questions/<case>.json` for all seven models:

```
python reproduce_qa_table.py
```

Recall is the fraction of reference key entities present in the answer. Precision
and the hallucination rate are computed over the Event IDs and executable names
an answer contains, checked against the case index. An answer with no such
identifier counts as precision 1 and hallucination 0, and coverage is the share
of answers with at least one checked identifier. BERTScore F1 measures closeness
of wording to the reference answer. These measures are averaged over the
completed runs of a question, then over the questions of a case and then over
the three cases. Consistency is the fraction of reference entities present in
all three runs, over the questions with three completed runs. Full methodology:
[../docs/QA_BENCHMARK.md](../docs/QA_BENCHMARK.md).

| Model | KDFS | Magnet | Hunter | Mean | Prec. | Halluc. | BERT F1 | Consist. | Coverage |
|-------|-----:|-------:|-------:|-----:|------:|--------:|--------:|---------:|---------:|
| DeepSeek V3.2      | 96.94 | 97.33 | 96.33 | 96.87 | 98.99 | 1.01 | 0.9045 | 93.93 | 44.6 |
| Claude Opus 4.1    | 96.67 | 97.83 | 96.50 | 97.00 | 99.12 | 0.88 | 0.8460 | 94.73 | 43.2 |
| Claude Sonnet 4.5  | 96.44 | 94.67 | 96.83 | 95.98 | 99.16 | 0.84 | 0.8434 | 93.34 | 42.2 |
| OpenAI GPT-5.1     | 93.24 | 87.50 | 86.89 | 89.21 | 98.83 | 1.17 | 0.8648 | 84.88 | 31.7 |
| Llama 3.1 8B + RAG | 87.56 | 68.94 | 72.67 | 76.39 | 100.00 | 0.00 | 0.8431 | 74.22 | 31.3 |
| Qwen 2.5 14B + RAG | 83.42 | 66.83 | 71.17 | 73.81 | 100.00 | 0.00 | 0.8550 | 71.08 | 21.0 |
| Phi-4 14B + RAG    | 83.82 | 70.00 | 71.44 | 75.09 | 99.94 | 0.06 | 0.8468 | 70.32 | 28.9 |

Recall, precision, hallucination, consistency and coverage in percent, BERTScore
F1 in [0,1]. The per-model summaries under [`qa/`](qa/) and
`summaries/local_rag_metrics.json` were computed for the submitted version with
per-model scripts and answer sets, and the table above supersedes them.

## 2. Closed-book control (Table 6)

Each of the four cloud models answered the same 300 questions with the case
index withheld and every forensic tool disabled. The answers are in
[`closed_book/`](closed_book/), one file of 100 answers per model and case.
Key entities that the question wording itself supplies are left out, which
leaves 1,244 entity checks across the 1,200 answers. The automatic matching
procedure credits 82 of them, or 6.6 percent, and no model-case combination
exceeds 15.8 percent. The table is produced by

```
python reproduce_closed_book_table.py
```

which re-matches every answer against the common key in
`benchmark/questions/<case>.json`; the `found`, `missing` and `recall` fields
stored in the answer files are those of the original run and are not used.

| Model | KDFS | Magnet | Hunter |
|-------|-----:|-------:|-------:|
| DeepSeek V4 Flash | 7.1 | 1.7 | 5.3 |
| Claude Opus 4.1   | 8.1 | 2.6 | 9.5 |
| Claude Sonnet 4.5 | 4.0 | 0.0 | 9.5 |
| OpenAI GPT-5.1    | 15.2 | 4.3 | 15.8 |

Credited share of the entity checks, in percent. The DeepSeek run was served by
a later version of the model than the answers in Section 1, so its row describes
that later version.

## 3. Chain reconstruction (Tables 7 and 8, Appendix C)

Four cloud models × three cases × three runs = 36 reconstructed chains, each
built from the evidence pool of the 105 anchors documented in
[`../ANCHORS.md`](../ANCHORS.md). The composite is

```
composite = 0.30 * step + 0.30 * tactic + 0.25 * (1 - halluc) + 0.15 * ordering
```

Step coverage is milestone coverage, the share of high-level incident milestones
recovered. Full methodology: [../docs/EVALUATION.md](../docs/EVALUATION.md).

| Model | KDFS | Magnet | Hunter | Mean | Step | Tactic | Order | Halluc. | Time (s) |
|-------|-----:|-------:|-------:|-----:|-----:|-------:|------:|--------:|---------:|
| DeepSeek V4.1 Flash | 92.10 | 91.95 | 93.17 | 92.40 | 98.89 | 85.74 | 80.10 | 0.00 | 11.5 |
| Claude Opus 4.8     | 91.97 | 89.39 | 90.47 | 90.61 | 92.78 | 84.75 | 82.90 | 0.34 | 46.9 |
| Claude Sonnet 4.5   | 93.71 | 91.59 | 84.28 | 89.86 | 91.11 | 84.51 | 81.17 | 0.00 | 43.2 |
| OpenAI GPT-5.1      | 96.50 | 91.74 | 96.95 | 95.06 | 98.89 | 90.43 | 88.66 | 0.14 | 40.2 |

Composite and sub-metrics in percent; time is the mean duration of the model call
per chain, in seconds. The mean composite over the twelve model-case
combinations is 91.98 percent, and eleven of them exceed 85 percent. The
evidence-grounding check tests all 1,473 steps the chains write and finds two
unsupported timestamps and no unsupported extracted entity.

Retrieval-only baseline (Table 8). The same 105 anchor queries with no model in
the loop: the first time-stamped record of every anchor in one variant and the
first two in another, ordered by time and sampled evenly down to the mean length
of the model chains on the case (40 events on KDFS_2023, 44 on Magnet CTF 2022,
39 on Hunter 4orensics). The figures are the mean of the two variants.

| | Anchors only | Anchors and a model |
|---|---:|---:|
| Reference events matched | 6.0 | 13.8 |
| Step coverage (%) | 32.50 | 95.42 |
| Tactic coverage (%) | 63.52 | 86.36 |
| Ordering, pooled over comparable pairs (%) | 83.33 | 85.39 |
| Composite (%) | 66.36 | 91.98 |

Under the 1,771 weightings that vary each composite weight in steps of 0.05 under
a sum of one, GPT-5.1 ranks first under 98.8 percent and the full order of the
table above holds under 73.2 percent. Of the 497 matches between reconstructed
steps and reference events, 48 percent are made at the first tier, 32 percent at
the second and 20 percent at the third (Appendix C).

Every number in this section is produced from the released files, with no model
call and no index, by

```
python reproduce_chain_tables.py
python reproduce_chain_tables.py --rebuild-baseline <new directory>
```

The second form also rebuilds the baseline chains from the released pools and
compares their composites with the stored ones. The stricter grounding check
runs as `python score_fabrication_strict.py <chain.json>`.

- **Raw chains and per-run scores** are in
  [`mode2_final/`](mode2_final/): `<provider>/<case>/chain_<case>_<provider>_run{1,2,3}.json`
  (the reconstructed chain) and `*.mode2_score.json` (its score). Each case's
  `evidence_<case>.json` in the same folder is the evidence pool of the 105
  anchors (the Stage-1 output of `retrieve_evidence_v2.py`), and
  `<provider>_summary.json` lists chain length, prompt size and model-call time
  per run.
- **Baseline chains** are in [`retrieval_only_baseline/`](retrieval_only_baseline/),
  with their scores and the same three pools.
- Reproduce one chain with `retrieve_evidence_v2.py` → `reconstruct_timeline.py`
  → `score_timeline_mode2.py` (see the main README).

## 4. Efficiency vs. the manual baseline (Table 11, Figure 5)

Manual baseline of twelve practitioners who worked the same three cases without
the platform. The comparison is drawn phase by phase, because only some phases
are comparable. Extraction and parsing followed by timeline construction is
matched against ArshaLab's ETL phase, the anchor queries and the mean model call
of one chain reconstruction. ETL timing is in
[`efficiency/etl_timing_summary.json`](efficiency/etl_timing_summary.json);
per-question latency and per-run chain time are in
[`efficiency/LATENCY_TIME_TABLES.md`](efficiency/LATENCY_TIME_TABLES.md).

| Case | Manual, extract + timeline (h) | ArshaLab, ETL + chain (min) | Speedup |
|------|-------------------------------:|----------------------------:|--------:|
| KDFS 2023        |  6.1 | 22.91 |  16× |
| Magnet CTF 2022  |  9.6 | 18.37 |  31× |
| Hunter 4orensics | 10.8 |  2.86 | 227× |

Investigation time by phase, twelve-practitioner means given as the range over
the three cases:

| Phase | Twelve practitioners | ArshaLab |
|-------|----------------------|----------|
| Extraction and parsing       | 3.1 to 5.0 h | 2 min to 22 min |
| Timeline construction        | 3.0 to 5.8 h | 13 s to 49 s |
| Verification of every event  | 3.7 to 6.5 h | performed by the user, not measured |

Per-case total effort was 9.8 h on KDFS 2023, 14.5 h on Magnet CTF 2022, and
17.3 h on Hunter 4orensics. ETL alone is 22:18 on KDFS 2023, 17:44 on Magnet CTF
2022, and 02:15 on Hunter 4orensics. A chain reconstruction takes 13 to 49 s, of
which the anchor queries account for 1.4 to 2.2 s and the model call for the
rest. Per-question latency means: cloud 5.65 s (OpenAI GPT-5.1) to 35.49 s
(DeepSeek V3.2); local 2.91 s to 3.75 s.
