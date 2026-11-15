# Results

Everything reported in the paper is produced from the files below. `RESULTS.md`
carries the headline numbers; the rest is the material they are computed from.

| Path | What it holds |
|---|---|
| `RESULTS.md` | Headline numbers for question answering, the closed-book control, chain reconstruction and the manual baseline |
| `answers/` | Every answer each of the seven models gave to the 300 reference questions, in full |
| `closed_book/` | The answers of the four cloud models to the same 300 questions with the case index withheld and every tool disabled |
| `qa/` | Per-model and per-case question-answering metrics |
| `mode2_final/` | The 36 reconstructed attack chains, four cloud models on three cases across three runs, each with its score file and the 105-anchor evidence pool it was built from |
| `retrieval_only_baseline/` | The same chain-reconstruction task with no language model in the loop, used to separate what the model contributes from what the anchors already deliver |
| `efficiency/` | Extraction and parsing times per case, and per-question latency by model |
| `summaries/` | Aggregate run summaries, cross-run consistency, and local-model metrics |

## Reproducing a score

Each chain sits next to the evidence pool it was scored against, so a single
chain can be re-scored on its own:

```
python score_timeline_mode2.py \
  benchmark_results/mode2_final/opus/magnet/chain_Magnet_CTF_2022_opus_run1.json \
  magnet
```

The case key is one of `kdfs`, `magnet`, `4orensics`. The scorer reads the
reference chain from `benchmark/ground_truth/<case>_attack_chain_gt.json` and
the evidence from `evidence_<case>.json` beside the chain, then rewrites the
chain's `.mode2_score.json`. The tables of the paper are recomputed from the
stored files by `reproduce_qa_table.py`, `reproduce_closed_book_table.py` and
`reproduce_chain_tables.py` in the repository root.

## Ground truth

Each case carries three files under `benchmark/ground_truth/`. The
`_attack_chain_gt.json` is the reference chain the scorer reads. The
`_docx_timeline.json` and `_timeline_v4_systematic.json` are the two sources it
was built from, and its `metadata.sources_consulted` field records how many
events came from each and how many survived curation.

## Evaluation images

The three disk images are not redistributed here. They are publicly released
forensic challenge images; their publishers are cited in the paper.
