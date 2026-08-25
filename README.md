# ArshaLab

ArshaLab is a modular platform that investigates Windows disk images with
language models. It parses Windows forensic artifacts into a searchable case
index and lets a language model answer investigative questions and reconstruct
attack chains, while a structural anti-hallucination design keeps every answer
grounded in the parsed evidence.

This repository is the artifact accompanying the paper. It contains the full
platform code, the reference benchmark (questions, ground-truth answers, and
reference attack chains for three cases), the evaluation methodology, and the
98-anchor retrieval catalog, so that the reported results can be reproduced.

## What the platform does

The platform is used in two ways, over the same parsed evidence:

- **Interactive question answering.** The user asks investigative questions in
  natural language; the model answers using forensic tools that return records
  from the case index. Scored by recall, precision, hallucination rate,
  consistency, and BERTScore F1 (see [docs/QA_BENCHMARK.md](docs/QA_BENCHMARK.md)).
- **Autonomous attack-chain reconstruction.** A fixed catalog of 98
  case-agnostic anchors retrieves a comprehensive evidence pool, which the model
  synthesizes into a chronologically ordered attack chain. Scored by a composite
  of step coverage, tactic coverage, hallucination rate, and ordering accuracy
  (see [docs/EVALUATION.md](docs/EVALUATION.md) and [ANCHORS.md](ANCHORS.md)).

## Architecture

A five-layer pipeline (see [ARCHITECTURE.md](ARCHITECTURE.md) for detail):

1. **Collection** — The Sleuth Kit extracts artifacts from the disk image.
2. **Parsing** — thirteen pluggable parser modules normalize the artifacts.
3. **Indexing** — parsed records are stored in Elasticsearch and a per-case
   SQLite database.
4. **Reasoning** — sixteen provider-neutral forensic tools and seven language
   models operate over the index.
5. **Access** — a web interface and a Model Context Protocol server.

Seven language models are supported: four cloud (DeepSeek V3, Claude Opus 4.1,
Claude Sonnet 4.5, OpenAI GPT-5.1) and three local via Ollama (Llama 3.1 8B,
Qwen 2.5 14B, Phi-4 14B).

## Setup

```bash
# 1. Python dependencies
python -m venv venv && venv\Scripts\activate          # Windows
pip install -r requirements.txt

# 2. Elasticsearch (single node, no security, for local use)
docker compose up -d

# 3. API keys for the cloud models
copy .env.example .env                                # then edit .env
```

`.env.example` lists the required keys (DeepSeek, Anthropic, OpenAI, optionally
Groq) and the Elasticsearch host. The local models run through a separate
[Ollama](https://ollama.com) install and need no key.

## Data

The three evaluation images are **public forensic challenge images** and are
**not redistributed** in this repository. They are obtained from their original
challenge sources (KDFS 2023, Magnet CTF 2022, Hunter / 4orensics). What this
repository does include is the full benchmark built on top of them:

- `benchmark/questions/` — 100 reference questions per case (300 total), each
  with its ground-truth key entities and a reference answer.
- `benchmark/ground_truth/` — the reference attack chains and curated
  ground-truth events for chain-reconstruction scoring.
- `benchmark_results/answers/` — every model answer to the 300 questions in full
  text, one file per model, 6,290 in total. Three runs were executed for every
  question and every model; in ten cases one run returned an API error and left
  no usable answer, which is why Claude Opus 4.1 has 899 and Claude Sonnet 4.5
  891 rather than 900. Each record carries the case, the question id, the run
  number, the answer text and the recall recorded at the time.
- `benchmark_results/mode2_final/` — the 36 reconstructed attack chains behind
  the published composite, each with its score file and the evidence pool it was
  built from.
- `benchmark_results/retrieval_only_baseline/` — the same task with the language
  model removed, the records the 98 anchors return ordered by time. Two variants
  per case, with their score files and the evidence they were built from.

## Reproducing the evaluation

```bash
# Interactive question answering (one provider, one case, three runs)
python benchmark.py --providers deepseek --case-id <case_id> --runs 3

# Autonomous attack-chain reconstruction
python retrieve_evidence_v2.py --case magnet            # stage 1: 98-anchor evidence pool
python reconstruct_timeline.py --provider deepseek --case magnet --run 1   # stage 2: chain
python score_timeline_mode2.py <chain_path> --case magnet \
    --evidence benchmark_results/mode2_final/opus/magnet/control/evidence_Magnet_CTF_2022.json

# Local-model question answering metrics
python eval_local_rag.py
```

Full scoring mechanics are documented in
[docs/QA_BENCHMARK.md](docs/QA_BENCHMARK.md) and
[docs/EVALUATION.md](docs/EVALUATION.md).

## Paper ↔ artifact map

| Paper element | Produced by |
|---------------|-------------|
| Question-answering results | `benchmark.py`, `eval_local_rag.py` |
| Chain-reconstruction composite | `retrieve_evidence_v2.py` → `reconstruct_timeline.py` → `score_timeline_mode2.py` |
| 98 retrieval anchors | `retrieve_evidence_v2.py` (`ANCHORS_V2`); documented in [ANCHORS.md](ANCHORS.md) |
| Reference questions / answers | `benchmark/questions/` |
| Reference attack chains | `benchmark/ground_truth/` |
| Model answers behind the question-answering tables | `benchmark_results/answers/` |
| The 36 chains behind the composite | `benchmark_results/mode2_final/` |

## Repository layout

```
src/                  five-layer platform (parsers, indexing, tools, models, MCP, web)
benchmark/            reference questions and ground truth
benchmark_results/    model answers, the 36 published chains, aggregate metrics
docs/                 evaluation methodology
_superseded/          earlier chain sets, kept for provenance and not used in the paper
ANCHORS.md            the 98 case-agnostic retrieval anchors
ARCHITECTURE.md       five-layer architecture and extensibility
retrieve_evidence_v2.py, reconstruct_timeline.py, score_timeline_mode2.py
benchmark.py, eval_local_rag.py, etl_pipeline.py, web_app.py, mcp_server.py
```

## License

Released under the MIT License (see [LICENSE](LICENSE)).
