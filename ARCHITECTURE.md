# Architecture

ArshaLab is organized as a five-layer pipeline. Each layer is independent and is
extended through its own **registration table**, so a new component is localized
to one or two files of its own layer plus one registration entry, with no edits
to neighboring layers.

```
   Disk image
      │
 ┌────▼─────────────────────────────────────────────────────────┐
 │ L1  Collection   The Sleuth Kit extracts artifacts            │
 ├──────────────────────────────────────────────────────────────┤
 │ L2  Parsing      13 parser modules normalize artifacts        │
 ├──────────────────────────────────────────────────────────────┤
 │ L3  Indexing     Elasticsearch + per-case SQLite              │
 ├──────────────────────────────────────────────────────────────┤
 │ L4  Reasoning    16 forensic tools + 7 language models        │
 ├──────────────────────────────────────────────────────────────┤
 │ L5  Access       web interface + MCP server                   │
 └──────────────────────────────────────────────────────────────┘
```

## L1 — Collection

The Sleuth Kit extracts the relevant artifact files (event logs, registry hives,
Prefetch, browser databases, MFT, USN journal, and others) from a Windows disk
image in E01, RAW, or DD format.

## L2 — Parsing

Thirteen pluggable parser modules, built mostly on the Eric Zimmerman suite,
normalize each artifact family into a uniform record schema. Covered families
include Prefetch, Event Logs, Registry, browser history, LNK, Jump Lists, the
Master File Table, the USN journal, Shimcache, Amcache, and SRUM, among others.
A new artifact type is added as one parser module plus one registration entry,
after which storage, search, and tool access follow from its declared fields.

## L3 — Indexing

Parsed records are written to Elasticsearch (one index per artifact family,
scoped by case) and to a per-case SQLite database. This index is the single
source of truth that every tool reads from, and the boundary that the
anti-hallucination design enforces.

## L4 — Reasoning

The reasoning layer exposes **sixteen forensic tools** in a provider-neutral
schema so that any of the seven supported language models can invoke them
without per-provider adapters. The tools fall into four groups:

- **Search and discovery** — `search_artifacts`, `get_case_stats`,
  `find_suspicious_activity`
- **Artifact-specific analysis** — `analyze_program_execution`,
  `analyze_web_activity`, `analyze_network_activity`,
  `analyze_powershell_commands`, `analyze_registry`, `analyze_security_events`
- **File activity** — `search_file_activity`, `search_file_changes`,
  `analyze_deleted_files`
- **Correlation and synthesis** — `get_full_timeline`, `correlate_activity`,
  `detect_lateral_movement`, `reconstruct_attack_chain`

`reconstruct_attack_chain` drives the autonomous two-stage pipeline: a fixed
catalog of 98 case-agnostic anchors collects an evidence pool, which the model
synthesizes into an attack chain (see [ANCHORS.md](ANCHORS.md)).

Seven language models are supported: four cloud (DeepSeek V3, Claude Opus 4.1,
Claude Sonnet 4.5, OpenAI GPT-5.1) and three local through Ollama (Llama 3.1 8B,
Qwen 2.5 14B, Phi-4 14B). The local models are wrapped in a retrieval-augmented
reader so they answer over the same case index.

## L5 — Access

A web interface for interactive investigation and a Model Context Protocol (MCP)
server that exposes the same tools to MCP-capable clients.

## Cross-cutting concerns

- **Extensibility through registration tables.** Every layer is organized around
  a registration table, so the platform extends along a single pattern rather
  than through edits scattered across the stack.
- **Structural anti-hallucination defense.** The defense narrows the model's
  data-interaction surface at the architectural level rather than through
  prompt-level instructions: the model reads only what the tools return from the
  index, must quote returned names and hashes verbatim, and returns an explicit
  no-data response on an empty result. Trust in an answer therefore rests on the
  construction of the pipeline rather than on the model.

## Extensibility recipe

| To add | You write |
|--------|-----------|
| A new artifact type | one parser module + one registration entry |
| A new language-model provider | one adapter module + one registration entry (inherits all sixteen tools and the anti-hallucination defense) |
| A new forensic tool | three small additions in one file of the reasoning layer: its description, its routing entry, and its handler |
