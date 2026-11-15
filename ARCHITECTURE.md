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
catalog of 105 case-agnostic anchors collects an evidence pool, which the model
synthesizes into an attack chain (see [ANCHORS.md](ANCHORS.md)).

Seven language models are supported: four cloud (DeepSeek, Claude Opus,
Claude Sonnet 4.5, OpenAI GPT-5.1) and three local through Ollama (Llama 3.1 8B,
Qwen 2.5 14B, Phi-4 14B). The model version behind each result is named in
[benchmark_results/RESULTS.md](benchmark_results/RESULTS.md). The local models are wrapped in a retrieval-augmented
reader so they answer over the same case index.

## L5 — Access

A web interface for interactive investigation and a Model Context Protocol (MCP)
server that exposes the same tools to MCP-capable clients.

## Cross-cutting concerns

- **Extensibility through registration tables.** Components are implemented
  within their respective layers and entered in the corresponding registration
  tables. Adding functionality follows the same procedure in every layer: a new
  component is written within its layer and given an entry in each registration
  table for its kind, from which the other layers pick it up, rather than
  through edits scattered across the stack.
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

## Extension examples

The three cases below show, for each kind of extension, the code that is
written, where it is registered, and what the rest of the platform derives from
it. The ShellBags parser, the `NewLLMAnalyzer` adapter and the
`find_folder_access` tool are illustrations and do not ship with the release.

### A new artifact type

**Write** a parser module in `src/parsers/` that subclasses `BaseParser`. The
`fields` it declares are the record schema: `BaseParser.get_es_mapping()` and
`BaseParser.get_sqlite_schema()` build the Elasticsearch mapping and the SQLite
table from them. `BaseParser.parse()` calls `_parse_impl()` once and
`_normalize_record()` on every raw record, then adds the case metadata.

```python
# src/parsers/shellbags_parser.py
from typing import Any, Dict, List

from .base import BaseParser


class Shellbags_SBECmd_Parser(BaseParser):
    """ShellBags (folders opened by each user) via SBECmd."""

    @property
    def name(self) -> str:
        return "Shellbags_SBECmd_Parser"

    @property
    def description(self) -> str:
        return "ShellBags - folders opened by each user"

    @property
    def index_name(self) -> str:
        return "forensic-shellbags"

    @property
    def artifact_type(self) -> str:
        return "shellbags"

    @property
    def database_table(self) -> str:
        return "shellbags"

    @property
    def fields(self) -> Dict[str, str]:
        # Types are keys of BaseParser._ES_TYPE_MAP
        return {
            "timestamp": "date_lenient",
            "path": "text_keyword",
            "user": "keyword",
            "source_file": "text",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        cmd = f'"{self.executable_path}" -d "{input_path}" --csv "{self.output_dir}"'
        self._run_command(cmd)
        records = []
        for csv_path in self._find_files_in_dir(self.output_dir, extensions=[".csv"]):
            records.extend(self._read_csv(csv_path))
        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        # Column names are illustrative; check them against the SBECmd version in use
        return {
            "artifact_type": "shellbags",
            "timestamp": record.get("LastWriteTime", ""),
            "path": record.get("AbsolutePath", ""),
            "user": record.get("User", ""),
            "source_file": record.get("SourceFile", ""),
        }
```

**Register** it once in the parser table and once in the configuration file.
The key is the same in both.

```python
# src/parsers/__init__.py
from .shellbags_parser import Shellbags_SBECmd_Parser

PARSERS = {
    # ... existing entries ...
    "shellbags": Shellbags_SBECmd_Parser,
}
```

```yaml
# config/artifacts.yaml
  shellbags:
    description: "ShellBags - folders opened by each user"
    paths:
      - "/Users/*/NTUSER.DAT"
      - "/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat"
    collector: "TSK"
    parser: "SBECmd"
    parser_config:
      executable: "tools/SBECmd/SBECmd.exe"
      args:
        - "-d"
        - "{input_dir}"
        - "--csv"
        - "{output_dir}"
    output_format: "csv"
    database_table: "shellbags"
    capabilities:
      - "folder access by user"
```

**Derived.** The `paths` and `collector` entries tell Layer 1 what to extract
from the image. The ETL pipeline and the loaders build the `forensic-shellbags`
index and the `shellbags` SQLite table from `fields`. The web interface lists the
new type among the artifacts to load, because it builds that list from
`PARSERS`. `BaseAnalyzer.get_all_indices()` also reads `PARSERS`, so
`get_case_stats`, `get_full_timeline` and `correlate_activity` cover the new
index, and `search_artifacts` reaches it when called with `artifact_type="all"`.
For a model to restrict `search_artifacts` to the new type alone, add
`"shellbags"` to that tool's `artifact_type` enum in `TOOL_DEFINITIONS`.

### A new language-model provider

**Write** an adapter module in `src/llm/` that subclasses `BaseAnalyzer` and
implements `analyze()`. The adapter only talks to the provider. The tools, their
handlers and the shared system prompt come from `BaseAnalyzer`.
`src/llm/deepseek_analyzer.py` is a complete reference. A minimal adapter for an
OpenAI-compatible endpoint looks like this.

```python
# src/llm/newllm_analyzer.py
import json
import os

from openai import OpenAI

from .base_analyzer import BaseAnalyzer


class NewLLMAnalyzer(BaseAnalyzer):
    """Adapter for an OpenAI-compatible endpoint."""

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None,
                 max_tool_calls: int = 25, max_tool_result_chars: int = 8000):
        super().__init__(es_url, case_id)
        self.client = OpenAI(api_key=os.getenv("NEWLLM_API_KEY"),
                             base_url="https://api.example.com/v1")
        self.model = "newllm-chat"
        self.max_tool_calls = max_tool_calls
        self.max_tool_result_chars = max_tool_result_chars
        self.tools = self.get_tools_openai()          # the forensic tools, converted once
        self.system_prompt = self.BASE_SYSTEM_PROMPT  # shared integrity rules

    def analyze(self, query: str, case_id: str = None) -> str:
        if case_id:
            self.case_id = case_id
        messages = [{"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": query}]
        calls = 0
        while True:
            response = self.client.chat.completions.create(
                model=self.model, messages=messages, tools=self.tools, temperature=0)
            message = response.choices[0].message
            if not message.tool_calls:
                return message.content or ""
            if calls >= self.max_tool_calls:
                messages.append({"role": "user", "content":
                                 "You have reached the maximum number of tool calls. "
                                 "Answer now from the data gathered so far."})
                final = self.client.chat.completions.create(
                    model=self.model, messages=messages, temperature=0)
                return final.choices[0].message.content or ""
            messages.append({"role": "assistant", "content": message.content,
                             "tool_calls": [{"id": tc.id, "type": "function",
                                             "function": {"name": tc.function.name,
                                                          "arguments": tc.function.arguments}}
                                            for tc in message.tool_calls]})
            for tc in message.tool_calls:
                calls += 1
                result = self._execute_tool(tc.function.name, json.loads(tc.function.arguments))
                if len(result) > self.max_tool_result_chars:
                    result = (result[:self.max_tool_result_chars]
                              + f"\n...[truncated, {len(result)} chars total]")
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
```

**Register** it in the provider table of each entry point that should offer it.
`benchmark.py` loads providers by module and class name, and the web interface
keeps its own table in `web_app.py`.

```python
# benchmark.py
PROVIDERS = {
    # ... existing entries ...
    "newllm": {
        "class": "NewLLMAnalyzer",
        "module": "src.llm.newllm_analyzer",
        "init_kwargs": {},
        "display_name": "NewLLM",
    },
}
```

```python
# web_app.py
from src.llm.newllm_analyzer import NewLLMAnalyzer

LLM_ANALYZERS = {
    # ... existing entries ...
    "newllm": NewLLMAnalyzer,
}
```

**Derived.** `get_tools_openai()` and `get_tools_anthropic()` convert
`TOOL_DEFINITIONS` into the provider's tool format, and `_execute_tool()` routes
every call to the same handlers that the other models use. The new model
therefore works over the same forensic tools, receives the same named fields
from them, and starts from the same system prompt.

### A new forensic tool

**Write** a handler in `src/llm/base_analyzer.py` that queries the index and
returns only named fields, never the whole indexed record.

```python
# src/llm/base_analyzer.py, class BaseAnalyzer
    def _tool_find_folder_access(self, path: str, limit: int = 20) -> Dict:
        """Folders opened by a user, from ShellBags."""
        results = self._es_search("forensic-shellbags", path, limit)
        return {
            "total_found": len(results),
            "folders": [
                {"timestamp": r.get("timestamp", ""),
                 "path": r.get("path", ""),
                 "user": r.get("user", "")}
                for r in results
            ],
        }
```

**Register** it in the same file with a declaration in `TOOL_DEFINITIONS` and a
routing entry in `TOOL_MAP`.

```python
# src/llm/base_analyzer.py, class BaseAnalyzer
    TOOL_DEFINITIONS = [
        # ... existing entries ...
        {
            "name": "find_folder_access",
            "description": "Find folders a user opened, from ShellBags.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string",
                             "description": "Folder path or part of it"},
                    "limit": {"type": "integer",
                              "description": "Maximum results (default: 20)"}
                },
                "required": ["path"]
            }
        },
    ]

    TOOL_MAP = {
        # ... existing entries ...
        "find_folder_access": "_tool_find_folder_access",
    }
```

**Derived.** The cloud models that call tools through function calling receive
the declaration through `get_tools_openai()` or `get_tools_anthropic()`. The MCP
server in `mcp_server.py` lists every entry of `TOOL_DEFINITIONS` and routes
calls through `_execute_tool()`, so MCP clients receive the tool as well. The
locally hosted models do not choose tools, because the platform invokes tools
for them by rule in `src/llm/ollama_rag_analyzer_v2.py`, so a new tool reaches
them only after it is added to those rules.
