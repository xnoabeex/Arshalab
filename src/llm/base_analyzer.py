# src/llm/base_analyzer.py
"""
BaseAnalyzer - Shared tool implementations for all LLM forensic analyzers.

Contains:
- ALL_INDICES (auto-generated from PARSERS registry)
- Canonical TOOL_DEFINITIONS (provider-neutral, convertible to Anthropic/OpenAI format)
- Elasticsearch search helpers
- All 16 forensic tool implementations
- Record summarization
- Tool dispatch
"""

import json
import requests
from typing import Dict, List, Any


class BaseAnalyzer:
    """
    Base class for LLM forensic analyzers.

    Subclasses must implement:
    - __init__(): Initialize LLM client, set self.es_url, call super().__init__()
    - analyze(query, case_id): Main analysis loop using provider-specific SDK

    Provides:
    - 16 forensic tool implementations
    - ES search helpers
    - Tool dispatch
    - Format converters for tool definitions
    """

    # ==================== LAZY-LOADED INDICES ====================

    _ALL_INDICES = None

    @classmethod
    def get_all_indices(cls) -> List[str]:
        """Get all forensic index names from PARSERS registry."""
        if cls._ALL_INDICES is None:
            from src.parsers import PARSERS
            cls._ALL_INDICES = [
                parser_cls.__new__(parser_cls).index_name
                for parser_cls in PARSERS.values()
            ]
        return cls._ALL_INDICES

    # ==================== SYSTEM PROMPT ====================

    BASE_SYSTEM_PROMPT = """You are ArshaLab - AI forensic assistant for Windows disk image analysis.

AVAILABLE ARTIFACTS (13 types):
- Prefetch: Program execution history (what ran, when, run count)
- EventLog: Windows events (logins, errors, service installs, security)
- Registry: System configuration, user activity, persistence mechanisms
- Browser: Web browsing history with timestamps and URLs
- LNK: Shortcuts showing recently accessed files/programs
- MFT: Master File Table - complete file system timeline (created, modified, accessed)
- JumpList: Recently used files per application (Word docs, Excel files, etc.)
- RecycleBin: Deleted files with original paths and deletion times
- Shimcache: Application compatibility cache - program execution evidence
- Amcache: Program installation info with SHA1 hashes and versions
- SRUM: System Resource Usage Monitor - network traffic per application (bytes sent/received)
- PowerShell: PSReadLine command history - executed PowerShell commands
- UsnJrnl: USN Journal - granular file system changes (create, delete, rename, modify)

RESPONSE FORMAT:
- Be concise and factual. Answer the question directly without unnecessary preamble.
- Do NOT use markdown headers (##, ###), emoji, or decorative formatting.
- Do NOT repeat the question or write "Based on my analysis" / "Let me provide".
- For simple factual questions: 1-3 sentences with exact values.
- For complex questions (timeline, analysis): use plain bullet points, no headers.
- Always include specific values: exact timestamps, file paths, counts, hashes.
- If a tool returns 0 results, try a different tool or search query before saying "no data found".

BEHAVIOR:
- Always answer in English
- Use tools to search forensic data before answering
- Correlate multiple artifact types to build complete picture

CRITICAL DATA INTEGRITY RULES:
- ONLY cite file names, paths, timestamps, Event IDs, and hashes that tools explicitly returned
- When a tool returns total_found=0 or empty results, state "No data found for this query" — do NOT invent data
- NEVER fabricate or guess file names. If the actual file is "ransom.exe", write exactly "ransom.exe" — NOT "ransomware.exe" or any other variation
- Quote exact values from tool results — do not paraphrase file names, registry keys, or hashes
- If you need to describe what a file does, separate the description from the exact name: "ransom.exe (a ransomware executable)" NOT "ransomware.exe"
- When unsure about exact names or values, use the search tools to verify before stating as fact"""

    # ==================== CANONICAL TOOL DEFINITIONS ====================
    # Provider-neutral format. Use get_tools_anthropic() / get_tools_openai()
    # to convert to provider-specific format.

    TOOL_DEFINITIONS = [
        {
            "name": "search_artifacts",
            "description": "Search forensic artifacts. Use for finding specific programs, files, URLs, keywords, or exact values (build numbers, version strings, hashes). For best results, search for the exact value you need (e.g. '22543' not 'Windows build number').",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (program name, URL, keyword)"
                    },
                    "artifact_type": {
                        "type": "string",
                        "enum": ["prefetch", "eventlog", "registry", "browser", "lnk",
                                 "mft", "jumplist", "recyclebin", "shimcache", "amcache",
                                 "srum", "powershell", "usnjrnl", "all"],
                        "description": "Type of artifact to search (default: all)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 20)"
                    }
                },
                "required": ["query"]
            }
        },
        {
            "name": "analyze_program_execution",
            "description": "Deep analysis of a specific program's execution history from Prefetch, LNK, Shimcache, Amcache, JumpList, and Registry.",
            "parameters": {
                "type": "object",
                "properties": {
                    "program_name": {
                        "type": "string",
                        "description": "Program name (e.g., chrome.exe, cmd.exe)"
                    }
                },
                "required": ["program_name"]
            }
        },
        {
            "name": "analyze_web_activity",
            "description": "Analyze browser history - visited sites, domains, patterns, and search queries.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Filter by domain (optional)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 30)"
                    }
                }
            }
        },
        {
            "name": "find_suspicious_activity",
            "description": "Find suspicious activity: TEMP executions, malware indicators, suspicious Event IDs (4625, 4648, 7045, 1102), persistence mechanisms.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "get_case_stats",
            "description": "Get statistics about available forensic data. CALL THIS FIRST to understand the case.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "analyze_deleted_files",
            "description": "Analyze deleted files from Recycle Bin. Shows what was deleted, when, original paths, and file sizes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Filter by filename (optional)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 30)"
                    }
                }
            }
        },
        {
            "name": "search_file_activity",
            "description": "Search file system activity using MFT, JumpLists, and LNK files. Find file access, creation, modification events.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Filename or path to search"
                    },
                    "extension": {
                        "type": "string",
                        "description": "File extension filter (e.g., .exe, .pdf, .docx)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 30)"
                    }
                }
            }
        },
        {
            "name": "analyze_network_activity",
            "description": "Analyze network activity from SRUM. Shows bytes sent/received per application, useful for detecting data exfiltration and C2.",
            "parameters": {
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Filter by application name (optional)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 50)"
                    }
                }
            }
        },
        {
            "name": "analyze_powershell_commands",
            "description": "Analyze PowerShell command history. Detects suspicious commands (downloads, encoded, bypass). Critical for LOTL attacks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "suspicious_only": {
                        "type": "boolean",
                        "description": "Show only suspicious commands (default: false)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 100)"
                    }
                }
            }
        },
        {
            "name": "search_file_changes",
            "description": "Search USN Journal for detailed file changes. Operations: CREATE, DELETE, RENAME, MODIFY, SECURITY.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Filename or path to search"
                    },
                    "operation": {
                        "type": "string",
                        "enum": ["CREATE", "DELETE", "RENAME", "MODIFY", "SECURITY", "all"],
                        "description": "Filter by operation type (default: all)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 50)"
                    }
                }
            }
        },
        {
            "name": "analyze_registry",
            "description": "Analyze Windows Registry for persistence mechanisms, autoruns, user activity, and malware indicators.",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": ["persistence", "user_activity", "network", "malware", "all"],
                        "description": "Category to analyze"
                    },
                    "query": {
                        "type": "string",
                        "description": "Search specific key path or value (optional)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 50)"
                    }
                }
            }
        },
        {
            "name": "analyze_security_events",
            "description": "Analyze Windows Security Event Logs: logons (4624/4625), privilege escalation (4672/4673), account management (4720-4738), service installs (7045), audit cleared (1102).",
            "parameters": {
                "type": "object",
                "properties": {
                    "event_category": {
                        "type": "string",
                        "enum": ["authentication", "privilege", "account_management",
                                 "service_install", "audit_clear", "all"],
                        "description": "Event category to analyze"
                    },
                    "event_id": {
                        "type": "integer",
                        "description": "Specific Event ID to filter (optional)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 100)"
                    }
                }
            }
        },
        {
            "name": "get_full_timeline",
            "description": "Build comprehensive timeline from ALL artifact types (13 sources). Best for incident reconstruction.",
            "parameters": {
                "type": "object",
                "properties": {
                    "start_time": {
                        "type": "string",
                        "description": "Start of time range (ISO format)"
                    },
                    "end_time": {
                        "type": "string",
                        "description": "End of time range (ISO format)"
                    },
                    "artifact_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of artifact types to include (default: all)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum events (default: 100)"
                    }
                }
            }
        },
        {
            "name": "correlate_activity",
            "description": "Correlate activity across all artifacts for a specific entity (file, program, user, IP). Finds related events across all data sources.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity": {
                        "type": "string",
                        "description": "Entity to correlate: filename, program name, username, IP, or domain"
                    },
                    "entity_type": {
                        "type": "string",
                        "enum": ["file", "program", "user", "network", "auto"],
                        "description": "Type of entity (auto-detect if not specified)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results per artifact type (default: 20)"
                    }
                },
                "required": ["entity"]
            }
        },
        {
            "name": "detect_lateral_movement",
            "description": "Detect potential lateral movement: remote logons, PsExec/SMB, RDP, WMI, scheduled tasks, suspicious services.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 50)"
                    }
                }
            }
        },
        {
            "name": "reconstruct_attack_chain",
            "description": "Reconstruct the adversary attack chain as a chronologically ordered sequence of 15-30 incident steps with MITRE ATT&CK phase classification and source attribution. Runs the standardized reconstruction pipeline: 98 case-agnostic anchor queries collect a comprehensive evidence dump (~1,000 records), which is then synthesized into the attack chain. Both the full evidence dump and the distilled chain are persisted to /reports/<case_id>/ for audit. The returned chain is checked against the persisted evidence and a `grounding` block reports, for this run, how many events state a checkable fact and how many cite an entity absent from the evidence. Use when the user asks: 'reconstruct the attack chain', 'show me the attack timeline', 'what happened in this incident', or similar attack-narrative requests.",
            "parameters": {
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "enum": ["deepseek", "openai", "sonnet", "opus"],
                        "description": "LLM backend for reconstruction. Default: deepseek (highest cloud recall in §5.3)."
                    },
                    "run": {
                        "type": "integer",
                        "description": "Independent run number (1, 2, or 3) for reproducibility across multiple invocations. Default: 1."
                    }
                }
            }
        },
        {
            "name": "request_artifact_load",
            "description": "Request to load a missing artifact into the case. Use when analysis requires data from an artifact that is not loaded yet (e.g., recyclebin returns no data). This will prompt the user for permission to load the artifact from the disk image.",
            "parameters": {
                "type": "object",
                "properties": {
                    "artifact_type": {
                        "type": "string",
                        "enum": ["prefetch", "eventlog", "registry", "browser", "lnk",
                                 "mft", "jumplist", "recyclebin", "shimcache", "amcache",
                                 "srum", "powershell", "usnjrnl", "wallet", "exchange"],
                        "description": "Type of artifact to load"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Explanation of why this artifact is needed for the analysis"
                    }
                },
                "required": ["artifact_type", "reason"]
            }
        },
        {
            "name": "get_wallet_artifacts",
            "description": (
                "Query crypto wallet and exchange artifacts (indices forensic-wallet and "
                "forensic-exchange). Use this INSTEAD of search_artifacts for anything crypto: "
                "wallet addresses, transaction hashes, encrypted vaults/keystores, wallet activity "
                "timeline, exchange deposit addresses. It matches identifiers EXACTLY, which normal "
                "keyword search cannot do reliably for a 42-character address or a 66-character hash. "
                "Call with no arguments first to see which wallets/exchanges exist in the case. "
                "Report only what the records contain; never invent an address, hash or balance."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Exact wallet address to look up (e.g. 0x502ed1..., bc1q...). Also finds the address inside stored values."
                    },
                    "tx_hash": {
                        "type": "string",
                        "description": "Transaction hash to look for inside stored wallet values"
                    },
                    "chain": {
                        "type": "string",
                        "enum": ["eth_evm", "btc", "ltc", "doge", "tron", "sol", "btc_testnet"],
                        "description": "Filter by blockchain"
                    },
                    "wallet_app": {
                        "type": "string",
                        "description": "Filter by wallet or exchange name (e.g. Trust Wallet, MetaMask, Coinbase Wallet)"
                    },
                    "record_type": {
                        "type": "string",
                        "enum": ["address", "activity", "secret", "kv", "cache"],
                        "description": "address = wallet addresses, activity = site/dApp usage with time, secret = encrypted vault/keystore, kv = raw stored key-value, cache = exchange API response"
                    },
                    "include_full_value": {
                        "type": "boolean",
                        "description": "Include the complete stored value. Off by default because a single record can hold hundreds of kilobytes."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum records to return (default: 30)"
                    }
                }
            }
        },
        {
            "name": "detect_timestamp_manipulation",
            "description": "Find files whose $STANDARD_INFORMATION timestamps contradict their $FILE_NAME timestamps, which is the signature of timestomping. Files carrying the installation image's own creation time are separated out as deployment noise instead of being reported as findings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path_contains": {
                        "type": "string",
                        "description": "Restrict to paths containing this text, for example Users or Temp (optional)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum anomalies to return (default: 20)"
                    }
                }
            }
        }
    ]

    # ==================== TOOL DISPATCH MAP ====================

    TOOL_MAP = {
        "search_artifacts": "_tool_search_artifacts",
        "analyze_program_execution": "_tool_analyze_program",
        "analyze_web_activity": "_tool_analyze_web",
        "find_suspicious_activity": "_tool_find_suspicious",
        "get_case_stats": "_tool_get_stats",
        "analyze_deleted_files": "_tool_analyze_deleted_files",
        "search_file_activity": "_tool_search_file_activity",
        "analyze_network_activity": "_tool_analyze_network_activity",
        "analyze_powershell_commands": "_tool_analyze_powershell_commands",
        "search_file_changes": "_tool_search_file_changes",
        "analyze_registry": "_tool_analyze_registry",
        "analyze_security_events": "_tool_analyze_security_events",
        "get_full_timeline": "_tool_get_full_timeline",
        "correlate_activity": "_tool_correlate_activity",
        "detect_lateral_movement": "_tool_detect_lateral_movement",
        "reconstruct_attack_chain": "_tool_reconstruct_attack_chain",
        "request_artifact_load": "_tool_request_artifact_load",
        "get_wallet_artifacts": "_tool_get_wallet_artifacts",
        "detect_timestamp_manipulation": "_tool_detect_timestamp_manipulation",
    }

    # ==================== FORMAT CONVERTERS ====================

    @classmethod
    def get_tools_anthropic(cls) -> List[Dict]:
        """Convert TOOL_DEFINITIONS to Anthropic format."""
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["parameters"]
            }
            for t in cls.TOOL_DEFINITIONS
        ]

    @classmethod
    def get_tools_openai(cls) -> List[Dict]:
        """Convert TOOL_DEFINITIONS to OpenAI/DeepSeek format."""
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["parameters"]
                }
            }
            for t in cls.TOOL_DEFINITIONS
        ]

    # ==================== INIT ====================

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None):
        """
        Initialize base analyzer.
        Subclasses should call super().__init__(es_url, case_id) and then set up their LLM client.

        Args:
            es_url: Elasticsearch URL
            case_id: Optional case ID to filter all queries (isolate analysis to specific image)
        """
        self.es_url = es_url
        self.case_id = case_id  # If set, all ES queries will be filtered to this case
        self.conversation_history: List[Dict] = []
        self.max_history_messages = 10

    # ==================== ES SEARCH HELPERS ====================

    def _es_search(self, index: str, query: str = None, size: int = 50) -> List[Dict]:
        """Execute Elasticsearch search using multi_match with query_string fallback."""
        try:
            body = {"size": size}

            # Build the main query
            if query:
                main_query = {
                    "multi_match": {
                        "query": query,
                        "fields": ["*"],
                        "type": "best_fields",
                        "lenient": True
                    }
                }
                # When query provided, sort by relevance (default _score)
            else:
                main_query = {"match_all": {}}
                # Without query, sort by timestamp desc
                body["sort"] = [{"timestamp.keyword": {"order": "desc", "unmapped_type": "keyword"}}]

            # Apply case_id filter if set
            if self.case_id:
                body["query"] = {
                    "bool": {
                        "must": [main_query],
                        "filter": [{"term": {"case_id.keyword": self.case_id}}]
                    }
                }
            else:
                body["query"] = main_query

            response = requests.post(
                f"{self.es_url}/{index}/_search",
                json=body,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                hits = data.get("hits", {}).get("hits", [])
                results = []
                for hit in hits:
                    record = hit["_source"]
                    # Infer artifact_type from index name if missing
                    if not record.get("artifact_type"):
                        idx = hit.get("_index", "")
                        if idx.startswith("forensic-"):
                            record["artifact_type"] = idx.replace("forensic-", "")
                    results.append(record)
                return results
            else:
                print(f"[ES Error] Status {response.status_code}: {response.text[:200]}")
        except Exception as e:
            print(f"[ES Error] {e}")
        return []

    def _es_exact_search(self, index: str, field: str, value: Any, size: int = 30) -> List[Dict]:
        """Execute Elasticsearch search with exact term match."""
        try:
            main_query = {"term": {field: value}}

            # Apply case_id filter if set
            if self.case_id:
                query = {
                    "bool": {
                        "must": [main_query],
                        "filter": [{"term": {"case_id.keyword": self.case_id}}]
                    }
                }
            else:
                query = main_query

            body = {
                "size": size,
                "query": query,
                "sort": [{"timestamp.keyword": {"order": "desc", "unmapped_type": "keyword"}}]
            }

            response = requests.post(
                f"{self.es_url}/{index}/_search",
                json=body,
                timeout=10
            )

            if response.status_code == 200:
                hits = response.json().get("hits", {}).get("hits", [])
                results = []
                for hit in hits:
                    record = hit["_source"]
                    if not record.get("artifact_type"):
                        idx = hit.get("_index", "")
                        if idx.startswith("forensic-"):
                            record["artifact_type"] = idx.replace("forensic-", "")
                    results.append(record)
                return results
        except Exception as e:
            print(f"[ES Error] {e}")
        return []

    def _get_data_time_range(self) -> Dict:
        """Get min/max timestamps from all data (filtered by case_id if set)."""
        try:
            body = {
                "size": 0,
                "aggs": {
                    "min_time": {"min": {"field": "timestamp"}},
                    "max_time": {"max": {"field": "timestamp"}}
                }
            }

            # Apply case_id filter if set
            if self.case_id:
                body["query"] = {"term": {"case_id.keyword": self.case_id}}

            response = requests.post(
                f"{self.es_url}/forensic-*/_search",
                json=body, timeout=5
            )
            if response.status_code == 200:
                aggs = response.json().get("aggregations", {})
                return {
                    "earliest": aggs.get("min_time", {}).get("value_as_string", ""),
                    "latest": aggs.get("max_time", {}).get("value_as_string", ""),
                    "case_id": self.case_id
                }
        except:
            pass
        return {}

    # ==================== RECORD HELPERS ====================

    def _summarize_record(self, record: Dict) -> str:
        """Create short summary of a forensic record."""
        art_type = record.get("artifact_type", "")

        if art_type == "prefetch":
            exe = record.get("executable_name", "Unknown")
            if "\\" in exe:
                exe = exe.split("\\")[-1]
            return f"Executed: {exe} (run count: {record.get('run_count', 0)})"

        elif art_type == "eventlog":
            return f"Event {record.get('event_id', '')} - {record.get('provider', '')} [{record.get('level', '')}]"

        elif art_type == "registry":
            return f"{record.get('hive_type', '')}: {record.get('key_path', '')[:60]}"

        elif art_type == "browser_history":
            return f"{record.get('browser', 'Browser')}: {record.get('title', '')[:40]} | {record.get('domain', '')}"

        elif art_type == "lnk":
            return f"Shortcut: {record.get('lnk_name', '')} -> {record.get('target_path', '')[:50]}"

        elif art_type == "mft":
            deleted = " [DELETED]" if record.get('is_deleted') else ""
            return f"File: {record.get('file_path', record.get('filename', ''))[:60]}{deleted}"

        elif art_type == "jumplist":
            return f"JumpList [{record.get('list_type', '')}]: {record.get('app_name', '')} -> {record.get('target_path', '')[:40]}"

        elif art_type == "recyclebin":
            return f"Deleted: {record.get('original_path', record.get('filename', ''))[:60]}"

        elif art_type == "shimcache":
            executed = " [Executed]" if record.get('executed') else ""
            return f"Shimcache: {record.get('path', record.get('filename', ''))[:60]}{executed}"

        elif art_type == "amcache":
            sha1 = record.get('sha1', '')
            sha1_str = f" SHA1:{sha1[:8]}..." if sha1 else ""
            return f"Amcache [{record.get('record_type', '')}]: {record.get('filename', record.get('path', ''))[:40]}{sha1_str}"

        elif art_type == "srum":
            sent = record.get('bytes_sent', 0)
            recv = record.get('bytes_received', 0)
            return f"SRUM [{record.get('record_type', '')}]: {record.get('app_name', '')[:30]} sent={sent} recv={recv}"

        elif art_type == "powershell":
            suspicious = " [SUSPICIOUS]" if record.get('is_suspicious') else ""
            return f"PS [{record.get('user', '')}]: {record.get('command', '')[:60]}{suspicious}"

        elif art_type == "usnjrnl":
            return f"USN [{record.get('operation', '')}]: {record.get('file_path', record.get('filename', ''))[:60]}"

        return str(record)[:100]

    def _filter_matched_files(self, files: list, query: str) -> list:
        """Filter files_loaded list to show matches + limit for context."""
        if not query or not files:
            return files[:5]  # Reduced from 20

        query_lower = query.lower()
        matched = [f for f in files if query_lower in f.lower()]

        if matched:
            return matched[:10]  # Reduced from 50
        return files[:5]

    # ==================== HISTORY MANAGEMENT ====================

    def _trim_history(self):
        """Keep only last N messages. Subclasses may override for safety."""
        if len(self.conversation_history) > self.max_history_messages:
            self.conversation_history = self.conversation_history[-self.max_history_messages:]

    def clear_history(self):
        """Clear conversation history."""
        self.conversation_history = []

    # ==================== TOOL IMPLEMENTATIONS ====================

    def _tool_search_artifacts(self, query: str, artifact_type: str = "all", limit: int = 10) -> Dict:
        """Search across forensic artifacts - returns detailed records per artifact type."""
        if artifact_type == "all":
            index = "forensic-*"
        else:
            index = f"forensic-{artifact_type}"

        # Special handling: prefetch queries → sort by run_count via aggregation
        query_lower = query.lower().strip()
        is_prefetch_overview = (
            artifact_type == "prefetch" and
            (query_lower in ("*", "all", "") or
             any(w in query_lower for w in ["top", "most", "frequent", "run count", "executed", "run_count", "programs"]))
        )
        if is_prefetch_overview:
            try:
                agg_body = {
                    "size": 0,
                    "aggs": {
                        "top_programs": {
                            "terms": {"field": "executable_name.keyword", "size": limit, "order": {"max_runs": "desc"}},
                            "aggs": {"max_runs": {"max": {"field": "run_count"}}}
                        }
                    }
                }
                if self.case_id:
                    agg_body["query"] = {"term": {"case_id.keyword": self.case_id}}
                resp = requests.post(f"{self.es_url}/forensic-prefetch/_search", json=agg_body, timeout=10)
                if resp.status_code == 200:
                    buckets = resp.json().get("aggregations", {}).get("top_programs", {}).get("buckets", [])
                    if buckets:
                        return {
                            "total_found": len(buckets),
                            "results": [
                                {
                                    "artifact_type": "prefetch",
                                    "executable_name": b["key"],
                                    "run_count": int(b["max_runs"]["value"]),
                                }
                                for b in buckets
                            ]
                        }
            except Exception as e:
                print(f"[Aggregation Error] {e}")
                pass  # Fall through to normal search

        results = self._es_search(index, query, limit)

        detailed_results = []
        for r in results[:limit]:
            art_type = r.get("artifact_type", "unknown")
            record = {
                "artifact_type": art_type,
                "timestamp": r.get("timestamp", ""),
            }

            if art_type == "prefetch":
                record.update({
                    "executable_name": r.get("executable_name", ""),
                    "executable_path": r.get("executable_path", ""),
                    "run_count": r.get("run_count", 0),
                    "prefetch_hash": r.get("prefetch_hash", ""),
                    "files_loaded": self._filter_matched_files(r.get("files_loaded", []), query),
                    "total_files_loaded": len(r.get("files_loaded", []))
                })
            elif art_type == "eventlog":
                # Parse structured event data from message JSON
                message = r.get("message", "")
                parsed_event_data = {}
                try:
                    import json as _json
                    msg_json = _json.loads(message) if message.startswith("{") else {}
                    event_data = msg_json.get("EventData", {}).get("Data", [])
                    if isinstance(event_data, list):
                        for item in event_data:
                            if isinstance(item, dict) and item.get("@Name") and item.get("#text"):
                                parsed_event_data[item["@Name"]] = item["#text"]
                except Exception:
                    pass

                record.update({
                    "event_id": r.get("event_id", ""),
                    "provider": r.get("provider", ""),
                    "channel": r.get("channel", ""),
                    "level": r.get("level", ""),
                    "computer_name": r.get("computer_name", ""),
                    "user_id": r.get("user_id", ""),
                    "message": message[:2000],
                    "event_data": parsed_event_data if parsed_event_data else None,
                })
            elif art_type == "registry":
                record.update({
                    "hive_type": r.get("hive_type", ""),
                    "key_path": r.get("key_path", ""),
                    "value_name": r.get("value_name", ""),
                    "value_data": r.get("value_data", ""),
                    "value_type": r.get("value_type", ""),
                    "category": r.get("category", ""),
                    "description": r.get("description", ""),
                })
            elif art_type == "browser_history":
                record.update({
                    "browser": r.get("browser", ""),
                    "url": r.get("url", ""),
                    "title": r.get("title", ""),
                    "visit_count": r.get("visit_count", 0),
                    "domain": r.get("domain", ""),
                })
            elif art_type == "lnk":
                record.update({
                    "lnk_name": r.get("lnk_name", ""),
                    "target_path": r.get("target_path", ""),
                    "working_directory": r.get("working_directory", ""),
                    "arguments": r.get("arguments", ""),
                    "source_created": r.get("source_created", ""),
                    "source_modified": r.get("source_modified", ""),
                    "source_accessed": r.get("source_accessed", ""),
                })
            elif art_type == "mft":
                record.update({
                    "filename": r.get("filename", ""),
                    "file_path": r.get("file_path", ""),
                    "extension": r.get("extension", ""),
                    "file_size": r.get("file_size", 0),
                    "is_directory": r.get("is_directory", False),
                    "is_deleted": r.get("is_deleted", False),
                    "created": r.get("created", ""),
                    "modified": r.get("modified", ""),
                    "accessed": r.get("accessed", ""),
                    "entry_modified": r.get("entry_modified", ""),
                })
            elif art_type == "jumplist":
                record.update({
                    "app_id": r.get("app_id", ""),
                    "app_name": r.get("app_name", ""),
                    "target_path": r.get("target_path", ""),
                    "target_created": r.get("target_created", ""),
                    "target_modified": r.get("target_modified", ""),
                    "target_accessed": r.get("target_accessed", ""),
                    "entry_name": r.get("entry_name", ""),
                })
            elif art_type == "recyclebin":
                record.update({
                    "filename": r.get("filename", ""),
                    "original_path": r.get("original_path", ""),
                    "file_size": r.get("file_size", 0),
                    "deleted_time": r.get("deleted_time", ""),
                })
            elif art_type == "shimcache":
                record.update({
                    "path": r.get("path", ""),
                    "last_modified": r.get("last_modified", ""),
                    "cache_entry_position": r.get("cache_entry_position", 0),
                    "executed": r.get("executed", ""),
                })
            elif art_type == "amcache":
                record.update({
                    "full_path": r.get("full_path", ""),
                    "name": r.get("name", ""),
                    "file_extension": r.get("file_extension", ""),
                    "sha1": r.get("sha1", ""),
                    "file_size": r.get("file_size", 0),
                    "product_name": r.get("product_name", ""),
                    "publisher": r.get("publisher", ""),
                    "link_date": r.get("link_date", ""),
                })
            elif art_type == "srum":
                record.update({
                    "app_name": r.get("app_name", ""),
                    "app_id": r.get("app_id", ""),
                    "user_name": r.get("user_name", ""),
                    "bytes_sent": r.get("bytes_sent", 0),
                    "bytes_received": r.get("bytes_received", 0),
                    "record_type": r.get("record_type", ""),
                })
            elif art_type == "powershell":
                record.update({
                    "command": r.get("command", ""),
                    "user": r.get("user", ""),
                    "line_number": r.get("line_number", 0),
                    "is_suspicious": r.get("is_suspicious", False),
                    "source_file": r.get("source_file", ""),
                })
            elif art_type == "usnjrnl":
                record.update({
                    "filename": r.get("filename", ""),
                    "file_path": r.get("file_path", ""),
                    "operation": r.get("operation", ""),
                    "update_reasons": r.get("update_reasons", ""),
                    "usn": r.get("usn", 0),
                })

            detailed_results.append(record)

        result = {
            "query": query,
            "artifact_type": artifact_type,
            "total_found": len(results),
            "results": detailed_results
        }
        if len(results) == 0:
            result["note"] = f"No data found for query '{query}' in {artifact_type}. Do NOT invent or guess data for this query."
        return result

    # File types where a manipulated timestamp is worth a user's attention. Documents and media
    # are left out: they are copied between volumes constantly, which produces the same signature
    # for entirely ordinary reasons and would bury the signal.
    _TIMESTOMP_EXTENSIONS = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs",
                             ".js", ".scr", ".sys", ".zip", ".7z", ".rar"]

    @staticmethod
    def _has_zeroed_subsecond(value: str) -> bool:
        """
        True when a timestamp carries no sub-second precision at all.

        NTFS stores file times at a resolution of 100 nanoseconds, so a value whose fractional
        part is entirely zero was not written by the file system in the ordinary way. It was
        supplied by something that works in whole seconds, which is what timestomping utilities
        do and also what software that ships its files with a fixed build time does.
        """
        if not value:
            return False
        _, separator, fraction = value.partition(".")
        if not separator:
            return True
        return set(fraction.rstrip("Zz")) <= {"0"}

    @classmethod
    def _rank_timestamp_anomalies(cls, records: List[Dict], limit: int = 20) -> Dict:
        """
        Group files whose $SI timestamps carry no sub-second precision.

        Reporting such files one by one is useless, because a single installation accounts for
        hundreds of them. They are therefore grouped by directory and by the shared timestamp, so
        that an installer that stamped every one of its files with the same value is one finding
        rather than four hundred.

        The comparison against $FILE_NAME is kept as an attribute of the group rather than as the
        selection rule. On a real image an $SI creation time earlier than the $FN one holds for
        the great majority of files, because copying a file preserves $SI while $FN is written
        afresh, so on its own it separates nothing.

        Timestamps are compared as strings. MFTECmd writes a fixed-width format, so lexicographic
        order matches chronological order and no parsing is needed.
        """
        groups: Dict[tuple, Dict] = {}
        matched = 0
        for record in records:
            created = record.get("created", "")
            if not cls._has_zeroed_subsecond(created):
                continue
            matched += 1
            path = record.get("file_path", "")
            directory = path.rsplit("\\", 1)[0] if "\\" in path else path
            group = groups.setdefault((directory, created), {
                "directory": directory, "si_created": created, "files": 0,
                "example": "", "deleted_files": 0, "si_earlier_than_fn": False,
            })
            group["files"] += 1
            if not group["example"]:
                group["example"] = record.get("filename", "") or path.rsplit("\\", 1)[-1]
            if record.get("is_deleted"):
                group["deleted_files"] += 1
            fn_created = record.get("fn_created", "")
            if fn_created and created < fn_created:
                group["si_earlier_than_fn"] = True

        ordered = sorted(groups.values(), key=lambda g: g["files"], reverse=True)
        return {
            "files_with_zeroed_subsecond": matched,
            "groups_found": len(ordered),
            "groups": ordered[:limit],
            "note": ("A group is a lead and not a conclusion. A whole-second timestamp is left "
                     "behind by timestamp manipulation utilities and equally by software that "
                     "ships its files with a fixed build time, so each group must be confirmed "
                     "against the installation history before it is reported as manipulation."),
        }

    def _tool_detect_timestamp_manipulation(self, path_contains: str = "Users",
                                            limit: int = 20) -> Dict:
        """Find files whose master-file-table timestamps show signs of manipulation."""
        must = [{"terms": {"extension": self._TIMESTOMP_EXTENSIONS}}]
        if path_contains:
            must.append({"match_phrase": {"file_path": path_contains}})

        # The case filter is unconditional. A tool that builds its own query body and leaves it
        # out returns records from whichever case sorts first once more than one case is indexed.
        filters = [{"term": {"case_id.keyword": self.case_id}}] if self.case_id else []

        body = {"size": 2000, "query": {"bool": {"must": must, "filter": filters}},
                "_source": ["file_path", "filename", "created", "modified",
                            "fn_created", "fn_modified", "is_deleted"]}

        try:
            response = requests.post(f"{self.es_url}/forensic-mft/_search", json=body, timeout=15)
            if response.status_code != 200:
                return {"error": f"Search failed with status {response.status_code}"}
            records = [hit["_source"] for hit in response.json().get("hits", {}).get("hits", [])]
        except Exception as e:
            return {"error": f"Search failed: {e}"}

        if not records:
            return {"groups": [], "note": "No executable, script or archive matches this scope in "
                                          "the master file table. Do NOT infer from this that no "
                                          "manipulation occurred."}

        result = self._rank_timestamp_anomalies(records, limit)
        result["records_examined"] = len(records)
        result["scope"] = {"path_contains": path_contains,
                           "extensions": self._TIMESTOMP_EXTENSIONS}
        if len(records) >= 2000:
            result["truncated"] = ("The scope returned at least 2000 records and was cut there. "
                                   "Narrow it with path_contains before reading the counts.")
        if not any(r.get("fn_created") for r in records):
            result["fn_timestamps_absent"] = ("This index holds no $FILE_NAME timestamps, so the "
                                              "cross-check against them could not be applied.")
        return result

    def _tool_analyze_program(self, program_name: str) -> Dict:
        """Analyze program execution across 6 artifact sources."""
        prefetch = self._es_search("forensic-prefetch", program_name, 100)
        lnk = self._es_search("forensic-lnk", program_name, 50)
        registry = self._es_search("forensic-registry", program_name, 50)
        shimcache = self._es_search("forensic-shimcache", program_name, 50)
        amcache = self._es_search("forensic-amcache", program_name, 50)
        jumplist = self._es_search("forensic-jumplist", program_name, 50)

        prefetch_details = []
        for r in prefetch:
            prefetch_details.append({
                "timestamp": r.get("timestamp", ""),
                "executable_name": r.get("executable_name", ""),
                "executable_path": r.get("executable_path", ""),
                "run_count": r.get("run_count", 0),
                "prefetch_hash": r.get("prefetch_hash", ""),
                "files_loaded": self._filter_matched_files(r.get("files_loaded", []), program_name),
                "total_files_loaded": len(r.get("files_loaded", []))
            })

        lnk_details = []
        for r in lnk:
            lnk_details.append({
                "timestamp": r.get("timestamp", ""),
                "lnk_name": r.get("lnk_name", ""),
                "target_path": r.get("target_path", ""),
                "working_directory": r.get("working_directory", ""),
                "arguments": r.get("arguments", ""),
                "source_created": r.get("source_created", ""),
                "source_modified": r.get("source_modified", ""),
            })

        registry_details = []
        for r in registry:
            registry_details.append({
                "timestamp": r.get("timestamp", ""),
                "hive_type": r.get("hive_type", ""),
                "key_path": r.get("key_path", ""),
                "value_name": r.get("value_name", ""),
                "value_data": r.get("value_data", ""),
                "category": r.get("category", ""),
            })

        shimcache_details = []
        for r in shimcache:
            shimcache_details.append({
                "timestamp": r.get("timestamp", ""),
                "path": r.get("path", ""),
                "last_modified": r.get("last_modified", ""),
                "cache_entry_position": r.get("cache_entry_position", 0),
                "executed": r.get("executed", ""),
            })

        amcache_details = []
        for r in amcache:
            amcache_details.append({
                "timestamp": r.get("timestamp", ""),
                "full_path": r.get("full_path", ""),
                "name": r.get("name", ""),
                "sha1": r.get("sha1", ""),
                "file_size": r.get("file_size", 0),
                "product_name": r.get("product_name", ""),
                "publisher": r.get("publisher", ""),
            })

        jumplist_details = []
        for r in jumplist:
            jumplist_details.append({
                "timestamp": r.get("timestamp", ""),
                "app_name": r.get("app_name", ""),
                "target_path": r.get("target_path", ""),
                "entry_name": r.get("entry_name", ""),
            })

        all_times = [r["timestamp"] for r in prefetch_details if r["timestamp"]]
        all_times.extend([r["timestamp"] for r in lnk_details if r["timestamp"]])
        all_times.extend([r["timestamp"] for r in shimcache_details if r["timestamp"]])
        all_times.extend([r["timestamp"] for r in amcache_details if r["timestamp"]])

        return {
            "program": program_name,
            "summary": {
                "prefetch_records": len(prefetch),
                "lnk_records": len(lnk),
                "registry_records": len(registry),
                "shimcache_records": len(shimcache),
                "amcache_records": len(amcache),
                "jumplist_records": len(jumplist),
                "first_seen": min(all_times) if all_times else None,
                "last_seen": max(all_times) if all_times else None,
            },
            "prefetch": prefetch_details,
            "lnk_shortcuts": lnk_details,
            "registry_entries": registry_details,
            "shimcache": shimcache_details,
            "amcache": amcache_details,
            "jumplist": jumplist_details
        }

    def _tool_analyze_web(self, domain: str = None, limit: int = 15) -> Dict:
        """Analyze web activity with domain stats, timeline, and search detection."""
        # Get REAL domain counts via aggregation (not limited by result set)
        real_domain_counts = {}
        try:
            agg_body = {
                "size": 0,
                "aggs": {"domains": {"terms": {"field": "domain.keyword", "size": 30}}}
            }
            if self.case_id:
                agg_body["query"] = {"term": {"case_id.keyword": self.case_id}}
            r = requests.post(f"{self.es_url}/forensic-browser/_search", json=agg_body, timeout=10)
            if r.status_code == 200:
                buckets = r.json().get("aggregations", {}).get("domains", {}).get("buckets", [])
                real_domain_counts = {b["key"]: b["doc_count"] for b in buckets}
        except Exception:
            pass

        results = self._es_search("forensic-browser", domain, limit)

        domains = {}
        timeline = []

        for r in results:
            d = r.get("domain", "unknown")
            if d not in domains:
                domains[d] = {"count": 0, "first_visit": None, "last_visit": None, "visits": []}
            domains[d]["count"] += r.get("visit_count", 1)

            visit_time = r.get("timestamp", "")
            if not domains[d]["first_visit"] or visit_time < domains[d]["first_visit"]:
                domains[d]["first_visit"] = visit_time
            if not domains[d]["last_visit"] or visit_time > domains[d]["last_visit"]:
                domains[d]["last_visit"] = visit_time

            domains[d]["visits"].append({
                "url": r.get("url", ""),
                "title": r.get("title", ""),
                "time": visit_time
            })

            timeline.append({
                "timestamp": visit_time,
                "domain": d,
                "title": r.get("title", "")[:60],
                "url": r.get("url", "")
            })

        timeline.sort(key=lambda x: x["timestamp"])

        top = sorted(domains.items(), key=lambda x: x[1]["count"], reverse=True)[:20]

        return {
            "search_query": domain,
            "total_records_returned": len(results),
            "unique_domains_returned": len(domains),
            "real_top_domains": [
                {"domain": d, "total_records": c}
                for d, c in sorted(real_domain_counts.items(), key=lambda x: -x[1])[:20]
            ],
            "note": "real_top_domains shows actual counts from all case records via aggregation. top_domains below only counts returned results.",
            "top_domains": [
                {
                    "domain": d,
                    "visits": v["count"],
                    "first_visit": v["first_visit"],
                    "last_visit": v["last_visit"]
                }
                for d, v in top
            ],
            "browsing_timeline": timeline[:30],
            "recent_searches": [
                t for t in timeline
                if "search" in t["url"].lower() or "google.com/search" in t["url"].lower()
            ][:10]
        }

    def _tool_find_suspicious(self) -> Dict:
        """Find suspicious activity - comprehensive malware/IOC detection."""
        suspicious = []

        # 1. Executions from TEMP/Downloads
        for search_term in ["TEMP", "Downloads", "AppData"]:
            temp_exec = self._es_search("forensic-prefetch", search_term, 30)
            for r in temp_exec:
                exe_path = r.get("executable_path", "").lower()
                exe_name = r.get("executable_name", "")
                if any(x in exe_path for x in ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\"]):
                    suspicious.append({
                        "type": "temp_execution",
                        "severity": "high",
                        "description": f"Program executed from suspicious folder: {exe_name}",
                        "executable_path": r.get("executable_path", ""),
                        "run_count": r.get("run_count", 0),
                        "timestamp": r.get("timestamp", "")
                    })

        # 2. Malware keywords in files_loaded
        malware_keywords = [
            "ransom", "locker", "malware", "virus", "trojan",
            "backdoor", "rootkit", "keylog", "stealer", "miner",
            "botnet", "mimikatz", "lazagne", "bloodhound", "cobalt",
            "payload", "exploit", "reverse", "beacon", "hack"
        ]
        system_exclusions = [
            "\\windows\\system32\\", "\\windows\\syswow64\\",
            "\\windows\\winsxs\\", "\\program files\\common files\\",
            ".dll", "bcrypt", "crypt32", "cryptsp", "cryptbase"
        ]

        for keyword in malware_keywords:
            results = self._es_search("forensic-prefetch", keyword, 50)
            for r in results:
                files_loaded = r.get("files_loaded", [])
                exe_name = r.get("executable_name", "")

                matched_files = []
                for f in files_loaded:
                    f_lower = f.lower()
                    if keyword.lower() in f_lower:
                        if not any(excl in f_lower for excl in system_exclusions):
                            matched_files.append(f)

                if matched_files:
                    suspicious.append({
                        "type": "malware_indicator",
                        "severity": "critical",
                        "description": f"Suspicious file loaded by {exe_name}: {keyword}",
                        "executable": exe_name,
                        "executable_path": r.get("executable_path", ""),
                        "matched_files": matched_files[:5],
                        "timestamp": r.get("timestamp", ""),
                        "run_count": r.get("run_count", 0)
                    })

                if keyword.lower() in exe_name.lower():
                    suspicious.append({
                        "type": "malware_executable",
                        "severity": "critical",
                        "description": f"Suspicious executable name: {exe_name}",
                        "executable_path": r.get("executable_path", ""),
                        "timestamp": r.get("timestamp", ""),
                        "run_count": r.get("run_count", 0)
                    })

        # 3. Malware keywords in registry
        for keyword in malware_keywords[:10]:
            reg_results = self._es_search("forensic-registry", keyword, 20)
            for r in reg_results:
                value_data = r.get("value_data", "")
                if keyword.lower() in value_data.lower():
                    suspicious.append({
                        "type": "registry_malware_indicator",
                        "severity": "critical",
                        "description": f"Suspicious registry value contains: {keyword}",
                        "key_path": r.get("key_path", ""),
                        "value_data": value_data[:200],
                        "timestamp": r.get("timestamp", "")
                    })

        # 4. Suspicious Event IDs (exact match)
        suspicious_events = {
            1102: ("critical", "Audit log cleared - anti-forensics"),
            1116: ("critical", "Windows Defender malware detected"),
            1117: ("critical", "Windows Defender action taken on malware"),
            4625: ("medium", "Failed login attempt"),
            4648: ("medium", "Explicit credentials used (pass-the-hash?)"),
            4672: ("low", "Special privileges assigned"),
            4697: ("high", "Service installed"),
            7045: ("high", "Service installed (System)"),
            4104: ("high", "PowerShell script block logging"),
        }

        for event_id, (severity, desc) in suspicious_events.items():
            hits = self._es_exact_search("forensic-eventlog", "event_id", event_id, 30)
            for r in hits:
                # Parse structured event data from message JSON
                message = r.get("message", "")
                parsed_event_data = {}
                try:
                    import json as _json
                    msg_json = _json.loads(message) if message.startswith("{") else {}
                    event_data = msg_json.get("EventData", {}).get("Data", [])
                    if isinstance(event_data, list):
                        for item in event_data:
                            if isinstance(item, dict) and item.get("@Name") and item.get("#text"):
                                parsed_event_data[item["@Name"]] = item["#text"]
                except Exception:
                    pass

                entry = {
                    "type": "suspicious_event",
                    "severity": severity,
                    "event_id": event_id,
                    "description": desc,
                    "message": message[:2000],
                    "timestamp": r.get("timestamp", ""),
                    "provider": r.get("provider", ""),
                    "channel": r.get("channel", ""),
                    "computer": r.get("computer_name", "")
                }
                if parsed_event_data:
                    entry["event_data"] = parsed_event_data
                suspicious.append(entry)

        # 5. Registry persistence (Run keys, Services)
        for key_term in ["Run", "RunOnce", "Services"]:
            reg_entries = self._es_search("forensic-registry", key_term, 20)
            for r in reg_entries:
                key_path = r.get("key_path", "").lower()
                if "\\run" in key_path or "\\services" in key_path:
                    suspicious.append({
                        "type": "persistence",
                        "severity": "medium",
                        "description": f"Persistence mechanism: {r.get('key_path', '')[:80]}",
                        "value": r.get("value_data", "")[:100],
                        "timestamp": r.get("timestamp", "")
                    })

        # Deduplicate
        seen = set()
        unique_suspicious = []
        for s in suspicious:
            key = (s.get("description", ""), s.get("timestamp", ""))
            if key not in seen:
                seen.add(key)
                unique_suspicious.append(s)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique_suspicious.sort(key=lambda x: severity_order.get(x["severity"], 99))

        return {
            "total_suspicious": len(unique_suspicious),
            "by_severity": {
                "critical": len([s for s in unique_suspicious if s["severity"] == "critical"]),
                "high": len([s for s in unique_suspicious if s["severity"] == "high"]),
                "medium": len([s for s in unique_suspicious if s["severity"] == "medium"]),
                "low": len([s for s in unique_suspicious if s["severity"] == "low"])
            },
            "findings": unique_suspicious[:100]
        }

    def _tool_get_stats(self) -> Dict:
        """Get case statistics for all 13 artifact types."""
        stats = {}
        total = 0

        for index in self.get_all_indices():
            try:
                if self.case_id:
                    body = {"query": {"term": {"case_id.keyword": self.case_id}}}
                    response = requests.post(f"{self.es_url}/{index}/_count", json=body, timeout=5)
                else:
                    response = requests.get(f"{self.es_url}/{index}/_count", timeout=5)
                if response.status_code == 200:
                    count = response.json().get("count", 0)
                    stats[index.replace("forensic-", "")] = count
                    total += count
                else:
                    stats[index.replace("forensic-", "")] = 0
            except:
                stats[index.replace("forensic-", "")] = 0

        time_range = self._get_data_time_range()

        return {
            "total_records": total,
            "by_artifact_type": stats,
            "data_time_range": time_range,
            "status": "data_available" if total > 0 else "no_data"
        }

    def _tool_analyze_deleted_files(self, filename: str = None, limit: int = 10) -> Dict:
        """Analyze deleted files from Recycle Bin."""
        results = self._es_search("forensic-recyclebin", filename, limit)

        deleted_files = []
        for r in results:
            deleted_files.append({
                "timestamp": r.get("timestamp", ""),
                "filename": r.get("filename", ""),
                "original_path": r.get("original_path", ""),
                "file_size": r.get("file_size", 0),
                "deleted_time": r.get("deleted_time", ""),
            })

        deleted_files.sort(key=lambda x: x.get("deleted_time", ""), reverse=True)

        total_size = sum(f.get("file_size", 0) for f in deleted_files)
        extensions = {}
        for f in deleted_files:
            fname = f.get("filename", "")
            if "." in fname:
                ext = fname.split(".")[-1].lower()
                extensions[ext] = extensions.get(ext, 0) + 1

        return {
            "search_query": filename,
            "total_deleted_files": len(deleted_files),
            "total_size_bytes": total_size,
            "by_extension": dict(sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:10]),
            "deleted_files": deleted_files[:limit]
        }

    def _tool_search_file_activity(self, filename: str = None, extension: str = None, limit: int = 10) -> Dict:
        """Search file activity across MFT, JumpList, and LNK."""
        query = filename or extension or ""

        mft_results = self._es_search("forensic-mft", query, limit)
        jumplist_results = self._es_search("forensic-jumplist", query, limit)
        lnk_results = self._es_search("forensic-lnk", query, limit)

        all_activity = []

        for r in mft_results:
            all_activity.append({
                "timestamp": r.get("timestamp", r.get("modified", "")),
                "source": "mft",
                "filename": r.get("filename", ""),
                "file_path": r.get("file_path", ""),
                "file_size": r.get("file_size", 0),
                "created": r.get("created", ""),
                "modified": r.get("modified", ""),
                "accessed": r.get("accessed", ""),
            })

        for r in jumplist_results:
            all_activity.append({
                "timestamp": r.get("timestamp", ""),
                "source": "jumplist",
                "app_name": r.get("app_name", ""),
                "target_path": r.get("target_path", ""),
                "entry_name": r.get("entry_name", ""),
            })

        for r in lnk_results:
            all_activity.append({
                "timestamp": r.get("timestamp", ""),
                "source": "lnk",
                "lnk_name": r.get("lnk_name", ""),
                "target_path": r.get("target_path", ""),
            })

        all_activity.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        return {
            "search_query": query,
            "summary": {
                "mft_records": len(mft_results),
                "jumplist_records": len(jumplist_results),
                "lnk_records": len(lnk_results),
                "total_records": len(all_activity)
            },
            "activity": all_activity[:limit]
        }

    def _tool_analyze_network_activity(self, app_name: str = None, limit: int = 15) -> Dict:
        """Analyze network activity from SRUM."""
        import requests as _req

        # Use ES aggregation to get top apps by actual traffic (not text search)
        must_clauses = []
        if self.case_id:
            must_clauses.append({"term": {"case_id.keyword": self.case_id}})
        if app_name:
            must_clauses.append({"match": {"app_name": app_name}})
        # Only records with actual traffic
        must_clauses.append({"bool": {"should": [
            {"range": {"bytes_sent": {"gt": 0}}},
            {"range": {"bytes_received": {"gt": 0}}}
        ]}})

        agg_query = {
            "size": 0,
            "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
            "aggs": {
                "by_app": {
                    "terms": {"field": "app_name.keyword", "size": limit},
                    "aggs": {
                        "total_sent": {"sum": {"field": "bytes_sent"}},
                        "total_recv": {"sum": {"field": "bytes_received"}}
                    }
                },
                "total_sent": {"sum": {"field": "bytes_sent"}},
                "total_recv": {"sum": {"field": "bytes_received"}}
            }
        }

        try:
            resp = _req.post(
                f"{self.es_url}/forensic-srum/_search",
                json=agg_query, timeout=15
            )
            data = resp.json()
            buckets = data.get("aggregations", {}).get("by_app", {}).get("buckets", [])
            total_sent = data.get("aggregations", {}).get("total_sent", {}).get("value", 0)
            total_recv = data.get("aggregations", {}).get("total_recv", {}).get("value", 0)

            top_apps = sorted(
                buckets,
                key=lambda b: b["total_sent"]["value"] + b["total_recv"]["value"],
                reverse=True
            )

            if not top_apps:
                return {
                    "status": "no_traffic_data",
                    "message": "SRUM data exists but all bytes_sent and bytes_received are 0. No meaningful network traffic recorded.",
                    "total_bytes_sent": 0,
                    "total_bytes_received": 0
                }

            return {
                "search_query": app_name,
                "total_bytes_sent": int(total_sent),
                "total_bytes_received": int(total_recv),
                "top_applications": [
                    {
                        "app_name": b["key"],
                        "bytes_sent": int(b["total_sent"]["value"]),
                        "bytes_received": int(b["total_recv"]["value"]),
                        "total_traffic": int(b["total_sent"]["value"] + b["total_recv"]["value"])
                    }
                    for b in top_apps[:20]
                ]
            }
        except Exception as e:
            # Fallback to text search
            results = self._es_search("forensic-srum", app_name, limit)
            return {"error": str(e), "fallback_records": len(results)}

    def _tool_analyze_powershell_commands(self, suspicious_only: bool = False, limit: int = 20) -> Dict:
        """Analyze PowerShell command history."""
        results = self._es_search("forensic-powershell", None, limit)

        commands = []
        suspicious_commands = []

        for r in results:
            cmd_data = {
                "timestamp": r.get("timestamp", ""),
                "command": r.get("command", ""),
                "user": r.get("user", ""),
                "is_suspicious": r.get("is_suspicious", False),
                "line_number": r.get("line_number", 0),
            }
            commands.append(cmd_data)
            if r.get("is_suspicious", False):
                suspicious_commands.append(cmd_data)

        if suspicious_only:
            commands = suspicious_commands

        return {
            "total_commands": len(results),
            "total_suspicious": len(suspicious_commands),
            "suspicious_commands": suspicious_commands,
            "commands": commands[:limit]
        }

    def _tool_search_file_changes(self, filename: str = None, operation: str = "all", limit: int = 15) -> Dict:
        """Search USN Journal for file changes."""
        results = self._es_search("forensic-usnjrnl", filename, limit * 2)

        if operation and operation != "all":
            results = [r for r in results if r.get("operation", "").upper() == operation.upper()]

        by_operation = {}
        for r in results:
            op = r.get("operation", "UNKNOWN")
            if op not in by_operation:
                by_operation[op] = []
            by_operation[op].append({
                "timestamp": r.get("timestamp", ""),
                "filename": r.get("filename", ""),
                "file_path": r.get("file_path", ""),
                "update_reasons": r.get("update_reasons", ""),
            })

        return {
            "search_query": filename,
            "operation_filter": operation,
            "total_changes": len(results),
            "by_operation": {op: len(changes) for op, changes in by_operation.items()},
            "changes": results[:limit]
        }

    def _tool_analyze_registry(self, category: str = "all", query: str = None, limit: int = 15) -> Dict:
        """Analyze Windows Registry for persistence, user activity, etc."""
        persistence_patterns = [
            "Run", "RunOnce", "Services", "Scheduled", "Startup",
            "Shell", "Userinit", "Winlogon", "AppInit", "Image File Execution"
        ]
        user_activity_patterns = [
            "RecentDocs", "MRU", "UserAssist", "TypedURLs", "RunMRU",
            "ComDlg32", "OpenSavePidlMRU", "LastVisited"
        ]
        network_patterns = [
            "Interfaces", "Tcpip", "NetworkList", "Profiles"
        ]
        malware_patterns = [
            "Debugger", "AppInit_DLLs", "InprocServer", "ShellExecuteHooks",
            "Browser Helper", "Explorer\\Browser"
        ]
        system_info_patterns = [
            "CurrentVersion", "ProductName", "CurrentBuild", "InstallDate",
            "ComputerName", "TimeZone", "USBSTOR", "MountPoints2"
        ]

        if category == "persistence":
            patterns = persistence_patterns
        elif category == "user_activity":
            patterns = user_activity_patterns
        elif category == "network":
            patterns = network_patterns
        elif category == "malware":
            patterns = malware_patterns
        elif category == "system_info":
            patterns = system_info_patterns
        else:
            patterns = persistence_patterns + user_activity_patterns + network_patterns + malware_patterns + system_info_patterns

        all_results = []
        for pattern in patterns[:10]:
            results = self._es_search("forensic-registry", pattern, limit // 5)
            all_results.extend(results)

        if query:
            query_results = self._es_search("forensic-registry", query, limit)
            all_results.extend(query_results)

        seen = set()
        unique_results = []
        for r in all_results:
            key = r.get("key_path", "") + r.get("value_name", "")
            if key not in seen:
                seen.add(key)
                unique_results.append(r)

        categorized = {
            "persistence": [],
            "user_activity": [],
            "network": [],
            "other": []
        }

        for r in unique_results:
            key_path = r.get("key_path", "").lower()
            entry = {
                "timestamp": r.get("timestamp", ""),
                "key_path": r.get("key_path", ""),
                "value_name": r.get("value_name", ""),
                "value_data": r.get("value_data", "")[:200],
                "hive": r.get("hive_type", ""),
            }

            if any(p.lower() in key_path for p in persistence_patterns):
                categorized["persistence"].append(entry)
            elif any(p.lower() in key_path for p in user_activity_patterns):
                categorized["user_activity"].append(entry)
            elif any(p.lower() in key_path for p in network_patterns):
                categorized["network"].append(entry)
            else:
                categorized["other"].append(entry)

        return {
            "category_filter": category,
            "query": query,
            "total_found": len(unique_results),
            "summary": {k: len(v) for k, v in categorized.items()},
            "persistence_keys": categorized["persistence"][:20],
            "user_activity": categorized["user_activity"][:20],
            "network_config": categorized["network"][:10],
            "other": categorized["other"][:10]
        }

    def _tool_analyze_security_events(self, event_category: str = "all", event_id: int = None, limit: int = 20) -> Dict:
        """Analyze Windows Security Event Logs."""
        event_categories = {
            "authentication": [4624, 4625, 4634, 4647, 4648, 4672],
            "privilege": [4672, 4673, 4674],
            "account_management": [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740],
            "service_install": [7045, 4697],
            "audit_clear": [1102, 104],
        }

        target_ids = []
        if event_id:
            target_ids = [event_id]
        elif event_category != "all" and event_category in event_categories:
            target_ids = event_categories[event_category]
        else:
            for ids in event_categories.values():
                target_ids.extend(ids)

        all_events = []
        event_counts = {}
        for eid in target_ids[:15]:
            # Use exact search on numeric event_id field (multi_match doesn't work on numeric fields)
            results = self._es_exact_search("forensic-eventlog", "event_id", eid, limit // len(target_ids) + 10)
            all_events.extend(results)
            # Also get total count for this event ID
            try:
                count_query = {"bool": {"must": [{"term": {"event_id": eid}}]}}
                if self.case_id:
                    count_query["bool"]["filter"] = [{"term": {"case_id.keyword": self.case_id}}]
                r = requests.post(f"{self.es_url}/forensic-eventlog/_count", json={"query": count_query}, timeout=5)
                if r.status_code == 200:
                    event_counts[str(eid)] = r.json().get("count", 0)
            except:
                pass

        seen = set()
        unique_events = []
        for e in all_events:
            key = f"{e.get('timestamp', '')}-{e.get('event_id', '')}-{e.get('record_id', '')}"
            if key not in seen:
                seen.add(key)
                unique_events.append(e)

        unique_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        by_category = {cat: [] for cat in event_categories}
        suspicious_events = []

        for e in unique_events[:limit]:
            eid = e.get("event_id", 0)
            message = e.get("message", "")

            # Parse structured event data from message JSON
            parsed_event_data = {}
            try:
                import json as _json
                msg_json = _json.loads(message) if message.startswith("{") else {}
                ed = msg_json.get("EventData", {}).get("Data", [])
                if isinstance(ed, list):
                    for item in ed:
                        if isinstance(item, dict) and item.get("@Name") and item.get("#text"):
                            parsed_event_data[item["@Name"]] = item["#text"]
            except Exception:
                pass

            event_data = {
                "timestamp": e.get("timestamp", ""),
                "event_id": eid,
                "provider": e.get("provider", ""),
                "channel": e.get("channel", ""),
                "computer": e.get("computer_name", ""),
                "user": e.get("user_id", ""),
                "message": message[:2000],
            }
            if parsed_event_data:
                event_data["event_data"] = parsed_event_data

            for cat, ids in event_categories.items():
                if eid in ids:
                    by_category[cat].append(event_data)
                    break

            if eid in [4625, 1102, 7045, 4648, 4672, 1116, 1117]:
                suspicious_events.append(event_data)

        # Compute REAL totals per category using event_id_counts
        cat_totals = {}
        for cat, ids in event_categories.items():
            cat_totals[cat] = sum(event_counts.get(str(eid), 0) for eid in ids)

        return {
            "category_filter": event_category,
            "event_id_filter": event_id,
            "total_events_returned": len(unique_events),
            "note": "total_events_returned is how many events are returned in this response. For REAL counts per event ID, see event_id_counts below.",
            "event_id_counts": event_counts,
            "real_totals_per_category": cat_totals,
            "summary_note": "Summary fields below show COUNT OF RETURNED EVENTS (may be limited), not real totals. Use event_id_counts for real totals.",
            "summary": {
                "authentication_events_shown": len(by_category["authentication"]),
                "privilege_events_shown": len(by_category["privilege"]),
                "account_management_shown": len(by_category["account_management"]),
                "service_installs_shown": len(by_category["service_install"]),
                "audit_cleared_shown": len(by_category["audit_clear"]),
            },
            "suspicious_events": suspicious_events[:20],
            "authentication": by_category["authentication"][:30],
            "privilege": by_category["privilege"][:15],
            "account_management": by_category["account_management"][:15],
            "service_installs": by_category["service_install"][:10],
            "audit_cleared": by_category["audit_clear"][:10]
        }

    def _tool_get_full_timeline(self, start_time: str = None, end_time: str = None,
                                 artifact_types: list = None, limit: int = 20) -> Dict:
        """Build comprehensive timeline from all artifact types."""
        all_indices = self.get_all_indices()

        if artifact_types:
            all_indices = [idx for idx in all_indices if idx.replace("forensic-", "") in artifact_types]

        query_body = {
            "size": limit,
            "sort": [{"timestamp.keyword": {"order": "asc", "unmapped_type": "keyword"}}]
        }

        must_clauses = []
        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time
            if end_time:
                time_range["lte"] = end_time
            must_clauses.append({"range": {"timestamp": time_range}})

        # Scope every timeline query to the active case, as the other tools do. Without this the
        # query carries no case filter at all, so on an index holding more than one case it returns
        # whichever records sort first, which may belong to a different investigation entirely.
        filter_clauses = []
        if self.case_id:
            filter_clauses.append({"term": {"case_id.keyword": self.case_id}})

        if must_clauses or filter_clauses:
            query_body["query"] = {"bool": {"must": must_clauses,
                                            "filter": filter_clauses}}

        timeline = []
        by_type = {}

        for index in all_indices:
            try:
                response = requests.post(
                    f"{self.es_url}/{index}/_search",
                    json=query_body,
                    timeout=10
                )
                if response.status_code == 200:
                    hits = response.json().get("hits", {}).get("hits", [])
                    art_type = index.replace("forensic-", "")
                    by_type[art_type] = len(hits)

                    for hit in hits:
                        r = hit["_source"]
                        timeline.append({
                            "timestamp": r.get("timestamp", ""),
                            "artifact_type": art_type,
                            "summary": self._summarize_record(r),
                            "details": {k: v for k, v in r.items() if k not in ["_meta", "artifact_type"]}
                        })
            except:
                continue

        timeline.sort(key=lambda x: x.get("timestamp", ""))

        return {
            "time_range": {"start": start_time, "end": end_time},
            "artifact_types_queried": [i.replace("forensic-", "") for i in all_indices],
            "events_by_type": by_type,
            "total_events": len(timeline),
            "timeline": timeline[:limit]
        }

    def _tool_reconstruct_attack_chain(self, provider: str = "deepseek",
                                        run: int = 1) -> Dict:
        """Run Mode 2 attack-chain reconstruction for the analyzer's case.

        Returns a chronologically ordered chain of 15-30 incident steps
        with MITRE ATT&CK phase classification and source attribution.
        Persists both the full evidence set (~1,000 records from 98
        case-agnostic anchors) and the distilled attack chain JSON to
        /reports/<case_id>/ for audit.

        Retrieval bounds what the model is shown, but it does not by itself
        keep a statement inside the evidence, so the returned chain is checked
        after the fact. The result carries a `grounding` block giving, for this
        run, how many events state a checkable fact, how many of those cite an
        entity absent from the persisted evidence, and which entities those
        were. Event IDs are matched against the records' typed `event_id`
        field rather than by substring, because anchor names embed Event IDs.
        """
        from src.tools.reconstruct_attack_chain import reconstruct_attack_chain
        return reconstruct_attack_chain(
            case_id=self.case_id,
            provider=provider,
            run=run,
        )

    def _tool_correlate_activity(self, entity: str, entity_type: str = "auto", limit: int = 20) -> Dict:
        """Correlate activity across all artifacts for a specific entity."""
        all_indices = self.get_all_indices()

        correlated = {}
        total_matches = 0

        for index in all_indices:
            art_type = index.replace("forensic-", "")
            results = self._es_search(index, entity, limit)

            if results:
                correlated[art_type] = {
                    "count": len(results),
                    "records": [
                        {
                            "timestamp": r.get("timestamp", ""),
                            "summary": self._summarize_record(r)
                        }
                        for r in results[:limit]
                    ]
                }
                total_matches += len(results)

        unified_timeline = []
        for art_type, data in correlated.items():
            for record in data["records"]:
                unified_timeline.append({
                    "timestamp": record["timestamp"],
                    "artifact_type": art_type,
                    "summary": record["summary"]
                })

        unified_timeline.sort(key=lambda x: x.get("timestamp", ""))

        return {
            "entity": entity,
            "entity_type": entity_type,
            "total_matches": total_matches,
            "matches_by_artifact": {k: v["count"] for k, v in correlated.items()},
            "correlated_data": correlated,
            "unified_timeline": unified_timeline[:limit * 3]
        }

    def _tool_detect_lateral_movement(self, limit: int = 15) -> Dict:
        """Detect potential lateral movement indicators."""
        indicators = {
            "remote_logons": [],
            "psexec_usage": [],
            "rdp_activity": [],
            "wmi_activity": [],
            "scheduled_tasks": [],
            "suspicious_services": []
        }

        # Remote logon events (4624 type 3, 10)
        logon_events = self._es_search("forensic-eventlog", "4624", limit)
        for e in logon_events:
            msg = str(e.get("message", "")).lower()
            if "type 3" in msg or "type 10" in msg or "network" in msg or "remoteinteractive" in msg:
                indicators["remote_logons"].append({
                    "timestamp": e.get("timestamp", ""),
                    "computer": e.get("computer_name", ""),
                    "user": e.get("user_id", ""),
                    "message": e.get("message", "")[:500]
                })

        # PsExec indicators
        psexec_results = self._es_search("forensic-prefetch", "psexec", limit)
        psexec_results.extend(self._es_search("forensic-shimcache", "psexec", limit))
        for r in psexec_results:
            indicators["psexec_usage"].append({
                "timestamp": r.get("timestamp", ""),
                "source": r.get("artifact_type", ""),
                "path": r.get("executable_name", r.get("path", "")),
            })

        # RDP activity
        rdp_results = self._es_search("forensic-eventlog", "rdp", limit)
        rdp_results.extend(self._es_search("forensic-eventlog", "Terminal", limit))
        for r in rdp_results:
            indicators["rdp_activity"].append({
                "timestamp": r.get("timestamp", ""),
                "event_id": r.get("event_id", ""),
                "message": r.get("message", "")[:500]
            })

        # WMI activity
        wmi_results = self._es_search("forensic-prefetch", "wmi", limit)
        wmi_results.extend(self._es_search("forensic-prefetch", "scrcons", limit))
        for r in wmi_results:
            indicators["wmi_activity"].append({
                "timestamp": r.get("timestamp", ""),
                "executable": r.get("executable_name", ""),
                "run_count": r.get("run_count", 0)
            })

        # Scheduled task creation
        schtask_results = self._es_search("forensic-eventlog", "schtasks", limit)
        schtask_results.extend(self._es_search("forensic-prefetch", "schtasks", limit))
        for r in schtask_results:
            indicators["scheduled_tasks"].append({
                "timestamp": r.get("timestamp", ""),
                "source": r.get("artifact_type", "eventlog"),
                "details": r.get("message", r.get("executable_name", ""))[:500]
            })

        # Suspicious service installs (Event 7045)
        service_events = self._es_search("forensic-eventlog", "7045", limit)
        for e in service_events:
            indicators["suspicious_services"].append({
                "timestamp": e.get("timestamp", ""),
                "message": e.get("message", "")[:300]
            })

        # Risk score
        risk_score = 0
        if len(indicators["remote_logons"]) > 5:
            risk_score += 20
        if len(indicators["psexec_usage"]) > 0:
            risk_score += 30
        if len(indicators["wmi_activity"]) > 3:
            risk_score += 15
        if len(indicators["suspicious_services"]) > 0:
            risk_score += 25
        if len(indicators["scheduled_tasks"]) > 5:
            risk_score += 10

        return {
            "risk_score": min(risk_score, 100),
            "summary": {k: len(v) for k, v in indicators.items()},
            "remote_logons": indicators["remote_logons"][:15],
            "psexec_usage": indicators["psexec_usage"][:10],
            "rdp_activity": indicators["rdp_activity"][:10],
            "wmi_activity": indicators["wmi_activity"][:10],
            "scheduled_tasks": indicators["scheduled_tasks"][:10],
            "suspicious_services": indicators["suspicious_services"][:10]
        }

    def _tool_get_wallet_artifacts(self, address: str = None, tx_hash: str = None,
                                   chain: str = None, wallet_app: str = None,
                                   record_type: str = None,
                                   include_full_value: bool = False,
                                   limit: int = 30) -> Dict:
        """Query crypto wallet / exchange artifacts with EXACT identifier matching.

        Covers both crypto indices at once. Addresses and transaction hashes are matched
        exactly (or as a phrase inside a stored value), which plain keyword search cannot
        do reliably for 42- and 66-character identifiers.
        """
        indices = "forensic-wallet,forensic-exchange"

        filters = []
        if self.case_id:
            filters.append({"term": {"case_id.keyword": self.case_id}})
        if chain:
            filters.append({"term": {"chain": chain}})
        if record_type:
            filters.append({"term": {"record_type": record_type}})
        if wallet_app:
            filters.append({"match": {"wallet_app": wallet_app}})

        lookup = None
        must = []
        if address:
            lookup = {"type": "address", "value": address}
            must.append({"bool": {"minimum_should_match": 1, "should": [
                {"term": {"wallet_address": address}},
                {"match_phrase": {"value_full": address}},
            ]}})
        elif tx_hash:
            lookup = {"type": "tx_hash", "value": tx_hash}
            must.append({"match_phrase": {"value_full": tx_hash}})

        query = {"bool": {"filter": filters, "must": must or [{"match_all": {}}]}}
        params = {"ignore_unavailable": "true"}
        result = {"lookup": lookup, "found": 0, "summary": {}, "records": []}

        # --- summary over the whole match set (not just the returned page) ---
        try:
            agg_body = {"size": 0, "query": query, "aggs": {
                "apps": {"terms": {"field": "wallet_app", "size": 20}},
                "chains": {"terms": {"field": "chain", "size": 20}},
                "types": {"terms": {"field": "record_type", "size": 10}},
                "states": {"terms": {"field": "record_state", "size": 5}},
                "addresses": {"terms": {"field": "wallet_address", "size": 100}},
            }}
            r = requests.post(f"{self.es_url}/{indices}/_search",
                              json=agg_body, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json()
                aggs = data.get("aggregations", {})

                def buckets(name):
                    return {b["key"]: b["doc_count"]
                            for b in aggs.get(name, {}).get("buckets", []) if b["key"] != ""}

                result["found"] = data.get("hits", {}).get("total", {}).get("value", 0)
                result["summary"] = {
                    "wallets_and_exchanges": buckets("apps"),
                    "records_by_chain": buckets("chains"),
                    "record_types": buckets("types"),
                    "record_state": buckets("states"),
                    "unique_addresses": list(buckets("addresses").keys()),
                }
        except Exception as e:
            result["summary_error"] = str(e)

        # --- the records themselves ---
        try:
            body = {"size": limit, "query": query,
                    "sort": [{"timestamp.keyword": {"order": "desc", "unmapped_type": "keyword"}}]}
            r = requests.post(f"{self.es_url}/{indices}/_search",
                              json=body, params=params, timeout=10)
            if r.status_code == 200:
                for hit in r.json().get("hits", {}).get("hits", []):
                    rec = dict(hit["_source"])
                    rec["_index"] = hit.get("_index", "")
                    if not include_full_value and rec.pop("value_full", None):
                        # The complete value stays stored in the index untouched; it is left
                        # out of the answer because one record can hold hundreds of kilobytes.
                        rec["value_full_omitted"] = True
                    result["records"].append(rec)
            else:
                result["error"] = f"Elasticsearch returned status {r.status_code}"
        except Exception as e:
            result["error"] = str(e)

        if not result["records"] and "error" not in result:
            result["note"] = ("No crypto wallet or exchange records matched. The wallet and "
                              "exchange artifacts may not be parsed into this case yet.")
        return result

    def _tool_request_artifact_load(self, artifact_type: str, reason: str) -> Dict:
        """
        Request to load a missing artifact.

        This tool is called when the LLM needs data from an artifact that
        is not yet loaded for the current case. It prompts the user for
        permission before loading.

        Returns status indicating whether loading was approved/completed.
        """
        from config.artifact_registry import is_known_artifact, get_index_name

        # Check if artifact type is known
        if not is_known_artifact(artifact_type):
            return {
                "status": "error",
                "message": f"Unknown artifact type: {artifact_type}. Available types: prefetch, eventlog, registry, browser, lnk, mft, jumplist, recyclebin, shimcache, amcache, srum, powershell, usnjrnl"
            }

        # Check if artifact is already loaded for this case
        if self.case_id:
            try:
                from src.loaders.elasticsearch_loader import ElasticsearchLoader
                es_loader = ElasticsearchLoader(self.es_url)

                if es_loader.is_artifact_loaded(self.case_id, artifact_type):
                    return {
                        "status": "already_loaded",
                        "artifact_type": artifact_type,
                        "message": f"Artifact '{artifact_type}' is already loaded for this case. Try your search again."
                    }

                # Get case metadata to find image_path
                case_meta = es_loader.get_case_metadata(self.case_id)
                if not case_meta:
                    return {
                        "status": "error",
                        "message": f"Case metadata not found for case_id: {self.case_id}"
                    }

                image_path = case_meta.get("image_path")
                if not image_path:
                    return {
                        "status": "error",
                        "message": "No image_path found in case metadata. Cannot load artifact."
                    }

            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to check artifact status: {str(e)}"
                }
        else:
            return {
                "status": "error",
                "message": "No case_id set. Cannot determine which case to load artifact for."
            }

        # Return request for user confirmation
        # The actual loading will be handled by the UI/callback mechanism
        return {
            "status": "confirmation_required",
            "artifact_type": artifact_type,
            "reason": reason,
            "case_id": self.case_id,
            "image_path": image_path,
            "message": f"Permission required to load '{artifact_type}' artifact from disk image.",
            "action": "load_artifact"
        }

    # ==================== TOOL DISPATCH ====================

    # Map tool names to artifact types for empty result detection
    TOOL_ARTIFACT_MAP = {
        "analyze_deleted_files": "recyclebin",
        "analyze_web_activity": "browser",
        "analyze_powershell_commands": "powershell",
        "analyze_network_activity": "srum",
        "search_file_changes": "usnjrnl",
        "get_wallet_artifacts": "wallet",
    }

    def _execute_tool(self, tool_name: str, tool_input: Dict) -> str:
        """Execute a tool by name and return JSON result."""
        try:
            method_name = self.TOOL_MAP.get(tool_name)
            if not method_name:
                return json.dumps({"error": f"Unknown tool: {tool_name}"})

            method = getattr(self, method_name)
            result = method(**tool_input)

            # Check if result suggests missing artifact data
            artifact_type = None

            # Determine artifact type from tool or input
            if tool_name in self.TOOL_ARTIFACT_MAP:
                artifact_type = self.TOOL_ARTIFACT_MAP[tool_name]
            elif tool_name == "search_artifacts" and tool_input.get("artifact_type") not in (None, "all"):
                artifact_type = tool_input.get("artifact_type")

            if self.case_id and artifact_type:
                is_empty = self._check_empty_result(result)

                if is_empty:
                    result["artifact_not_loaded_hint"] = (
                        f"No {artifact_type} data found. This artifact may not be loaded for this case. "
                        f"You can use the 'request_artifact_load' tool with artifact_type='{artifact_type}' "
                        f"to request loading this artifact from the disk image."
                    )

            return json.dumps(result, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({"error": str(e)})

    def _check_empty_result(self, result: Dict) -> bool:
        """Check if tool result indicates no data found."""
        if not isinstance(result, dict):
            return False

        # Check various indicators of empty results
        total_fields = ["total_found", "total_records", "total_deleted_files",
                        "total_commands", "total_changes", "total_events"]
        for field in total_fields:
            if field in result and result[field] == 0:
                return True

        # Check results/records arrays
        for field in ["results", "records", "deleted_files", "commands", "changes"]:
            if field in result and isinstance(result[field], list) and len(result[field]) == 0:
                return True

        return False

    # ==================== ABSTRACT METHOD ====================

    def analyze(self, query: str, case_id: str = None) -> str:
        """
        Analyze forensic data based on user query.
        Must be implemented by each provider subclass.
        """
        raise NotImplementedError("Subclasses must implement analyze()")
