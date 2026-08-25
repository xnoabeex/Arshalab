# src/mcp/server.py
"""
MCP Server - Model Context Protocol server for forensic analysis.

Integrates with Cursor/Claude and provides tools for:
- Searching Windows artifacts
- Building event timeline
- Analyzing user activity
- Correlating data from different sources
"""

import json
import sys
from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    raise ImportError("mcp package required. Install: pip install mcp")

from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.elastic.client import ElasticClient
from etl_pipeline import ETLPipeline


class ForensicMCPServer:
    """
    MCP Server for forensic analysis.

    Provides tools for LLM:
    - search_artifacts: Search across all artifacts
    - get_timeline: Build event timeline
    - analyze_program_execution: Analyze program executions
    - analyze_web_activity: Analyze web activity
    - get_registry_autoruns: Get autorun entries
    - get_case_stats: Case statistics
    - reconstruct_attack_chain: Run autonomous attack-chain reconstruction
      (98 anchors -> evidence dump -> LLM synthesis -> JSON chain) with
      audit-trail persistence under /reports/<case_id>/
    """

    def __init__(self, elastic_host: str = "http://localhost:9200"):
        self.server = Server("forensic-analyzer")
        self.elastic = ElasticClient(elastic_host)
        self._setup_tools()

    def _setup_tools(self):
        """Register MCP tools."""

        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="search_artifacts",
                    description="""
                    Search Windows forensic artifacts.

                    Artifact types:
                    - prefetch: Program execution history
                    - eventlog: Windows event logs
                    - registry: Windows registry
                    - browser: Browser history
                    - lnk: Shortcuts (recent files)
                    - mft: Master File Table (file system)
                    - jumplist: Jump Lists (recent files by application)
                    - recyclebin: Recycle Bin (deleted files)
                    - shimcache: Shimcache (execution evidence)
                    - amcache: Amcache (SHA1 hashes of programs)
                    - srum: SRUM (network activity by application)
                    - powershell: PowerShell command history
                    - usnjrnl: USN Journal (detailed file system changes)

                    Query examples:
                    - "calc.exe" - find calculator executions
                    - "google.com" - find Google visits
                    - "Run" - find autorun registry entries
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query (filename, URL, registry key, etc.)"
                            },
                            "artifact_type": {
                                "type": "string",
                                "enum": ["prefetch", "eventlog", "registry", "browser", "lnk",
                                        "mft", "jumplist", "recyclebin", "shimcache", "amcache",
                                        "srum", "powershell", "usnjrnl", "all"],
                                "description": "Artifact type to search (default: all)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "Case ID for filtering"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results (default: 50)"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="get_timeline",
                    description="""
                    Build event timeline for a specified period.
                    Combines data from all artifacts and sorts by time.

                    Useful for:
                    - Reconstructing sequence of actions
                    - Incident analysis
                    - Understanding what happened at a specific time
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "start_time": {
                                "type": "string",
                                "description": "Start of period (ISO format: 2024-01-15T10:00:00)"
                            },
                            "end_time": {
                                "type": "string",
                                "description": "End of period (ISO format: 2024-01-15T18:00:00)"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum events (default: 100)"
                            }
                        },
                        "required": ["case_id"]
                    }
                ),
                Tool(
                    name="analyze_program_execution",
                    description="""
                    Analyze program executions.
                    Shows when and how many times a program was executed.

                    Data from:
                    - Prefetch files (exact execution times)
                    - LNK files (shortcuts to the program)
                    - Shimcache (execution evidence)
                    - Amcache (SHA1 hashes and versions)
                    - Jump Lists (usage through applications)
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "program_name": {
                                "type": "string",
                                "description": "Program name (e.g.: chrome.exe, cmd.exe)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            }
                        },
                        "required": ["program_name"]
                    }
                ),
                Tool(
                    name="analyze_web_activity",
                    description="""
                    Analyze user web activity.

                    Shows:
                    - Visited websites
                    - Visit frequency
                    - Time patterns
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Domain to filter by (optional)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_registry_autoruns",
                    description="""
                    Get Windows autorun programs.

                    Checks keys:
                    - Run / RunOnce
                    - Services
                    - Scheduled Tasks
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_case_stats",
                    description="""
                    Get case statistics.

                    Shows:
                    - Record count by artifact type
                    - Data time range
                    - Top programs/websites
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "Case ID (optional, if not specified - overall statistics)"
                            }
                        }
                    }
                ),
                Tool(
                    name="find_suspicious_activity",
                    description="""
                    Find suspicious activity.

                    Checks:
                    - Executions from TEMP/Downloads
                    - Suspicious Event IDs (4625, 4648, 7045)
                    - Unusual autoruns
                    - Night-time activity
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            }
                        },
                        "required": ["case_id"]
                    }
                ),
                Tool(
                    name="analyze_deleted_files",
                    description="""
                    Analyze deleted files from Recycle Bin ($Recycle.Bin).

                    Shows:
                    - Deleted files with original paths
                    - Deletion time
                    - File sizes
                    - Grouping by extension
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "extension": {
                                "type": "string",
                                "description": "Filter by extension (e.g.: .docx, .pdf)"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results (default: 100)"
                            }
                        }
                    }
                ),
                Tool(
                    name="search_file_activity",
                    description="""
                    Search file activity through MFT and Jump Lists.

                    Searches:
                    - File creation/modification/access (MFT)
                    - File usage in applications (Jump Lists)
                    - File deletion (Recycle Bin)
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filename": {
                                "type": "string",
                                "description": "Filename or part of path"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results (default: 50)"
                            }
                        },
                        "required": ["filename"]
                    }
                ),
                Tool(
                    name="load_disk_image",
                    description="""
                    Load disk image and extract artifacts.

                    Runs ETL pipeline:
                    1. Extract - extract files from image via TSK
                    2. Transform - parse artifacts (PECmd, EvtxECmd, RECmd, etc.)
                    3. Load - load into Elasticsearch

                    Supported formats: E01, RAW, DD, IMG

                    Available artifacts (13 types):
                    - prefetch: Program execution history
                    - eventlog: Windows event logs
                    - registry: Windows registry
                    - browser: Browser history
                    - lnk: Shortcuts
                    - mft: Master File Table
                    - jumplist: Jump Lists
                    - recyclebin: Recycle Bin
                    - shimcache: Shimcache
                    - amcache: Amcache
                    - srum: SRUM (network activity by application)
                    - powershell: PowerShell command history
                    - usnjrnl: USN Journal (detailed FS changes)

                    Example: load_disk_image("images/test.E01", ["prefetch", "mft", "shimcache", "srum"])
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "image_path": {
                                "type": "string",
                                "description": "Path to disk image (e.g.: images/test.E01)"
                            },
                            "artifacts": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of artifacts: prefetch, eventlog, registry, browser, lnk, mft, jumplist, recyclebin, shimcache, amcache, srum, powershell, usnjrnl"
                            }
                        },
                        "required": ["image_path", "artifacts"]
                    }
                ),
                Tool(
                    name="list_available_images",
                    description="""
                    Show available disk images in images/ folder.
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="analyze_network_activity",
                    description="""
                    Analyze network activity via SRUM (System Resource Usage Monitor).

                    Shows:
                    - Network traffic by application (bytes sent/received)
                    - Top applications by network activity
                    - Network usage time patterns
                    - Application to network activity correlation

                    Useful for:
                    - Detecting data exfiltration
                    - C2 communication analysis
                    - Lateral movement detection
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "app_name": {
                                "type": "string",
                                "description": "Filter by application name (optional)"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results (default: 100)"
                            }
                        }
                    }
                ),
                Tool(
                    name="analyze_powershell_history",
                    description="""
                    Analyze PowerShell commands from PSReadLine history.

                    Shows:
                    - All executed PowerShell commands
                    - Suspicious commands (downloads, encoded, bypass)
                    - Grouping by users
                    - Execution timeline

                    Useful for:
                    - Detecting malicious scripts
                    - Analyzing attacker actions
                    - Living-off-the-land (LOTL) attacks
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "suspicious_only": {
                                "type": "boolean",
                                "description": "Show only suspicious commands"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results (default: 200)"
                            }
                        }
                    }
                ),
                Tool(
                    name="search_file_changes",
                    description="""
                    Search file changes via USN Journal ($UsnJrnl).

                    Shows detailed operations:
                    - CREATE: File creation
                    - DELETE: File deletion
                    - RENAME: Renaming
                    - MODIFY: Content modification
                    - SECURITY: Permission changes

                    Useful for:
                    - Reconstructing detailed timeline
                    - Tracking deleted files
                    - Analyzing activity in specific folder
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filename": {
                                "type": "string",
                                "description": "Filename or part of path"
                            },
                            "operation": {
                                "type": "string",
                                "enum": ["CREATE", "DELETE", "RENAME", "MODIFY", "SECURITY", "all"],
                                "description": "Operation type (default: all)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results (default: 100)"
                            }
                        }
                    }
                ),
                # =====================================================================
                # NEW TOOLS FOR IN-DEPTH ANALYSIS
                # =====================================================================
                Tool(
                    name="analyze_registry",
                    description="""
                    In-depth Windows registry analysis by categories.

                    Categories:
                    - persistence: Persistence mechanisms (Run, RunOnce, Services, Scheduled Tasks, Startup folders, Winlogon, Shell extensions, COM objects, Browser Helper Objects)
                    - user_activity: User activity (RecentDocs, MRU lists, UserAssist, TypedURLs, TypedPaths, ComDlg32, LastVisitedMRU, RunMRU, OpenSaveMRU)
                    - network: Network settings (Interfaces, Profiles, Proxy, NetworkList, Firewall, Winsock)
                    - malware_indicators: Malware indicators (Image File Execution Options, Debuggers, AppInit_DLLs, Known DLLs, Safe mode boot, Disabled security)
                    - all: All categories

                    Useful for:
                    - Finding malware persistence
                    - Analyzing user activity
                    - Detecting system compromise
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "category": {
                                "type": "string",
                                "enum": ["persistence", "user_activity", "network", "malware_indicators", "all"],
                                "description": "Analysis category (default: all)"
                            },
                            "query": {
                                "type": "string",
                                "description": "Additional search query (optional)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results (default: 50)"
                            }
                        }
                    }
                ),
                Tool(
                    name="analyze_security_events",
                    description="""
                    Analyze Windows security events by Event ID categories.

                    Categories:
                    - authentication: Authentication (4624 successful logon, 4625 failed, 4634 logoff, 4647 user-initiated logoff, 4648 explicit credentials, 4672 special privileges)
                    - privilege: Privileges (4672 special privileges, 4673 sensitive privilege use, 4674 privileged operation)
                    - account_management: Account management (4720-4726 create/delete/modify, 4738 change, 4740 lockout)
                    - service_install: Service installation (7045 new service, 4697 service installed)
                    - audit_clear: Log clearing (1102 Security log cleared, 104 Event log cleared)
                    - all: All categories

                    Suspicious patterns:
                    - Multiple 4625 (brute force)
                    - 7045 with suspicious paths (malware service)
                    - 1102/104 (covering tracks)
                    - 4648 (pass-the-hash/ticket)
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "event_category": {
                                "type": "string",
                                "enum": ["authentication", "privilege", "account_management", "service_install", "audit_clear", "all"],
                                "description": "Event category (default: all)"
                            },
                            "event_id": {
                                "type": "integer",
                                "description": "Specific Event ID to search (optional)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results (default: 100)"
                            }
                        }
                    }
                ),
                Tool(
                    name="correlate_activity",
                    description="""
                    Cross-correlation of activity by entity (file, program, user).

                    Searches entity across ALL 13 artifact types:
                    - prefetch, eventlog, registry, browser, lnk
                    - mft, jumplist, recyclebin, shimcache, amcache
                    - srum, powershell, usnjrnl

                    Entity types:
                    - executable: Executable file (.exe, .dll, .bat, .ps1)
                    - file: Any file
                    - path: Folder path
                    - user: User
                    - url: URL or domain
                    - auto: Auto-detect type

                    Returns:
                    - Unified timeline with all events
                    - Grouping by artifact types
                    - First and last occurrence
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "entity": {
                                "type": "string",
                                "description": "Entity to search (filename, path, user, URL)"
                            },
                            "entity_type": {
                                "type": "string",
                                "enum": ["executable", "file", "path", "user", "url", "auto"],
                                "description": "Entity type (default: auto)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results per index (default: 20)"
                            }
                        },
                        "required": ["entity"]
                    }
                ),
                Tool(
                    name="detect_lateral_movement",
                    description="""
                    Detect lateral movement.

                    Checks:
                    - remote_logons: Remote logons (Event 4624 Type 3/10)
                    - psexec_usage: PsExec usage (prefetch, services, shimcache)
                    - rdp_activity: RDP activity (Event 4624 Type 10, mstsc.exe)
                    - wmi_activity: WMI activity (wmic.exe, wmiprvse.exe, scrcons.exe)
                    - scheduled_tasks: Scheduled Tasks (schtasks.exe, at.exe)
                    - suspicious_services: Suspicious services (Event 7045)

                    Returns:
                    - findings: Found indicators by category
                    - risk_score: 0-100 (high = many indicators)
                    - timeline: Lateral movement event timeline
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "Case ID"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results per category (default: 50)"
                            }
                        }
                    }
                ),
                Tool(
                    name="reconstruct_attack_chain",
                    description="""
                    Reconstruct the adversary attack chain.

                    Runs the standardized reconstruction pipeline:
                    1. Collects evidence via 98 case-agnostic anchor queries
                       (~1,000 records) and persists the full dump.
                    2. Synthesizes 15-30 meaningful attack-chain steps with
                       chronological ordering, MITRE ATT&CK phase classification,
                       source attribution, and confidence per step.

                    Both the evidence dump and the distilled chain are saved
                    under /reports/<case_id>/ for audit. The result also
                    carries a `grounding` block measured on this chain: how
                    many of its events state a checkable fact, and how many
                    of those cite an entity absent from the persisted
                    evidence.

                    Use when the user asks: "reconstruct the attack chain",
                    "show me the attack timeline", "what happened in this
                    incident", or any attack-narrative request.

                    Returns:
                    - status: completed | error
                    - evidence_dump: path, record count, anchor count, size
                    - attack_chain: list of 15-30 steps with timestamp,
                      event, supporting_artifact, confidence, phase
                    - notification: user-facing message with audit-trail info
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "Case ID (e.g. case_20260323_032324)"
                            },
                            "provider": {
                                "type": "string",
                                "enum": ["deepseek", "openai", "sonnet", "opus"],
                                "description": "LLM backend for reconstruction (default: deepseek)"
                            },
                            "run": {
                                "type": "integer",
                                "description": "Independent run number 1-3 (default: 1)"
                            }
                        },
                        "required": ["case_id"]
                    }
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            try:
                result = await self._handle_tool(name, arguments)
                return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False, default=str))]
            except Exception as e:
                return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def _handle_tool(self, name: str, args: Dict[str, Any]) -> Any:
        """Tool call handler."""

        if name == "search_artifacts":
            return self._search_artifacts(
                query=args.get("query"),
                artifact_type=args.get("artifact_type", "all"),
                case_id=args.get("case_id"),
                limit=args.get("limit", 50)
            )

        elif name == "get_timeline":
            return self._get_timeline(
                case_id=args.get("case_id"),
                start_time=args.get("start_time"),
                end_time=args.get("end_time"),
                limit=args.get("limit", 100)
            )

        elif name == "analyze_program_execution":
            return self._analyze_program(
                program_name=args.get("program_name"),
                case_id=args.get("case_id")
            )

        elif name == "analyze_web_activity":
            return self._analyze_web(
                domain=args.get("domain"),
                case_id=args.get("case_id"),
                limit=args.get("limit", 100)
            )

        elif name == "get_registry_autoruns":
            return self._get_autoruns(case_id=args.get("case_id"))

        elif name == "get_case_stats":
            return self._get_stats(case_id=args.get("case_id"))

        elif name == "find_suspicious_activity":
            return self._find_suspicious(case_id=args.get("case_id"))

        elif name == "analyze_deleted_files":
            return self._analyze_deleted_files(
                case_id=args.get("case_id"),
                extension=args.get("extension"),
                limit=args.get("limit", 100)
            )

        elif name == "search_file_activity":
            return self._search_file_activity(
                filename=args.get("filename"),
                case_id=args.get("case_id"),
                limit=args.get("limit", 50)
            )

        elif name == "load_disk_image":
            return self._load_disk_image(
                image_path=args.get("image_path"),
                artifacts=args.get("artifacts")
            )

        elif name == "list_available_images":
            return self._list_images()

        elif name == "analyze_network_activity":
            return self._analyze_network_activity(
                case_id=args.get("case_id"),
                app_name=args.get("app_name"),
                limit=args.get("limit", 100)
            )

        elif name == "analyze_powershell_history":
            return self._analyze_powershell_history(
                case_id=args.get("case_id"),
                suspicious_only=args.get("suspicious_only", False),
                limit=args.get("limit", 200)
            )

        elif name == "search_file_changes":
            return self._search_file_changes(
                filename=args.get("filename"),
                operation=args.get("operation", "all"),
                case_id=args.get("case_id"),
                limit=args.get("limit", 100)
            )

        # =====================================================================
        # NEW TOOLS FOR IN-DEPTH ANALYSIS
        # =====================================================================
        elif name == "analyze_registry":
            return self._analyze_registry(
                category=args.get("category", "all"),
                query=args.get("query"),
                case_id=args.get("case_id"),
                limit=args.get("limit", 50)
            )

        elif name == "analyze_security_events":
            return self._analyze_security_events(
                event_category=args.get("event_category", "all"),
                event_id=args.get("event_id"),
                case_id=args.get("case_id"),
                limit=args.get("limit", 100)
            )

        elif name == "correlate_activity":
            return self._correlate_activity(
                entity=args.get("entity"),
                entity_type=args.get("entity_type", "auto"),
                case_id=args.get("case_id"),
                limit=args.get("limit", 20)
            )

        elif name == "detect_lateral_movement":
            return self._detect_lateral_movement(
                case_id=args.get("case_id"),
                limit=args.get("limit", 50)
            )

        elif name == "reconstruct_attack_chain":
            return self._reconstruct_attack_chain(
                case_id=args.get("case_id"),
                provider=args.get("provider", "deepseek"),
                run=args.get("run", 1)
            )

        else:
            raise ValueError(f"Unknown tool: {name}")

    def _reconstruct_attack_chain(self, case_id: str,
                                    provider: str = "deepseek",
                                    run: int = 1) -> Dict:
        """Run Mode 2 attack-chain reconstruction with audit-trail persistence."""
        from src.tools.reconstruct_attack_chain import reconstruct_attack_chain
        return reconstruct_attack_chain(
            case_id=case_id,
            provider=provider,
            run=run,
        )

    def _search_artifacts(self, query: str, artifact_type: str, case_id: str, limit: int) -> Dict:
        """Search artifacts."""
        index = "forensic-*"
        if artifact_type and artifact_type != "all":
            index = f"forensic-{artifact_type}"

        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id

        results = self.elastic.search(
            index_name=index,
            query=query,
            filters=filters if filters else None,
            size=limit
        )

        return {
            "query": query,
            "artifact_type": artifact_type,
            "total": len(results),
            "results": results
        }

    def _get_timeline(self, case_id: str, start_time: str, end_time: str, limit: int) -> Dict:
        """Build timeline."""
        results = self.elastic.get_timeline(
            case_id=case_id,
            start_time=start_time,
            end_time=end_time,
            size=limit
        )

        return {
            "case_id": case_id,
            "time_range": {"start": start_time, "end": end_time},
            "total_events": len(results),
            "timeline": results
        }

    def _analyze_program(self, program_name: str, case_id: str) -> Dict:
        """Analyze program executions from all sources."""
        filters = {"_meta.case_id": case_id} if case_id else None

        # Search in Prefetch
        prefetch_results = self.elastic.search(
            index_name="forensic-prefetch",
            query=program_name,
            filters=filters,
            size=100
        )

        # Search in LNK
        lnk_results = self.elastic.search(
            index_name="forensic-lnk",
            query=program_name,
            filters=filters,
            size=100
        )

        # Search in Shimcache (execution evidence)
        shimcache_results = self.elastic.search(
            index_name="forensic-shimcache",
            query=program_name,
            filters=filters,
            size=100
        )

        # Search in Amcache (SHA1 hashes)
        amcache_results = self.elastic.search(
            index_name="forensic-amcache",
            query=program_name,
            filters=filters,
            size=100
        )

        # Search in Jump Lists
        jumplist_results = self.elastic.search(
            index_name="forensic-jumplist",
            query=program_name,
            filters=filters,
            size=100
        )

        # Collect execution times
        execution_times = []
        for r in prefetch_results:
            if r.get("timestamp"):
                execution_times.append({
                    "time": r["timestamp"],
                    "source": "prefetch",
                    "executable": r.get("executable_name", ""),
                    "run_count": r.get("run_count", 0)
                })

        for r in lnk_results:
            if r.get("timestamp"):
                execution_times.append({
                    "time": r["timestamp"],
                    "source": "lnk",
                    "target": r.get("target_path", "")
                })

        for r in shimcache_results:
            if r.get("timestamp"):
                execution_times.append({
                    "time": r["timestamp"],
                    "source": "shimcache",
                    "path": r.get("path", ""),
                    "executed": r.get("executed")
                })

        for r in amcache_results:
            if r.get("timestamp"):
                execution_times.append({
                    "time": r["timestamp"],
                    "source": "amcache",
                    "path": r.get("path", ""),
                    "sha1": r.get("sha1", ""),
                    "publisher": r.get("publisher", "")
                })

        for r in jumplist_results:
            if r.get("timestamp"):
                execution_times.append({
                    "time": r["timestamp"],
                    "source": "jumplist",
                    "app_name": r.get("app_name", ""),
                    "target_path": r.get("target_path", "")
                })

        # Sort by time
        execution_times.sort(key=lambda x: x.get("time", ""))

        # Collect SHA1 hashes from Amcache
        sha1_hashes = list(set(r.get("sha1", "") for r in amcache_results if r.get("sha1")))

        return {
            "program": program_name,
            "total_executions": len(prefetch_results),
            "related_shortcuts": len(lnk_results),
            "shimcache_entries": len(shimcache_results),
            "amcache_entries": len(amcache_results),
            "jumplist_entries": len(jumplist_results),
            "sha1_hashes": sha1_hashes,
            "execution_history": execution_times,
            "first_seen": execution_times[0]["time"] if execution_times else None,
            "last_seen": execution_times[-1]["time"] if execution_times else None
        }

    def _analyze_web(self, domain: str, case_id: str, limit: int) -> Dict:
        """Analyze web activity."""
        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id
        if domain:
            filters["domain"] = domain

        results = self.elastic.search(
            index_name="forensic-browser",
            query=domain if domain else None,
            filters=filters if filters else None,
            size=limit
        )

        # Group by domains
        domains = {}
        for r in results:
            d = r.get("domain", "unknown")
            if d not in domains:
                domains[d] = {"count": 0, "visits": []}
            domains[d]["count"] += r.get("visit_count", 1)
            domains[d]["visits"].append({
                "url": r.get("url", ""),
                "title": r.get("title", ""),
                "time": r.get("timestamp", "")
            })

        # Top domains
        top_domains = sorted(domains.items(), key=lambda x: x[1]["count"], reverse=True)[:20]

        return {
            "total_records": len(results),
            "unique_domains": len(domains),
            "top_domains": [{"domain": d, "visit_count": v["count"]} for d, v in top_domains],
            "recent_visits": results[:20]
        }

    def _get_autoruns(self, case_id: str) -> Dict:
        """Get autoruns from registry."""
        filters = {"category": "autorun"}
        if case_id:
            filters["_meta.case_id"] = case_id

        results = self.elastic.search(
            index_name="forensic-registry",
            filters=filters,
            size=200
        )

        # Also search by keywords
        run_results = self.elastic.search(
            index_name="forensic-registry",
            query="Run OR RunOnce OR Services",
            filters={"_meta.case_id": case_id} if case_id else None,
            size=200
        )

        # Merge and remove duplicates
        all_results = {r.get("key_path", ""): r for r in results + run_results}

        return {
            "total_autoruns": len(all_results),
            "autoruns": list(all_results.values())
        }

    def _get_stats(self, case_id: str) -> Dict:
        """Get case statistics."""
        stats = self.elastic.get_stats(case_id)

        total = sum(s.get("count", 0) for s in stats.values())

        return {
            "case_id": case_id or "all",
            "total_records": total,
            "by_artifact_type": stats
        }

    def _find_suspicious(self, case_id: str) -> Dict:
        """Find suspicious activity."""
        suspicious = []

        # 1. Executions from TEMP
        temp_executions = self.elastic.search(
            index_name="forensic-prefetch",
            query="TEMP OR Downloads OR AppData",
            filters={"_meta.case_id": case_id} if case_id else None,
            size=50
        )
        for r in temp_executions:
            suspicious.append({
                "type": "temp_execution",
                "severity": "medium",
                "description": f"Program executed from temp folder: {r.get('executable_name', '')}",
                "timestamp": r.get("timestamp"),
                "details": r
            })

        # 2. Suspicious Event IDs
        suspicious_events = self.elastic.search(
            index_name="forensic-eventlog",
            query="4625 OR 4648 OR 7045 OR 1102",  # Failed login, explicit creds, service install, log cleared
            filters={"_meta.case_id": case_id} if case_id else None,
            size=50
        )
        for r in suspicious_events:
            event_id = r.get("event_id", 0)
            severity = "high" if event_id in [7045, 1102] else "medium"
            suspicious.append({
                "type": "suspicious_event",
                "severity": severity,
                "description": f"Suspicious Event ID {event_id}: {r.get('message', '')[:100]}",
                "timestamp": r.get("timestamp"),
                "details": r
            })

        # Sort by severity
        severity_order = {"high": 0, "medium": 1, "low": 2}
        suspicious.sort(key=lambda x: severity_order.get(x["severity"], 99))

        return {
            "case_id": case_id,
            "total_suspicious": len(suspicious),
            "by_severity": {
                "high": len([s for s in suspicious if s["severity"] == "high"]),
                "medium": len([s for s in suspicious if s["severity"] == "medium"]),
                "low": len([s for s in suspicious if s["severity"] == "low"])
            },
            "findings": suspicious
        }

    def _analyze_deleted_files(self, case_id: str, extension: str, limit: int) -> Dict:
        """Analyze deleted files from Recycle Bin."""
        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id
        if extension:
            filters["extension"] = extension.lower() if extension.startswith('.') else f".{extension.lower()}"

        results = self.elastic.search(
            index_name="forensic-recyclebin",
            filters=filters if filters else None,
            size=limit
        )

        # Group by extension
        by_extension = {}
        total_size = 0

        for r in results:
            ext = r.get("extension", "unknown") or "unknown"
            if ext not in by_extension:
                by_extension[ext] = {"count": 0, "total_size": 0}
            by_extension[ext]["count"] += 1
            by_extension[ext]["total_size"] += r.get("file_size", 0)
            total_size += r.get("file_size", 0)

        # Sort by deletion time
        results_sorted = sorted(results, key=lambda x: x.get("timestamp", ""), reverse=True)

        return {
            "case_id": case_id or "all",
            "total_deleted_files": len(results),
            "total_size_bytes": total_size,
            "by_extension": by_extension,
            "deleted_files": results_sorted
        }

    def _search_file_activity(self, filename: str, case_id: str, limit: int) -> Dict:
        """Search file activity through MFT, Jump Lists and Recycle Bin."""
        filters = {"_meta.case_id": case_id} if case_id else None

        # Search in MFT
        mft_results = self.elastic.search(
            index_name="forensic-mft",
            query=filename,
            filters=filters,
            size=limit
        )

        # Search in Jump Lists
        jumplist_results = self.elastic.search(
            index_name="forensic-jumplist",
            query=filename,
            filters=filters,
            size=limit
        )

        # Search in Recycle Bin
        recyclebin_results = self.elastic.search(
            index_name="forensic-recyclebin",
            query=filename,
            filters=filters,
            size=limit
        )

        # Search in LNK
        lnk_results = self.elastic.search(
            index_name="forensic-lnk",
            query=filename,
            filters=filters,
            size=limit
        )

        # Build activity timeline
        activity = []

        for r in mft_results:
            if r.get("created"):
                activity.append({
                    "time": r["created"],
                    "action": "created",
                    "source": "mft",
                    "path": r.get("file_path", ""),
                    "is_deleted": r.get("is_deleted", False)
                })
            if r.get("modified"):
                activity.append({
                    "time": r["modified"],
                    "action": "modified",
                    "source": "mft",
                    "path": r.get("file_path", "")
                })

        for r in jumplist_results:
            if r.get("timestamp"):
                activity.append({
                    "time": r["timestamp"],
                    "action": "used_in_app",
                    "source": "jumplist",
                    "app_name": r.get("app_name", ""),
                    "path": r.get("target_path", "")
                })

        for r in recyclebin_results:
            if r.get("timestamp"):
                activity.append({
                    "time": r["timestamp"],
                    "action": "deleted",
                    "source": "recyclebin",
                    "original_path": r.get("original_path", ""),
                    "file_size": r.get("file_size", 0)
                })

        for r in lnk_results:
            if r.get("timestamp"):
                activity.append({
                    "time": r["timestamp"],
                    "action": "accessed_via_shortcut",
                    "source": "lnk",
                    "lnk_name": r.get("lnk_name", ""),
                    "target_path": r.get("target_path", "")
                })

        # Sort by time
        activity.sort(key=lambda x: x.get("time", ""))

        return {
            "filename": filename,
            "case_id": case_id or "all",
            "mft_entries": len(mft_results),
            "jumplist_entries": len(jumplist_results),
            "recyclebin_entries": len(recyclebin_results),
            "lnk_entries": len(lnk_results),
            "activity_timeline": activity,
            "first_seen": activity[0]["time"] if activity else None,
            "last_seen": activity[-1]["time"] if activity else None
        }

    def _load_disk_image(self, image_path: str, artifacts: List[str]) -> Dict:
        """Load disk image and extract artifacts."""
        import os

        # Check if file exists
        if not os.path.exists(image_path):
            return {
                "status": "error",
                "message": f"Image not found: {image_path}"
            }

        # Validate artifacts (all 13 types)
        valid_artifacts = [
            "prefetch", "eventlog", "registry", "browser", "lnk",
            "mft", "jumplist", "recyclebin", "shimcache", "amcache",
            "srum", "powershell", "usnjrnl"
        ]
        invalid = [a for a in artifacts if a not in valid_artifacts]
        if invalid:
            return {
                "status": "error",
                "message": f"Invalid artifacts: {invalid}. Valid: {valid_artifacts}"
            }

        try:
            # Run ETL pipeline
            pipeline = ETLPipeline(
                image_path=image_path,
                output_dir="output/mcp_pipeline",
                artifacts=artifacts,
                es_url=self.elastic.host
            )

            # Collect logs
            logs = []
            def log_callback(msg):
                logs.append(msg)

            pipeline.run(status_callback=log_callback)

            return {
                "status": "success",
                "case_id": pipeline.case_id,
                "image_path": image_path,
                "artifacts_extracted": artifacts,
                "logs": logs[-10:],  # Last 10 logs
                "message": f"Successfully loaded {image_path}. Case ID: {pipeline.case_id}"
            }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    def _list_images(self) -> Dict:
        """List available disk images."""
        import os
        import glob

        images_dir = "images"
        if not os.path.exists(images_dir):
            return {
                "status": "error",
                "message": "images/ folder not found"
            }

        # Search for images
        patterns = ["*.E01", "*.e01", "*.raw", "*.dd", "*.img", "*.001"]
        images = []

        for pattern in patterns:
            for path in glob.glob(os.path.join(images_dir, pattern)):
                stat = os.stat(path)
                images.append({
                    "path": path,
                    "name": os.path.basename(path),
                    "size_mb": round(stat.st_size / (1024*1024), 2)
                })

        return {
            "status": "success",
            "total": len(images),
            "images": images,
            "available_artifacts": [
                "prefetch", "eventlog", "registry", "browser", "lnk",
                "mft", "jumplist", "recyclebin", "shimcache", "amcache",
                "srum", "powershell", "usnjrnl"
            ]
        }

    def _analyze_network_activity(self, case_id: str, app_name: str, limit: int) -> Dict:
        """Analyze network activity from SRUM data."""
        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id
        if app_name:
            filters["app_name"] = app_name

        # Search in SRUM for network records
        results = self.elastic.search(
            index_name="forensic-srum",
            query=app_name if app_name else None,
            filters=filters if filters else None,
            size=limit
        )

        # Aggregate by application
        by_app = {}
        total_sent = 0
        total_received = 0

        for r in results:
            app = r.get("app_name", "unknown") or "unknown"
            if app not in by_app:
                by_app[app] = {
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "record_count": 0
                }
            by_app[app]["bytes_sent"] += r.get("bytes_sent", 0)
            by_app[app]["bytes_received"] += r.get("bytes_received", 0)
            by_app[app]["record_count"] += 1
            total_sent += r.get("bytes_sent", 0)
            total_received += r.get("bytes_received", 0)

        # Top applications by network activity
        top_apps = sorted(
            by_app.items(),
            key=lambda x: x[1]["bytes_sent"] + x[1]["bytes_received"],
            reverse=True
        )[:20]

        return {
            "case_id": case_id or "all",
            "total_records": len(results),
            "total_bytes_sent": total_sent,
            "total_bytes_received": total_received,
            "total_traffic": total_sent + total_received,
            "unique_applications": len(by_app),
            "top_applications": [
                {
                    "app_name": app,
                    "bytes_sent": stats["bytes_sent"],
                    "bytes_received": stats["bytes_received"],
                    "total_traffic": stats["bytes_sent"] + stats["bytes_received"],
                    "record_count": stats["record_count"]
                }
                for app, stats in top_apps
            ],
            "recent_activity": results[:20]
        }

    def _analyze_powershell_history(self, case_id: str, suspicious_only: bool, limit: int) -> Dict:
        """Analyze PowerShell command history."""
        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id
        if suspicious_only:
            filters["is_suspicious"] = True

        results = self.elastic.search(
            index_name="forensic-powershell",
            filters=filters if filters else None,
            size=limit
        )

        # Group by user
        by_user = {}
        suspicious_commands = []

        for r in results:
            user = r.get("user", "Unknown")
            if user not in by_user:
                by_user[user] = {"commands": [], "suspicious_count": 0}
            by_user[user]["commands"].append({
                "command": r.get("command", ""),
                "line_number": r.get("line_number", 0),
                "is_suspicious": r.get("is_suspicious", False)
            })
            if r.get("is_suspicious", False):
                by_user[user]["suspicious_count"] += 1
                suspicious_commands.append({
                    "user": user,
                    "command": r.get("command", ""),
                    "source_file": r.get("source_file", "")
                })

        return {
            "case_id": case_id or "all",
            "total_commands": len(results),
            "total_suspicious": len(suspicious_commands),
            "users": list(by_user.keys()),
            "by_user": {
                user: {
                    "total_commands": len(data["commands"]),
                    "suspicious_count": data["suspicious_count"]
                }
                for user, data in by_user.items()
            },
            "suspicious_commands": suspicious_commands,
            "all_commands": results if not suspicious_only else None
        }

    def _search_file_changes(self, filename: str, operation: str, case_id: str, limit: int) -> Dict:
        """Search file changes in USN Journal."""
        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id
        if operation and operation != "all":
            filters["operation"] = operation.upper()

        results = self.elastic.search(
            index_name="forensic-usnjrnl",
            query=filename if filename else None,
            filters=filters if filters else None,
            size=limit
        )

        # Group by operation type
        by_operation = {}
        for r in results:
            op = r.get("operation", "UNKNOWN")
            if op not in by_operation:
                by_operation[op] = []
            by_operation[op].append({
                "filename": r.get("filename", ""),
                "file_path": r.get("file_path", ""),
                "timestamp": r.get("timestamp", ""),
                "update_reasons": r.get("update_reasons", "")
            })

        # Sort by timestamp
        sorted_results = sorted(results, key=lambda x: x.get("timestamp", ""), reverse=True)

        return {
            "case_id": case_id or "all",
            "search_filename": filename,
            "operation_filter": operation,
            "total_changes": len(results),
            "by_operation": {op: len(changes) for op, changes in by_operation.items()},
            "operation_details": by_operation,
            "recent_changes": sorted_results[:50],
            "first_change": sorted_results[-1]["timestamp"] if sorted_results else None,
            "last_change": sorted_results[0]["timestamp"] if sorted_results else None
        }

    # =========================================================================
    # NEW METHODS FOR IN-DEPTH ANALYSIS
    # =========================================================================

    def _analyze_registry(self, category: str, query: str, case_id: str, limit: int) -> Dict:
        """In-depth Windows registry analysis by categories."""

        # Patterns for each category
        category_patterns = {
            "persistence": [
                "Run", "RunOnce", "RunServices", "RunServicesOnce",
                "Policies\\Explorer\\Run", "Services", "Startup",
                "Winlogon", "Shell", "Userinit", "AppInit_DLLs",
                "ShellServiceObjectDelayLoad", "Browser Helper Objects",
                "ScheduledTasks", "CurrentVersion\\Explorer\\Shell Folders",
                "Active Setup\\Installed Components", "StubPath"
            ],
            "user_activity": [
                "RecentDocs", "MRUList", "MRU", "UserAssist",
                "TypedURLs", "TypedPaths", "ComDlg32", "LastVisitedMRU",
                "RunMRU", "OpenSaveMRU", "Map Network Drive MRU",
                "ReadingLocations", "Explorer\\WordWheelQuery",
                "FileExts", "SoftwareMicrosoft"
            ],
            "network": [
                "Interfaces", "NetworkList", "Profiles",
                "ProxyEnable", "ProxyServer", "AutoConfigURL",
                "Firewall", "Winsock", "Tcpip\\Parameters",
                "Internet Settings", "EnableProxy"
            ],
            "malware_indicators": [
                "Image File Execution Options", "Debugger",
                "AppInit_DLLs", "LoadAppInit_DLLs",
                "Known DLLs", "SafeBoot", "DisableAntiSpyware",
                "DisableAntiVirus", "DisableRealtimeMonitoring",
                "DisableBehaviorMonitoring", "DisableOnAccessProtection",
                "DisableScanOnRealtimeEnable", "DisableFirewall",
                "Policies\\Microsoft Windows Defender"
            ]
        }

        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id

        results_by_category = {}
        all_results = []

        # Determine categories to search
        if category == "all":
            categories_to_search = list(category_patterns.keys())
        else:
            categories_to_search = [category] if category in category_patterns else []

        for cat in categories_to_search:
            patterns = category_patterns[cat]
            cat_results = []

            for pattern in patterns:
                # Search by pattern
                search_query = pattern if not query else f"{pattern} AND {query}"
                results = self.elastic.search(
                    index_name="forensic-registry",
                    query=search_query,
                    filters=filters if filters else None,
                    size=limit // len(patterns) + 1  # Distribute limit
                )
                cat_results.extend(results)

            # Deduplicate by key_path
            seen_keys = set()
            unique_results = []
            for r in cat_results:
                key = r.get("key_path", "")
                if key and key not in seen_keys:
                    seen_keys.add(key)
                    r["_detected_category"] = cat
                    unique_results.append(r)

            results_by_category[cat] = unique_results[:limit]
            all_results.extend(unique_results[:limit])

        # Additional search by query if specified
        if query:
            additional = self.elastic.search(
                index_name="forensic-registry",
                query=query,
                filters=filters if filters else None,
                size=limit
            )
            for r in additional:
                r["_detected_category"] = "query_match"
            all_results.extend(additional)

        # Global deduplication
        seen = set()
        final_results = []
        for r in all_results:
            key = r.get("key_path", "") + str(r.get("value_name", ""))
            if key not in seen:
                seen.add(key)
                final_results.append(r)

        return {
            "case_id": case_id or "all",
            "category": category,
            "query": query,
            "total_results": len(final_results),
            "by_category": {cat: len(items) for cat, items in results_by_category.items()},
            "results": final_results[:limit],
            "persistence_count": len(results_by_category.get("persistence", [])),
            "user_activity_count": len(results_by_category.get("user_activity", [])),
            "network_count": len(results_by_category.get("network", [])),
            "malware_indicators_count": len(results_by_category.get("malware_indicators", []))
        }

    def _analyze_security_events(self, event_category: str, event_id: int, case_id: str, limit: int) -> Dict:
        """Analyze Windows security events by categories."""

        # Map categories to Event IDs
        event_categories = {
            "authentication": [4624, 4625, 4634, 4647, 4648, 4672],
            "privilege": [4672, 4673, 4674],
            "account_management": [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740],
            "service_install": [7045, 4697],
            "audit_clear": [1102, 104]
        }

        # Event ID descriptions
        event_descriptions = {
            4624: "Successful logon",
            4625: "Failed logon",
            4634: "Logoff",
            4647: "User initiated logoff",
            4648: "Explicit credentials used",
            4672: "Special privileges assigned",
            4673: "Privileged service called",
            4674: "Privileged operation attempted",
            4720: "User account created",
            4722: "User account enabled",
            4723: "Password change attempt",
            4724: "Password reset attempt",
            4725: "User account disabled",
            4726: "User account deleted",
            4738: "User account changed",
            4740: "User account locked out",
            7045: "Service installed",
            4697: "Service installed in system",
            1102: "Audit log cleared",
            104: "Event log cleared"
        }

        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id

        results_by_category = {}
        all_results = []

        # If specific event_id is provided
        if event_id:
            results = self.elastic.search(
                index_name="forensic-eventlog",
                query=str(event_id),
                filters=filters if filters else None,
                size=limit
            )
            # Filter by event_id
            results = [r for r in results if r.get("event_id") == event_id]
            for r in results:
                r["_event_description"] = event_descriptions.get(event_id, "Unknown")
            return {
                "case_id": case_id or "all",
                "event_category": "specific",
                "event_id": event_id,
                "event_description": event_descriptions.get(event_id, "Unknown"),
                "total_results": len(results),
                "results": results[:limit]
            }

        # Search by categories
        if event_category == "all":
            categories_to_search = list(event_categories.keys())
        else:
            categories_to_search = [event_category] if event_category in event_categories else []

        for cat in categories_to_search:
            event_ids = event_categories[cat]
            cat_results = []

            for eid in event_ids:
                results = self.elastic.search(
                    index_name="forensic-eventlog",
                    query=str(eid),
                    filters=filters if filters else None,
                    size=limit // len(event_ids) + 1
                )
                # Filter by event_id
                results = [r for r in results if r.get("event_id") == eid]
                for r in results:
                    r["_event_description"] = event_descriptions.get(eid, "Unknown")
                    r["_security_category"] = cat
                cat_results.extend(results)

            results_by_category[cat] = cat_results
            all_results.extend(cat_results)

        # Sort by time
        all_results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        # Count by severity
        high_severity_ids = [7045, 1102, 104, 4648, 4625]  # High risk
        medium_severity_ids = [4672, 4720, 4726, 4740]  # Medium risk

        high_count = len([r for r in all_results if r.get("event_id") in high_severity_ids])
        medium_count = len([r for r in all_results if r.get("event_id") in medium_severity_ids])
        low_count = len(all_results) - high_count - medium_count

        return {
            "case_id": case_id or "all",
            "event_category": event_category,
            "total_results": len(all_results),
            "by_category": {cat: len(items) for cat, items in results_by_category.items()},
            "by_severity": {
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "suspicious_events": [r for r in all_results if r.get("event_id") in high_severity_ids][:20],
            "results": all_results[:limit]
        }

    def _correlate_activity(self, entity: str, entity_type: str, case_id: str, limit: int) -> Dict:
        """Cross-correlate activity by entity."""

        if not entity:
            return {"error": "entity is required"}

        # Auto-detect entity type
        if entity_type == "auto":
            if any(entity.lower().endswith(ext) for ext in ['.exe', '.dll', '.bat', '.ps1', '.cmd', '.vbs', '.js']):
                entity_type = "executable"
            elif entity.startswith("http") or "." in entity and "/" not in entity:
                entity_type = "url"
            elif "\\" in entity or "/" in entity:
                entity_type = "path"
            else:
                entity_type = "file"

        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id

        # All 13 indices to search
        indices = [
            "forensic-prefetch", "forensic-eventlog", "forensic-registry",
            "forensic-browser", "forensic-lnk", "forensic-mft",
            "forensic-jumplist", "forensic-recyclebin", "forensic-shimcache",
            "forensic-amcache", "forensic-srum", "forensic-powershell",
            "forensic-usnjrnl"
        ]

        results_by_source = {}
        timeline = []
        total_found = 0

        for index in indices:
            try:
                results = self.elastic.search(
                    index_name=index,
                    query=entity,
                    filters=filters if filters else None,
                    size=limit
                )

                if results:
                    source_name = index.replace("forensic-", "")
                    results_by_source[source_name] = results
                    total_found += len(results)

                    # Add to timeline
                    for r in results:
                        timestamp = r.get("timestamp")
                        if timestamp:
                            timeline.append({
                                "timestamp": timestamp,
                                "source": source_name,
                                "entity": entity,
                                "details": self._extract_key_details(r, source_name)
                            })
            except Exception:
                continue  # Index may not exist

        # Sort timeline
        timeline.sort(key=lambda x: x.get("timestamp", ""))

        return {
            "entity": entity,
            "entity_type": entity_type,
            "case_id": case_id or "all",
            "total_found": total_found,
            "sources_with_matches": len(results_by_source),
            "by_source": {source: len(items) for source, items in results_by_source.items()},
            "timeline": timeline[:100],  # Limit timeline
            "first_seen": timeline[0]["timestamp"] if timeline else None,
            "last_seen": timeline[-1]["timestamp"] if timeline else None,
            "detailed_results": {
                source: items[:10] for source, items in results_by_source.items()
            }
        }

    def _extract_key_details(self, record: Dict, source: str) -> str:
        """Extract key details from record for timeline."""
        if source == "prefetch":
            return f"Executed: {record.get('executable_name', 'N/A')}, run_count={record.get('run_count', 0)}"
        elif source == "eventlog":
            return f"Event {record.get('event_id', 'N/A')}: {record.get('message', '')[:100]}"
        elif source == "registry":
            return f"{record.get('key_path', 'N/A')}: {record.get('value_data', '')[:50]}"
        elif source == "browser":
            return f"URL: {record.get('url', 'N/A')[:80]}"
        elif source == "lnk":
            return f"Shortcut to: {record.get('target_path', 'N/A')}"
        elif source == "mft":
            return f"File: {record.get('file_path', 'N/A')}"
        elif source == "jumplist":
            return f"App: {record.get('app_name', 'N/A')}, target: {record.get('target_path', '')[:50]}"
        elif source == "recyclebin":
            return f"Deleted: {record.get('original_path', 'N/A')}"
        elif source == "shimcache":
            return f"Path: {record.get('path', 'N/A')}"
        elif source == "amcache":
            return f"SHA1: {record.get('sha1', 'N/A')}, path: {record.get('path', '')[:50]}"
        elif source == "srum":
            return f"App: {record.get('app_name', 'N/A')}, bytes: {record.get('bytes_sent', 0)}/{record.get('bytes_received', 0)}"
        elif source == "powershell":
            return f"Command: {record.get('command', 'N/A')[:80]}"
        elif source == "usnjrnl":
            return f"Op: {record.get('operation', 'N/A')}, file: {record.get('filename', 'N/A')}"
        else:
            return str(record)[:100]

    def _detect_lateral_movement(self, case_id: str, limit: int) -> Dict:
        """Detect lateral movement."""

        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id

        findings = {
            "remote_logons": [],
            "psexec_usage": [],
            "rdp_activity": [],
            "wmi_activity": [],
            "scheduled_tasks": [],
            "suspicious_services": []
        }
        timeline = []
        risk_score = 0

        # 1. Remote logons (Event 4624 Type 3, 10)
        logon_results = self.elastic.search(
            index_name="forensic-eventlog",
            query="4624",
            filters=filters if filters else None,
            size=limit
        )
        for r in logon_results:
            if r.get("event_id") == 4624:
                message = r.get("message", "").lower()
                if "type 3" in message or "type 10" in message or "network" in message:
                    findings["remote_logons"].append({
                        "timestamp": r.get("timestamp"),
                        "user": r.get("user_id"),
                        "computer": r.get("computer_name"),
                        "logon_type": "Network" if "type 3" in message else "RemoteInteractive",
                        "message": r.get("message", "")[:200]
                    })
                    timeline.append({
                        "timestamp": r.get("timestamp"),
                        "category": "remote_logon",
                        "details": f"Remote logon from {r.get('computer_name', 'N/A')}"
                    })

        # 2. PsExec usage
        psexec_patterns = ["PSEXESVC", "psexec", "paexec", "remcom"]
        for pattern in psexec_patterns:
            # In Prefetch
            prefetch_results = self.elastic.search(
                index_name="forensic-prefetch",
                query=pattern,
                filters=filters if filters else None,
                size=limit // 4
            )
            for r in prefetch_results:
                findings["psexec_usage"].append({
                    "timestamp": r.get("timestamp"),
                    "source": "prefetch",
                    "executable": r.get("executable_name"),
                    "run_count": r.get("run_count")
                })
                timeline.append({
                    "timestamp": r.get("timestamp"),
                    "category": "psexec",
                    "details": f"PsExec executed: {r.get('executable_name', 'N/A')}"
                })

            # In Shimcache
            shimcache_results = self.elastic.search(
                index_name="forensic-shimcache",
                query=pattern,
                filters=filters if filters else None,
                size=limit // 4
            )
            for r in shimcache_results:
                findings["psexec_usage"].append({
                    "timestamp": r.get("timestamp"),
                    "source": "shimcache",
                    "path": r.get("path")
                })

        # 3. RDP activity
        rdp_patterns = ["mstsc", "rdpclip", "rdpinit", "termsrv"]
        for pattern in rdp_patterns:
            rdp_results = self.elastic.search(
                index_name="forensic-prefetch",
                query=pattern,
                filters=filters if filters else None,
                size=limit // 4
            )
            for r in rdp_results:
                findings["rdp_activity"].append({
                    "timestamp": r.get("timestamp"),
                    "executable": r.get("executable_name"),
                    "run_count": r.get("run_count")
                })
                timeline.append({
                    "timestamp": r.get("timestamp"),
                    "category": "rdp",
                    "details": f"RDP tool: {r.get('executable_name', 'N/A')}"
                })

        # 4. WMI activity
        wmi_patterns = ["wmic", "wmiprvse", "scrcons", "mofcomp"]
        for pattern in wmi_patterns:
            wmi_results = self.elastic.search(
                index_name="forensic-prefetch",
                query=pattern,
                filters=filters if filters else None,
                size=limit // 4
            )
            for r in wmi_results:
                findings["wmi_activity"].append({
                    "timestamp": r.get("timestamp"),
                    "executable": r.get("executable_name"),
                    "run_count": r.get("run_count")
                })
                timeline.append({
                    "timestamp": r.get("timestamp"),
                    "category": "wmi",
                    "details": f"WMI tool: {r.get('executable_name', 'N/A')}"
                })

        # 5. Scheduled tasks
        schtasks_patterns = ["schtasks", "at.exe", "taskeng", "taskhost"]
        for pattern in schtasks_patterns:
            task_results = self.elastic.search(
                index_name="forensic-prefetch",
                query=pattern,
                filters=filters if filters else None,
                size=limit // 4
            )
            for r in task_results:
                findings["scheduled_tasks"].append({
                    "timestamp": r.get("timestamp"),
                    "executable": r.get("executable_name"),
                    "run_count": r.get("run_count")
                })
                timeline.append({
                    "timestamp": r.get("timestamp"),
                    "category": "scheduled_task",
                    "details": f"Task scheduler: {r.get('executable_name', 'N/A')}"
                })

        # 6. Suspicious services (Event 7045)
        service_results = self.elastic.search(
            index_name="forensic-eventlog",
            query="7045",
            filters=filters if filters else None,
            size=limit
        )
        suspicious_paths = ["temp", "appdata", "public", "programdata", "\\users\\"]
        for r in service_results:
            if r.get("event_id") == 7045:
                message = r.get("message", "").lower()
                is_suspicious = any(p in message for p in suspicious_paths)
                findings["suspicious_services"].append({
                    "timestamp": r.get("timestamp"),
                    "message": r.get("message", "")[:300],
                    "is_suspicious_path": is_suspicious
                })
                if is_suspicious:
                    timeline.append({
                        "timestamp": r.get("timestamp"),
                        "category": "suspicious_service",
                        "details": f"Service installed from suspicious path"
                    })

        # Calculate risk score (0-100)
        risk_score = 0
        risk_score += min(len(findings["remote_logons"]) * 5, 20)
        risk_score += min(len(findings["psexec_usage"]) * 15, 30)  # PsExec - high risk
        risk_score += min(len(findings["rdp_activity"]) * 5, 15)
        risk_score += min(len(findings["wmi_activity"]) * 10, 20)
        risk_score += min(len(findings["scheduled_tasks"]) * 3, 10)
        risk_score += min(len([s for s in findings["suspicious_services"] if s.get("is_suspicious_path")]) * 10, 20)

        # Sort timeline
        timeline.sort(key=lambda x: x.get("timestamp", ""))

        # Count totals
        total_indicators = sum(len(v) for v in findings.values())

        return {
            "case_id": case_id or "all",
            "risk_score": min(risk_score, 100),
            "risk_level": "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW",
            "total_indicators": total_indicators,
            "summary": {
                "remote_logons": len(findings["remote_logons"]),
                "psexec_usage": len(findings["psexec_usage"]),
                "rdp_activity": len(findings["rdp_activity"]),
                "wmi_activity": len(findings["wmi_activity"]),
                "scheduled_tasks": len(findings["scheduled_tasks"]),
                "suspicious_services": len(findings["suspicious_services"])
            },
            "findings": findings,
            "timeline": timeline[:50],
            "recommendations": self._get_lateral_movement_recommendations(findings, risk_score)
        }

    def _get_lateral_movement_recommendations(self, findings: Dict, risk_score: int) -> List[str]:
        """Generate recommendations based on found indicators."""
        recommendations = []

        if findings["psexec_usage"]:
            recommendations.append("CRITICAL: PsExec usage detected. Investigate all instances for unauthorized remote execution.")

        if findings["remote_logons"]:
            recommendations.append("Review remote logon events for unauthorized access. Check source IP addresses.")

        if any(s.get("is_suspicious_path") for s in findings["suspicious_services"]):
            recommendations.append("CRITICAL: Services installed from suspicious paths. Check for malware persistence.")

        if findings["wmi_activity"]:
            recommendations.append("WMI activity detected. Review for signs of WMI-based lateral movement or persistence.")

        if risk_score >= 60:
            recommendations.append("HIGH RISK: Multiple lateral movement indicators found. Recommend full incident response.")
        elif risk_score >= 30:
            recommendations.append("MEDIUM RISK: Some lateral movement indicators present. Further investigation recommended.")

        if not recommendations:
            recommendations.append("LOW RISK: No significant lateral movement indicators detected.")

        return recommendations

    async def run(self):
        """Run MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream, self.server.create_initialization_options())


# Entry point
async def main():
    import os
    elastic_host = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
    server = ForensicMCPServer(elastic_host)
    await server.run()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
