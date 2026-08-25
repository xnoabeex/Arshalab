#!/usr/bin/env python3
"""
ArshaLab Forensic MCP Server

Exposes 16 forensic analysis tools to Claude Desktop via MCP protocol.
Supports case_id filtering to analyze specific forensic images.

Tools:
- list_cases: Show available forensic cases
- set_case: Select a case for analysis (filters all queries)
- 16 forensic tools from BaseAnalyzer
"""

import asyncio
import json
import logging
import os
import requests
from mcp.server import Server
from mcp.types import Tool, TextContent, Resource, ResourceTemplate
from mcp.server.stdio import stdio_server

from src.llm.base_analyzer import BaseAnalyzer

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("forensic-mcp")

# ES URL
ES_URL = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")

# MCP Server instructions — strict rules for Claude Desktop
# This is part of MCP protocol, not just a prompt suggestion
SERVER_INSTRUCTIONS = """
You are a digital forensic analyst. You MUST follow these rules strictly:

## CRITICAL RULES

1. **NEVER use web search, WebSearch, WebFetch, or any internet lookup.**
   You must ONLY answer based on data returned by forensic MCP tools.
   If the data is not in Elasticsearch — say "Data not found in loaded artifacts"
   and suggest which artifacts need to be loaded.

2. **NEVER reference CTF writeups, published solutions, or external knowledge
   about specific forensic cases.** Every answer must come from actual artifact data.

3. **If a forensic tool returns no results**, do NOT guess or fabricate the answer.
   Instead, respond:
   - What you searched for
   - Which indices/artifacts were checked
   - What artifacts might need to be loaded to answer the question

4. **Data integrity**: Your analysis is potential evidence.
   Never speculate without data. Clearly separate facts (from tools) from hypotheses.

## WORKFLOW
1. First call `list_cases` or `get_current_case` to verify the active case
2. Use forensic tools to query Elasticsearch
3. Analyze ONLY the returned data
4. Present findings with references to specific artifacts and timestamps
"""

# Create server instance
app = Server("arshalab-forensics", instructions=SERVER_INSTRUCTIONS)

# Current case_id for filtering (None = all cases)
current_case_id = None

# Analyzer instance (recreated when case changes)
analyzer = BaseAnalyzer(es_url=ES_URL, case_id=current_case_id)

# Response format mode: "auto", "short", "detailed"
response_mode = "auto"

# Response format instructions (local, no cloud dependency)
RESPONSE_FORMAT_INSTRUCTIONS = """
## RESPONSE LENGTH - ADAPT TO QUESTION TYPE

**Current mode: {mode}**

### SHORT answers (1-3 sentences) for simple/factual questions:
- "What is the user account?" → "The primary user account is 'defaultuser0'."
- "How many prefetch records?" → "There are 1,247 prefetch records in this case."
- "When was chrome.exe last run?" → "chrome.exe was last executed on 2023-09-22 at 14:30:15 with run count 42."
- "What browsers are installed?" → "Chrome, Firefox, and Edge are present based on prefetch and browser history."
- "List deleted files" → Brief list with key details only.

### DETAILED answers for analysis/investigation questions:
- "Analyze suspicious activity" → Full format with Summary, Findings, Timeline
- "What happened on this system?" → Comprehensive investigation report
- "Find evidence of malware" → Detailed analysis with correlations
- "Create investigation timeline" → Full timeline with all sections
- "Investigate the incident" → Complete forensic report

### Detection rules:
- Question contains "analyze", "investigate", "explain", "timeline", "report" → DETAILED
- Question is a simple "what/when/how many/list" → SHORT
- When in doubt, match complexity of answer to complexity of question

### Examples of SHORT responses:
Q: "What user accounts exist?"
A: "Found 3 user accounts: defaultuser0 (primary), Administrator, Guest."

Q: "When was the last login?"
A: "Last successful login: 2023-09-22 14:30:15 by defaultuser0."

### Examples of DETAILED responses:
Q: "Analyze suspicious network activity"
A: "## Summary
[2-3 sentence overview]

## Key Findings
1. **Finding 1**: [details with evidence]
2. **Finding 2**: [details with evidence]

## Timeline
- [timestamp]: [event]
- [timestamp]: [event]

## Recommendations
- [action items]"
"""


def get_available_cases():
    """Get list of available cases from Elasticsearch."""
    try:
        body = {
            "size": 0,
            "aggs": {
                "cases": {
                    "terms": {"field": "case_id.keyword", "size": 100},
                    "aggs": {
                        "name": {
                            "terms": {"field": "case_name.keyword", "size": 1}
                        }
                    }
                }
            }
        }
        r = requests.post(f"{ES_URL}/forensic-*/_search", json=body, timeout=5)
        if r.status_code == 200:
            buckets = r.json().get("aggregations", {}).get("cases", {}).get("buckets", [])
            results = []
            for b in buckets:
                case = {
                    "case_id": b["key"],
                    "record_count": b["doc_count"]
                }
                name_buckets = b.get("name", {}).get("buckets", [])
                if name_buckets:
                    case["case_name"] = name_buckets[0]["key"]
                results.append(case)
            return results
    except Exception as e:
        logger.error(f"Failed to get cases: {e}")
    return []


@app.list_resources()
async def list_resources() -> list[Resource]:
    """List available resources."""
    return [
        Resource(
            uri="forensic://response-format",
            name="Response Format Instructions",
            description="Instructions for adapting response length to question type (short vs detailed)",
            mimeType="text/markdown"
        ),
        Resource(
            uri="forensic://current-case",
            name="Current Case Info",
            description="Information about the currently selected forensic case",
            mimeType="application/json"
        )
    ]


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource by URI."""
    global response_mode, current_case_id

    if uri == "forensic://response-format":
        return RESPONSE_FORMAT_INSTRUCTIONS.format(mode=response_mode)

    elif uri == "forensic://current-case":
        cases = get_available_cases()
        current_info = None
        if current_case_id:
            for c in cases:
                if c["case_id"] == current_case_id:
                    current_info = c
                    break
        return json.dumps({
            "current_case_id": current_case_id or "all",
            "current_case_info": current_info,
            "available_cases_count": len(cases)
        }, indent=2)

    return json.dumps({"error": f"Unknown resource: {uri}"})


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List all available forensic tools."""
    tools = []

    # Add case management tools
    tools.append(Tool(
        name="list_cases",
        description="List all available forensic cases (disk images) in the database. Returns case IDs and record counts.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ))

    tools.append(Tool(
        name="set_case",
        description="Set the current case for analysis. All subsequent queries will be filtered to this case only. Use case_id from list_cases, or empty string to analyze all cases.",
        inputSchema={
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "Case ID to filter (e.g., 'case_20260128_141256'). Empty string for all cases."
                }
            },
            "required": ["case_id"]
        }
    ))

    tools.append(Tool(
        name="get_current_case",
        description="Get the currently selected case for analysis.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ))

    tools.append(Tool(
        name="set_response_mode",
        description="Set response format mode: 'auto' (adapts to question), 'short' (always concise), 'detailed' (always full report). Default is 'auto'.",
        inputSchema={
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["auto", "short", "detailed"],
                    "description": "Response mode: auto, short, or detailed"
                }
            },
            "required": ["mode"]
        }
    ))

    tools.append(Tool(
        name="get_response_mode",
        description="Get current response format mode.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ))

    # Add forensic tools from BaseAnalyzer
    for tool_def in analyzer.TOOL_DEFINITIONS:
        tools.append(Tool(
            name=tool_def["name"],
            description=tool_def["description"],
            inputSchema=tool_def["parameters"]
        ))

    logger.info(f"Listed {len(tools)} tools (5 management + {len(analyzer.TOOL_DEFINITIONS)} forensic)")
    return tools


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute forensic tool."""
    global current_case_id, analyzer, response_mode

    logger.info(f"Executing tool: {name} with args: {arguments}")

    try:
        # Handle case management tools
        if name == "list_cases":
            cases = get_available_cases()
            result = {
                "cases": cases,
                "count": len(cases),
                "current_case": current_case_id or "all"
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "set_case":
            case_id = arguments.get("case_id", "").strip()
            if case_id == "":
                case_id = None

            # Verify case exists (if not empty) - accept both case_id and case_name
            case_name_display = None
            if case_id:
                cases = get_available_cases()
                valid_ids = [c["case_id"] for c in cases]
                # Also try matching by case_name
                name_to_id = {c.get("case_name", ""): c["case_id"] for c in cases}
                if case_id not in valid_ids and case_id in name_to_id:
                    case_id = name_to_id[case_id]
                if case_id not in valid_ids:
                    return [TextContent(type="text", text=json.dumps({
                        "error": f"Case '{case_id}' not found",
                        "available_cases": [
                            {"case_id": c["case_id"], "case_name": c.get("case_name", "")}
                            for c in cases
                        ]
                    }, indent=2))]
                # Find display name
                for c in cases:
                    if c["case_id"] == case_id:
                        case_name_display = c.get("case_name", case_id)
                        break

            # Update case and recreate analyzer
            current_case_id = case_id
            analyzer = BaseAnalyzer(es_url=ES_URL, case_id=current_case_id)

            result = {
                "status": "success",
                "current_case": current_case_id or "all",
                "case_name": case_name_display or "all cases",
                "message": f"Now analyzing: {current_case_id or 'all cases'}"
            }
            logger.info(f"Switched to case: {current_case_id or 'all'}")
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "get_current_case":
            result = {
                "current_case": current_case_id or "all",
                "message": f"Currently analyzing: {current_case_id or 'all cases'}"
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "set_response_mode":
            mode = arguments.get("mode", "auto").lower()
            if mode not in ["auto", "short", "detailed"]:
                return [TextContent(type="text", text=json.dumps({
                    "error": f"Invalid mode '{mode}'. Use: auto, short, or detailed"
                }, indent=2))]

            response_mode = mode
            mode_descriptions = {
                "auto": "Adapts response length to question complexity",
                "short": "Always gives concise 1-3 sentence answers",
                "detailed": "Always gives full forensic reports"
            }
            result = {
                "status": "success",
                "mode": response_mode,
                "description": mode_descriptions[response_mode],
                "instructions": RESPONSE_FORMAT_INSTRUCTIONS.format(mode=response_mode)
            }
            logger.info(f"Response mode set to: {response_mode}")
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "get_response_mode":
            mode_descriptions = {
                "auto": "Adapts response length to question complexity",
                "short": "Always gives concise 1-3 sentence answers",
                "detailed": "Always gives full forensic reports"
            }
            result = {
                "mode": response_mode,
                "description": mode_descriptions[response_mode]
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        # Execute forensic tool via BaseAnalyzer
        result = analyzer._execute_tool(name, arguments)

        # Return result as JSON text with anti-hallucination reminder
        result_json = json.dumps(result, ensure_ascii=False, indent=2)
        return [TextContent(
            type="text",
            text=f"{result_json}\n\n---\n[SYSTEM] Your answer MUST be based ONLY on the data above. "
                 f"Do NOT use web search. Do NOT reference external writeups or CTF solutions. "
                 f"If the data above does not contain the answer, say so explicitly."
        )]

    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": str(e),
                            "_note": "Answer ONLY from forensic data. Do NOT use web search or external knowledge."})
        )]


async def main():
    """Run MCP server."""
    logger.info("=" * 60)
    logger.info("ArshaLab Forensic MCP Server")
    logger.info("=" * 60)
    logger.info(f"Elasticsearch: {ES_URL}")
    logger.info(f"Forensic tools: {len(analyzer.TOOL_DEFINITIONS)}")

    # Show available cases
    cases = get_available_cases()
    logger.info(f"Available cases: {len(cases)}")
    for c in cases:
        logger.info(f"  - {c['case_id']}: {c['record_count']:,} records")

    logger.info("=" * 60)
    logger.info("Ready for Claude Desktop connection")
    logger.info("=" * 60)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
