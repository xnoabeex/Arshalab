"""MCP-CLI analyzer: drives Claude via the `claude` CLI in headless mode
with the forensic MCP server (no Anthropic API credits — uses Claude Pro).

Exposes the same minimal interface the orchestrator expects:
    analyze(prompt: str) -> str
    clear_history()             # no-op: each CLI call is stateless

Each analyze() call spawns:
    claude -p --mcp-config mcp_config.json --model <model>
           --dangerously-skip-permissions "<set_case + prompt>"
"""
import subprocess
import time
from pathlib import Path

import os
# Claude CLI: uses "claude" from PATH by default; override with the CLAUDE_CMD env var.
CLAUDE_CMD = os.environ.get("CLAUDE_CMD", "claude")
PROJECT_DIR = Path(__file__).resolve().parents[2]
MCP_CONFIG = str(PROJECT_DIR / "mcp_config.json")

# model aliases accepted by claude CLI
MODEL_ALIASES = {
    "sonnet": "sonnet",
    "opus": "opus",
    "claude-sonnet-4-6": "sonnet",
    "claude-opus-4-7": "opus",
}


class MCPCLIAnalyzer:
    def __init__(self, case_id: str, model: str = "sonnet",
                 timeout: int = 600, mcp_config: str = None):
        self.case_id = case_id
        self.model = MODEL_ALIASES.get(model, model)
        self.timeout = timeout
        self.mcp_config = mcp_config or MCP_CONFIG
        self.last_latency = 0.0
        self.call_count = 0

    def clear_history(self):
        # Each CLI invocation is a fresh process — nothing to clear.
        return

    def analyze(self, query: str, case_id: str = None) -> str:
        cid = case_id or self.case_id
        # Every call is stateless, so always (re)select the case first.
        full_prompt = (
            f"Call set_case with case_id='{cid}'. "
            f"Then complete this task using only the forensic MCP tools "
            f"(no web search). {query}"
        )

        cmd = [
            CLAUDE_CMD, "-p",
            "--mcp-config", self.mcp_config,
            "--model", self.model,
            "--dangerously-skip-permissions",
            full_prompt,
        ]

        t0 = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(PROJECT_DIR),
            )
            self.last_latency = round(time.time() - t0, 1)
            self.call_count += 1

            if result.returncode != 0:
                err = (result.stderr or "").strip()[:300]
                return f"ERROR: claude CLI exit {result.returncode}: {err}"

            return (result.stdout or "").strip()

        except subprocess.TimeoutExpired:
            self.last_latency = round(time.time() - t0, 1)
            return f"ERROR: timeout after {self.timeout}s"
        except FileNotFoundError:
            return (f"ERROR: claude CLI not found at {CLAUDE_CMD}. "
                    f"Check the path / npm global install.")
        except Exception as e:
            return f"ERROR: {e}"
