# src/llm/openai_analyzer.py
"""
OpenAI Analyzer - GPT-4.1 forensic analysis with Tool Use.
Inherits all 16 tool implementations from BaseAnalyzer.

Token optimization:
- temperature=0 (deterministic, no wasted variation)
- max_tokens=2048 (enough for forensic answers, not wasteful)
- Tool results truncated at 6000 chars (GPT-4.1 has 1M context but we pay per token)
- History carries only user/assistant text (no tool call replay)
- max_completion_tokens used instead of max_tokens for precise control
"""

import os
import json

from openai import OpenAI
from dotenv import load_dotenv

from .base_analyzer import BaseAnalyzer

load_dotenv()


class OpenAIAnalyzer(BaseAnalyzer):
    """
    Forensic analyzer using OpenAI GPT-4.1 API.

    Inherits 16 forensic tools from BaseAnalyzer.
    Optimized to minimize token usage while maintaining quality.
    """

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None,
                 model: str = None, max_tokens: int = 2048, max_tool_calls: int = 25,
                 max_tool_result_chars: int = 8000):
        super().__init__(es_url, case_id)

        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not found in environment")

        self.client = OpenAI(api_key=self.api_key)
        self.model = model or "gpt-5.1"
        self.max_tokens = max_tokens
        self.max_tool_calls = max_tool_calls
        # Per-tool-result truncation budget. Default 8000 preserves the
        # retrieval benchmark behavior published in FINAL_BENCHMARK_REPORT.md.
        # Timeline orchestrator passes 20000 for fair multi-model timeline
        # enumeration; do NOT raise this default without re-running retrieval.
        self.max_tool_result_chars = max_tool_result_chars

        # All 16 tools in OpenAI format
        self.tools = self.get_tools_openai()

        # System prompt with OpenAI-specific guidance
        self.system_prompt = self.BASE_SYSTEM_PROMPT + """

SEARCH STRATEGY:
- If a specialized tool (analyze_registry, analyze_security_events) does not return the answer, follow up with search_artifacts using direct keywords. Do NOT stop after one tool if the answer is incomplete.
- When looking for specific values (usernames, file names, IPs), use search_artifacts with that value as query — it searches across ALL artifact types.
- Cross-reference multiple artifact types: registry, event logs, MFT, prefetch, browser history may all contain complementary evidence about the same entity.
- Provide exact values from tool results. If a tool returns a name, path, or timestamp, quote it exactly."""

    def analyze(self, query: str, case_id: str = None) -> str:
        """Analyze forensic data using OpenAI GPT-4.1 with tool use."""
        if case_id:
            self.case_id = case_id
        self._trim_history()

        self.conversation_history.append({
            "role": "user",
            "content": query
        })

        try:
            # Build messages — only user/assistant text, no old tool calls (saves tokens)
            messages = [{"role": "system", "content": self.system_prompt}]
            for msg in self.conversation_history:
                if msg["role"] in ["user", "assistant"] and "tool_calls" not in msg:
                    messages.append({"role": msg["role"], "content": msg["content"]})

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=self.tools,
                tool_choice="auto",
                max_completion_tokens=self.max_tokens,
                temperature=0,
                seed=42
            )

            message = response.choices[0].message

            # Tool call loop — separate context, not saved to history
            tool_messages = list(messages)
            tool_call_count = 0

            while message.tool_calls and tool_call_count < self.max_tool_calls:
                tool_messages.append({
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        }
                        for tc in message.tool_calls
                    ]
                })

                for tool_call in message.tool_calls:
                    tool_call_count += 1
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)

                    print(f"[Tool] {tool_name}")
                    result = self._execute_tool(tool_name, tool_args)

                    # Truncate large results. Budget is configurable via
                    # constructor (default 8000 preserves retrieval-bench baseline).
                    MAX_TOOL_RESULT = self.max_tool_result_chars
                    if len(result) > MAX_TOOL_RESULT:
                        result = result[:MAX_TOOL_RESULT] + f"\n...[truncated, {len(result)} chars total]"

                    tool_messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result
                    })

                if tool_call_count >= self.max_tool_calls:
                    tool_messages.append({
                        "role": "user",
                        "content": "Maximum tool calls reached. Provide your final answer now based on the data gathered."
                    })
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=tool_messages,
                        max_completion_tokens=self.max_tokens,
                        temperature=0
                    )
                    message = response.choices[0].message
                    break

                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=tool_messages,
                    tools=self.tools,
                    tool_choice="auto",
                    max_completion_tokens=self.max_tokens,
                    temperature=0
                )
                message = response.choices[0].message

            final_text = message.content or ""

            self.conversation_history.append({
                "role": "assistant",
                "content": final_text
            })

            return final_text

        except Exception as e:
            return f"Error: {str(e)}"


# CLI interface
if __name__ == "__main__":
    print("=" * 50)
    print("OpenAI GPT-4.1 Forensic Analyzer")
    print("=" * 50)

    try:
        analyzer = OpenAIAnalyzer()
        print(f"[OK] Connected to OpenAI API (model: {analyzer.model})")
    except ValueError as e:
        print(f"[ERROR] {e}")
        exit(1)

    print("\nCommands: /clear, /quit\n")

    while True:
        try:
            query = input("You: ").strip()
            if not query:
                continue
            if query == "/quit":
                break
            if query == "/clear":
                analyzer.clear_history()
                print("[Cleared]\n")
                continue

            print("\nAnalyzing...\n")
            print(analyzer.analyze(query))
            print()
        except KeyboardInterrupt:
            break
