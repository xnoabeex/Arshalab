# src/llm/deepseek_analyzer.py
"""
DeepSeek Analyzer - LLM-powered forensic analysis with Tool Use (OpenAI-compatible SDK).
Inherits all tool implementations from BaseAnalyzer.
"""

import os
import json

from openai import OpenAI
from dotenv import load_dotenv

from .base_analyzer import BaseAnalyzer

load_dotenv()


class DeepSeekAnalyzer(BaseAnalyzer):
    """
    Forensic analyzer using DeepSeek API (OpenAI-compatible).

    Inherits 16 forensic tools from BaseAnalyzer.
    Uses OpenAI SDK with DeepSeek endpoint.
    """

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None,
                 max_tokens: int = 2048, max_tool_calls: int = 25,
                 max_tool_result_chars: int = 8000):
        super().__init__(es_url, case_id)

        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            raise ValueError("DEEPSEEK_API_KEY not found in environment")

        self.client = OpenAI(
            api_key=self.api_key,
            base_url="https://api.deepseek.com"
        )
        self.model = "deepseek-chat"
        self.max_tokens = max_tokens
        self.max_tool_calls = max_tool_calls
        # Per-tool-result truncation budget. Default 8000 preserves the
        # retrieval benchmark behavior published in FINAL_BENCHMARK_REPORT.md.
        # Timeline orchestrator passes 20000 for fair multi-model timeline
        # enumeration; do NOT raise this default without re-running retrieval.
        self.max_tool_result_chars = max_tool_result_chars

        # Tools in OpenAI format
        self.tools = self.get_tools_openai()

        # System prompt
        self.system_prompt = self.BASE_SYSTEM_PROMPT

    def analyze(self, query: str, case_id: str = None) -> str:
        """Analyze forensic data using DeepSeek with tool use."""
        if case_id:
            self.case_id = case_id
        self._trim_history()

        self.conversation_history.append({
            "role": "user",
            "content": query
        })

        try:
            # Build messages (user/assistant only, no tool calls in history)
            messages = [{"role": "system", "content": self.system_prompt}]
            for msg in self.conversation_history:
                if msg["role"] in ["user", "assistant"] and "tool_calls" not in msg:
                    messages.append({"role": msg["role"], "content": msg["content"]})

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=self.tools,
                tool_choice="auto",
                max_tokens=self.max_tokens,
                temperature=0
            )

            message = response.choices[0].message

            # Handle tool calls in a separate loop (not saved to history)
            tool_messages = list(messages)
            tool_call_count = 0
            MAX_TOOL_CALLS = getattr(self, 'max_tool_calls', 25)

            while message.tool_calls and tool_call_count < MAX_TOOL_CALLS:
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

                    # Truncate large tool results. Budget is configurable via
                    # constructor (default 8000 preserves retrieval-bench baseline).
                    MAX_TOOL_RESULT = self.max_tool_result_chars
                    if len(result) > MAX_TOOL_RESULT:
                        result = result[:MAX_TOOL_RESULT] + f"\n...[truncated, {len(result)} chars total]"

                    tool_messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result
                    })

                if tool_call_count >= MAX_TOOL_CALLS:
                    # Force final answer without more tools
                    tool_messages.append({
                        "role": "user",
                        "content": "You have reached the maximum number of tool calls. Please provide your final answer now based on the data you have gathered so far."
                    })
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=tool_messages,
                        max_tokens=self.max_tokens,
                        temperature=0
                    )
                    message = response.choices[0].message
                    break

                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=tool_messages,
                    tools=self.tools,
                    tool_choice="auto",
                    max_tokens=self.max_tokens,
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
    print("DeepSeek Forensic Analyzer")
    print("=" * 50)

    try:
        analyzer = DeepSeekAnalyzer()
        print("[OK] Connected to DeepSeek API")
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
