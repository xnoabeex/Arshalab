# src/llm/groq_analyzer.py
"""
Groq Analyzer - LLM-powered forensic analysis with Tool Use (FREE).
Uses Groq API with Llama 3.3 70B.
Inherits all tool implementations from BaseAnalyzer.
"""

import os
import re
import json
import time

from groq import Groq
from dotenv import load_dotenv

from .base_analyzer import BaseAnalyzer

load_dotenv()


class GroqAnalyzer(BaseAnalyzer):
    """
    Forensic analyzer using Groq API with Llama 3.3.
    FREE tier with rate limits.

    Inherits 16 forensic tools from BaseAnalyzer.
    Uses OpenAI-compatible tool format.
    """

    MAX_TOOL_RETRIES = 2  # Retries on malformed tool call errors

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None, max_tokens: int = 2048, max_tool_calls: int = 25):
        super().__init__(es_url, case_id)

        self.api_key = os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("GROQ_API_KEY not found in environment. Get free key at https://console.groq.com")

        self.client = Groq(api_key=self.api_key)
        self.model = "llama-3.3-70b-versatile"
        self.max_tokens = max_tokens
        self.MAX_TOOL_ROUNDS = max_tool_calls

        # Simplified tools to reduce token usage (Groq free tier is limited)
        self.tools = self._get_simplified_tools()

        # Valid tool names for fallback parsing
        self._valid_tools = {t["function"]["name"] for t in self.tools}

        # System prompt with guidance for tool usage
        self.system_prompt = self.BASE_SYSTEM_PROMPT + """
IMPORTANT: Always include exact numbers, counts, and values from tool results. Be concise (1-3 sentences).
"""

    def _get_simplified_tools(self):
        """Simplified tools to reduce token count for Groq free tier."""
        return [
            {"type": "function", "function": {
                "name": "search_artifacts",
                "description": "Search forensic artifacts for keywords (filenames, usernames, IPs, paths).",
                "parameters": {"type": "object", "properties": {
                    "query": {"type": "string", "description": "Search keyword"},
                    "artifact_type": {"type": "string", "enum": ["all","prefetch","eventlog","registry","browser","mft","shimcache","amcache","srum"], "description": "Artifact type (default: all)"}
                }, "required": ["query"]}
            }},
            {"type": "function", "function": {
                "name": "get_events",
                "description": "Get events by Event ID (4624=logon, 4625=failed, 4647=logoff, 4720=account created, 7045=service).",
                "parameters": {"type": "object", "properties": {
                    "event_id": {"type": "integer", "description": "Event ID number"}
                }, "required": ["event_id"]}
            }},
            {"type": "function", "function": {
                "name": "get_top_programs",
                "description": "Get most executed programs from Prefetch sorted by run count.",
                "parameters": {"type": "object", "properties": {}}
            }},
            {"type": "function", "function": {
                "name": "get_network_traffic",
                "description": "Get per-application network traffic from SRUM.",
                "parameters": {"type": "object", "properties": {
                    "app_name": {"type": "string", "description": "App name filter (optional)"}
                }}
            }},
            {"type": "function", "function": {
                "name": "get_case_info",
                "description": "Get case overview with record counts per artifact type.",
                "parameters": {"type": "object", "properties": {}}
            }},
        ]

    def _execute_tool(self, name, args):
        """Route simplified tool names to base implementations."""
        if name == "get_events":
            return self._tool_analyze_security_events(event_id=args.get("event_id"), limit=20)
        elif name == "get_top_programs":
            return self._tool_search_artifacts(query="*", artifact_type="prefetch", limit=15)
        elif name == "get_network_traffic":
            return self._tool_analyze_network_activity(app_name=args.get("app_name"), limit=15)
        elif name == "get_case_info":
            return self._tool_get_stats()
        else:
            return super()._execute_tool(name, args)

    def _parse_failed_tool_call(self, failed_gen: str) -> list:
        """
        Parse malformed tool calls from Groq's failed_generation string.
        Handles patterns like:
          <function=search_artifacts>{"artifact_type": "browser"}</function>
          search_artifacts={"artifact_type": "browser", "query": "google"}
          search_artifacts {"artifact_type": "eventlog", "query": "4624"}
        Returns list of (tool_name, tool_args) tuples.
        """
        results = []

        # Pattern 1: <function=TOOL_NAME>ARGS</function>
        pattern1 = re.findall(r'<function=(\w+)>(.*?)(?:</function>|$)', failed_gen, re.DOTALL)
        for name, args_str in pattern1:
            if name in self._valid_tools:
                try:
                    # Fix incomplete JSON (missing closing brace)
                    args_str = args_str.strip()
                    if args_str.startswith('{') and not args_str.endswith('}'):
                        args_str += '}'
                    args = json.loads(args_str)
                    results.append((name, args))
                except json.JSONDecodeError:
                    pass

        if results:
            return results

        # Pattern 2: TOOL_NAME={"key": "value"} or TOOL_NAME {"key": "value"}
        pattern2 = re.findall(r'(\w+)[= ]\s*(\{[^}]+\})', failed_gen)
        for name, args_str in pattern2:
            # The name might include a prefix like "function="
            clean_name = name.split('=')[-1] if '=' in name else name
            if clean_name in self._valid_tools:
                try:
                    args = json.loads(args_str)
                    results.append((clean_name, args))
                except json.JSONDecodeError:
                    pass

        return results

    def _make_api_call(self, messages):
        """
        Make an API call with fallback for malformed tool calls and rate limit retries.
        If Groq returns tool_use_failed, parse the failed_generation and execute tools manually.
        If rate limited, wait and retry.
        """
        for attempt in range(4):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=self.tools,
                    tool_choice="auto",
                    max_tokens=self.max_tokens
                )
                return response.choices[0].message, None
            except Exception as e:
                error_msg = str(e)

                # Handle malformed tool calls
                if "tool_use_failed" in error_msg and "failed_generation" in error_msg:
                    fg_match = re.search(r"'failed_generation': '(.*?)'(?:\s*\})", error_msg, re.DOTALL)
                    if not fg_match:
                        fg_match = re.search(r'"failed_generation": "(.*?)"', error_msg, re.DOTALL)
                    if fg_match:
                        failed_gen = fg_match.group(1)
                        parsed = self._parse_failed_tool_call(failed_gen)
                        if parsed:
                            return None, parsed

                # Handle rate limits with backoff
                if "rate_limit" in error_msg.lower():
                    wait = [60, 120, 180, 240][attempt]
                    print(f"\n⚠️  Groq rate limit! Waiting {wait}s... (attempt {attempt+1}/4)", flush=True)
                    time.sleep(wait)
                    continue

                # Re-raise other errors
                raise

        raise Exception("Groq rate limit exceeded after 4 retries")

    def analyze(self, query: str, case_id: str = None) -> str:
        """Analyze forensic data using Groq/Llama with tool use."""
        if case_id:
            self.case_id = case_id
        self._trim_history()

        self.conversation_history.append({
            "role": "user",
            "content": query
        })

        try:
            messages = [{"role": "system", "content": self.system_prompt}] + self.conversation_history
            tool_rounds = 0

            message, fallback_tools = self._make_api_call(messages)

            while tool_rounds < self.MAX_TOOL_ROUNDS:
                tool_rounds += 1

                # Case 1: Normal tool calls from API
                if message and message.tool_calls:
                    self.conversation_history.append({
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
                        tool_name = tool_call.function.name
                        tool_args = json.loads(tool_call.function.arguments)

                        print(f"[Tool] Executing: {tool_name}")
                        result = self._execute_tool(tool_name, tool_args)

                        self.conversation_history.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": result
                        })

                # Case 2: Fallback - parsed from failed_generation
                elif fallback_tools:
                    tool_results = []
                    for tool_name, tool_args in fallback_tools:
                        print(f"[Tool] Executing (fallback): {tool_name}")
                        result = self._execute_tool(tool_name, tool_args)
                        tool_results.append((tool_name, result))

                    # Build a context message with tool results for the model
                    results_text = "\n\n".join(
                        f"[Tool: {name}]\n{res[:3000]}" for name, res in tool_results
                    )
                    self.conversation_history.append({
                        "role": "assistant",
                        "content": f"I called the following tools:\n{results_text}"
                    })
                    # Ask model to continue with the tool results
                    self.conversation_history.append({
                        "role": "user",
                        "content": "Please continue your analysis based on the tool results above."
                    })

                # Case 3: No tool calls - we're done
                else:
                    break

                # Next API call
                messages = [{"role": "system", "content": self.system_prompt}] + self.conversation_history
                message, fallback_tools = self._make_api_call(messages)

            # Final response
            if message:
                final_text = message.content or ""
            else:
                # If last iteration was a fallback, make one more call for final answer
                messages = [{"role": "system", "content": self.system_prompt}] + self.conversation_history
                try:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=messages,
                        max_tokens=self.max_tokens
                    )
                    final_text = response.choices[0].message.content or ""
                except Exception:
                    final_text = self.conversation_history[-2].get("content", "")  # Use tool results

            self.conversation_history.append({
                "role": "assistant",
                "content": final_text
            })

            return final_text

        except Exception as e:
            error_msg = str(e)
            if "rate_limit" in error_msg.lower():
                # Auto-retry with backoff for rate limits
                for wait_time in [30, 60, 90]:
                    print(f"\n⚠️  Groq rate limit! Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    try:
                        messages = [{"role": "system", "content": self.system_prompt}] + self.conversation_history
                        message, fallback_tools = self._make_api_call(messages)
                        if message and message.content:
                            final_text = message.content
                            self.conversation_history.append({
                                "role": "assistant",
                                "content": final_text
                            })
                            return final_text
                    except Exception as retry_e:
                        if "rate_limit" not in str(retry_e).lower():
                            return f"Error: {retry_e}"
                        continue
                return "Error: Rate limit exceeded after retries. (Groq free tier limit)"
            return f"Error: {error_msg}"


# CLI interface
if __name__ == "__main__":
    import sys

    print("=" * 50)
    print("Groq Forensic Analyzer (FREE - Llama 3.3 70B)")
    print("=" * 50)

    try:
        analyzer = GroqAnalyzer()
        print("[OK] Connected to Groq API")
    except ValueError as e:
        print(f"[ERROR] {e}")
        print("\nGet your free API key at: https://console.groq.com")
        sys.exit(1)

    print("\nCommands:")
    print("  /clear - Clear conversation")
    print("  /quit - Exit")
    print("\nAsk any question about the forensic data.\n")

    while True:
        try:
            query = input("You: ").strip()

            if not query:
                continue

            if query == "/quit":
                break
            elif query == "/clear":
                analyzer.clear_history()
                print("\n[Conversation cleared]\n")
                continue

            print("\nAnalyzing...\n")
            response = analyzer.analyze(query)

            print(response)
            print()

        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
