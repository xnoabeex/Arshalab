# src/llm/claude_analyzer.py
"""
Claude Analyzer - LLM-powered forensic analysis with Tool Use (Anthropic SDK).
Inherits all tool implementations from BaseAnalyzer.
"""

import os

import anthropic
from dotenv import load_dotenv

from .base_analyzer import BaseAnalyzer

load_dotenv()


class ClaudeAnalyzer(BaseAnalyzer):
    """
    Forensic analyzer using Claude with Tool Use.

    Claude decides which tools to call based on user query.
    Inherits 16 forensic tools from BaseAnalyzer.
    """

    def __init__(self, es_url: str = "http://localhost:9200",
                 incident_context: str = None, session_id: str = None,
                 model: str = "claude-sonnet-4-5-20250929", case_id: str = None):
        super().__init__(es_url, case_id)

        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment")

        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model = model
        self.incident_context = incident_context
        self.session_id = session_id or "default"

        # Tools in Anthropic format
        self.tools = self.get_tools_anthropic()

        # Build system prompt with incident context
        self.system_prompt = self._build_system_prompt()

    def _build_system_prompt(self) -> str:
        """Build system prompt with optional incident context."""
        prompt = self.BASE_SYSTEM_PROMPT

        if self.incident_context:
            prompt += f"""

=== INCIDENT BRIEFING ===
The following incident details have been provided. Use this information to focus your investigation:

{self.incident_context}

Focus your analysis on finding evidence related to this incident. Correlate timestamps, look for IOCs mentioned, and prioritize relevant artifacts.
========================="""

        return prompt

    def set_incident_context(self, context: str):
        """Update incident context and rebuild system prompt."""
        self.incident_context = context
        self.system_prompt = self._build_system_prompt()

    def _trim_history(self):
        """Trim history while preserving tool_use/tool_result pairs.

        Anthropic API requires tool_use and tool_result messages to be paired.
        Cutting in the middle of a tool exchange causes a 400 error.
        """
        if len(self.conversation_history) <= self.max_history_messages:
            return

        cut_start = len(self.conversation_history) - self.max_history_messages

        # Scan forward to find a safe cut point (user message with simple text content)
        for i in range(cut_start, len(self.conversation_history)):
            msg = self.conversation_history[i]
            if msg.get("role") == "user":
                content = msg.get("content")
                # Simple text message (not tool_result)
                if isinstance(content, str):
                    self.conversation_history = self.conversation_history[i:]
                    return
                # List content - check it's not tool_result
                if isinstance(content, list):
                    is_tool_result = any(
                        isinstance(c, dict) and c.get("type") == "tool_result"
                        for c in content
                    )
                    if not is_tool_result:
                        self.conversation_history = self.conversation_history[i:]
                        return

        # No safe point found - clear history
        self.conversation_history = []

    def analyze(self, query: str, case_id: str = None) -> str:
        """Analyze forensic data using Claude with tool use."""
        self._trim_history()

        self.conversation_history.append({
            "role": "user",
            "content": query
        })

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=6144,
                system=self.system_prompt,
                tools=self.tools,
                messages=self.conversation_history
            )

            # Tool use loop
            while response.stop_reason == "tool_use":
                tool_uses = [block for block in response.content if block.type == "tool_use"]

                self.conversation_history.append({
                    "role": "assistant",
                    "content": response.content
                })

                tool_results = []
                for tool_use in tool_uses:
                    print(f"[Tool] Executing: {tool_use.name}")
                    result = self._execute_tool(tool_use.name, tool_use.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use.id,
                        "content": result
                    })

                self.conversation_history.append({
                    "role": "user",
                    "content": tool_results
                })

                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=6144,
                    system=self.system_prompt,
                    tools=self.tools,
                    messages=self.conversation_history
                )

            # Extract final text
            final_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    final_text += block.text

            self.conversation_history.append({
                "role": "assistant",
                "content": final_text
            })

            return final_text

        except anthropic.RateLimitError as e:
            # Rate limit detected - wait and retry
            import time
            print("\n⚠️  Rate limit detected! Waiting 60 seconds...")
            print("    (Batch API doesn't support tool execution)\n")

            time.sleep(60)

            print("⏳ Retrying request...\n")

            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=6144,
                    system=self.system_prompt,
                    tools=self.tools,
                    messages=self.conversation_history
                )

                # Tool use loop
                while response.stop_reason == "tool_use":
                    tool_uses = [block for block in response.content if block.type == "tool_use"]

                    self.conversation_history.append({
                        "role": "assistant",
                        "content": response.content
                    })

                    tool_results = []
                    for tool_use in tool_uses:
                        print(f"[Tool] Executing: {tool_use.name}")
                        result = self._execute_tool(tool_use.name, tool_use.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use.id,
                            "content": result
                        })

                    self.conversation_history.append({
                        "role": "user",
                        "content": tool_results
                    })

                    response = self.client.messages.create(
                        model=self.model,
                        max_tokens=6144,
                        system=self.system_prompt,
                        tools=self.tools,
                        messages=self.conversation_history
                    )

                # Extract final text
                final_text = ""
                for block in response.content:
                    if hasattr(block, "text"):
                        final_text += block.text

                self.conversation_history.append({
                    "role": "assistant",
                    "content": final_text
                })

                return final_text

            except anthropic.RateLimitError:
                return "Error: Rate limit persists after retry. Please wait a few minutes and try again."

        except Exception as e:
            return f"Error: {str(e)}"

    def _analyze_via_batch(self, query: str) -> str:
        """Fallback to batch API when rate limited."""
        import time

        print("📤 Sending request via Batch API...")

        # Create batch request
        request = {
            "custom_id": f"query_{int(time.time())}",
            "params": {
                "model": self.model,
                "max_tokens": 8192,
                "system": self.system_prompt,
                "messages": self.conversation_history
            }
        }

        # Create batch
        batch = self.client.beta.messages.batches.create(requests=[request])
        batch_id = batch.id

        print(f"✅ Batch created: {batch_id}")
        print(f"⏳ Waiting for result (checking every 15 seconds)...\n")

        # Wait for completion
        start_time = time.time()
        while True:
            time.sleep(15)

            # Check status
            batch = self.client.beta.messages.batches.retrieve(batch_id)
            elapsed = int(time.time() - start_time)

            print(f"\r   [{elapsed}s] Status: {batch.processing_status}", end='', flush=True)

            if batch.processing_status == "ended":
                print("\n\n✅ Result ready!")
                break

            if elapsed > 600:  # 10 minutes timeout
                return "Error: Batch processing timeout (10 minutes)"

        # Get results
        results = list(self.client.beta.messages.batches.results(batch_id))

        if not results:
            return "Error: No results from batch"

        result = results[0]

        if hasattr(result, 'error') and result.error:
            return f"Error: {result.error}"

        if hasattr(result, 'result') and hasattr(result.result, 'message'):
            message = result.result.message
            content = message.content

            if not content or len(content) == 0:
                return "Error: Empty content in batch result"

            # Extract text from all content blocks
            final_text = ""
            for block in content:
                if hasattr(block, 'text'):
                    final_text += block.text
                elif hasattr(block, 'type') and block.type == 'text':
                    final_text += getattr(block, 'text', '')

            if final_text:
                # Update conversation history
                self.conversation_history.append({
                    "role": "assistant",
                    "content": final_text
                })

                return final_text

        # Debug: print result structure
        import json
        try:
            debug_info = str(result)[:500]
            return f"Error: Could not extract response from batch result. Debug: {debug_info}"
        except:
            return "Error: Could not extract response from batch result"


# CLI interface
if __name__ == "__main__":
    import sys

    print("=" * 50)
    print("Claude Forensic Analyzer (Tool Use)")
    print("=" * 50)

    try:
        analyzer = ClaudeAnalyzer()
        print("[OK] Connected to Claude API")
    except ValueError as e:
        print(f"[ERROR] {e}")
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

            print("\nClaude: Analyzing...\n")
            response = analyzer.analyze(query)

            print(response)
            print()

        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
