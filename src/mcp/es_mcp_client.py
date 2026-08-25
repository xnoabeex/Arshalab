# src/mcp/es_mcp_client.py
"""
Elasticsearch MCP Client - Client for interacting with Elasticsearch via MCP protocol.

Uses the official Elasticsearch MCP Server by Elastic.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


class ElasticsearchMCPClient:
    """
    Client for working with Elasticsearch via MCP protocol.

    Usage:
        async with ElasticsearchMCPClient() as client:
            indices = await client.list_indices()
            results = await client.search("forensic-prefetch", {"match_all": {}})
    """

    def __init__(self, mcp_url: str = "http://localhost:8090/mcp"):
        """
        Initialize the client.

        Args:
            mcp_url: MCP server URL (default localhost:8090)
        """
        self.mcp_url = mcp_url
        self._session: Optional[ClientSession] = None
        self._streams = None

    async def __aenter__(self):
        """Async context manager - enter."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager - exit."""
        await self.disconnect()

    async def connect(self):
        """Connect to MCP server."""
        self._streams = streamablehttp_client(self.mcp_url)
        read_stream, write_stream, _ = await self._streams.__aenter__()
        self._session = ClientSession(read_stream, write_stream)
        await self._session.__aenter__()
        await self._session.initialize()
        print(f"[MCP] Connected to {self.mcp_url}")

    async def disconnect(self):
        """Disconnect from MCP server."""
        if self._session:
            await self._session.__aexit__(None, None, None)
            self._session = None
        if self._streams:
            await self._streams.__aexit__(None, None, None)
            self._streams = None
        print("[MCP] Disconnected")

    async def list_tools(self) -> List[Dict]:
        """Get list of available MCP server tools."""
        if not self._session:
            raise RuntimeError("Not connected to MCP server")

        result = await self._session.list_tools()
        return [{"name": t.name, "description": t.description} for t in result.tools]

    async def call_tool(self, name: str, arguments: Dict[str, Any] = None) -> Any:
        """
        Call an MCP tool.

        Args:
            name: Tool name (list_indices, get_mappings, search, esql, get_shards)
            arguments: Tool arguments

        Returns:
            Tool execution result
        """
        if not self._session:
            raise RuntimeError("Not connected to MCP server")

        result = await self._session.call_tool(name, arguments or {})

        # Extract text from result
        if result.content:
            for content in result.content:
                if hasattr(content, 'text'):
                    try:
                        return json.loads(content.text)
                    except json.JSONDecodeError:
                        return content.text
        return result

    # ========== High-level methods ==========

    async def list_indices(self, pattern: str = "*") -> List[str]:
        """
        Get list of all Elasticsearch indices.

        Args:
            pattern: Index pattern (default: "*" for all)

        Returns:
            List of index names
        """
        result = await self.call_tool("list_indices", {"index_pattern": pattern})
        if isinstance(result, dict) and "indices" in result:
            return result["indices"]
        if isinstance(result, list):
            return result
        return [result] if result else []

    async def get_mappings(self, index: str) -> Dict:
        """
        Get index mapping.

        Args:
            index: Index name

        Returns:
            Index field mapping
        """
        return await self.call_tool("get_mappings", {"index": index})

    async def search(self, index: str, query: Dict, size: int = 50) -> List[Dict]:
        """
        Execute search in index.

        Args:
            index: Index name
            query: Elasticsearch Query DSL
            size: Number of results

        Returns:
            List of found documents
        """
        body = {
            "query": query,
            "size": size
        }
        result = await self.call_tool("search", {
            "index": index,
            "query_body": body  # Pass as dict, not JSON string
        })

        # Extract documents from result
        if isinstance(result, dict):
            if "hits" in result and "hits" in result["hits"]:
                return [hit.get("_source", hit) for hit in result["hits"]["hits"]]
        if isinstance(result, list):
            return result
        return [result] if result else []

    async def esql(self, query: str) -> Any:
        """
        Execute ES|QL query.

        Args:
            query: ES|QL query

        Returns:
            Query result
        """
        return await self.call_tool("esql", {"query": query})

    async def get_shards(self, index: str = None) -> Dict:
        """
        Get shard information.

        Args:
            index: Index name (optional)

        Returns:
            Shard information
        """
        args = {"index": index} if index else {}
        return await self.call_tool("get_shards", args)

    # ========== Forensic-specific methods ==========

    async def search_prefetch(self, executable: str = None, limit: int = 50) -> List[Dict]:
        """
        Search prefetch data.

        Args:
            executable: Executable file name (optional)
            limit: Maximum results

        Returns:
            Prefetch records
        """
        if executable:
            query = {
                "bool": {
                    "should": [
                        {"match": {"executable_name": executable}},
                        {"wildcard": {"executable_name": f"*{executable}*"}}
                    ]
                }
            }
        else:
            query = {"match_all": {}}

        return await self.search("forensic-prefetch", query, limit)

    async def search_events(self, event_ids: List[int] = None,
                           provider: str = None,
                           keyword: str = None,
                           limit: int = 100) -> List[Dict]:
        """
        Search Windows Event Log.

        Args:
            event_ids: List of Event IDs to filter
            provider: Provider name
            keyword: Search keyword
            limit: Maximum results

        Returns:
            Event Log records
        """
        must = []

        if event_ids:
            must.append({"terms": {"event_id": event_ids}})
        if provider:
            must.append({"match": {"provider": provider}})
        if keyword:
            must.append({"multi_match": {"query": keyword, "fields": ["*"]}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}
        return await self.search("forensic-eventlog", query, limit)

    async def search_browser(self, url: str = None, domain: str = None, limit: int = 100) -> List[Dict]:
        """
        Search browser history.

        Args:
            url: URL to search
            domain: Domain
            limit: Maximum results

        Returns:
            Browser history records
        """
        must = []

        if url:
            must.append({"match": {"url": url}})
        if domain:
            must.append({"term": {"domain": domain}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}
        return await self.search("forensic-browser", query, limit)

    async def search_registry(self, key_path: str = None,
                             value_name: str = None,
                             category: str = None,
                             limit: int = 100) -> List[Dict]:
        """
        Search registry data.

        Args:
            key_path: Registry key path
            value_name: Value name
            category: Category (UserAssist, RecentDocs, etc.)
            limit: Maximum results

        Returns:
            Registry records
        """
        must = []

        if key_path:
            must.append({"match": {"key_path": key_path}})
        if value_name:
            must.append({"match": {"value_name": value_name}})
        if category:
            must.append({"term": {"category": category}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}
        return await self.search("forensic-registry", query, limit)

    async def get_timeline(self, hours_back: int = 24, limit: int = 100) -> List[Dict]:
        """
        Get combined timeline across all artifacts.

        Args:
            hours_back: How many hours back
            limit: Maximum events

        Returns:
            Combined events with timestamps
        """
        # Simplified version - can be extended for all indices
        # ES|QL would be ideal for cross-index queries

        indices = ["forensic-prefetch", "forensic-browser", "forensic-lnk"]
        all_events = []

        for index in indices:
            try:
                events = await self.search(index, {"match_all": {}}, limit // len(indices))
                for event in events:
                    event["_index"] = index
                all_events.extend(events)
            except Exception as e:
                print(f"[MCP] Error querying {index}: {e}")

        # Sort by timestamp
        all_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return all_events[:limit]


# ========== Synchronous wrapper ==========

class ElasticsearchMCPClientSync:
    """
    Synchronous wrapper for ElasticsearchMCPClient.

    For use in synchronous code.
    """

    def __init__(self, mcp_url: str = "http://localhost:8090/mcp"):
        self._async_client = ElasticsearchMCPClient(mcp_url)
        self._loop = None

    def _get_loop(self):
        """Get or create event loop."""
        try:
            return asyncio.get_running_loop()
        except RuntimeError:
            if self._loop is None or self._loop.is_closed():
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
            return self._loop

    def _run(self, coro):
        """Execute coroutine synchronously."""
        loop = self._get_loop()
        return loop.run_until_complete(coro)

    def connect(self):
        """Connect to MCP server."""
        return self._run(self._async_client.connect())

    def disconnect(self):
        """Disconnect from MCP server."""
        return self._run(self._async_client.disconnect())

    def list_indices(self) -> List[str]:
        return self._run(self._async_client.list_indices())

    def get_mappings(self, index: str) -> Dict:
        return self._run(self._async_client.get_mappings(index))

    def search(self, index: str, query: Dict, size: int = 50) -> List[Dict]:
        return self._run(self._async_client.search(index, query, size))

    def search_prefetch(self, executable: str = None, limit: int = 50) -> List[Dict]:
        return self._run(self._async_client.search_prefetch(executable, limit))

    def search_events(self, event_ids: List[int] = None, provider: str = None,
                     keyword: str = None, limit: int = 100) -> List[Dict]:
        return self._run(self._async_client.search_events(event_ids, provider, keyword, limit))

    def search_browser(self, url: str = None, domain: str = None, limit: int = 100) -> List[Dict]:
        return self._run(self._async_client.search_browser(url, domain, limit))

    def search_registry(self, key_path: str = None, value_name: str = None,
                       category: str = None, limit: int = 100) -> List[Dict]:
        return self._run(self._async_client.search_registry(key_path, value_name, category, limit))

    def get_timeline(self, hours_back: int = 24, limit: int = 100) -> List[Dict]:
        return self._run(self._async_client.get_timeline(hours_back, limit))


# ========== Testing ==========

async def test_mcp_client():
    """Test MCP client."""
    print("=" * 50)
    print("Testing Elasticsearch MCP Client")
    print("=" * 50)

    async with ElasticsearchMCPClient() as client:
        # 1. List tools
        print("\n1. Available tools:")
        tools = await client.list_tools()
        for tool in tools:
            print(f"   - {tool['name']}: {tool['description'][:60]}...")

        # 2. List indices
        print("\n2. Elasticsearch indices:")
        indices = await client.list_indices("forensic-*")
        print(f"   Found indices: {indices}")
        if isinstance(indices, list):
            for idx in indices:
                print(f"   - {idx}")
        elif isinstance(indices, str):
            print(f"   - {indices}")

        # 3. Search prefetch
        print("\n3. Latest prefetch records:")
        prefetch = await client.search_prefetch(limit=5)
        print(f"   Raw result type: {type(prefetch)}, len: {len(prefetch) if isinstance(prefetch, list) else 'N/A'}")
        if prefetch and len(prefetch) > 0:
            print(f"   First item type: {type(prefetch[0])}")
            print(f"   First item: {str(prefetch[0])[:200]}...")
        for p in prefetch[:3]:
            if isinstance(p, dict):
                print(f"   - {p.get('executable_name', 'N/A')} @ {p.get('timestamp', 'N/A')}")
            else:
                print(f"   - {str(p)[:100]}...")

        # 4. Search browser
        print("\n4. Latest browser records:")
        browser = await client.search_browser(limit=5)
        for b in browser[:3]:
            title = str(b.get('title', 'N/A'))[:40]
            print(f"   - {b.get('domain', 'N/A')}: {title}...")

        print("\n" + "=" * 50)
        print("Test completed successfully!")


if __name__ == "__main__":
    asyncio.run(test_mcp_client())
