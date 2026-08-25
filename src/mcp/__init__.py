# src/mcp/__init__.py
"""
MCP Server for Forensic Analysis
================================

Model Context Protocol server for integration with Cursor/Claude.
"""

# Don't import server here to avoid circular import when running as __main__
__all__ = ["ForensicMCPServer", "ElasticsearchMCPClient", "ElasticsearchMCPClientSync"]
