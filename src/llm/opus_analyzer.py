# src/llm/opus_analyzer.py
"""
Claude Opus Analyzer - wrapper for Claude Opus 4.1 model.
"""

from .claude_analyzer import ClaudeAnalyzer


class OpusAnalyzer(ClaudeAnalyzer):
    """
    Forensic analyzer using Claude Opus 4.1.

    Same as ClaudeAnalyzer but uses Opus model.
    More expensive but higher quality analysis.
    """

    def __init__(self, es_url: str = "http://localhost:9200",
                 incident_context: str = None, session_id: str = None, case_id: str = None):
        super().__init__(
            es_url=es_url,
            incident_context=incident_context,
            session_id=session_id,
            model="claude-opus-4-1-20250805",
            case_id=case_id
        )
