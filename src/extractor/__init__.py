# src/extractor/__init__.py
"""
TSK Collector - extract artifacts from disk images via The Sleuth Kit.

Main class TSKCollector is used in etl_pipeline.py
"""

from ..collectors.tsk_collector import TSKCollector

# Alias for backward compatibility
TSKExtractor = TSKCollector

__all__ = ["TSKCollector", "TSKExtractor"]
