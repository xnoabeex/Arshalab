# src/elastic/__init__.py
"""
Elasticsearch Integration
=========================

Module for working with Elasticsearch:
- Load data from parsers
- Search across indices
- Index management
"""

from .client import ElasticClient

__all__ = ["ElasticClient"]
