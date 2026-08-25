# src/loaders/__init__.py
"""
Loaders module - load data into storage backends.

Supported backends:
- Elasticsearch (primary)
- SQLite (local fallback)
"""

from .elasticsearch_loader import ElasticsearchLoader, load_to_elasticsearch
from .sqlite_loader import SQLiteLoader

__all__ = [
    "ElasticsearchLoader",
    "load_to_elasticsearch",
    "SQLiteLoader",
]
