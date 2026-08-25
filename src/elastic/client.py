# src/elastic/client.py
"""
Elasticsearch Client - client for working with Elasticsearch.

Features:
- Creating indices with proper mappings
- Bulk loading data from parsers
- Search and aggregations
- Case management
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
except ImportError:
    raise ImportError("elasticsearch package required. Install: pip install elasticsearch")


class ElasticClient:
    """
    Client for working with Elasticsearch.

    Index mappings are auto-generated from parser FIELDS definitions.

    Usage:
        client = ElasticClient("http://localhost:9200")
        client.index_records("forensic-prefetch", records)
        results = client.search("forensic-prefetch", "calc.exe")
    """

    @staticmethod
    def _build_index_mappings() -> Dict[str, Any]:
        """Build INDEX_MAPPINGS from PARSERS registry (single source of truth)."""
        from src.parsers import PARSERS

        mappings = {}
        for key, parser_cls in PARSERS.items():
            parser = parser_cls.__new__(parser_cls)
            mappings[parser.index_name] = parser.get_es_mapping()
        return mappings

    INDEX_MAPPINGS = None  # Populated lazily on first access

    @classmethod
    def get_index_mappings(cls) -> Dict[str, Any]:
        """Get index mappings, building from PARSERS if needed."""
        if cls.INDEX_MAPPINGS is None:
            cls.INDEX_MAPPINGS = cls._build_index_mappings()
        return cls.INDEX_MAPPINGS

    def __init__(self, host: str = "http://localhost:9200", api_key: str = None):
        """
        Args:
            host: Elasticsearch URL (e.g.: http://localhost:9200)
            api_key: API key for authentication (optional)
        """
        self.host = host
        self._connected = False

        if api_key:
            self.es = Elasticsearch(host, api_key=api_key)
        else:
            self.es = Elasticsearch(host)

        # Check connection (don't crash if offline)
        try:
            if self.es.ping():
                self._connected = True
                print(f"[Elastic] Connected to {host}")
            else:
                print(f"[Elastic] Cannot connect to Elasticsearch at {host}")
        except Exception as e:
            print(f"[Elastic] Elasticsearch offline: {e}")

    @property
    def is_connected(self) -> bool:
        """Check if Elasticsearch is currently reachable."""
        try:
            return self.es.ping()
        except:
            return False

    def create_index(self, index_name: str, force: bool = False) -> bool:
        """
        Creates an index with proper mapping.

        Args:
            index_name: Index name (e.g.: forensic-prefetch)
            force: Delete existing index

        Returns:
            True if index created
        """
        if self.es.indices.exists(index=index_name):
            if force:
                print(f"[Elastic] Deleting existing index: {index_name}")
                self.es.indices.delete(index=index_name)
            else:
                print(f"[Elastic] Index already exists: {index_name}")
                return True

        # Get mapping
        mapping = self.get_index_mappings().get(index_name, {})

        body = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": mapping
        }

        self.es.indices.create(index=index_name, body=body)
        print(f"[Elastic] Created index: {index_name}")
        return True

    def index_records(self, index_name: str, records: List[Dict[str, Any]]) -> int:
        """
        Loads records into Elasticsearch (bulk).

        Args:
            index_name: Index name
            records: List of records to load

        Returns:
            Number of loaded records
        """
        if not records:
            return 0

        # Create index if not exists
        self.create_index(index_name)

        # Prepare bulk actions
        actions = []
        for record in records:
            action = {
                "_index": index_name,
                "_source": record
            }
            actions.append(action)

        # Bulk load
        success, errors = bulk(self.es, actions, raise_on_error=False)

        if errors:
            print(f"[Elastic] Bulk errors: {len(errors)}")

        print(f"[Elastic] Indexed {success} records to {index_name}")
        return success

    def search(
        self,
        index_name: str,
        query: str = None,
        filters: Dict[str, Any] = None,
        time_range: Dict[str, str] = None,
        size: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search by index.

        Args:
            index_name: Index name or pattern (forensic-*)
            query: Text query
            filters: Filters {field: value}
            time_range: {"gte": "2024-01-01", "lte": "2024-12-31"}
            size: Maximum results

        Returns:
            List of found documents
        """
        must = []

        # Text search
        if query:
            must.append({
                "multi_match": {
                    "query": query,
                    "fields": ["*"],
                    "type": "best_fields"
                }
            })

        # Filters
        if filters:
            for field, value in filters.items():
                must.append({"term": {field: value}})

        # Time range
        if time_range:
            must.append({
                "range": {
                    "timestamp": time_range
                }
            })

        # Build query (without sorting by timestamp - may be text)
        body = {
            "query": {
                "bool": {
                    "must": must if must else [{"match_all": {}}]
                }
            },
            "size": size
        }

        result = self.es.search(index=index_name, body=body)

        # Extract documents
        hits = result.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    def get_timeline(
        self,
        case_id: str,
        start_time: str = None,
        end_time: str = None,
        size: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Gets timeline of all events for a case.

        Args:
            case_id: Case ID
            start_time: Start of period (ISO format)
            end_time: End of period (ISO format)
            size: Maximum events

        Returns:
            List of events sorted by time
        """
        must = [{"term": {"_meta.case_id": case_id}}]

        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time
            if end_time:
                time_range["lte"] = end_time
            must.append({"range": {"timestamp": time_range}})

        body = {
            "query": {"bool": {"must": must}},
            "size": size
        }

        result = self.es.search(index="forensic-*", body=body)
        hits = result.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    def get_stats(self, case_id: str = None) -> Dict[str, Any]:
        """
        Gets statistics for indices.

        Returns:
            Dictionary with statistics
        """
        stats = {}

        for index_name in self.get_index_mappings().keys():
            if not self.es.indices.exists(index=index_name):
                stats[index_name] = {"count": 0}
                continue

            # Count documents
            query = {"match_all": {}}
            if case_id:
                query = {"term": {"_meta.case_id": case_id}}

            result = self.es.count(index=index_name, body={"query": query})
            stats[index_name] = {"count": result.get("count", 0)}

        return stats

    def delete_case(self, case_id: str) -> int:
        """
        Deletes all data for a case.

        Returns:
            Number of deleted documents
        """
        body = {
            "query": {
                "term": {"_meta.case_id": case_id}
            }
        }

        result = self.es.delete_by_query(index="forensic-*", body=body)
        deleted = result.get("deleted", 0)

        print(f"[Elastic] Deleted {deleted} documents for case {case_id}")
        return deleted
