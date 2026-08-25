# src/loaders/elasticsearch_loader.py
"""
Elasticsearch Loader - Load forensic data into Elasticsearch.

Features:
- Create indices with proper mappings
- Bulk data loading
- Support for all artifact types
"""

import os
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False


class ElasticsearchLoader:
    """
    Data loader for Elasticsearch.

    Index mappings are auto-generated from parser FIELDS definitions.

    Usage:
        loader = ElasticsearchLoader("http://localhost:9200")
        loader.load_records("forensic-prefetch", records, case_id="case_001")
    """

    @staticmethod
    def _build_index_mappings() -> Dict[str, Any]:
        """Build INDEX_MAPPINGS from PARSERS registry (single source of truth)."""
        from src.parsers import PARSERS

        mappings = {}
        for key, parser_cls in PARSERS.items():
            parser = parser_cls.__new__(parser_cls)
            mappings[parser.index_name] = {"mappings": parser.get_es_mapping()}
        return mappings

    INDEX_MAPPINGS = None  # Populated lazily on first access

    @classmethod
    def get_index_mappings(cls) -> Dict[str, Any]:
        """Get index mappings, building from PARSERS if needed."""
        if cls.INDEX_MAPPINGS is None:
            cls.INDEX_MAPPINGS = cls._build_index_mappings()
        return cls.INDEX_MAPPINGS

    def __init__(self, es_url: str = "http://localhost:9200",
                 username: str = None, password: str = None,
                 api_key: str = None, verify_certs: bool = True):
        """
        Initialize Elasticsearch connection.

        Args:
            es_url: Elasticsearch URL (e.g., http://localhost:9200)
            username: Username (optional)
            password: Password (optional)
            api_key: API key (optional)
            verify_certs: Verify SSL certificates
        """
        if not ES_AVAILABLE:
            raise ImportError("elasticsearch package not installed. Run: pip install elasticsearch")

        self.es_url = es_url

        # Configure authentication
        es_config = {
            "hosts": [es_url],
            "verify_certs": verify_certs,
        }

        if api_key:
            es_config["api_key"] = api_key
        elif username and password:
            es_config["basic_auth"] = (username, password)

        self.es = Elasticsearch(**es_config)

        # Check connection
        if not self.es.ping():
            raise ConnectionError(f"Cannot connect to Elasticsearch at {es_url}")

        print(f"[ElasticsearchLoader] Connected to {es_url}")

    def create_index(self, index_name: str, force: bool = False) -> bool:
        """
        Create index with proper mapping.

        Args:
            index_name: Index name (e.g., forensic-prefetch)
            force: Delete and recreate if exists

        Returns:
            True if successful
        """
        # Check if index exists
        if self.es.indices.exists(index=index_name):
            if force:
                print(f"[ElasticsearchLoader] Deleting existing index: {index_name}")
                self.es.indices.delete(index=index_name)
            else:
                print(f"[ElasticsearchLoader] Index already exists: {index_name}")
                return True

        # Index creation is left to Elasticsearch's dynamic mapping by default, because that is
        # what produced every published artefact and the retrieval layer depends on its behaviour.
        # Applying the parser-generated mapping instead changes results in two ways that surface as
        # missing evidence rather than as an error:
        #   * `timestamp` becomes a date, and parser output uses a space separator with seven
        #     fractional digits, which Elasticsearch cannot read. Under ignore_malformed the value
        #     is discarded silently, and the `timestamp.keyword` sub-field that the Mode 2 anchors
        #     filter and sort on does not exist at all, so all 19 BOUNDED_ES anchors return nothing
        #     and roughly a fifth of the evidence pool disappears;
        #   * fields such as `extension` become exact keywords, so an anchor querying "*.ps1" stops
        #     matching. Measured on the Magnet case, the explicit mapping returns 1 record where the
        #     published pool holds 4 for mft_ps1_files, 4 against 12 for mft_bat_files, and so on.
        # Set ARSHALAB_EXPLICIT_ES_MAPPING=1 to restore the previous behaviour deliberately.
        if os.environ.get("ARSHALAB_EXPLICIT_ES_MAPPING") == "1":
            mapping = self.get_index_mappings().get(index_name, {})
            self.es.indices.create(index=index_name, body=mapping)
            print(f"[ElasticsearchLoader] Created index with explicit mapping: {index_name}")
        else:
            self.es.indices.create(index=index_name)
            print(f"[ElasticsearchLoader] Created index (dynamic mapping): {index_name}")

        return True

    def load_records(self, index_name: str, records: List[Dict[str, Any]],
                     case_id: str = None, case_name: str = None,
                     batch_size: int = 1000) -> int:
        """
        Load records into Elasticsearch.

        Args:
            index_name: Index name
            records: List of records to load
            case_id: Case ID for filtering
            case_name: Human-readable case name
            batch_size: Batch size for bulk loading

        Returns:
            Number of loaded records
        """
        if not records:
            print(f"[ElasticsearchLoader] No records to load")
            return 0

        # Create index if not exists
        self.create_index(index_name)

        # Prepare documents for bulk
        def generate_actions():
            for record in records:
                doc = record.copy()

                # Add case_id at top level (for MCP/BaseAnalyzer queries)
                if case_id:
                    doc["case_id"] = case_id
                    if "_meta" in doc:
                        doc["_meta"]["case_id"] = case_id

                # Add case_name at top level
                if case_name:
                    doc["case_name"] = case_name

                yield {
                    "_index": index_name,
                    "_source": doc
                }

        # Load via bulk
        success, failed = bulk(
            self.es,
            generate_actions(),
            chunk_size=batch_size,
            raise_on_error=False
        )

        if failed:
            print(f"[ElasticsearchLoader] Failed to load {len(failed)} records")
            # Show first errors
            for error in failed[:3]:
                print(f"  Error: {error}")

        print(f"[ElasticsearchLoader] Loaded {success} records into {index_name}")
        return success

    def load_json_file(self, json_file: str, index_name: str,
                       case_id: str = None, case_name: str = None) -> int:
        """
        Load data from JSON file into Elasticsearch.

        Args:
            json_file: Path to JSON file
            index_name: Index name
            case_id: Case ID

        Returns:
            Number of loaded records
        """
        if not os.path.exists(json_file):
            print(f"[ElasticsearchLoader] File not found: {json_file}")
            return 0

        with open(json_file, 'r', encoding='utf-8') as f:
            records = json.load(f)

        return self.load_records(index_name, records, case_id, case_name)

    def search(self, index_name: str, query: Dict = None,
               case_id: str = None, size: int = 100) -> List[Dict]:
        """
        Search in index.

        Args:
            index_name: Index name
            query: Elasticsearch query
            case_id: Filter by case_id
            size: Number of results

        Returns:
            List of found documents
        """
        if query is None:
            query = {"match_all": {}}

        # Add case_id filter
        if case_id:
            query = {
                "bool": {
                    "must": [query],
                    "filter": [{"term": {"_meta.case_id": case_id}}]
                }
            }

        result = self.es.search(
            index=index_name,
            query=query,
            size=size
        )

        return [hit["_source"] for hit in result["hits"]["hits"]]

    def get_stats(self, index_name: str, case_id: str = None) -> Dict:
        """
        Get index statistics.

        Returns:
            Statistics (document count, size, etc.)
        """
        # Total count
        if case_id:
            count_query = {"term": {"_meta.case_id": case_id}}
        else:
            count_query = {"match_all": {}}

        count = self.es.count(index=index_name, query=count_query)

        return {
            "index": index_name,
            "count": count["count"],
            "case_id": case_id
        }

    # ===================== CASE METADATA METHODS =====================

    CASES_INDEX = "forensic-cases"

    def _ensure_cases_index(self):
        """Create forensic-cases index if not exists."""
        if not self.es.indices.exists(index=self.CASES_INDEX):
            mapping = {
                "mappings": {
                    "properties": {
                        "case_id": {"type": "keyword"},
                        "case_name": {"type": "text"},
                        "image_path": {"type": "keyword"},
                        "loaded_artifacts": {"type": "keyword"},
                        "created_at": {"type": "date"},
                        "updated_at": {"type": "date"},
                        "status": {"type": "keyword"},
                        "total_records": {"type": "long"}
                    }
                }
            }
            self.es.indices.create(index=self.CASES_INDEX, body=mapping)

    def save_case_metadata(self, case_id: str, case_name: str = None,
                           image_path: str = None, loaded_artifacts: List[str] = None,
                           status: str = "processing") -> bool:
        """
        Save or update case metadata in ES.

        Args:
            case_id: Unique case identifier
            case_name: Human-readable case name
            image_path: Path to disk image
            loaded_artifacts: List of loaded artifact types
            status: Case status (processing, completed, failed)

        Returns:
            True if successful
        """
        self._ensure_cases_index()

        # Check if case exists
        existing = self.get_case_metadata(case_id)

        if existing:
            # Update existing case
            doc = {}
            if case_name:
                doc["case_name"] = case_name
            if image_path:
                doc["image_path"] = image_path
            if loaded_artifacts:
                # Merge with existing artifacts
                current = existing.get("loaded_artifacts", [])
                merged = list(set(current + loaded_artifacts))
                doc["loaded_artifacts"] = merged
            if status:
                doc["status"] = status
            doc["updated_at"] = datetime.utcnow().isoformat()

            self.es.update(
                index=self.CASES_INDEX,
                id=case_id,
                doc=doc
            )
        else:
            # Create new case
            doc = {
                "case_id": case_id,
                "case_name": case_name or case_id,
                "image_path": image_path,
                "loaded_artifacts": loaded_artifacts or [],
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
                "status": status,
                "total_records": 0
            }
            self.es.index(index=self.CASES_INDEX, id=case_id, document=doc)

        return True

    def get_case_metadata(self, case_id: str) -> Optional[Dict]:
        """
        Get case metadata from ES.

        Args:
            case_id: Case identifier

        Returns:
            Case metadata dict or None if not found
        """
        self._ensure_cases_index()

        try:
            result = self.es.get(index=self.CASES_INDEX, id=case_id)
            return result["_source"]
        except Exception:
            return None

    def add_loaded_artifact(self, case_id: str, artifact_type: str) -> bool:
        """
        Add artifact to case's loaded_artifacts list.

        Args:
            case_id: Case identifier
            artifact_type: Artifact type to add

        Returns:
            True if successful
        """
        existing = self.get_case_metadata(case_id)
        if not existing:
            return False

        current = existing.get("loaded_artifacts", [])
        if artifact_type not in current:
            current.append(artifact_type)
            self.es.update(
                index=self.CASES_INDEX,
                id=case_id,
                doc={
                    "loaded_artifacts": current,
                    "updated_at": datetime.utcnow().isoformat()
                }
            )
        return True

    def is_artifact_loaded(self, case_id: str, artifact_type: str) -> bool:
        """
        Check if artifact is loaded for a case.

        Args:
            case_id: Case identifier
            artifact_type: Artifact type to check

        Returns:
            True if artifact is loaded
        """
        meta = self.get_case_metadata(case_id)
        if not meta:
            return False
        return artifact_type in meta.get("loaded_artifacts", [])

    def delete_case(self, case_id: str, indices: List[str] = None) -> Dict:
        """
        Delete all case data.

        Args:
            case_id: Case ID to delete
            indices: List of indices (default: all forensic-*)

        Returns:
            Deletion statistics
        """
        if indices is None:
            indices = list(self.get_index_mappings().keys())

        deleted = {}
        for index in indices:
            try:
                result = self.es.delete_by_query(
                    index=index,
                    query={"term": {"_meta.case_id": case_id}}
                )
                deleted[index] = result.get("deleted", 0)
            except Exception as e:
                deleted[index] = f"Error: {e}"

        return deleted


# Convenience function for quick loading
def load_to_elasticsearch(json_file: str, es_url: str = "http://localhost:9200",
                          index_name: str = None, case_id: str = None) -> int:
    """
    Quick load JSON file into Elasticsearch.

    Args:
        json_file: Path to JSON file
        es_url: Elasticsearch URL
        index_name: Index name (auto-detect from data if not specified)
        case_id: Case ID

    Returns:
        Number of loaded records
    """
    loader = ElasticsearchLoader(es_url)

    # Auto-detect index
    if not index_name:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if data and isinstance(data, list):
                artifact_type = data[0].get("artifact_type", "unknown")
                index_name = f"forensic-{artifact_type}"

    return loader.load_json_file(json_file, index_name, case_id)
