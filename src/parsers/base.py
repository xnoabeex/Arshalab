# src/parsers/base.py
"""
BaseParser - Abstract base class for all forensic artifact parsers.

To create a new parser:
1. Inherit from BaseParser
2. Implement properties: name, description, index_name, artifact_type, database_table, fields
3. Implement methods: _parse_impl, _normalize_record
4. Add to PARSERS dict in __init__.py

The `fields` property is the single source of truth for the artifact schema.
ES mappings, SQLite tables, and UI are all generated from it automatically.
"""

import os
import json
import csv
import sys
import subprocess
import ctypes
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime


def get_short_path(long_path: str) -> str:
    """
    Convert long path to Windows 8.3 short path format.
    This helps avoid encoding issues with non-ASCII characters in paths.
    """
    if os.name != 'nt':
        return long_path

    try:
        # Use Windows API to get short path
        buf = ctypes.create_unicode_buffer(512)
        get_short_path_name = ctypes.windll.kernel32.GetShortPathNameW
        result = get_short_path_name(long_path, buf, 512)
        if result:
            return buf.value
    except Exception:
        pass

    return long_path


class BaseParser(ABC):
    """
    Abstract base class for all forensic artifact parsers.

    Attributes:
        executable_path: Path to parser executable (PECmd, EvtxECmd, etc.)
        output_dir: Directory for temporary output files
    """

    def __init__(self, executable_path: str = None, output_dir: str = "output"):
        """
        Args:
            executable_path: Path to parser exe file (optional for some parsers)
            output_dir: Directory for output files
        """
        self.executable_path = os.path.abspath(executable_path) if executable_path else None
        self.output_dir = os.path.abspath(output_dir)

        if self.executable_path and not os.path.exists(self.executable_path):
            raise FileNotFoundError(f"{self.name} executable not found: {self.executable_path}")

    @property
    @abstractmethod
    def name(self) -> str:
        """Parser name (e.g., 'PrefetchParser')"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of what the parser handles (e.g., 'Windows Prefetch files')"""
        pass

    @property
    @abstractmethod
    def index_name(self) -> str:
        """Elasticsearch index name (e.g., 'forensic-prefetch')"""
        pass

    @property
    @abstractmethod
    def artifact_type(self) -> str:
        """Artifact type key (e.g., 'prefetch'). Must match PARSERS dict key."""
        pass

    @property
    @abstractmethod
    def database_table(self) -> str:
        """SQLite table name (e.g., 'prefetch')."""
        pass

    @property
    @abstractmethod
    def fields(self) -> Dict[str, str]:
        """
        Field schema for this artifact type.
        Maps field_name -> field_type. This is the single source of truth.

        Supported types:
            keyword     - exact match, filterable (ES keyword, SQLite TEXT)
            text        - full-text searchable (ES text, SQLite TEXT)
            text_keyword - full-text + exact match (ES text with keyword sub-field)
            integer     - 32-bit integer
            long        - 64-bit integer
            boolean     - true/false (SQLite stores as INTEGER 0/1)
            date        - date/time value (SQLite stores as TEXT)
            date_lenient - date with ignore_malformed for inconsistent formats

        Note: 'artifact_type' and 'timestamp' are always included automatically.
              '_meta' (parser, case_id, parsed_at, source_path) is added automatically.
        """
        pass

    # ============== Schema generation methods ==============

    # ES type mapping from field type strings
    _ES_TYPE_MAP = {
        "keyword": {"type": "keyword"},
        "text": {"type": "text"},
        "text_keyword": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        "integer": {"type": "integer"},
        "long": {"type": "long"},
        "boolean": {"type": "boolean"},
        "date": {"type": "date", "ignore_malformed": True},
        "date_lenient": {"type": "date", "ignore_malformed": True},
    }

    # SQLite type mapping
    _SQLITE_TYPE_MAP = {
        "keyword": "TEXT",
        "text": "TEXT",
        "text_keyword": "TEXT",
        "integer": "INTEGER",
        "long": "INTEGER",
        "boolean": "INTEGER",
        "date": "TEXT",
        "date_lenient": "TEXT",
    }

    def get_es_mapping(self) -> Dict[str, Any]:
        """Generate Elasticsearch mapping from fields definition."""
        properties = {
            "artifact_type": {"type": "keyword"},
            # `timestamp` must keep a .keyword sub-field. Parsers emit times in the form
            # "2022-02-04 05:53:33.5831587" - a space separator with seven fractional digits -
            # which Elasticsearch cannot read as a date. Mapped as `date` with ignore_malformed the
            # value is dropped in silence: the document stays searchable by text but disappears from
            # every range query, and `timestamp.keyword` does not exist at all. The Mode 2 anchor
            # queries filter and sort on `timestamp.keyword`, so under a date mapping all 19
            # BOUNDED_ES anchors return nothing and roughly a fifth of the evidence pool vanishes
            # without an error. Lexicographic range over this fixed-width format is order-preserving,
            # so text_keyword gives the intended behaviour.
            "timestamp": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        }

        for field_name, field_type in self.fields.items():
            if field_name in ("artifact_type", "timestamp"):
                continue
            properties[field_name] = self._ES_TYPE_MAP.get(
                field_type, {"type": field_type}
            )

        properties["_meta"] = {
            "properties": {
                "parser": {"type": "keyword"},
                "case_id": {"type": "keyword"},
                "parsed_at": {"type": "date"},
                "source_path": {"type": "text"}
            }
        }

        return {"properties": properties}

    def get_sqlite_schema(self) -> List[tuple]:
        """
        Generate SQLite column definitions from fields.

        Returns:
            List of (column_name, column_type) tuples.
            Always includes 'case_id TEXT NOT NULL' as first column.
        """
        columns = [("case_id", "TEXT NOT NULL")]

        for field_name, field_type in self.fields.items():
            if field_name == "artifact_type":
                continue  # Not stored as separate SQLite column
            sqlite_type = self._SQLITE_TYPE_MAP.get(field_type, "TEXT")
            default = ""
            if field_type in ("integer", "long"):
                default = " DEFAULT 0"
            elif field_type == "boolean":
                default = " DEFAULT 0"
            columns.append((field_name, f"{sqlite_type}{default}"))

        return columns

    @abstractmethod
    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """
        Internal parsing implementation.

        Args:
            input_path: Path to file or directory with artifacts

        Returns:
            List of dictionaries with parsed data
        """
        pass

    @abstractmethod
    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize record to standard format for Elasticsearch.

        Args:
            record: Raw record from parser

        Returns:
            Normalized record
        """
        pass

    def _safe_print(self, msg: str):
        """Print message with encoding safety for Windows console."""
        try:
            safe_msg = str(msg).encode('cp1252', errors='replace').decode('cp1252')
            print(safe_msg)
        except:
            print(str(msg).encode('ascii', errors='replace').decode('ascii'))

    def parse(self, input_path: str, case_id: str = None) -> List[Dict[str, Any]]:
        """
        Main parsing method. Calls _parse_impl and adds metadata.

        Args:
            input_path: Path to file or directory
            case_id: Case ID for data grouping

        Returns:
            List of normalized records with metadata
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input path not found: {input_path}")

        self._safe_print(f"[{self.name}] Parsing: {input_path}")

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

        # Parse artifacts
        raw_records = self._parse_impl(input_path)

        if not raw_records:
            self._safe_print(f"[{self.name}] No records found")
            return []

        # Normalize and add metadata
        normalized = []
        timestamp = datetime.utcnow().isoformat()

        for record in raw_records:
            normalized_record = self._normalize_record(record)

            # Add common metadata
            normalized_record["_meta"] = {
                "parser": self.name,
                "case_id": case_id or "default",
                "parsed_at": timestamp,
                "source_path": input_path
            }

            normalized.append(normalized_record)

        self._safe_print(f"[{self.name}] Parsed {len(normalized)} records")
        return normalized

    def parse_to_json(self, input_path: str, case_id: str = None) -> str:
        """
        Parse and save to JSON file.

        Returns:
            Path to created JSON file
        """
        records = self.parse(input_path, case_id)

        if not records:
            return None

        # Save JSON
        output_file = os.path.join(
            self.output_dir,
            f"{self.index_name.replace('forensic-', '')}_{case_id or 'default'}.json"
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(records, f, indent=2, ensure_ascii=False, default=str)

        self._safe_print(f"[{self.name}] Saved to: {output_file}")
        return output_file

    # ============== Utility methods for subclasses ==============

    def _run_command(self, cmd: str, timeout: int = 300) -> subprocess.CompletedProcess:
        """Run external command with support for non-ASCII paths."""
        import re

        # Find all quoted paths in command and convert them to short paths
        def convert_path(match):
            path = match.group(1)
            if os.path.exists(path):
                return f'"{get_short_path(path)}"'
            return match.group(0)

        # Convert quoted paths
        cmd_converted = re.sub(r'"([^"]+)"', convert_path, cmd)

        # Safely print command (handle unicode in paths)
        self._safe_print(f"[{self.name}] Running: {cmd_converted[:100]}...")

        result = subprocess.run(
            cmd_converted,
            capture_output=True,
            text=True,
            shell=True,
            timeout=timeout,
            encoding='utf-8',
            errors='ignore'
        )

        if result.returncode != 0 and result.stderr:
            self._safe_print(f"[{self.name}] Warning: {result.stderr[:300]}")

        return result

    # Eric Zimmerman tools emit very long fields - PECmd's FilesLoaded column routinely exceeds
    # Python's default 131072-byte csv field limit. When it does, csv raises mid-iteration, the
    # except below swallows it, and a PARTIAL record list is returned with no warning. That is how
    # 216 of 549 Hunter prefetch records (57 of 130 executables) lost run_count, prefetch_hash,
    # source_file and files_loaded: the read stopped at PYTHON-3.5.1.EXE and everything after it
    # was indexed with empty metadata. Raise the limit once, at import time.
    _CSV_LIMIT_SET = False

    @classmethod
    def _raise_csv_field_limit(cls):
        if cls._CSV_LIMIT_SET:
            return
        limit = sys.maxsize
        while True:
            try:
                csv.field_size_limit(limit)
                break
            except OverflowError:      # 64-bit maxsize overflows the C long on Windows
                limit //= 10
        cls._CSV_LIMIT_SET = True

    def _read_csv(self, csv_path: str) -> List[Dict[str, Any]]:
        """Read CSV file into list of dictionaries."""
        self._raise_csv_field_limit()
        records = []

        try:
            # Use utf-8-sig to handle BOM (Byte Order Mark) that Eric Zimmerman tools add
            with open(csv_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(dict(row))
        except Exception as e:
            # A truncated read is far more damaging than a failed one, because the caller cannot
            # tell the difference. Say how much was lost instead of returning quietly.
            self._safe_print(
                f"[{self.name}] TRUNCATED CSV READ {csv_path}: {e} "
                f"- only {len(records)} rows were parsed, the rest of the file was NOT read")

        return records

    def _find_csv_files(self, directory: str) -> List[str]:
        """Find all CSV files in directory (including subdirectories).

        Note: Uses os.walk instead of glob because glob has issues with
        special characters like $ in filenames (e.g., $MFT).
        """
        csv_files = []

        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for f in files:
                    if f.endswith('.csv'):
                        csv_files.append(os.path.join(root, f))

        return csv_files

    def _find_files_in_dir(self, directory: str, extensions: List[str] = None,
                           pattern: str = None) -> List[str]:
        """Find files in directory matching extensions or pattern.

        Uses os.listdir instead of glob to handle special characters like $.

        Args:
            directory: Directory to search in
            extensions: List of extensions to match (e.g., ['.hve', '.dat'])
            pattern: Substring that must be in filename (case-insensitive)

        Returns:
            List of matching file paths
        """
        files = []

        if not os.path.exists(directory) or not os.path.isdir(directory):
            return files

        for f in os.listdir(directory):
            filepath = os.path.join(directory, f)

            if not os.path.isfile(filepath):
                continue

            # Match by extension
            if extensions:
                if any(f.lower().endswith(ext.lower()) for ext in extensions):
                    files.append(filepath)
                    continue

            # Match by pattern in filename
            if pattern:
                if pattern.lower() in f.lower():
                    files.append(filepath)
                    continue

            # If no filters, return all files
            if not extensions and not pattern:
                files.append(filepath)

        return files

    def _safe_int(self, value: Any, default: int = 0) -> int:
        """Safe conversion to int."""
        try:
            return int(value) if value else default
        except (ValueError, TypeError):
            return default

    def _safe_str(self, value: Any, max_len: int = None) -> str:
        """Safe conversion to string with optional length limit."""
        s = str(value) if value else ""
        if max_len and len(s) > max_len:
            s = s[:max_len]
        return s
