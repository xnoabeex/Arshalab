# etl_pipeline.py
"""
ETL Pipeline: Extract → Transform → Load

Full forensic image processing cycle:
1. Extract: TSK extracts files from disk image
2. Transform: Parsers convert to JSON
3. Load: Load into Elasticsearch (primary) + SQLite (automatic backup)

Features:
- Robust error handling: continues on failures
- Retry mechanism: 3 attempts for ES operations
- Automatic SQLite backup: always saves data even if ES fails
- Detailed statistics: tracks success/failure counts
"""

import os
import json
import glob
import time
from datetime import datetime
from typing import Dict, List, Tuple
import yaml


class ETLPipeline:
    """
    ETL Pipeline for forensic analysis with robust error handling.

    Storage modes:
    - Elasticsearch (primary) + SQLite (automatic backup)
    - SQLite only (if ES unavailable)

    Error handling:
    - Retries failed operations
    - Continues processing on failures
    - Always saves data to SQLite as backup
    """

    @staticmethod
    def _get_index_name(artifact_type: str) -> str:
        """Get ES index name from PARSERS registry."""
        from src.parsers import PARSERS
        if artifact_type in PARSERS:
            parser = PARSERS[artifact_type].__new__(PARSERS[artifact_type])
            return parser.index_name
        return f"forensic-{artifact_type}"

    def __init__(self, image_path: str, output_dir: str, artifacts: list,
                 es_url: str = None, es_username: str = None, es_password: str = None,
                 use_sqlite: bool = False, case_name: str = None, case_id: str = None):
        """
        Args:
            image_path: Path to disk image (E01, RAW, etc)
            output_dir: Directory for output files
            artifacts: List of artifacts to process
            es_url: Elasticsearch URL (optional, default http://localhost:9200)
            es_username: Username for ES (optional)
            es_password: Password for ES (optional)
            use_sqlite: Use SQLite instead of ES (for testing)
            case_name: Human-readable case name (e.g. "Magnet CTF 2022")
            case_id: Existing case_id to append artifacts (avoids duplicates)
        """
        self.image_path = image_path
        self.output_dir = output_dir
        self.artifacts = artifacts
        self.case_id = case_id or f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.case_name = case_name or self.case_id

        # Elasticsearch settings
        self.es_url = es_url or os.getenv("ES_URL", "http://localhost:9200")
        self.es_username = es_username or os.getenv("ES_USERNAME")
        self.es_password = es_password or os.getenv("ES_PASSWORD")
        self.use_sqlite = use_sqlite

        # Load configuration
        config_path = os.path.join(os.path.dirname(__file__), "config/artifacts.yaml")
        with open(config_path, encoding='utf-8') as f:
            self.config = yaml.safe_load(f)

        # Create case-specific directories to avoid mixing data from different images
        case_output_dir = os.path.join(output_dir, self.case_id)
        self.raw_dir = os.path.join(case_output_dir, "raw")
        self.parsed_dir = os.path.join(case_output_dir, "parsed")

        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.parsed_dir, exist_ok=True)

        # Initialize storage
        self.es_loader = None
        self.db_path = None

        # Statistics
        self.stats = {
            'artifacts_processed': 0,
            'artifacts_failed': 0,
            'files_extracted': 0,
            'records_parsed': 0,
            'records_to_es': 0,
            'records_to_sqlite': 0,
            'es_failures': 0
        }

        # Always initialize SQLite for backup
        self._init_sqlite()

        # Track successfully loaded artifacts
        self.loaded_artifacts = []

        # Try to initialize Elasticsearch if not explicitly disabled
        if not use_sqlite:
            self._init_elasticsearch()

    def _init_elasticsearch(self):
        """Initialize Elasticsearch connection."""
        try:
            from src.loaders import ElasticsearchLoader

            self.es_loader = ElasticsearchLoader(
                es_url=self.es_url,
                username=self.es_username,
                password=self.es_password
            )
            print(f"[OK] Connected to Elasticsearch: {self.es_url}")
            print(f"[INFO] SQLite backup enabled at: {self.db_path}")

        except Exception as e:
            print(f"[!] Elasticsearch not available: {e}")
            print(f"[!] Will use SQLite only")
            print(f"[INFO] Data will be saved to: {self.db_path}")
            self.use_sqlite = True
            self.es_loader = None

    def _init_sqlite(self):
        """Initialize SQLite database."""
        import sqlite3

        # Store database in case-specific directory
        case_output_dir = os.path.join(self.output_dir, self.case_id)
        os.makedirs(case_output_dir, exist_ok=True)
        self.db_path = os.path.join(case_output_dir, f"{self.case_id}.db")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Read SQL schema
        schema_path = os.path.join(os.path.dirname(__file__), "database_schema.sql")
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema = f.read()

        cursor.executescript(schema)

        # Add case record
        cursor.execute("""
            INSERT INTO cases (case_id, image_path, created_at, status)
            VALUES (?, ?, ?, ?)
        """, (self.case_id, self.image_path, datetime.now(), 'processing'))

        conn.commit()
        conn.close()

        print(f"[OK] SQLite database initialized: {self.db_path}")

    def run(self, status_callback=None):
        """
        Run full ETL process.

        Args:
            status_callback: function to update status (for GUI)
        """
        def log(msg):
            """Log to console and via callback."""
            # Sanitize for Windows console (cp1252)
            try:
                safe_msg = str(msg).encode('cp1252', errors='replace').decode('cp1252')
                print(safe_msg)
            except:
                print(str(msg).encode('ascii', errors='replace').decode('ascii'))
            if status_callback:
                status_callback(str(msg))

        storage_type = "SQLite" if self.use_sqlite else "Elasticsearch"

        log(f"ETL Pipeline Started")
        log(f"Case: {self.case_name}")
        log(f"Case ID: {self.case_id}")
        log(f"Image: {self.image_path}")
        log(f"Artifacts: {', '.join(self.artifacts)}")
        log(f"Storage: {storage_type}")

        # Save case metadata to ES at the start
        if self.es_loader:
            try:
                self.es_loader.save_case_metadata(
                    case_id=self.case_id,
                    case_name=self.case_name,
                    image_path=self.image_path,
                    status="processing"
                )
                log(f"[OK] Case metadata saved to ES")
            except Exception as e:
                log(f"[!] Failed to save case metadata to ES: {e}")

        for artifact_type in self.artifacts:
            try:
                log(f"\n--- Processing: {artifact_type} ---")

                # 1. Extract
                log(f"Step 1: Extracting {artifact_type}...")
                extracted_files = self._extract_artifact(artifact_type, log)

                if not extracted_files:
                    log(f"[!] No files extracted for {artifact_type}")
                    self.stats['artifacts_failed'] += 1
                    continue

                self.stats['files_extracted'] += len(extracted_files)
                log(f"[OK] Extracted {len(extracted_files)} files")

                # 2. Transform (Parse)
                log(f"Step 2: Parsing {artifact_type}...")
                parsed_json, record_count = self._parse_artifact(artifact_type, log)

                if not parsed_json:
                    log(f"[!] Parsing failed for {artifact_type}")
                    self.stats['artifacts_failed'] += 1
                    continue

                self.stats['records_parsed'] += record_count
                log(f"[OK] Parsed {record_count} records")

                # 3. Load
                log(f"Step 3: Loading data...")
                success = self._load_data(artifact_type, parsed_json, log)

                if success:
                    log(f"[OK] Successfully loaded {artifact_type}")
                    self.stats['artifacts_processed'] += 1
                    self.loaded_artifacts.append(artifact_type)

                    # Update case metadata in ES
                    if self.es_loader:
                        try:
                            self.es_loader.add_loaded_artifact(self.case_id, artifact_type)
                        except Exception:
                            pass  # Non-critical, continue
                else:
                    log(f"[!] Partial failure loading {artifact_type}")
                    self.stats['artifacts_failed'] += 1

            except Exception as e:
                log(f"[X] Error processing {artifact_type}: {e}")
                self.stats['artifacts_failed'] += 1
                import traceback
                log(f"[X] {traceback.format_exc()}")
                # Continue processing other artifacts

        # Finalize
        self._finalize()

        # Print statistics
        log(f"\n{'='*60}")
        log(f"ETL Pipeline Completed!")
        log(f"{'='*60}")
        log(f"Case ID: {self.case_id}")
        log(f"Artifacts processed: {self.stats['artifacts_processed']}/{len(self.artifacts)}")
        log(f"Artifacts failed: {self.stats['artifacts_failed']}")
        log(f"Files extracted: {self.stats['files_extracted']}")
        log(f"Records parsed: {self.stats['records_parsed']}")
        log(f"Records to Elasticsearch: {self.stats['records_to_es']}")
        log(f"Records to SQLite: {self.stats['records_to_sqlite']}")
        if self.stats['es_failures'] > 0:
            log(f"[!] Elasticsearch failures: {self.stats['es_failures']}")
        log(f"SQLite backup: {self.db_path}")
        log(f"{'='*60}")

    def _extract_artifact(self, artifact_type: str, log=None) -> list:
        """Extract artifacts via TSK."""
        if log is None:
            log = print

        if artifact_type not in self.config['artifacts']:
            return []

        artifact_config = self.config['artifacts'][artifact_type]
        paths = artifact_config['paths']

        output_artifact_dir = os.path.join(self.raw_dir, artifact_type)
        os.makedirs(output_artifact_dir, exist_ok=True)

        from src.collectors.tsk_collector import TSKCollector

        collector = TSKCollector(self.image_path)
        extracted = collector.extract_files(paths, output_artifact_dir, log_callback=log)

        return extracted

    def _parse_artifact(self, artifact_type: str, log=None) -> Tuple[str, int]:
        """
        Parse artifacts via unified parser architecture.

        Returns:
            Tuple[str, int]: (json_file_path, record_count) or (None, 0) on failure
        """
        if log is None:
            log = print

        try:
            from src.parsers import PARSERS

            if artifact_type not in PARSERS:
                log(f"  [!] No parser registered for: {artifact_type}")
                return None, 0

            artifact_config = self.config['artifacts'][artifact_type]
            # Use absolute paths
            input_dir = os.path.abspath(os.path.join(self.raw_dir, artifact_type))
            output_dir = os.path.abspath(os.path.join(self.parsed_dir, artifact_type))

            os.makedirs(output_dir, exist_ok=True)

            # Check for files
            input_files = glob.glob(os.path.join(input_dir, "*"))
            if not input_files:
                log(f"  [!] No input files found in {input_dir}")
                return None, 0

            log(f"  Found {len(input_files)} files to parse")

            # Create parser
            ParserClass = PARSERS[artifact_type]
            parser_config = artifact_config['parser_config']
            executable_path = parser_config.get('executable')
            batch_file = parser_config.get('batch_file')  # For Registry parser

            # Initialize parser with all relevant config parameters
            parser_kwargs = {
                'executable_path': executable_path,
                'output_dir': output_dir
            }

            # Add batch_file if present (for Registry parser)
            if batch_file:
                parser_kwargs['batch_file'] = batch_file

            parser = ParserClass(**parser_kwargs)

            # Parse and save to JSON
            json_output = parser.parse_to_json(input_dir, self.case_id)

            # Count records
            if json_output and os.path.exists(json_output):
                with open(json_output, 'r', encoding='utf-8') as f:
                    records = json.load(f)
                    return json_output, len(records)

            return None, 0

        except Exception as e:
            log(f"  [X] Parsing error: {e}")
            import traceback
            log(f"  {traceback.format_exc()}")
            return None, 0

    def _load_data(self, artifact_type: str, json_file: str, log=None) -> bool:
        """
        Load data into storage with automatic backup.

        Strategy:
        1. Always load to SQLite (backup)
        2. If ES available, try to load to ES (with retry)
        3. Continue even if ES fails (data is in SQLite)

        Returns:
            bool: True if fully successful, False if partial failure
        """
        if log is None:
            log = print

        success = True

        # Always load to SQLite first (backup)
        try:
            log(f"  -> Saving to SQLite backup...")
            sqlite_count = self._load_to_sqlite(artifact_type, json_file, log)
            self.stats['records_to_sqlite'] += sqlite_count
            log(f"  [OK] SQLite: {sqlite_count} records")
        except Exception as e:
            log(f"  [X] SQLite error: {e}")
            success = False

        # If Elasticsearch available, try to load there too
        if self.es_loader and not self.use_sqlite:
            try:
                log(f"  -> Loading to Elasticsearch...")
                es_count = self._load_to_elasticsearch_with_retry(artifact_type, json_file, log)
                self.stats['records_to_es'] += es_count
                log(f"  [OK] Elasticsearch: {es_count} records")
            except Exception as e:
                log(f"  [!] Elasticsearch error: {e}")
                log(f"  [INFO] Data is safe in SQLite backup")
                self.stats['es_failures'] += 1
                # Don't mark as failure - data is in SQLite

        return success

    def _load_to_elasticsearch_with_retry(self, artifact_type: str, json_file: str, log=None, max_retries: int = 3) -> int:
        """
        Load JSON into Elasticsearch with retry mechanism.

        Args:
            artifact_type: Type of artifact
            json_file: Path to JSON file
            log: Logging function
            max_retries: Maximum number of retry attempts

        Returns:
            int: Number of records successfully loaded

        Raises:
            Exception: If all retries fail
        """
        if log is None:
            log = print

        index_name = self._get_index_name(artifact_type)

        with open(json_file, 'r', encoding='utf-8') as f:
            records = json.load(f)

        total_records = len(records)
        last_error = None

        for attempt in range(1, max_retries + 1):
            try:
                loaded = self.es_loader.load_records(
                    index_name=index_name,
                    records=records,
                    case_id=self.case_id,
                    case_name=self.case_name
                )

                if loaded == total_records:
                    return loaded
                else:
                    log(f"  [!] Partial load: {loaded}/{total_records} (attempt {attempt}/{max_retries})")
                    if attempt < max_retries:
                        time.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    return loaded

            except Exception as e:
                last_error = e
                log(f"  [!] ES error (attempt {attempt}/{max_retries}): {e}")
                if attempt < max_retries:
                    wait_time = 2 ** attempt
                    log(f"  [INFO] Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    raise Exception(f"Failed after {max_retries} attempts: {last_error}")

        return 0

    def _load_to_sqlite(self, artifact_type: str, json_file: str, log=None) -> int:
        """
        Load JSON into SQLite using parser schema.

        Returns:
            int: Number of records successfully loaded
        """
        if log is None:
            log = print
        import sqlite3
        from src.parsers import PARSERS

        with open(json_file, 'r', encoding='utf-8') as f:
            records = json.load(f)

        if artifact_type not in PARSERS:
            log(f"  [!] Unknown artifact type for SQLite: {artifact_type}")
            return 0

        # Get schema from parser (single source of truth)
        parser_cls = PARSERS[artifact_type]
        parser = parser_cls.__new__(parser_cls)
        table_name = parser.database_table
        schema = parser.get_sqlite_schema()  # [(col_name, col_type), ...]
        field_types = parser.fields  # {field_name: type_string}

        # Build INSERT statement
        col_names = [col[0] for col in schema]
        placeholders = ', '.join(['?'] * len(col_names))
        col_list = ', '.join(col_names)
        sql = f"INSERT INTO {table_name} ({col_list}) VALUES ({placeholders})"

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        loaded_count = 0
        failed_count = 0

        for idx, record in enumerate(records):
            try:
                values = []
                for col_name, _ in schema:
                    if col_name == "case_id":
                        values.append(self.case_id)
                        continue

                    val = record.get(col_name)
                    field_type = field_types.get(col_name, "text")

                    # Type conversion: Python → SQLite
                    if field_type == "boolean":
                        if val is True:
                            values.append(1)
                        elif val is False:
                            values.append(0)
                        else:
                            values.append(None)
                    elif field_type in ("integer", "long"):
                        try:
                            values.append(int(val) if val is not None else 0)
                        except (ValueError, TypeError):
                            values.append(0)
                    elif isinstance(val, (list, dict)):
                        values.append(json.dumps(val, default=str))
                    else:
                        values.append(str(val) if val is not None else '')

                cursor.execute(sql, values)
                loaded_count += 1

            except Exception as e:
                failed_count += 1
                if failed_count <= 3:  # Log first 3 failures
                    log(f"  [!] Failed to load record {idx}: {e}")

        conn.commit()
        conn.close()

        if failed_count > 0:
            log(f"  [!] {failed_count} records failed to load to SQLite")

        return loaded_count

    def _finalize(self):
        """Finalize processing."""
        # Update SQLite
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE cases SET status = 'completed' WHERE case_id = ?
        """, (self.case_id,))
        conn.commit()
        conn.close()

        # Update ES case metadata with final status
        if self.es_loader:
            try:
                self.es_loader.save_case_metadata(
                    case_id=self.case_id,
                    loaded_artifacts=self.loaded_artifacts,
                    status="completed"
                )
            except Exception:
                pass  # Non-critical


if __name__ == "__main__":
    # Test run with SQLite (fallback)
    pipeline = ETLPipeline(
        image_path="images/test.E01",
        output_dir="output/test_pipeline",
        artifacts=["prefetch"],
        use_sqlite=True  # For testing without ES
    )

    pipeline.run()
