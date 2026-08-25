# src/parsers/parsers.py
"""
Unified Forensic Artifact Parsers
=================================

All parsers in one file with unified architecture.
Each parser inherits BaseParser and implements a common interface.

Parsers:
- Prefetch_PECmd_Parser: Windows Prefetch via PECmd
- EventLog_EvtxECmd_Parser: Windows Event Logs via EvtxECmd
- Registry_RECmd_Parser: Windows Registry via RECmd
- Browser_SQLite_Parser: Browser History (Chrome, Edge, Firefox)
- LNK_LECmd_Parser: Windows Shortcuts via LECmd

To add a new parser:
1. Create a class inheriting from BaseParser
2. Implement: name, description, index_name, artifact_type, database_table, fields,
   _parse_impl, _normalize_record
3. Add to PARSERS dict in __init__.py
"""

import os
import sqlite3
import shutil
import subprocess
from typing import List, Dict, Any
from datetime import datetime
from .base import BaseParser


# =============================================================================
# PREFETCH PARSER (PECmd)
# =============================================================================

class Prefetch_PECmd_Parser(BaseParser):
    """
    Windows Prefetch files (.pf) parser via PECmd.

    Prefetch files contain program execution information:
    - Executable file name
    - Run time (up to 8 last runs)
    - Files loaded at startup
    - Volume information

    Usage:
        parser = Prefetch_PECmd_Parser("tools/PECmd/PECmd.exe")
        records = parser.parse("C:/Windows/Prefetch")
    """

    @property
    def name(self) -> str:
        return "Prefetch_PECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows Prefetch files - program execution history"

    @property
    def index_name(self) -> str:
        return "forensic-prefetch"

    @property
    def artifact_type(self) -> str:
        return "prefetch"

    @property
    def database_table(self) -> str:
        return "prefetch"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "executable_name": "keyword",
            "executable_path": "text",
            "prefetch_hash": "keyword",
            "source_file": "text",
            "run_count": "integer",
            "files_loaded": "text",
            "volume_info": "text",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run PECmd and parse results."""
        if os.path.isfile(input_path):
            cmd = f'"{self.executable_path}" -f "{input_path}" --csv "{self.output_dir}"'
        else:
            cmd = f'"{self.executable_path}" -d "{input_path}" --csv "{self.output_dir}"'

        self._run_command(cmd)

        # Search for CSV files using helper (handles special characters in filenames)
        timeline_files = self._find_files_in_dir(self.output_dir, pattern='Timeline.csv')
        main_files = self._find_files_in_dir(self.output_dir, pattern='PECmd_Output.csv')

        # Also check old names for compatibility
        if not timeline_files:
            timeline_files = self._find_files_in_dir(self.output_dir, pattern='prefetch_Timeline')
        if not main_files:
            main_files = self._find_files_in_dir(self.output_dir, pattern='prefetch.csv')

        timeline_csv = timeline_files[0] if timeline_files else None
        main_csv = main_files[0] if main_files else None

        # Read metadata from main CSV (here ExecutableName = clean name, e.g. "AI.EXE")
        metadata = {}
        if main_csv and os.path.exists(main_csv):
            for row in self._read_csv(main_csv):
                exe_name = row.get('ExecutableName', '').upper()
                if exe_name:
                    # Volume0Name contains path like \VOLUME{...}
                    volume_info = row.get('Volume0Name', row.get('VolumeInformation', ''))
                    metadata[exe_name] = {
                        'hash': row.get('Hash', ''),
                        'file_path': row.get('SourceFilename', ''),
                        'files_loaded': row.get('FilesLoaded', ''),
                        'volume': volume_info,
                        'run_count': row.get('RunCount', '0')
                    }

        # Read Timeline
        records = []
        if timeline_csv and os.path.exists(timeline_csv):
            for row in self._read_csv(timeline_csv):
                exe_path = row.get('ExecutableName', '')  # Full path: \VOLUME{...}\...\AI.EXE
                run_time = row.get('RunTime', '')

                if exe_path and run_time:
                    # Extract clean exe name from full path for matching with metadata
                    exe_name_clean = os.path.basename(exe_path).upper()

                    record = {
                        'executable_name': exe_name_clean,  # Clean name: AI.EXE
                        'executable_path': exe_path,  # Full path for reference
                        'run_time': run_time,
                        'prefetch_hash': '',
                        'source_file': '',
                        'files_loaded': [],
                        'volume_info': '',
                        'run_count': 0
                    }

                    # Match by clean exe name
                    if exe_name_clean in metadata:
                        meta = metadata[exe_name_clean]
                        record['prefetch_hash'] = meta['hash']
                        record['source_file'] = meta['file_path']
                        record['volume_info'] = meta['volume']
                        record['run_count'] = self._safe_int(meta['run_count'])

                        if meta['files_loaded']:
                            files = [f.strip() for f in meta['files_loaded'].split(',') if f.strip()]
                            record['files_loaded'] = files[:100]

                    records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Prefetch record."""
        return {
            "artifact_type": "prefetch",
            "timestamp": record.get('run_time', ''),
            "executable_name": self._safe_str(record.get('executable_name', '')),
            "executable_path": self._safe_str(record.get('executable_path', ''), 500),
            "prefetch_hash": self._safe_str(record.get('prefetch_hash', '')),
            "source_file": self._safe_str(record.get('source_file', '')),
            "run_count": self._safe_int(record.get('run_count', 0)),
            "files_loaded": record.get('files_loaded', []),
            "volume_info": self._safe_str(record.get('volume_info', ''), 500),
        }


# =============================================================================
# EVENT LOG PARSER (EvtxECmd)
# =============================================================================

class EventLog_EvtxECmd_Parser(BaseParser):
    """
    Windows Event Logs (.evtx) parser via EvtxECmd.

    Windows Event Logs contain:
    - System events
    - User logins/logouts
    - Errors and warnings
    - Software installation
    - Network activity

    Usage:
        parser = EventLog_EvtxECmd_Parser("tools/EvtxeCmd/EvtxECmd.exe")
        records = parser.parse("C:/Windows/System32/winevt/Logs")
    """

    @property
    def name(self) -> str:
        return "EventLog_EvtxECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows Event Logs - system events, authentication, errors"

    @property
    def index_name(self) -> str:
        return "forensic-eventlog"

    @property
    def artifact_type(self) -> str:
        return "eventlog"

    @property
    def database_table(self) -> str:
        return "eventlog"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "event_id": "integer",
            "provider": "keyword",
            "channel": "keyword",
            "level": "keyword",
            "severity": "keyword",
            "computer_name": "keyword",
            "user_id": "keyword",
            "message": "text",
            "record_id": "integer",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run EvtxECmd and parse results."""
        if os.path.isfile(input_path):
            cmd = f'"{self.executable_path}" -f "{input_path}" --csv "{self.output_dir}" --csvf "eventlog.csv"'
        else:
            cmd = f'"{self.executable_path}" -d "{input_path}" --csv "{self.output_dir}" --csvf "eventlog.csv"'

        self._run_command(cmd, timeout=600)

        records = []
        seen_keys = set()  # For deduplication by (channel, record_id)
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            for row in self._read_csv(csv_file):
                # Deduplicate by channel + record_id (unique per evtx log file)
                channel = row.get('Channel', '')
                record_id = row.get('RecordId', row.get('EventRecordId', ''))
                dedup_key = f"{channel}:{record_id}"

                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                record = {
                    'event_id': row.get('EventId', row.get('Event Id', '')),
                    'timestamp': row.get('TimeCreated', row.get('Timestamp', '')),
                    'provider': row.get('Provider', row.get('Source', '')),
                    'channel': channel,
                    'level': row.get('Level', ''),
                    'computer': row.get('Computer', row.get('ComputerName', '')),
                    'user_id': row.get('UserId', row.get('User', '')),
                    'payload': row.get('Payload', row.get('Message', '')),
                    'record_id': record_id,
                }
                records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Event Log record."""
        level = self._safe_str(record.get('level', '')).lower()
        severity = "info"
        if "error" in level or "critical" in level:
            severity = "error"
        elif "warning" in level:
            severity = "warning"

        return {
            "artifact_type": "eventlog",
            "timestamp": self._safe_str(record.get('timestamp', '')),
            "event_id": self._safe_int(record.get('event_id', 0)),
            "provider": self._safe_str(record.get('provider', '')),
            "channel": self._safe_str(record.get('channel', '')),
            "level": self._safe_str(record.get('level', '')),
            "severity": severity,
            "computer_name": self._safe_str(record.get('computer', '')),
            "user_id": self._safe_str(record.get('user_id', '')),
            "message": self._safe_str(record.get('payload', ''), 2000),
            "record_id": self._safe_int(record.get('record_id', 0)),
        }


# =============================================================================
# REGISTRY PARSER (RECmd)
# =============================================================================

class Registry_RECmd_Parser(BaseParser):
    """
    Windows Registry hives parser via RECmd.

    Windows Registry contains:
    - System configuration
    - Installed programs
    - Autorun (Run/RunOnce)
    - User profiles
    - Network settings

    Supported hives: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat

    Usage:
        parser = Registry_RECmd_Parser("tools/RECmd/RECmd/RECmd.exe")
        records = parser.parse("C:/Windows/System32/config")
    """

    def __init__(self, executable_path: str = None, output_dir: str = "output", batch_file: str = None):
        super().__init__(executable_path, output_dir)
        self.batch_file = os.path.abspath(batch_file) if batch_file else None

    @property
    def name(self) -> str:
        return "Registry_RECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows Registry - system config, autoruns, installed software"

    @property
    def index_name(self) -> str:
        return "forensic-registry"

    @property
    def artifact_type(self) -> str:
        return "registry"

    @property
    def database_table(self) -> str:
        return "registry"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "hive_type": "keyword",
            "key_path": "text_keyword",
            "value_name": "text_keyword",
            "value_data": "text",
            "value_type": "keyword",
            "category": "keyword",
            "description": "text",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run RECmd and parse results."""
        if os.path.isfile(input_path):
            base_cmd = f'"{self.executable_path}" -f "{input_path}"'
        else:
            base_cmd = f'"{self.executable_path}" -d "{input_path}"'

        if self.batch_file and os.path.exists(self.batch_file):
            base_cmd += f' --bn "{self.batch_file}"'

        cmd = f'{base_cmd} --csv "{self.output_dir}"'
        self._run_command(cmd, timeout=600)

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            csv_name = os.path.basename(csv_file).upper()

            # Skip duplicate files (_1, _2, _3 suffixes)
            if '_1.' in csv_name or '_2.' in csv_name or '_3.' in csv_name:
                continue

            for row in self._read_csv(csv_file):
                hive_type = self._detect_hive_type(csv_name, row)

                # Handle different CSV formats from RECmd
                # Main batch file: KeyPath, ValueName, ValueData, LastWriteTimestamp
                # Subfolder files: BatchKeyPath, Name, specific columns per type
                key_path = (row.get('KeyPath') or row.get('BatchKeyPath') or
                           row.get('Key') or row.get('HivePath') or '')

                # For specialized CSVs, construct meaningful value from available fields
                value_name = row.get('ValueName') or row.get('Name') or row.get('Value') or ''

                # Collect all potential data fields
                value_data = (row.get('ValueData') or row.get('ValueData2') or
                             row.get('ValueData3') or row.get('Data') or
                             row.get('DisplayName') or row.get('ImagePath') or
                             row.get('ServiceDLL') or '')

                # Timestamp from various possible columns
                last_write = (row.get('LastWriteTimestamp') or row.get('LastModified') or
                             row.get('NameKeyLastWrite') or row.get('ParametersKeyLastWrite') or '')

                record = {
                    'hive_type': hive_type,
                    'key_path': key_path,
                    'value_name': value_name,
                    'value_data': value_data,
                    'value_type': row.get('ValueType', row.get('Type', '')),
                    'last_write': last_write,
                    'description': row.get('Description', ''),
                    'category': row.get('Category', ''),
                }
                records.append(record)

        return records

    def _detect_hive_type(self, csv_name: str, row: Dict) -> str:
        """Detect registry hive type from CSV name or row data."""
        # Check CSV filename first (most reliable for subfolder files)
        csv_upper = csv_name.upper()
        if '__SYSTEM' in csv_upper or '_SYSTEM.' in csv_upper:
            return "SYSTEM"
        elif '__SOFTWARE' in csv_upper or '_SOFTWARE.' in csv_upper:
            return "SOFTWARE"
        elif '__NTUSER' in csv_upper or '_NTUSER' in csv_upper:
            return "NTUSER.DAT"
        elif '__SAM' in csv_upper or '_SAM.' in csv_upper:
            return "SAM"
        elif '__SECURITY' in csv_upper or '_SECURITY.' in csv_upper:
            return "SECURITY"
        elif 'USRCLASS' in csv_upper:
            return "UsrClass.dat"

        # Check HiveType field (main batch CSV)
        hive_type_field = str(row.get('HiveType', '')).upper()
        if hive_type_field:
            if 'SYSTEM' in hive_type_field:
                return "SYSTEM"
            elif 'SOFTWARE' in hive_type_field:
                return "SOFTWARE"
            elif 'NTUSER' in hive_type_field or 'NTUSR' in hive_type_field:
                return "NTUSER.DAT"
            elif 'SAM' in hive_type_field:
                return "SAM"
            elif 'SECURITY' in hive_type_field:
                return "SECURITY"

        # Check KeyPath/HivePath as fallback
        key_path = str(row.get('KeyPath') or row.get('BatchKeyPath') or row.get('HivePath') or '').upper()
        if '\\SYSTEM\\' in key_path or key_path.startswith('SYSTEM'):
            return "SYSTEM"
        elif '\\SOFTWARE\\' in key_path or key_path.startswith('SOFTWARE'):
            return "SOFTWARE"
        elif 'NTUSER' in key_path:
            return "NTUSER.DAT"

        return "UNKNOWN"

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Registry record."""
        category = record.get('category', '')
        if not category:
            key_path = self._safe_str(record.get('key_path', '')).lower()
            if 'run' in key_path:
                category = "autorun"
            elif 'services' in key_path:
                category = "services"
            elif 'uninstall' in key_path:
                category = "installed_software"
            elif 'network' in key_path or 'tcpip' in key_path:
                category = "network"
            else:
                category = "other"

        return {
            "artifact_type": "registry",
            "timestamp": self._safe_str(record.get('last_write', '')),
            "hive_type": self._safe_str(record.get('hive_type', '')),
            "key_path": self._safe_str(record.get('key_path', ''), 1000),
            "value_name": self._safe_str(record.get('value_name', '')),
            "value_data": self._safe_str(record.get('value_data', ''), 1000),
            "value_type": self._safe_str(record.get('value_type', '')),
            "category": category,
            "description": self._safe_str(record.get('description', ''), 500),
        }


# =============================================================================
# BROWSER HISTORY PARSER (SQLite)
# =============================================================================

class Browser_SQLite_Parser(BaseParser):
    """
    Browser history parser (Chrome, Edge, Firefox).

    Works directly with browser SQLite databases.
    Supported browsers: Chrome, Edge, Firefox, Opera, Brave

    Usage:
        parser = Browser_SQLite_Parser()
        records = parser.parse("C:/Users/*/AppData/Local/Google/Chrome/User Data/Default/History")
    """

    BROWSER_PATHS = {
        "chrome": ["AppData/Local/Google/Chrome/User Data/*/History"],
        "edge": ["AppData/Local/Microsoft/Edge/User Data/*/History"],
        "firefox": ["AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite"],
    }

    def __init__(self, executable_path: str = None, output_dir: str = "output"):
        super().__init__(None, output_dir)  # executable not needed

    @property
    def name(self) -> str:
        return "Browser_SQLite_Parser"

    @property
    def description(self) -> str:
        return "Browser History - web browsing activity, URLs, searches"

    @property
    def index_name(self) -> str:
        return "forensic-browser"

    @property
    def artifact_type(self) -> str:
        return "browser_history"

    @property
    def database_table(self) -> str:
        return "browser_history"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "browser": "keyword",
            "url": "text_keyword",
            "domain": "keyword",
            "title": "text",
            "visit_count": "integer",
            "typed_count": "integer",
            "hidden": "boolean",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Parse browser SQLite databases."""
        records = []
        files_to_parse = []

        if os.path.isfile(input_path):
            files_to_parse.append(input_path)
        elif os.path.isdir(input_path):
            for root, dirs, files in os.walk(input_path):
                for f in files:
                    if f.lower() in ('history', 'places.sqlite'):
                        files_to_parse.append(os.path.join(root, f))

        for db_file in files_to_parse:
            browser = self._detect_browser(db_file)
            print(f"[{self.name}] Processing {browser}: {os.path.basename(db_file)}")

            try:
                temp_db = os.path.join(self.output_dir, f"temp_{browser}_{os.getpid()}.db")
                shutil.copy2(db_file, temp_db)

                if browser == "Firefox":
                    browser_records = self._parse_firefox(temp_db, browser)
                else:
                    browser_records = self._parse_chromium(temp_db, browser)

                records.extend(browser_records)
                os.remove(temp_db)

            except Exception as e:
                print(f"[{self.name}] Error parsing {db_file}: {e}")
                continue

        return records

    def _detect_browser(self, file_path: str) -> str:
        """Detect browser by file path and DB structure."""
        path_lower = file_path.lower()

        # First check by path
        if 'chrome' in path_lower:
            return "Chrome"
        elif 'edge' in path_lower:
            return "Edge"
        elif 'firefox' in path_lower or 'places.sqlite' in path_lower:
            return "Firefox"
        elif 'opera' in path_lower:
            return "Opera"
        elif 'brave' in path_lower:
            return "Brave"

        # If not detected by path - analyze DB structure
        try:
            conn = sqlite3.connect(file_path)
            cursor = conn.cursor()

            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0].lower() for row in cursor.fetchall()]
            conn.close()

            # Firefox has moz_places table
            if 'moz_places' in tables:
                return "Firefox"

            # Chromium-based browsers have urls table
            if 'urls' in tables:
                # Could try to detect by meta data or keyword_search_terms
                # But generally this is Chromium-based (Chrome, Edge, Opera, Brave)
                # Default to Chromium as generic
                return "Chromium"

        except Exception as e:
            print(f"[{self.name}] Cannot detect browser from DB structure: {e}")

        return "Unknown"

    def _parse_chromium(self, db_path: str, browser: str) -> List[Dict[str, Any]]:
        """Parse Chromium-based browsers."""
        records = []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT url, title, visit_count, typed_count, last_visit_time, hidden
                FROM urls ORDER BY last_visit_time DESC LIMIT 10000
            """)

            for row in cursor.fetchall():
                timestamp = self._chrome_timestamp_to_iso(row[4])
                records.append({
                    'browser': browser,
                    'url': row[0],
                    'title': row[1],
                    'visit_count': row[2] or 1,
                    'typed_count': row[3] or 0,
                    'visit_time': timestamp,
                    'hidden': bool(row[5]) if row[5] else False,
                })

            conn.close()

        except Exception as e:
            print(f"[{self.name}] Chromium parse error: {e}")

        return records

    def _parse_firefox(self, db_path: str, browser: str) -> List[Dict[str, Any]]:
        """Parse Firefox places.sqlite."""
        records = []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT url, title, visit_count, last_visit_date, hidden
                FROM moz_places WHERE visit_count > 0
                ORDER BY last_visit_date DESC LIMIT 10000
            """)

            for row in cursor.fetchall():
                timestamp = self._firefox_timestamp_to_iso(row[3])
                records.append({
                    'browser': browser,
                    'url': row[0],
                    'title': row[1],
                    'visit_count': row[2] or 1,
                    'typed_count': 0,
                    'visit_time': timestamp,
                    'hidden': bool(row[4]) if row[4] else False,
                })

            conn.close()

        except Exception as e:
            print(f"[{self.name}] Firefox parse error: {e}")

        return records

    def _chrome_timestamp_to_iso(self, timestamp: int) -> str:
        """Convert Chrome timestamp to ISO format."""
        if not timestamp:
            return ""
        try:
            unix_timestamp = (timestamp / 1000000) - 11644473600
            dt = datetime.utcfromtimestamp(unix_timestamp)
            return dt.isoformat() + "Z"
        except:
            return ""

    def _firefox_timestamp_to_iso(self, timestamp: int) -> str:
        """Convert Firefox timestamp to ISO format."""
        if not timestamp:
            return ""
        try:
            dt = datetime.utcfromtimestamp(timestamp / 1000000)
            return dt.isoformat() + "Z"
        except:
            return ""

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Browser History record."""
        url = self._safe_str(record.get('url', ''))

        domain = ""
        search_query = ""
        try:
            from urllib.parse import urlparse, parse_qs, unquote
            parsed = urlparse(url)
            domain = parsed.netloc
            # Extract decoded search query from search engine URLs
            qs = parse_qs(parsed.query)
            q = qs.get('q') or qs.get('query') or qs.get('p') or qs.get('text')
            if q:
                search_query = unquote(q[0])
        except:
            pass

        result = {
            "artifact_type": "browser_history",
            "timestamp": self._safe_str(record.get('visit_time', '')),
            "browser": self._safe_str(record.get('browser', '')),
            "url": url,
            "domain": domain,
            "title": self._safe_str(record.get('title', ''), 500),
            "visit_count": self._safe_int(record.get('visit_count', 1)),
            "typed_count": self._safe_int(record.get('typed_count', 0)),
            "hidden": bool(record.get('hidden', False)),
        }
        if search_query:
            result["search_query"] = search_query
        return result


# =============================================================================
# LNK PARSER (LECmd)
# =============================================================================

class LNK_LECmd_Parser(BaseParser):
    """
    Windows LNK (shortcut) files parser via LECmd.

    LNK files contain:
    - Target file path
    - Working directory
    - Command line arguments
    - Timestamps (creation, access, modification)
    - MAC addresses (sometimes)

    Usage:
        parser = LNK_LECmd_Parser("tools/LECmd/LECmd.exe")
        records = parser.parse("C:/Users/*/Recent")
    """

    @property
    def name(self) -> str:
        return "LNK_LECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows LNK shortcuts - recently accessed files and locations"

    @property
    def index_name(self) -> str:
        return "forensic-lnk"

    @property
    def artifact_type(self) -> str:
        return "lnk"

    @property
    def database_table(self) -> str:
        return "lnk_files"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "lnk_name": "keyword",
            "target_path": "text_keyword",
            "target_name": "text",
            "target_extension": "keyword",
            "working_directory": "text",
            "arguments": "text",
            "target_created": "date_lenient",
            "target_modified": "date_lenient",
            "target_accessed": "date_lenient",
            "source_created": "date_lenient",
            "source_modified": "date_lenient",
            "source_accessed": "date_lenient",
            "file_size": "long",
            "drive_type": "keyword",
            "volume_label": "keyword",
            "volume_serial": "keyword",
            "machine_id": "keyword",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run LECmd and parse results."""
        if os.path.isfile(input_path):
            cmd = f'"{self.executable_path}" -f "{input_path}" --csv "{self.output_dir}" --csvf "lnk.csv"'
        else:
            cmd = f'"{self.executable_path}" -d "{input_path}" --csv "{self.output_dir}" --csvf "lnk.csv"'

        self._run_command(cmd)

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            for row in self._read_csv(csv_file):
                # Determine target_path with priority for Unicode fields
                # LocalPath may contain corrupted non-ASCII characters
                # TargetIDAbsolutePath usually contains correct Unicode
                local_path = row.get('LocalPath', '')
                target_id_path = row.get('TargetIDAbsolutePath', '')
                working_dir = row.get('WorkingDirectory', '')

                # Check if LocalPath contains corrupted characters
                # (if there are non-ASCII and they are not correct Unicode)
                target_path = local_path
                if target_id_path:
                    # If TargetIDAbsolutePath exists and contains filename,
                    # combine with working directory for full path
                    if working_dir and not target_id_path.startswith(('C:', 'D:', 'E:', '\\', '/')):
                        target_path = os.path.join(working_dir, target_id_path)
                    elif target_id_path.startswith(('C:', 'D:', 'E:', '\\')):
                        target_path = target_id_path
                    # Otherwise use LocalPath if available
                    elif not local_path:
                        target_path = target_id_path

                record = {
                    'lnk_name': row.get('SourceFile', row.get('SourceFilename',
                                row.get('LnkName', row.get('FileName', '')))),
                    'target_path': target_path,
                    'target_name': target_id_path,  # Store filename separately
                    'working_directory': working_dir,
                    'arguments': row.get('Arguments', row.get('CommandLineArguments', '')),
                    'target_created': row.get('TargetCreated', row.get('TargetCreationDate', '')),
                    'target_modified': row.get('TargetModified', row.get('TargetModificationDate', '')),
                    'target_accessed': row.get('TargetAccessed', row.get('TargetAccessDate', '')),
                    'source_created': row.get('SourceCreated', row.get('CreationTime', '')),
                    'source_modified': row.get('SourceModified', row.get('ModifiedTime', '')),
                    'source_accessed': row.get('SourceAccessed', row.get('AccessTime', '')),
                    'file_size': row.get('FileSize', row.get('TargetFileSize', '')),
                    'drive_type': row.get('DriveType', ''),
                    'volume_label': row.get('VolumeLabel', row.get('VolumeName', '')),
                    'volume_serial': row.get('VolumeSerialNumber', row.get('VolumeSerial', '')),
                    'machine_id': row.get('MachineID', row.get('MachineMACAddress', row.get('TrackerCreatedMachineMac', ''))),
                    'relative_path': row.get('RelativePath', ''),
                }

                if record['lnk_name']:
                    record['lnk_name'] = os.path.basename(record['lnk_name'])

                records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize LNK record."""
        timestamp = (
            record.get('target_accessed') or
            record.get('source_accessed') or
            record.get('source_modified') or
            ''
        )

        target_path = self._safe_str(record.get('target_path', ''))
        target_name = self._safe_str(record.get('target_name', ''))
        target_ext = ""

        # Determine extension from target_name (more reliable) or target_path
        ext_source = target_name if target_name else target_path
        if ext_source:
            _, ext = os.path.splitext(ext_source)
            target_ext = ext.lower()

        return {
            "artifact_type": "lnk",
            "timestamp": self._safe_str(timestamp),
            "lnk_name": self._safe_str(record.get('lnk_name', '')),
            "target_path": target_path,
            "target_name": target_name,
            "target_extension": target_ext,
            "working_directory": self._safe_str(record.get('working_directory', '')),
            "arguments": self._safe_str(record.get('arguments', ''), 500),
            "target_created": self._safe_str(record.get('target_created', '')),
            "target_modified": self._safe_str(record.get('target_modified', '')),
            "target_accessed": self._safe_str(record.get('target_accessed', '')),
            "source_created": self._safe_str(record.get('source_created', '')),
            "source_modified": self._safe_str(record.get('source_modified', '')),
            "source_accessed": self._safe_str(record.get('source_accessed', '')),
            "file_size": self._safe_int(record.get('file_size', 0)),
            "drive_type": self._safe_str(record.get('drive_type', '')),
            "volume_label": self._safe_str(record.get('volume_label', '')),
            "volume_serial": self._safe_str(record.get('volume_serial', '')),
            "machine_id": self._safe_str(record.get('machine_id', '')),
        }


# =============================================================================
# MFT PARSER (MFTECmd)
# =============================================================================

class MFT_MFTECmd_Parser(BaseParser):
    """
    Master File Table ($MFT) parser via MFTECmd.

    $MFT contains complete file system metadata:
    - All file names (including deleted)
    - Creation, modification, access timestamps
    - File sizes and attributes
    - Parent directory relationships

    Usage:
        parser = MFT_MFTECmd_Parser("tools/MFTECmd/MFTECmd.exe")
        records = parser.parse("$MFT")
    """

    @property
    def name(self) -> str:
        return "MFT_MFTECmd_Parser"

    @property
    def description(self) -> str:
        return "Master File Table - complete file system timeline"

    @property
    def index_name(self) -> str:
        return "forensic-mft"

    @property
    def artifact_type(self) -> str:
        return "mft"

    @property
    def database_table(self) -> str:
        return "mft"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "entry_number": "integer",
            "sequence_number": "integer",
            "filename": "text_keyword",
            "extension": "keyword",
            "file_path": "text",
            "file_size": "long",
            "is_directory": "boolean",
            "is_deleted": "boolean",
            "created": "date_lenient",
            "modified": "date_lenient",
            "accessed": "date_lenient",
            "entry_modified": "date_lenient",
            "fn_created": "date_lenient",
            "fn_modified": "date_lenient",
            "fn_accessed": "date_lenient",
            "attributes": "keyword",
            "is_ads": "boolean",
            "zone_id": "text",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run MFTECmd and parse results."""
        # Find $MFT file - input can be file or directory
        if os.path.isfile(input_path):
            mft_file = input_path
        else:
            # Look for $MFT in directory using helper that handles $ in filenames
            mft_files = self._find_files_in_dir(input_path, pattern='MFT')
            if not mft_files:
                mft_files = self._find_files_in_dir(input_path)
            mft_file = mft_files[0] if mft_files else None

        if not mft_file or not os.path.isfile(mft_file):
            self._safe_print(f"[{self.name}] $MFT file not found in: {input_path}")
            return []

        # MFTECmd expects single file
        cmd = f'"{self.executable_path}" -f "{mft_file}" --csv "{self.output_dir}"'
        self._run_command(cmd, timeout=1200)  # MFT can be large, 20 min timeout

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            for row in self._read_csv(csv_file):
                # Skip system metadata entries
                entry_number = self._safe_int(row.get('EntryNumber', 0))
                if entry_number < 16:  # First 16 entries are system metadata
                    continue

                record = {
                    'entry_number': entry_number,
                    'sequence_number': row.get('SequenceNumber', ''),
                    'parent_entry': row.get('ParentEntryNumber', ''),
                    'parent_sequence': row.get('ParentSequenceNumber', ''),
                    'filename': row.get('FileName', ''),
                    'extension': row.get('Extension', ''),
                    'file_size': row.get('FileSize', row.get('LogicalSize', '')),
                    'is_directory': row.get('IsDirectory', '') == 'True',
                    'is_deleted': row.get('InUse', 'True') != 'True',
                    'created': row.get('Created0x10', row.get('SI_Created', '')),
                    'modified': row.get('LastModified0x10', row.get('SI_Modified', '')),
                    'accessed': row.get('LastAccess0x10', row.get('SI_Accessed', '')),
                    'entry_modified': row.get('LastRecordChange0x10', row.get('SI_EntryModified', '')),
                    'fn_created': row.get('Created0x30', row.get('FN_Created', '')),
                    'fn_modified': row.get('LastModified0x30', row.get('FN_Modified', '')),
                    'fn_accessed': row.get('LastAccess0x30', row.get('FN_Accessed', '')),
                    'full_path': row.get('ParentPath', ''),
                    'attributes': row.get('Attributes', ''),
                    'is_ads': row.get('IsAds', '') == 'True',
                    'zone_id': row.get('ZoneIdContents', ''),
                }
                records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize MFT record."""
        # Use SI timestamps as primary, FN timestamps are more reliable for some cases
        timestamp = (
            record.get('modified') or
            record.get('created') or
            record.get('accessed') or
            ''
        )

        filename = self._safe_str(record.get('filename', ''))
        extension = self._safe_str(record.get('extension', '')).lower()
        full_path = self._safe_str(record.get('full_path', ''))

        # Construct full file path
        if full_path and filename:
            if not full_path.endswith('\\'):
                full_path += '\\'
            file_path = full_path + filename
        else:
            file_path = filename

        return {
            "artifact_type": "mft",
            "timestamp": self._safe_str(timestamp),
            "entry_number": self._safe_int(record.get('entry_number', 0)),
            "sequence_number": self._safe_int(record.get('sequence_number', 0)),
            "filename": filename,
            "extension": extension,
            "file_path": self._safe_str(file_path, 1000),
            "file_size": self._safe_int(record.get('file_size', 0)),
            "is_directory": bool(record.get('is_directory', False)),
            "is_deleted": bool(record.get('is_deleted', False)),
            "created": self._safe_str(record.get('created', '')),
            "modified": self._safe_str(record.get('modified', '')),
            "accessed": self._safe_str(record.get('accessed', '')),
            "entry_modified": self._safe_str(record.get('entry_modified', '')),
            # $FILE_NAME (0x30) timestamps. Parsed since the first version but dropped here, so they
            # never reached the index or the database. Carried through now: they resist timestomping,
            # which $STANDARD_INFORMATION does not, and the comparison between the two sets is the
            # cross-check the platform could not offer before.
            "fn_created": self._safe_str(record.get('fn_created', '')),
            "fn_modified": self._safe_str(record.get('fn_modified', '')),
            "fn_accessed": self._safe_str(record.get('fn_accessed', '')),
            "attributes": self._safe_str(record.get('attributes', '')),
            "is_ads": bool(record.get('is_ads', False)),
            "zone_id": self._safe_str(record.get('zone_id', ''), 500),
        }


# =============================================================================
# JUMP LISTS PARSER (JLECmd)
# =============================================================================

class JumpList_JLECmd_Parser(BaseParser):
    """
    Windows Jump Lists parser via JLECmd.

    Jump Lists contain recently accessed files per application:
    - AutomaticDestinations - system-managed recent files
    - CustomDestinations - application-specific pinned items
    - Application-specific file access history

    Usage:
        parser = JumpList_JLECmd_Parser("tools/JLECmd/JLECmd.exe")
        records = parser.parse("Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations")
    """

    @property
    def name(self) -> str:
        return "JumpList_JLECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows Jump Lists - recent files per application"

    @property
    def index_name(self) -> str:
        return "forensic-jumplist"

    @property
    def artifact_type(self) -> str:
        return "jumplist"

    @property
    def database_table(self) -> str:
        return "jumplist"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "list_type": "keyword",
            "app_id": "keyword",
            "app_name": "text_keyword",
            "target_path": "text_keyword",
            "target_name": "text",
            "extension": "keyword",
            "arguments": "text",
            "target_created": "date_lenient",
            "target_modified": "date_lenient",
            "target_accessed": "date_lenient",
            "file_size": "long",
            "drive_type": "keyword",
            "volume_label": "keyword",
            "volume_serial": "keyword",
            "machine_id": "keyword",
            "interaction_count": "integer",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run JLECmd and parse results."""
        if os.path.isfile(input_path):
            cmd = f'"{self.executable_path}" -f "{input_path}" --csv "{self.output_dir}"'
        else:
            cmd = f'"{self.executable_path}" -d "{input_path}" --csv "{self.output_dir}" --all'

        self._run_command(cmd, timeout=600)

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            csv_name = os.path.basename(csv_file).lower()
            list_type = "automatic" if "automatic" in csv_name else "custom"

            for row in self._read_csv(csv_file):
                record = {
                    'list_type': list_type,
                    'app_id': row.get('AppId', row.get('ApplicationId', '')),
                    'app_name': row.get('AppIdDescription', row.get('ApplicationName', '')),
                    'target_path': row.get('Path', row.get('LocalPath', row.get('TargetPath', ''))),
                    'target_name': row.get('TargetIDAbsolutePath', ''),
                    'arguments': row.get('Arguments', ''),
                    'target_created': row.get('TargetCreated', row.get('CreationTime', '')),
                    'target_modified': row.get('TargetModified', row.get('ModificationTime', '')),
                    'target_accessed': row.get('TargetAccessed', row.get('AccessTime', '')),
                    'file_size': row.get('FileSize', ''),
                    'drive_type': row.get('DriveType', ''),
                    'volume_label': row.get('VolumeLabel', ''),
                    'volume_serial': row.get('VolumeSerialNumber', ''),
                    'machine_id': row.get('MachineId', row.get('MachineMACAddress', '')),
                    'entry_number': row.get('EntryNumber', ''),
                    'source_file': row.get('SourceFile', ''),
                    'interaction_count': row.get('InteractionCount', ''),
                }
                records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Jump List record."""
        timestamp = (
            record.get('target_accessed') or
            record.get('target_modified') or
            record.get('target_created') or
            ''
        )

        target_path = self._safe_str(record.get('target_path', ''))
        target_name = self._safe_str(record.get('target_name', ''))
        extension = ""

        ext_source = target_name if target_name else target_path
        if ext_source:
            _, ext = os.path.splitext(ext_source)
            extension = ext.lower()

        return {
            "artifact_type": "jumplist",
            "timestamp": self._safe_str(timestamp),
            "list_type": self._safe_str(record.get('list_type', '')),
            "app_id": self._safe_str(record.get('app_id', '')),
            "app_name": self._safe_str(record.get('app_name', '')),
            "target_path": target_path,
            "target_name": target_name,
            "extension": extension,
            "arguments": self._safe_str(record.get('arguments', ''), 500),
            "target_created": self._safe_str(record.get('target_created', '')),
            "target_modified": self._safe_str(record.get('target_modified', '')),
            "target_accessed": self._safe_str(record.get('target_accessed', '')),
            "file_size": self._safe_int(record.get('file_size', 0)),
            "drive_type": self._safe_str(record.get('drive_type', '')),
            "volume_label": self._safe_str(record.get('volume_label', '')),
            "volume_serial": self._safe_str(record.get('volume_serial', '')),
            "machine_id": self._safe_str(record.get('machine_id', '')),
            "interaction_count": self._safe_int(record.get('interaction_count', 0)),
        }


# =============================================================================
# RECYCLE BIN PARSER (RBCmd)
# =============================================================================

class RecycleBin_RBCmd_Parser(BaseParser):
    """
    Windows Recycle Bin ($Recycle.Bin) parser via RBCmd.

    Recycle Bin contains:
    - Deleted file metadata ($I files)
    - Original file paths
    - Deletion timestamps
    - File sizes

    Usage:
        parser = RecycleBin_RBCmd_Parser("tools/RBCmd/RBCmd.exe")
        records = parser.parse("$Recycle.Bin")
    """

    @property
    def name(self) -> str:
        return "RecycleBin_RBCmd_Parser"

    @property
    def description(self) -> str:
        return "Windows Recycle Bin - deleted files metadata"

    @property
    def index_name(self) -> str:
        return "forensic-recyclebin"

    @property
    def artifact_type(self) -> str:
        return "recyclebin"

    @property
    def database_table(self) -> str:
        return "recyclebin"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "filename": "text_keyword",
            "original_path": "text",
            "extension": "keyword",
            "file_size": "long",
            "user_sid": "keyword",
            "recycle_file": "keyword",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run RBCmd and parse results."""
        if os.path.isfile(input_path):
            cmd = f'"{self.executable_path}" -f "{input_path}" --csv "{self.output_dir}"'
        else:
            cmd = f'"{self.executable_path}" -d "{input_path}" --csv "{self.output_dir}" -q'

        self._run_command(cmd, timeout=300)

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            for row in self._read_csv(csv_file):
                record = {
                    'source_file': row.get('SourceName', row.get('FileName', '')),
                    'original_path': row.get('OriginalPath', row.get('FullPath', '')),
                    'deleted_time': row.get('DeletedOn', row.get('DeletionTime', '')),
                    'file_size': row.get('FileSize', ''),
                    'user_sid': row.get('UserSid', row.get('SID', '')),
                    'version': row.get('Version', ''),
                    'recycle_file': row.get('RecycleBinFile', row.get('RecycleFile', '')),
                }
                records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Recycle Bin record."""
        original_path = self._safe_str(record.get('original_path', ''))
        extension = ""
        filename = ""

        if original_path:
            filename = os.path.basename(original_path)
            _, ext = os.path.splitext(original_path)
            extension = ext.lower()

        return {
            "artifact_type": "recyclebin",
            "timestamp": self._safe_str(record.get('deleted_time', '')),
            "filename": filename,
            "original_path": original_path,
            "extension": extension,
            "file_size": self._safe_int(record.get('file_size', 0)),
            "user_sid": self._safe_str(record.get('user_sid', '')),
            "recycle_file": self._safe_str(record.get('recycle_file', '')),
        }


# =============================================================================
# SHIMCACHE PARSER (AppCompatCacheParser)
# =============================================================================

class Shimcache_AppCompat_Parser(BaseParser):
    """
    Windows Application Compatibility Cache (Shimcache) parser.

    Shimcache tracks program execution:
    - Executable paths
    - Last modification time
    - Execution flag (Windows 7/Server 2008 R2 only)
    - File size

    Location: SYSTEM registry hive

    Usage:
        parser = Shimcache_AppCompat_Parser("tools/AppCompatCacheParser/AppCompatCacheParser.exe")
        records = parser.parse("SYSTEM")  # Registry hive file
    """

    @property
    def name(self) -> str:
        return "Shimcache_AppCompat_Parser"

    @property
    def description(self) -> str:
        return "Windows Shimcache - program execution evidence"

    @property
    def index_name(self) -> str:
        return "forensic-shimcache"

    @property
    def artifact_type(self) -> str:
        return "shimcache"

    @property
    def database_table(self) -> str:
        return "shimcache"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "path": "text_keyword",
            "filename": "text_keyword",
            "extension": "keyword",
            "cache_position": "integer",
            "executed": "boolean",
            "controlset": "keyword",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run AppCompatCacheParser and parse results."""
        # Find SYSTEM hive file(s) - input can be file or directory
        if os.path.isfile(input_path):
            input_files = [input_path]
        else:
            # Look for SYSTEM hive in directory using helper
            input_files = self._find_files_in_dir(input_path, pattern='SYSTEM')
            if not input_files:
                input_files = self._find_files_in_dir(input_path)

        records = []

        for input_file in input_files:
            if not os.path.isfile(input_file):
                continue

            cmd = f'"{self.executable_path}" -f "{input_file}" --csv "{self.output_dir}" --nl'
            self._run_command(cmd, timeout=300)

        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            for row in self._read_csv(csv_file):
                record = {
                    'cache_entry_position': row.get('CacheEntryPosition', row.get('Position', '')),
                    'path': row.get('Path', row.get('FileName', '')),
                    'last_modified': row.get('LastModifiedTimeUTC', row.get('Modified', '')),
                    'executed': row.get('Executed', ''),  # Only reliable on Win7/2008R2
                    'duplicate': row.get('Duplicate', ''),
                    'source_file': row.get('SourceFile', ''),
                    'controlset': row.get('ControlSet', ''),
                }
                records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Shimcache record."""
        path = self._safe_str(record.get('path', ''))
        filename = ""
        extension = ""

        if path:
            filename = os.path.basename(path)
            _, ext = os.path.splitext(path)
            extension = ext.lower()

        executed = record.get('executed', '')
        executed_flag = None
        if executed.lower() == 'true':
            executed_flag = True
        elif executed.lower() == 'false':
            executed_flag = False

        return {
            "artifact_type": "shimcache",
            "timestamp": self._safe_str(record.get('last_modified', '')),
            "path": path,
            "filename": filename,
            "extension": extension,
            "cache_position": self._safe_int(record.get('cache_entry_position', 0)),
            "executed": executed_flag,
            "controlset": self._safe_str(record.get('controlset', '')),
        }


# =============================================================================
# AMCACHE PARSER (AmcacheParser)
# =============================================================================

class Amcache_Parser(BaseParser):
    """
    Windows Amcache.hve parser via AmcacheParser.

    Amcache contains detailed program execution info:
    - Full file path
    - SHA1 hash (!)
    - File size
    - Publisher/Company name
    - First execution time
    - PE header info

    Location: C:\\Windows\\AppCompat\\Programs\\Amcache.hve

    Usage:
        parser = Amcache_Parser("tools/AmcacheParser/AmcacheParser.exe")
        records = parser.parse("Amcache.hve")
    """

    @property
    def name(self) -> str:
        return "Amcache_Parser"

    @property
    def description(self) -> str:
        return "Windows Amcache - program execution with SHA1 hashes"

    @property
    def index_name(self) -> str:
        return "forensic-amcache"

    @property
    def artifact_type(self) -> str:
        return "amcache"

    @property
    def database_table(self) -> str:
        return "amcache"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "record_type": "keyword",
            "path": "text_keyword",
            "filename": "text_keyword",
            "extension": "keyword",
            "sha1": "keyword",
            "file_size": "long",
            "publisher": "text_keyword",
            "product_name": "text_keyword",
            "product_version": "keyword",
            "binary_type": "keyword",
            "link_date": "date_lenient",
            "is_os_component": "boolean",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run AmcacheParser and parse results."""
        # Find Amcache.hve file - input can be file or directory
        if os.path.isfile(input_path):
            amcache_file = input_path
        else:
            # Look for Amcache.hve in directory using helper
            amcache_files = self._find_files_in_dir(input_path, pattern='Amcache')
            if not amcache_files:
                amcache_files = self._find_files_in_dir(input_path, extensions=['.hve'])
            if not amcache_files:
                amcache_files = self._find_files_in_dir(input_path)
            amcache_file = amcache_files[0] if amcache_files else None

        if not amcache_file or not os.path.isfile(amcache_file):
            self._safe_print(f"[{self.name}] Amcache.hve not found in: {input_path}")
            return []

        cmd = f'"{self.executable_path}" -f "{amcache_file}" --csv "{self.output_dir}" -i --nl'
        self._run_command(cmd, timeout=600)

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            csv_name = os.path.basename(csv_file).lower()

            # AmcacheParser creates multiple CSV files
            # Main ones: Amcache_UnassociatedFileEntries.csv, Amcache_ProgramEntries.csv

            for row in self._read_csv(csv_file):
                # Determine record type from file name
                record_type = "file"
                if "program" in csv_name:
                    record_type = "program"
                elif "shortcut" in csv_name:
                    record_type = "shortcut"
                elif "devicecontainer" in csv_name or "device" in csv_name:
                    record_type = "device"
                elif "driverbin" in csv_name:
                    record_type = "driver"

                record = {
                    'record_type': record_type,
                    'path': row.get('FullPath', row.get('Path', row.get('FilePath', ''))),
                    'name': row.get('Name', row.get('FileName', '')),
                    'sha1': row.get('SHA1', row.get('Sha1', '')),
                    'file_size': row.get('FileSize', row.get('Size', '')),
                    'publisher': row.get('Publisher', row.get('CompanyName', '')),
                    'product_name': row.get('ProductName', ''),
                    'product_version': row.get('ProductVersion', row.get('Version', '')),
                    'binary_type': row.get('BinaryType', ''),
                    'pe_header_checksum': row.get('PEHeaderChecksum', ''),
                    'pe_header_hash': row.get('PEHeaderHash', ''),
                    'link_date': row.get('LinkDate', row.get('LinkTime', '')),
                    'file_key_last_write': row.get('FileKeyLastWriteTimestamp', ''),
                    'first_run': row.get('FirstRun', row.get('FileIDLastWriteTimestamp', '')),
                    'program_id': row.get('ProgramId', ''),
                    'language': row.get('Language', ''),
                    'is_pe': row.get('IsPeFile', ''),
                    'is_os_component': row.get('IsOsComponent', ''),
                }

                # Only add if we have meaningful data
                if record['path'] or record['name'] or record['sha1']:
                    records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Amcache record."""
        path = self._safe_str(record.get('path', ''))
        name = self._safe_str(record.get('name', ''))

        if not name and path:
            name = os.path.basename(path)

        extension = ""
        if name:
            _, ext = os.path.splitext(name)
            extension = ext.lower()
        elif path:
            _, ext = os.path.splitext(path)
            extension = ext.lower()

        # Use first_run or file_key_last_write as timestamp
        timestamp = (
            record.get('first_run') or
            record.get('file_key_last_write') or
            record.get('link_date') or
            ''
        )

        sha1 = self._safe_str(record.get('sha1', ''))
        # Clean SHA1 - sometimes has prefix
        if sha1.startswith('0000'):
            sha1 = sha1[4:]

        return {
            "artifact_type": "amcache",
            "timestamp": self._safe_str(timestamp),
            "record_type": self._safe_str(record.get('record_type', 'file')),
            "path": path,
            "filename": name,
            "extension": extension,
            "sha1": sha1,
            "file_size": self._safe_int(record.get('file_size', 0)),
            "publisher": self._safe_str(record.get('publisher', '')),
            "product_name": self._safe_str(record.get('product_name', '')),
            "product_version": self._safe_str(record.get('product_version', '')),
            "binary_type": self._safe_str(record.get('binary_type', '')),
            "link_date": self._safe_str(record.get('link_date', '')),
            "is_os_component": record.get('is_os_component', '').lower() == 'true',
        }


# =============================================================================
# SRUM PARSER (SrumECmd)
# =============================================================================

class SRUM_SrumECmd_Parser(BaseParser):
    """
    Windows SRUM (System Resource Usage Monitor) parser via SrumECmd.

    SRUM tracks system resource usage per application:
    - Network usage by application (bytes sent/received)
    - Application execution time
    - CPU/Memory usage
    - Energy usage

    Location: C:\\Windows\\System32\\sru\\SRUDB.dat

    Usage:
        parser = SRUM_SrumECmd_Parser("tools/SrumECmd/SrumECmd.exe")
        records = parser.parse("SRUDB.dat")
    """

    @property
    def name(self) -> str:
        return "SRUM_SrumECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows SRUM - network/application resource usage"

    @property
    def index_name(self) -> str:
        return "forensic-srum"

    @property
    def artifact_type(self) -> str:
        return "srum"

    @property
    def database_table(self) -> str:
        return "srum"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "record_type": "keyword",
            "app_id": "keyword",
            "app_name": "text_keyword",
            "user_sid": "keyword",
            "user_name": "keyword",
            "bytes_sent": "long",
            "bytes_received": "long",
            "interface_luid": "keyword",
            "profile_id": "integer",
            "background_bytes_read": "long",
            "background_bytes_written": "long",
            "foreground_bytes_read": "long",
            "foreground_bytes_written": "long",
            "background_cycle_time": "long",
            "foreground_cycle_time": "long",
            "face_time": "long",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run SrumECmd and parse results."""
        # Find SRUDB.dat file - input can be file or directory
        if os.path.isfile(input_path):
            srum_file = input_path
        else:
            # Look for SRUDB.dat in directory
            srum_files = self._find_files_in_dir(input_path, pattern='SRUDB')
            if not srum_files:
                srum_files = self._find_files_in_dir(input_path, extensions=['.dat'])
            srum_file = srum_files[0] if srum_files else None

        if not srum_file or not os.path.isfile(srum_file):
            self._safe_print(f"[{self.name}] SRUDB.dat not found in: {input_path}")
            return []

        # ESE databases from forensic images are often "dirty" (not cleanly shut down).
        # Use esentutl.exe to repair the database before parsing.
        self._repair_ese_database(srum_file)

        # SrumECmd needs SOFTWARE hive for app ID resolution (optional)
        software_hive = ""
        parent_dir = os.path.dirname(srum_file)
        software_files = self._find_files_in_dir(parent_dir, pattern='SOFTWARE')
        if software_files:
            software_hive = f'-r "{software_files[0]}"'

        cmd = f'"{self.executable_path}" -f "{srum_file}" {software_hive} --csv "{self.output_dir}"'
        self._run_command(cmd, timeout=600)

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            csv_name = os.path.basename(csv_file).lower()

            # SrumECmd creates multiple CSV files for different tables
            # NetworkUsages, AppResourceUseInfo, EnergyUsage, etc.
            record_type = "unknown"
            if "network" in csv_name:
                record_type = "network"
            elif "appresource" in csv_name or "application" in csv_name:
                record_type = "application"
            elif "energy" in csv_name:
                record_type = "energy"
            elif "push" in csv_name:
                record_type = "push_notification"

            for row in self._read_csv(csv_file):
                record = {
                    'record_type': record_type,
                    'timestamp': row.get('Timestamp', row.get('TimeStamp', '')),
                    'app_id': row.get('AppId', row.get('ApplicationId', '')),
                    'app_name': row.get('ExeInfo', row.get('AppName', row.get('ExecutableName', ''))),
                    'user_sid': row.get('UserId', row.get('UserSid', '')),
                    'user_name': row.get('UserName', ''),
                    # Network fields
                    'bytes_sent': row.get('BytesSent', ''),
                    'bytes_received': row.get('BytesRecvd', row.get('BytesReceived', '')),
                    'interface_luid': row.get('InterfaceLuid', ''),
                    'profile_id': row.get('ProfileId', row.get('NetworkProfileId', '')),
                    'l2_profile_id': row.get('L2ProfileId', ''),
                    # Application resource fields
                    'background_bytes_read': row.get('BackgroundBytesRead', ''),
                    'background_bytes_written': row.get('BackgroundBytesWritten', ''),
                    'foreground_bytes_read': row.get('ForegroundBytesRead', ''),
                    'foreground_bytes_written': row.get('ForegroundBytesWritten', ''),
                    'background_cycle_time': row.get('BackgroundCycleTime', ''),
                    'foreground_cycle_time': row.get('ForegroundCycleTime', ''),
                    'face_time': row.get('FaceTime', ''),
                    'foreground_context_switches': row.get('ForegroundContextSwitches', ''),
                    'background_context_switches': row.get('BackgroundContextSwitches', ''),
                    'background_num_read_ops': row.get('BackgroundNumReadOperations', ''),
                    'background_num_write_ops': row.get('BackgroundNumWriteOperations', ''),
                }
                records.append(record)

        return records

    def _repair_ese_database(self, db_path: str) -> None:
        """Repair a dirty ESE database using esentutl.exe.

        Forensic images typically have dirty ESE databases because the system
        wasn't gracefully shut down before imaging. esentutl /p performs a
        hard repair that fixes the dirty shutdown state.
        """
        esentutl = shutil.which("esentutl") or "esentutl.exe"
        try:
            self._safe_print(f"[{self.name}] Repairing ESE database: {os.path.basename(db_path)}")
            result = subprocess.run(
                [esentutl, "/p", db_path, "/o"],
                capture_output=True, text=True, timeout=120,
                cwd=os.path.dirname(db_path)
            )
            if result.returncode == 0:
                self._safe_print(f"[{self.name}] ESE database repaired successfully")
            else:
                self._safe_print(f"[{self.name}] esentutl repair returned code {result.returncode}: {result.stderr.strip()}")
        except FileNotFoundError:
            self._safe_print(f"[{self.name}] esentutl.exe not found - skipping ESE repair")
        except subprocess.TimeoutExpired:
            self._safe_print(f"[{self.name}] esentutl repair timed out")
        except Exception as e:
            self._safe_print(f"[{self.name}] ESE repair failed: {e}")

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize SRUM record."""
        return {
            "artifact_type": "srum",
            "timestamp": self._safe_str(record.get('timestamp', '')),
            "record_type": self._safe_str(record.get('record_type', '')),
            "app_id": self._safe_str(record.get('app_id', '')),
            "app_name": self._safe_str(record.get('app_name', '')),
            "user_sid": self._safe_str(record.get('user_sid', '')),
            "user_name": self._safe_str(record.get('user_name', '')),
            "bytes_sent": self._safe_int(record.get('bytes_sent', 0)),
            "bytes_received": self._safe_int(record.get('bytes_received', 0)),
            "interface_luid": self._safe_str(record.get('interface_luid', '')),
            "profile_id": self._safe_int(record.get('profile_id', 0)),
            "background_bytes_read": self._safe_int(record.get('background_bytes_read', 0)),
            "background_bytes_written": self._safe_int(record.get('background_bytes_written', 0)),
            "foreground_bytes_read": self._safe_int(record.get('foreground_bytes_read', 0)),
            "foreground_bytes_written": self._safe_int(record.get('foreground_bytes_written', 0)),
            "background_cycle_time": self._safe_int(record.get('background_cycle_time', 0)),
            "foreground_cycle_time": self._safe_int(record.get('foreground_cycle_time', 0)),
            "face_time": self._safe_int(record.get('face_time', 0)),
        }


# =============================================================================
# POWERSHELL HISTORY PARSER
# =============================================================================

class PowerShellHistory_Parser(BaseParser):
    """
    PowerShell command history parser.

    PowerShell saves command history in:
    - ConsoleHost_history.txt (PSReadLine)
    - Event Logs (PowerShell/Operational, Microsoft-Windows-PowerShell/Operational)

    Location: C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt

    Usage:
        parser = PowerShellHistory_Parser()
        records = parser.parse("ConsoleHost_history.txt")
    """

    def __init__(self, executable_path: str = None, output_dir: str = "output"):
        super().__init__(None, output_dir)  # No external tool needed for text files

    @property
    def name(self) -> str:
        return "PowerShellHistory_Parser"

    @property
    def description(self) -> str:
        return "PowerShell command history - executed commands"

    @property
    def index_name(self) -> str:
        return "forensic-powershell"

    @property
    def artifact_type(self) -> str:
        return "powershell"

    @property
    def database_table(self) -> str:
        return "powershell"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "command": "text",
            "line_number": "integer",
            "user": "keyword",
            "source_file": "text",
            "is_suspicious": "boolean",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Parse PowerShell history files."""
        records = []
        files_to_parse = []

        if os.path.isfile(input_path):
            files_to_parse.append(input_path)
        elif os.path.isdir(input_path):
            # Search for ConsoleHost_history.txt files
            for root, dirs, files in os.walk(input_path):
                for f in files:
                    if 'history' in f.lower() and f.endswith('.txt'):
                        files_to_parse.append(os.path.join(root, f))
                    # Also look for PSReadLine folder structure
                    if f.lower() == 'consolehost_history.txt':
                        files_to_parse.append(os.path.join(root, f))

        for history_file in files_to_parse:
            try:
                # Determine user from path
                user = "Unknown"
                path_parts = history_file.replace('\\', '/').split('/')
                for i, part in enumerate(path_parts):
                    if part.lower() == 'users' and i + 1 < len(path_parts):
                        user = path_parts[i + 1]
                        break

                # Get file modification time as approximate timestamp
                file_mtime = os.path.getmtime(history_file)
                file_timestamp = datetime.utcfromtimestamp(file_mtime).isoformat() + "Z"

                with open(history_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                for line_num, line in enumerate(lines, 1):
                    command = line.strip()
                    if command:  # Skip empty lines
                        record = {
                            'command': command,
                            'line_number': line_num,
                            'user': user,
                            'source_file': history_file,
                            'file_timestamp': file_timestamp,
                        }
                        records.append(record)

            except Exception as e:
                self._safe_print(f"[{self.name}] Error parsing {history_file}: {e}")
                continue

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize PowerShell history record."""
        command = self._safe_str(record.get('command', ''))

        # Detect suspicious patterns
        is_suspicious = False
        suspicious_patterns = [
            'invoke-expression', 'iex ', 'downloadstring', 'downloadfile',
            'webclient', 'invoke-webrequest', 'start-bitstransfer',
            'bypass', 'hidden', 'encodedcommand', '-enc ', '-e ',
            'powershell -', 'cmd /c', 'certutil', 'bitsadmin',
            'net user', 'net localgroup', 'reg add', 'schtasks',
            'mimikatz', 'sekurlsa', 'lsass', 'procdump',
            'invoke-mimikatz', 'invoke-shellcode', 'invoke-reflectivepe',
            'get-credential', 'convertto-securestring',
        ]
        command_lower = command.lower()
        for pattern in suspicious_patterns:
            if pattern in command_lower:
                is_suspicious = True
                break

        return {
            "artifact_type": "powershell",
            "timestamp": self._safe_str(record.get('file_timestamp', '')),
            "command": command,
            "line_number": self._safe_int(record.get('line_number', 0)),
            "user": self._safe_str(record.get('user', '')),
            "source_file": self._safe_str(record.get('source_file', '')),
            "is_suspicious": is_suspicious,
        }


# =============================================================================
# USN JOURNAL PARSER (MFTECmd)
# =============================================================================

class UsnJrnl_MFTECmd_Parser(BaseParser):
    """
    Windows USN Journal ($UsnJrnl:$J) parser via MFTECmd.

    USN Journal tracks detailed file system changes:
    - File creation, deletion, rename
    - Attribute changes
    - Security changes
    - Very granular timeline

    Location: \\$Extend\\$UsnJrnl:$J

    Usage:
        parser = UsnJrnl_MFTECmd_Parser("tools/MFTECmd/MFTECmd.exe")
        records = parser.parse("$J")
    """

    @property
    def name(self) -> str:
        return "UsnJrnl_MFTECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows USN Journal - detailed file system changes"

    @property
    def index_name(self) -> str:
        return "forensic-usnjrnl"

    @property
    def artifact_type(self) -> str:
        return "usnjrnl"

    @property
    def database_table(self) -> str:
        return "usnjrnl"

    @property
    def fields(self) -> Dict[str, str]:
        return {
            "timestamp": "date_lenient",
            "filename": "text_keyword",
            "extension": "keyword",
            "file_path": "text",
            "entry_number": "integer",
            "parent_entry": "integer",
            "usn": "long",
            "operation": "keyword",
            "update_reasons": "text",
            "file_attributes": "keyword",
        }

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run MFTECmd on $J file and parse results."""
        # Find $J file - input can be file or directory
        if os.path.isfile(input_path):
            usn_file = input_path
        else:
            # Look for $J or $UsnJrnl in directory
            usn_files = self._find_files_in_dir(input_path, pattern='$J')
            if not usn_files:
                usn_files = self._find_files_in_dir(input_path, pattern='UsnJrnl')
            if not usn_files:
                usn_files = self._find_files_in_dir(input_path, pattern='J')
            usn_file = usn_files[0] if usn_files else None

        if not usn_file or not os.path.isfile(usn_file):
            self._safe_print(f"[{self.name}] $UsnJrnl:$J not found in: {input_path}")
            return []

        # MFTECmd with --usn flag processes USN Journal
        cmd = f'"{self.executable_path}" -f "{usn_file}" --csv "{self.output_dir}"'
        self._run_command(cmd, timeout=1800)  # USN can be very large, 30 min timeout

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            for row in self._read_csv(csv_file):
                record = {
                    'entry_number': row.get('EntryNumber', row.get('ParentEntryNumber', '')),
                    'parent_entry': row.get('ParentEntryNumber', ''),
                    'parent_path': row.get('ParentPath', ''),
                    'filename': row.get('Name', row.get('FileName', '')),
                    'extension': row.get('Extension', ''),
                    'usn': row.get('USN', row.get('Usn', '')),
                    'timestamp': row.get('UpdateTimestamp', row.get('Timestamp', '')),
                    'update_reasons': row.get('UpdateReasons', row.get('Reason', '')),
                    'update_sequence_number': row.get('UpdateSequenceNumber', ''),
                    'file_attributes': row.get('FileAttributes', row.get('Attributes', '')),
                    'source_info': row.get('SourceInfo', ''),
                    'security_id': row.get('SecurityId', ''),
                }
                records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize USN Journal record."""
        filename = self._safe_str(record.get('filename', ''))
        extension = self._safe_str(record.get('extension', '')).lower()
        parent_path = self._safe_str(record.get('parent_path', ''))

        # Construct full path
        if parent_path and filename:
            if not parent_path.endswith('\\'):
                parent_path += '\\'
            file_path = parent_path + filename
        else:
            file_path = filename

        # Parse update reasons to determine operation type
        reasons = self._safe_str(record.get('update_reasons', '')).upper()
        operation = "UNKNOWN"
        if 'FILE_CREATE' in reasons:
            operation = "CREATE"
        elif 'FILE_DELETE' in reasons:
            operation = "DELETE"
        elif 'RENAME' in reasons:
            operation = "RENAME"
        elif 'DATA_EXTEND' in reasons or 'DATA_OVERWRITE' in reasons:
            operation = "MODIFY"
        elif 'SECURITY_CHANGE' in reasons:
            operation = "SECURITY"
        elif 'CLOSE' in reasons:
            operation = "CLOSE"

        return {
            "artifact_type": "usnjrnl",
            "timestamp": self._safe_str(record.get('timestamp', '')),
            "filename": filename,
            "extension": extension,
            "file_path": self._safe_str(file_path, 1000),
            "entry_number": self._safe_int(record.get('entry_number', 0)),
            "parent_entry": self._safe_int(record.get('parent_entry', 0)),
            "usn": self._safe_int(record.get('usn', 0)),
            "operation": operation,
            "update_reasons": self._safe_str(record.get('update_reasons', '')),
            "file_attributes": self._safe_str(record.get('file_attributes', '')),
        }


# =============================================================================
# LEGACY ALIASES (for backward compatibility)
# =============================================================================

# Old class names for backward compatibility
PrefetchParser = Prefetch_PECmd_Parser
EventLogParser = EventLog_EvtxECmd_Parser
RegistryParser = Registry_RECmd_Parser
BrowserHistoryParser = Browser_SQLite_Parser
LnkParser = LNK_LECmd_Parser

# New parser aliases
MFTParser = MFT_MFTECmd_Parser
JumpListParser = JumpList_JLECmd_Parser
RecycleBinParser = RecycleBin_RBCmd_Parser
ShimcacheParser = Shimcache_AppCompat_Parser
AmcacheParserAlias = Amcache_Parser

# Enterprise level parser aliases
SRUMParser = SRUM_SrumECmd_Parser
PowerShellHistoryParser = PowerShellHistory_Parser
UsnJrnlParser = UsnJrnl_MFTECmd_Parser
