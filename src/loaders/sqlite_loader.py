# -*- coding: utf-8 -*-
"""
SQLite Loader - Local backup storage for forensic data
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional


class SQLiteLoader:
    """Saves forensic data to local SQLite database as backup"""

    def __init__(self, db_path: str = "output/forensic_data.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database with tables for all artifact types"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Generic records table - stores all artifact types
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS forensic_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                artifact_type TEXT,
                timestamp TEXT,
                data JSON,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create indexes for fast queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_case_id ON forensic_records(case_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_artifact_type ON forensic_records(artifact_type)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON forensic_records(timestamp)
        ''')

        # Metadata table for case info
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS case_metadata (
                case_id TEXT PRIMARY KEY,
                image_path TEXT,
                created_at TEXT,
                artifacts TEXT,
                record_counts JSON
            )
        ''')

        conn.commit()
        conn.close()
        print(f"[SQLiteLoader] Database initialized: {self.db_path}")

    def load_records(self, artifact_type: str, records: List[Dict], case_id: str = "default") -> int:
        """Load records into SQLite database"""
        if not records:
            return 0

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        count = 0
        for record in records:
            try:
                # Extract timestamp if present
                timestamp = record.get('timestamp', '')

                # Store full record as JSON
                cursor.execute('''
                    INSERT INTO forensic_records (case_id, artifact_type, timestamp, data)
                    VALUES (?, ?, ?, ?)
                ''', (case_id, artifact_type, timestamp, json.dumps(record, ensure_ascii=False)))
                count += 1
            except Exception as e:
                print(f"[SQLiteLoader] Error inserting record: {e}")

        conn.commit()
        conn.close()

        print(f"[SQLiteLoader] Loaded {count} {artifact_type} records to {self.db_path}")
        return count

    def delete_by_case(self, case_id: str, artifact_type: Optional[str] = None):
        """Delete records for a case (optionally only specific artifact type)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if artifact_type:
            cursor.execute('''
                DELETE FROM forensic_records WHERE case_id = ? AND artifact_type = ?
            ''', (case_id, artifact_type))
        else:
            cursor.execute('''
                DELETE FROM forensic_records WHERE case_id = ?
            ''', (case_id,))

        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        print(f"[SQLiteLoader] Deleted {deleted} records for case {case_id}")
        return deleted

    def query(self, artifact_type: Optional[str] = None, case_id: Optional[str] = None,
              search_text: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        """Query records from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT data FROM forensic_records WHERE 1=1"
        params = []

        if artifact_type:
            query += " AND artifact_type = ?"
            params.append(artifact_type)

        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)

        if search_text:
            query += " AND data LIKE ?"
            params.append(f"%{search_text}%")

        query += f" LIMIT {limit}"

        cursor.execute(query, params)
        results = []

        for row in cursor.fetchall():
            try:
                results.append(json.loads(row[0]))
            except:
                pass

        conn.close()
        return results

    def get_counts(self, case_id: Optional[str] = None) -> Dict[str, int]:
        """Get record counts by artifact type"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if case_id:
            cursor.execute('''
                SELECT artifact_type, COUNT(*) FROM forensic_records
                WHERE case_id = ? GROUP BY artifact_type
            ''', (case_id,))
        else:
            cursor.execute('''
                SELECT artifact_type, COUNT(*) FROM forensic_records
                GROUP BY artifact_type
            ''')

        counts = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        return counts

    def save_case_metadata(self, case_id: str, image_path: str, artifacts: List[str],
                          record_counts: Dict[str, int]):
        """Save case metadata"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO case_metadata (case_id, image_path, created_at, artifacts, record_counts)
            VALUES (?, ?, ?, ?, ?)
        ''', (case_id, image_path, datetime.now().isoformat(), ','.join(artifacts),
              json.dumps(record_counts)))

        conn.commit()
        conn.close()

    def get_case_metadata(self, case_id: str) -> Optional[Dict]:
        """Get case metadata"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM case_metadata WHERE case_id = ?', (case_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                'case_id': row[0],
                'image_path': row[1],
                'created_at': row[2],
                'artifacts': row[3].split(',') if row[3] else [],
                'record_counts': json.loads(row[4]) if row[4] else {}
            }
        return None

    def export_to_json(self, output_path: str, case_id: Optional[str] = None) -> str:
        """Export all records to JSON file"""
        records = self.query(case_id=case_id, limit=1000000)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(records, f, ensure_ascii=False, indent=2)

        print(f"[SQLiteLoader] Exported {len(records)} records to {output_path}")
        return output_path
