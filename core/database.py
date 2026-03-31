"""
Database Module for the Tamper-Evident Logging System.

Manages SQLite database connections, schema creation, and provides
CRUD operations for log entries and integrity anchors.

The database schema is designed to support:
    - Sequential log entry storage with hash chain references
    - Integrity anchor checkpoints for periodic verification
    - Efficient querying with pagination and filtering
"""

import sqlite3
import os
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATABASE_PATH


class Database:
    """
    SQLite database manager for tamper-evident log storage.
    
    Provides context-managed connections, automatic schema initialization,
    and typed query methods for log entries and anchors.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to SQLite database file. 
                     Uses configured path if not provided.
        """
        self.db_path = db_path or DATABASE_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._initialize_schema()
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for database connections.
        
        Yields a connection with row_factory set to sqlite3.Row
        for dictionary-like access to query results.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _initialize_schema(self):
        """Create database tables if they don't exist."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS log_entries (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT    NOT NULL,
                    event_type      TEXT    NOT NULL,
                    severity        TEXT    NOT NULL DEFAULT 'INFO',
                    source          TEXT    NOT NULL,
                    description     TEXT    NOT NULL,
                    metadata        TEXT    DEFAULT '{}',
                    previous_hash   TEXT    NOT NULL,
                    current_hash    TEXT    NOT NULL,
                    hmac_signature  TEXT    NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS anchors (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id        INTEGER NOT NULL,
                    anchor_hash     TEXT    NOT NULL,
                    entry_count     INTEGER NOT NULL,
                    created_at      TEXT    NOT NULL,
                    FOREIGN KEY (entry_id) REFERENCES log_entries(id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_log_timestamp 
                    ON log_entries(timestamp);
                CREATE INDEX IF NOT EXISTS idx_log_event_type 
                    ON log_entries(event_type);
                CREATE INDEX IF NOT EXISTS idx_log_severity 
                    ON log_entries(severity);
            """)
    
    # --- Log Entry Operations ---
    
    def insert_entry(self, entry: Dict[str, Any]) -> int:
        """
        Insert a new log entry into the database.
        
        Args:
            entry: Dictionary containing all log entry fields
            
        Returns:
            The auto-generated ID of the inserted entry
        """
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO log_entries 
                    (timestamp, event_type, severity, source, description,
                     metadata, previous_hash, current_hash, hmac_signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry["timestamp"],
                entry["event_type"],
                entry["severity"],
                entry["source"],
                entry["description"],
                entry.get("metadata", "{}"),
                entry["previous_hash"],
                entry["current_hash"],
                entry["hmac_signature"]
            ))
            return cursor.lastrowid
    
    def get_entry(self, entry_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a single log entry by ID.
        
        Args:
            entry_id: The unique identifier of the entry
            
        Returns:
            Dictionary of entry fields, or None if not found
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM log_entries WHERE id = ?", (entry_id,)
            ).fetchone()
            return dict(row) if row else None
    
    def get_all_entries(self) -> List[Dict[str, Any]]:
        """
        Retrieve all log entries in chronological order.
        
        Returns:
            List of entry dictionaries ordered by ID
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM log_entries ORDER BY id ASC"
            ).fetchall()
            return [dict(row) for row in rows]
    
    def get_entries_paginated(self, page: int = 1, per_page: int = 20,
                               event_type: Optional[str] = None,
                               severity: Optional[str] = None,
                               search: Optional[str] = None) -> Tuple[List[Dict], int]:
        """
        Retrieve log entries with pagination and optional filtering.
        
        Args:
            page: Page number (1-indexed)
            per_page: Number of entries per page
            event_type: Filter by event type
            severity: Filter by severity level
            search: Search in description and source fields
            
        Returns:
            Tuple of (list of entry dicts, total count)
        """
        conditions = []
        params = []
        
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if search:
            conditions.append("(description LIKE ? OR source LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        with self._get_connection() as conn:
            # Get total count
            count_row = conn.execute(
                f"SELECT COUNT(*) as total FROM log_entries WHERE {where_clause}",
                params
            ).fetchone()
            total = count_row["total"]
            
            # Get paginated results
            offset = (page - 1) * per_page
            rows = conn.execute(
                f"""SELECT * FROM log_entries 
                    WHERE {where_clause} 
                    ORDER BY id DESC 
                    LIMIT ? OFFSET ?""",
                params + [per_page, offset]
            ).fetchall()
            
            return [dict(row) for row in rows], total
    
    def get_last_entry(self) -> Optional[Dict[str, Any]]:
        """
        Retrieve the most recent log entry.
        
        Returns:
            Dictionary of the last entry, or None if no entries exist
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM log_entries ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None
    
    def get_entry_count(self) -> int:
        """Get the total number of log entries."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM log_entries").fetchone()
            return row["cnt"]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Compute aggregate statistics for the log database.
        
        Returns:
            Dictionary with event type counts, severity counts,
            total entries, and time range.
        """
        with self._get_connection() as conn:
            total = conn.execute(
                "SELECT COUNT(*) as cnt FROM log_entries"
            ).fetchone()["cnt"]
            
            event_types = conn.execute("""
                SELECT event_type, COUNT(*) as cnt 
                FROM log_entries 
                GROUP BY event_type 
                ORDER BY cnt DESC
            """).fetchall()
            
            severities = conn.execute("""
                SELECT severity, COUNT(*) as cnt 
                FROM log_entries 
                GROUP BY severity 
                ORDER BY cnt DESC
            """).fetchall()
            
            time_range = conn.execute("""
                SELECT MIN(timestamp) as earliest, MAX(timestamp) as latest 
                FROM log_entries
            """).fetchone()
            
            recent = conn.execute("""
                SELECT * FROM log_entries ORDER BY id DESC LIMIT 5
            """).fetchall()
            
            return {
                "total_entries": total,
                "event_types": {row["event_type"]: row["cnt"] for row in event_types},
                "severities": {row["severity"]: row["cnt"] for row in severities},
                "earliest_entry": time_range["earliest"],
                "latest_entry": time_range["latest"],
                "recent_entries": [dict(row) for row in recent]
            }
    
    # --- Tamper Simulation (Demo Only) ---
    
    def tamper_modify_entry(self, entry_id: int, new_description: str) -> bool:
        """
        [DEMO] Directly modify a log entry's description in the database.
        
        This simulates a tamper attack by bypassing the hash chain.
        The modification will be detectable during verification.
        
        Args:
            entry_id: ID of the entry to modify
            new_description: New description to overwrite with
            
        Returns:
            True if the entry was found and modified
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE log_entries SET description = ? WHERE id = ?",
                (new_description, entry_id)
            )
            return cursor.rowcount > 0
    
    def tamper_delete_entry(self, entry_id: int) -> bool:
        """
        [DEMO] Delete a log entry from the database.
        
        This simulates a deletion attack. The missing entry will
        cause a chain break detectable during verification.
        
        Args:
            entry_id: ID of the entry to delete
            
        Returns:
            True if the entry was found and deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM log_entries WHERE id = ?", (entry_id,)
            )
            return cursor.rowcount > 0
    
    def tamper_swap_entries(self, id_a: int, id_b: int) -> bool:
        """
        [DEMO] Swap the data of two log entries to simulate reordering.
        
        Swaps descriptions, event types, and sources between two entries
        while keeping their IDs and hashes intact, creating a detectable
        inconsistency.
        
        Args:
            id_a: ID of the first entry
            id_b: ID of the second entry
            
        Returns:
            True if both entries existed and were swapped
        """
        with self._get_connection() as conn:
            a = conn.execute("SELECT * FROM log_entries WHERE id = ?", (id_a,)).fetchone()
            b = conn.execute("SELECT * FROM log_entries WHERE id = ?", (id_b,)).fetchone()
            
            if not a or not b:
                return False
            
            conn.execute("""
                UPDATE log_entries 
                SET description = ?, event_type = ?, source = ? 
                WHERE id = ?
            """, (b["description"], b["event_type"], b["source"], id_a))
            
            conn.execute("""
                UPDATE log_entries 
                SET description = ?, event_type = ?, source = ? 
                WHERE id = ?
            """, (a["description"], a["event_type"], a["source"], id_b))
            
            return True
    
    # --- Anchor Operations ---
    
    def insert_anchor(self, anchor: Dict[str, Any]) -> int:
        """Insert a new integrity anchor checkpoint."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO anchors (entry_id, anchor_hash, entry_count, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                anchor["entry_id"],
                anchor["anchor_hash"],
                anchor["entry_count"],
                anchor["created_at"]
            ))
            return cursor.lastrowid
    
    def get_anchors(self) -> List[Dict[str, Any]]:
        """Retrieve all integrity anchors."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM anchors ORDER BY id DESC"
            ).fetchall()
            return [dict(row) for row in rows]
    
    def get_latest_anchor(self) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent anchor."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM anchors ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None
    
    def reset_database(self):
        """
        [DEMO] Reset the entire database by dropping and recreating tables.
        Used after tamper simulations.
        """
        with self._get_connection() as conn:
            conn.executescript("""
                DROP TABLE IF EXISTS anchors;
                DROP TABLE IF EXISTS log_entries;
            """)
        self._initialize_schema()
