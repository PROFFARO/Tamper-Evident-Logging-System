"""
Log Manager for the Tamper-Evident Logging System.

Provides high-level operations for creating cryptographically chained
log entries. Orchestrates the hash engine, HMAC signer, and database
to ensure every new entry is securely linked to the chain.

Each entry creation follows this process:
    1. Construct the entry data (timestamp, event type, etc.)
    2. Retrieve the previous entry's hash (or use genesis hash)
    3. Compute the SHA-256 hash chain link
    4. Generate an HMAC signature for authentication
    5. Persist the complete entry to the database
"""

import json
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple

from .hash_engine import HashEngine
from .hmac_signer import HMACSigner
from .database import Database


class LogManager:
    """
    High-level manager for creating and retrieving tamper-evident log entries.
    
    Coordinates hash chaining, HMAC signing, and database persistence
    to maintain a cryptographically linked log chain.
    """
    
    EVENT_TYPES = [
        "LOGIN_ATTEMPT",
        "LOGIN_SUCCESS",
        "LOGIN_FAILURE",
        "LOGOUT",
        "USER_ACTIVITY",
        "DATA_ACCESS",
        "DATA_MODIFICATION",
        "TRANSACTION",
        "SYSTEM_EVENT",
        "SECURITY_ALERT",
        "CONFIGURATION_CHANGE",
        "ERROR",
    ]
    
    SEVERITY_LEVELS = ["INFO", "WARNING", "ERROR", "CRITICAL"]
    
    def __init__(self, db: Optional[Database] = None, signer: Optional[HMACSigner] = None):
        """
        Initialize the LogManager.
        
        Args:
            db: Database instance. Creates a new one if not provided.
            signer: HMAC signer instance. Creates a new one if not provided.
        """
        self.db = db or Database()
        self.signer = signer or HMACSigner()
        self.hash_engine = HashEngine()
        self._lock = threading.Lock()  # Thread-safety for chain writes
    
    def add_entry(self, event_type: str, severity: str, source: str,
                  description: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Create a new log entry and add it to the hash chain.
        
        Generates a timestamp, computes the chain hash linking to the
        previous entry, creates an HMAC signature, and persists everything
        to the database.
        
        Args:
            event_type: Category of event (e.g., LOGIN_ATTEMPT, TRANSACTION)
            severity: Severity level (INFO, WARNING, ERROR, CRITICAL)
            source: Origin system or user identifier
            description: Human-readable event description
            metadata: Optional dictionary of additional key-value data
            
        Returns:
            Complete entry dictionary including generated ID, hash, and signature
            
        Raises:
            ValueError: If event_type or severity is not recognized
        """
        # Validate inputs
        if event_type not in self.EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type '{event_type}'. "
                f"Must be one of: {', '.join(self.EVENT_TYPES)}"
            )
        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity '{severity}'. "
                f"Must be one of: {', '.join(self.SEVERITY_LEVELS)}"
            )
        
        # Thread-safe critical section: read last hash → compute → write
        with self._lock:
            # Build entry data
            timestamp = datetime.now(timezone.utc).isoformat()
            metadata_str = json.dumps(metadata or {}, sort_keys=True)
            
            entry_data = {
                "timestamp": timestamp,
                "event_type": event_type,
                "severity": severity,
                "source": source,
                "description": description,
                "metadata": metadata_str,
            }
            
            # Get previous hash from the last entry in the chain
            last_entry = self.db.get_last_entry()
            previous_hash = last_entry["current_hash"] if last_entry else HashEngine.GENESIS_HASH
            
            # Compute the chain hash
            current_hash = self.hash_engine.compute_entry_hash(entry_data, previous_hash)
            
            # Generate HMAC signature
            hmac_signature = self.signer.sign(current_hash)
            
            # Assemble the complete entry
            complete_entry = {
                **entry_data,
                "previous_hash": previous_hash,
                "current_hash": current_hash,
                "hmac_signature": hmac_signature,
            }
            
            # Persist to database
            entry_id = self.db.insert_entry(complete_entry)
            complete_entry["id"] = entry_id
        
        return complete_entry
    
    def get_entries(self, page: int = 1, per_page: int = 20,
                    event_type: Optional[str] = None,
                    severity: Optional[str] = None,
                    search: Optional[str] = None) -> Tuple[List[Dict], int]:
        """
        Retrieve paginated and optionally filtered log entries.
        
        Args:
            page: Page number (1-indexed)
            per_page: Entries per page
            event_type: Filter by event type
            severity: Filter by severity
            search: Search string for description/source
            
        Returns:
            Tuple of (list of entries, total count)
        """
        return self.db.get_entries_paginated(page, per_page, event_type, severity, search)
    
    def get_entry(self, entry_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single entry by ID."""
        return self.db.get_entry(entry_id)
    
    def get_all_entries(self) -> List[Dict[str, Any]]:
        """Retrieve all entries in chronological order."""
        return self.db.get_all_entries()
    
    def get_chain_length(self) -> int:
        """Get the total number of entries in the chain."""
        return self.db.get_entry_count()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregate log statistics."""
        return self.db.get_statistics()
    
    def get_event_types(self) -> List[str]:
        """Get all valid event type options."""
        return self.EVENT_TYPES
    
    def get_severity_levels(self) -> List[str]:
        """Get all valid severity level options."""
        return self.SEVERITY_LEVELS
