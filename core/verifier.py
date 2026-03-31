"""
Integrity Verification Engine for the Tamper-Evident Logging System.

Performs comprehensive chain verification to detect:
    - Modified entries (hash mismatch)
    - Deleted entries (ID gaps / chain breaks)
    - Reordered entries (chronological inconsistencies)
    - Unauthorized entries (HMAC signature failures)

The verifier walks the entire chain from the genesis block,
recomputing each hash and comparing it against the stored value.
Any discrepancy is recorded with detailed diagnostic information.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from .hash_engine import HashEngine
from .hmac_signer import HMACSigner
from .database import Database


class VerificationResult:
    """
    Structured result of a single entry verification check.
    
    Attributes:
        entry_id: The log entry ID being verified
        is_valid: Whether all checks passed
        hash_valid: Whether the hash chain link is valid
        hmac_valid: Whether the HMAC signature is valid
        sequence_valid: Whether the entry is in correct sequence
        timestamp_valid: Whether the timestamp ordering is correct
        error_message: Description of the failure, if any
        expected_hash: The recomputed hash (for diagnostics)
        stored_hash: The hash stored in the database
    """
    
    def __init__(self, entry_id: int):
        self.entry_id = entry_id
        self.is_valid = True
        self.hash_valid = True
        self.hmac_valid = True
        self.sequence_valid = True
        self.timestamp_valid = True
        self.error_message = ""
        self.expected_hash = ""
        self.stored_hash = ""
        self.issues = []
    
    def add_issue(self, issue_type: str, message: str):
        """Record a verification failure."""
        self.is_valid = False
        self.issues.append({"type": issue_type, "message": message})
        if self.error_message:
            self.error_message += "; "
        self.error_message += message
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for API responses."""
        return {
            "entry_id": self.entry_id,
            "is_valid": self.is_valid,
            "hash_valid": self.hash_valid,
            "hmac_valid": self.hmac_valid,
            "sequence_valid": self.sequence_valid,
            "timestamp_valid": self.timestamp_valid,
            "error_message": self.error_message,
            "expected_hash": self.expected_hash,
            "stored_hash": self.stored_hash,
            "issues": self.issues,
        }


class ChainVerificationReport:
    """
    Comprehensive report of the full chain verification.
    
    Aggregates individual entry results and provides summary statistics.
    """
    
    def __init__(self):
        self.entries: List[VerificationResult] = []
        self.total_entries = 0
        self.valid_entries = 0
        self.tampered_entries = 0
        self.missing_entries = []
        self.reordered_entries = []
        self.chain_intact = True
        self.first_tamper_point = None
        self.verification_timestamp = datetime.now(timezone.utc).isoformat()
        self.duration_ms = 0
    
    def add_result(self, result: VerificationResult):
        """Add an entry verification result to the report."""
        self.entries.append(result)
        self.total_entries += 1
        if result.is_valid:
            self.valid_entries += 1
        else:
            self.tampered_entries += 1
            self.chain_intact = False
            if self.first_tamper_point is None:
                self.first_tamper_point = result.entry_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for API responses."""
        return {
            "chain_intact": self.chain_intact,
            "total_entries": self.total_entries,
            "valid_entries": self.valid_entries,
            "tampered_entries": self.tampered_entries,
            "missing_entries": self.missing_entries,
            "reordered_entries": self.reordered_entries,
            "first_tamper_point": self.first_tamper_point,
            "verification_timestamp": self.verification_timestamp,
            "duration_ms": self.duration_ms,
            "entries": [e.to_dict() for e in self.entries],
        }


class Verifier:
    """
    Chain integrity verification engine.
    
    Walks the entire hash chain from genesis, recomputing hashes,
    validating HMAC signatures, checking sequence continuity,
    and verifying chronological ordering.
    """
    
    def __init__(self, db: Optional[Database] = None, signer: Optional[HMACSigner] = None):
        """
        Initialize the verifier.
        
        Args:
            db: Database instance
            signer: HMAC signer for signature verification
        """
        self.db = db or Database()
        self.signer = signer or HMACSigner()
        self.hash_engine = HashEngine()
    
    def verify_full_chain(self) -> ChainVerificationReport:
        """
        Perform complete chain verification on all log entries.
        
        Checks performed for each entry:
            1. Hash chain integrity (recomputed hash matches stored hash)
            2. HMAC signature authenticity
            3. Sequential ID continuity (detects deletions)
            4. Chronological timestamp ordering (detects reordering)
        
        Returns:
            ChainVerificationReport with detailed per-entry results
        """
        import time
        start_time = time.time()
        
        report = ChainVerificationReport()
        entries = self.db.get_all_entries()
        
        if not entries:
            report.duration_ms = round((time.time() - start_time) * 1000, 2)
            return report
        
        previous_hash = HashEngine.GENESIS_HASH
        previous_id = 0
        previous_timestamp = None
        
        for entry in entries:
            result = VerificationResult(entry["id"])
            
            # === Check 1: Sequential ID continuity ===
            if entry["id"] != previous_id + 1:
                result.sequence_valid = False
                missing_ids = list(range(previous_id + 1, entry["id"]))
                result.add_issue(
                    "DELETION_DETECTED",
                    f"Missing entry IDs: {missing_ids}. "
                    f"Expected ID {previous_id + 1}, found {entry['id']}"
                )
                report.missing_entries.extend(missing_ids)
            
            # === Check 2: Previous hash pointer ===
            if entry["previous_hash"] != previous_hash:
                result.add_issue(
                    "CHAIN_BREAK",
                    f"Previous hash mismatch. Entry points to "
                    f"{entry['previous_hash'][:16]}... but chain expects "
                    f"{previous_hash[:16]}..."
                )
            
            # === Check 3: Hash chain integrity ===
            entry_data = HashEngine.get_data_fields(entry)
            expected_hash = self.hash_engine.compute_entry_hash(
                entry_data, entry["previous_hash"]
            )
            result.expected_hash = expected_hash
            result.stored_hash = entry["current_hash"]
            
            if expected_hash != entry["current_hash"]:
                result.hash_valid = False
                result.add_issue(
                    "HASH_MISMATCH",
                    f"Content has been modified. "
                    f"Expected hash {expected_hash[:16]}... "
                    f"but found {entry['current_hash'][:16]}..."
                )
            
            # === Check 4: HMAC signature verification ===
            if not self.signer.verify(entry["current_hash"], entry["hmac_signature"]):
                result.hmac_valid = False
                result.add_issue(
                    "HMAC_FAILURE",
                    f"HMAC signature verification failed. "
                    f"Entry may have been created by an unauthorized source."
                )
            
            # === Check 5: Chronological ordering ===
            if previous_timestamp is not None:
                try:
                    current_ts = datetime.fromisoformat(entry["timestamp"])
                    prev_ts = datetime.fromisoformat(previous_timestamp)
                    if current_ts < prev_ts:
                        result.timestamp_valid = False
                        result.add_issue(
                            "REORDER_DETECTED",
                            f"Timestamp {entry['timestamp']} is earlier than "
                            f"previous entry's {previous_timestamp}"
                        )
                        report.reordered_entries.append(entry["id"])
                except (ValueError, TypeError):
                    pass
            
            report.add_result(result)
            
            # Update chain state for next iteration
            # Use the STORED hash (not recomputed) as previous_hash
            # to isolate each entry's verification
            previous_hash = entry["current_hash"]
            previous_id = entry["id"]
            previous_timestamp = entry["timestamp"]
        
        report.duration_ms = round((time.time() - start_time) * 1000, 2)
        return report
    
    def verify_single_entry(self, entry_id: int) -> Optional[VerificationResult]:
        """
        Verify a single log entry's integrity.
        
        Checks the entry's hash against its content and verifies
        its HMAC signature. For full chain integrity, use verify_full_chain().
        
        Args:
            entry_id: ID of the entry to verify
            
        Returns:
            VerificationResult, or None if entry not found
        """
        entry = self.db.get_entry(entry_id)
        if not entry:
            return None
        
        result = VerificationResult(entry_id)
        
        # Recompute hash
        entry_data = HashEngine.get_data_fields(entry)
        expected_hash = self.hash_engine.compute_entry_hash(
            entry_data, entry["previous_hash"]
        )
        result.expected_hash = expected_hash
        result.stored_hash = entry["current_hash"]
        
        if expected_hash != entry["current_hash"]:
            result.hash_valid = False
            result.add_issue(
                "HASH_MISMATCH",
                f"Content modified. Expected {expected_hash[:16]}... "
                f"got {entry['current_hash'][:16]}..."
            )
        
        if not self.signer.verify(entry["current_hash"], entry["hmac_signature"]):
            result.hmac_valid = False
            result.add_issue("HMAC_FAILURE", "HMAC signature verification failed")
        
        return result
    
    def create_anchor(self) -> Optional[Dict[str, Any]]:
        """
        Create an integrity anchor at the current chain position.
        
        An anchor records the hash of the latest entry as a checkpoint.
        This allows future verification to confirm the chain state at
        this point in time.
        
        Returns:
            Anchor dictionary, or None if no entries exist
        """
        last_entry = self.db.get_last_entry()
        if not last_entry:
            return None
        
        anchor = {
            "entry_id": last_entry["id"],
            "anchor_hash": last_entry["current_hash"],
            "entry_count": self.db.get_entry_count(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        anchor_id = self.db.insert_anchor(anchor)
        anchor["id"] = anchor_id
        return anchor
    
    def get_anchors(self) -> List[Dict[str, Any]]:
        """Retrieve all integrity anchors."""
        return self.db.get_anchors()
