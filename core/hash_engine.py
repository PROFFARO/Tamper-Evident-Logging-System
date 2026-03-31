"""
Cryptographic Hash Chain Engine for the Tamper-Evident Logging System.

Implements SHA-256 hash chaining with deterministic canonicalization
to create an unbreakable sequence of linked log entries. Any modification
to a previous entry invalidates all subsequent hashes in the chain.

Algorithm:
    H_n = SHA-256( canonical(data_n) || H_{n-1} )

Where:
    - canonical(data_n) is the deterministic JSON serialization of entry data
    - H_{n-1} is the hash of the previous entry
    - || denotes string concatenation
"""

import hashlib
import json
from typing import Dict, Any, Optional


class HashEngine:
    """
    Core cryptographic engine for computing and verifying hash chains.
    
    Uses SHA-256 for hashing and deterministic JSON serialization
    (sorted keys, no extra whitespace) for canonicalization.
    """
    
    GENESIS_HASH = "0" * 64  # 64-character hex string of zeros
    
    @staticmethod
    def canonicalize(data: Dict[str, Any]) -> str:
        """
        Convert a dictionary to a canonical (deterministic) string representation.
        
        Uses JSON serialization with sorted keys and consistent formatting
        to ensure the same data always produces the same string representation,
        regardless of insertion order.
        
        Args:
            data: Dictionary containing log entry fields
            
        Returns:
            Canonical JSON string
            
        Raises:
            ValueError: If data is not a dictionary
            TypeError: If data contains non-serializable values
        """
        if not isinstance(data, dict):
            raise ValueError(f"Expected dict, got {type(data).__name__}")
        
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str
        )
    
    @staticmethod
    def compute_hash(canonical_data: str, previous_hash: str) -> str:
        """
        Compute the SHA-256 hash for a log entry in the chain.
        
        Concatenates the canonical data string with the previous entry's
        hash and produces a SHA-256 digest, creating a cryptographic link
        between consecutive entries.
        
        Args:
            canonical_data: Deterministic string representation of the entry
            previous_hash: SHA-256 hash of the previous entry (hex string)
            
        Returns:
            SHA-256 hash as a 64-character hexadecimal string
        """
        hash_input = f"{canonical_data}{previous_hash}".encode("utf-8")
        return hashlib.sha256(hash_input).hexdigest()
    
    @classmethod
    def compute_entry_hash(cls, entry_data: Dict[str, Any], previous_hash: Optional[str] = None) -> str:
        """
        Compute the hash for a complete log entry.
        
        Convenience method that handles canonicalization and hash computation
        in a single call.
        
        Args:
            entry_data: Dictionary of log entry fields (excluding hash fields)
            previous_hash: Hash of the previous entry; uses GENESIS_HASH if None
            
        Returns:
            SHA-256 hash as a 64-character hexadecimal string
        """
        if previous_hash is None:
            previous_hash = cls.GENESIS_HASH
        
        canonical = cls.canonicalize(entry_data)
        return cls.compute_hash(canonical, previous_hash)
    
    @classmethod
    def verify_entry_hash(cls, entry_data: Dict[str, Any], stored_hash: str, previous_hash: Optional[str] = None) -> bool:
        """
        Verify that a stored hash matches the recomputed hash for an entry.
        
        Args:
            entry_data: Dictionary of log entry fields
            stored_hash: The hash value stored in the database
            previous_hash: Hash of the previous entry
            
        Returns:
            True if the recomputed hash matches the stored hash
        """
        computed = cls.compute_entry_hash(entry_data, previous_hash)
        return computed == stored_hash
    
    @staticmethod
    def get_data_fields(entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract the hashable data fields from a complete log entry record.
        
        Removes chain-specific fields (hashes, signatures, internal ID) 
        that should not be part of the hashed content, returning only 
        the original event data.
        
        Args:
            entry: Complete log entry record from database
            
        Returns:
            Dictionary containing only the hashable data fields
        """
        exclude_fields = {"id", "current_hash", "previous_hash", "hmac_signature"}
        return {k: v for k, v in entry.items() if k not in exclude_fields}
