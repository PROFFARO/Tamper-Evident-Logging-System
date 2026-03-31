"""
HMAC Signing Module for the Tamper-Evident Logging System.

Provides HMAC-SHA256 authentication for log entry hashes.
This adds a layer of security beyond hash chaining — even if an attacker
rebuilds a valid hash chain after modification, they cannot generate
valid HMAC signatures without possessing the secret key.

This prevents:
    - Full chain replacement attacks
    - Insertion of fraudulent entries
    - Replay attacks with recomputed hashes
"""

import hmac
import hashlib
from typing import Optional

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import HMAC_SECRET_KEY


class HMACSigner:
    """
    HMAC-SHA256 signer for authenticating log entry hashes.
    
    Uses a secret key to generate and verify message authentication codes,
    ensuring that only authorized systems can create valid log entries.
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        """
        Initialize the HMAC signer.
        
        Args:
            secret_key: The secret key for HMAC computation.
                        Uses the configured key if not provided.
        """
        self._secret_key = (secret_key or HMAC_SECRET_KEY).encode("utf-8")
    
    def sign(self, hash_value: str) -> str:
        """
        Generate an HMAC-SHA256 signature for a hash value.
        
        Args:
            hash_value: The SHA-256 hash of a log entry (hex string)
            
        Returns:
            HMAC-SHA256 signature as a hexadecimal string
            
        Raises:
            ValueError: If hash_value is empty or None
        """
        if not hash_value:
            raise ValueError("Cannot sign an empty hash value")
        
        return hmac.new(
            self._secret_key,
            hash_value.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
    
    def verify(self, hash_value: str, signature: str) -> bool:
        """
        Verify an HMAC-SHA256 signature against a hash value.
        
        Uses constant-time comparison to prevent timing attacks.
        
        Args:
            hash_value: The SHA-256 hash of a log entry
            signature: The stored HMAC signature to verify
            
        Returns:
            True if the signature is valid for the given hash
        """
        if not hash_value or not signature:
            return False
        
        expected = self.sign(hash_value)
        return hmac.compare_digest(expected, signature)
