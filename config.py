"""
Configuration module for the Tamper-Evident Logging System.

Manages application-wide settings including cryptographic keys,
database paths, and runtime configuration.
"""

import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Database Configuration ---
DATABASE_PATH = os.path.join(BASE_DIR, "data", "tamper_evident.db")

# --- Cryptographic Configuration ---
# HMAC secret key — in production, load from environment variable or vault
# For demo purposes, we generate a persistent key stored in a file
SECRET_KEY_FILE = os.path.join(BASE_DIR, "data", ".secret_key")

def get_or_create_secret_key():
    """
    Retrieve existing HMAC secret key or generate a new one.
    The key is stored persistently so HMAC signatures remain valid
    across application restarts.
    """
    os.makedirs(os.path.dirname(SECRET_KEY_FILE), exist_ok=True)
    
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r") as f:
            return f.read().strip()
    
    # Generate a cryptographically secure 64-character hex key
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(key)
    
    return key

HMAC_SECRET_KEY = get_or_create_secret_key()

# --- Application Configuration ---
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = True

# --- Logging Configuration ---
GENESIS_HASH = "0" * 64  # SHA-256 zero hash for the first entry
HASH_ALGORITHM = "sha256"
ENTRIES_PER_PAGE = 20

# --- Anchor Configuration ---
ANCHOR_INTERVAL = 50  # Auto-anchor every N entries
