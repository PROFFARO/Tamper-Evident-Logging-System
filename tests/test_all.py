"""
Unit tests for the Hash Engine, Verifier, and tamper detection.
Run with: python -m pytest tests/ -v
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.hash_engine import HashEngine
from core.hmac_signer import HMACSigner
from core.database import Database
from core.log_manager import LogManager
from core.verifier import Verifier

# Use a temporary test database
TEST_DB_PATH = os.path.join(os.path.dirname(__file__), "test_tamper_evident.db")


def get_test_components():
    """Create fresh test database and components."""
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    db = Database(db_path=TEST_DB_PATH)
    signer = HMACSigner(secret_key="test_secret_key_12345")
    log_mgr = LogManager(db=db, signer=signer)
    verifier = Verifier(db=db, signer=signer)
    return db, signer, log_mgr, verifier


def cleanup():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)


# ============================================================
#  Test 1: Deterministic Canonicalization
# ============================================================
def test_canonicalize_deterministic():
    """Same data in different insertion order must produce identical canonical form."""
    data_a = {"zebra": "1", "alpha": "2", "middle": "3"}
    data_b = {"alpha": "2", "middle": "3", "zebra": "1"}
    
    assert HashEngine.canonicalize(data_a) == HashEngine.canonicalize(data_b)
    print("  ✓ Canonicalization is deterministic (order-independent)")


# ============================================================
#  Test 2: Hash Computation Consistency
# ============================================================
def test_hash_consistency():
    """Same input must always produce the same hash."""
    data = {"event": "test", "value": "123"}
    prev_hash = "a" * 64
    
    h1 = HashEngine.compute_entry_hash(data, prev_hash)
    h2 = HashEngine.compute_entry_hash(data, prev_hash)
    
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 produces 64 hex characters
    print("  ✓ Hash computation is consistent and correct length")


# ============================================================
#  Test 3: Genesis Hash
# ============================================================
def test_genesis_hash():
    """First entry should use genesis hash (all zeros) as previous hash."""
    data = {"event": "genesis_test"}
    
    h_with_genesis = HashEngine.compute_entry_hash(data, HashEngine.GENESIS_HASH)
    h_with_none = HashEngine.compute_entry_hash(data, None)
    
    assert h_with_genesis == h_with_none
    print("  ✓ Genesis hash handling works correctly")


# ============================================================
#  Test 4: Hash Changes on Data Modification
# ============================================================
def test_hash_changes_on_modification():
    """Any modification to data must produce a different hash."""
    prev_hash = "b" * 64
    data_original = {"message": "original data"}
    data_modified = {"message": "modified data"}
    
    h_original = HashEngine.compute_entry_hash(data_original, prev_hash)
    h_modified = HashEngine.compute_entry_hash(data_modified, prev_hash)
    
    assert h_original != h_modified
    print("  ✓ Hash changes when data is modified")


# ============================================================
#  Test 5: HMAC Signing & Verification
# ============================================================
def test_hmac_sign_verify():
    """HMAC signature must verify with correct key and fail with wrong key."""
    signer = HMACSigner(secret_key="correct_key")
    hash_val = "abc123def456"
    
    signature = signer.sign(hash_val)
    assert signer.verify(hash_val, signature) is True
    
    wrong_signer = HMACSigner(secret_key="wrong_key")
    assert wrong_signer.verify(hash_val, signature) is False
    print("  ✓ HMAC signing and verification works correctly")


# ============================================================
#  Test 6: Valid Chain Passes Verification
# ============================================================
def test_valid_chain_verification():
    """A chain built normally must pass all verification checks."""
    db, signer, log_mgr, verifier = get_test_components()
    
    for i in range(5):
        log_mgr.add_entry(
            event_type="SYSTEM_EVENT", severity="INFO",
            source="test", description=f"Test event {i+1}"
        )
    
    report = verifier.verify_full_chain()
    assert report.chain_intact is True
    assert report.total_entries == 5
    assert report.valid_entries == 5
    assert report.tampered_entries == 0
    print("  ✓ Valid chain passes all verification checks")
    cleanup()


# ============================================================
#  Test 7: Modification Detection
# ============================================================
def test_detect_modification():
    """Modified entry must be detected by verification."""
    db, signer, log_mgr, verifier = get_test_components()
    
    for i in range(5):
        log_mgr.add_entry(
            event_type="LOGIN_ATTEMPT", severity="INFO",
            source="test", description=f"Login event {i+1}"
        )
    
    # Tamper: modify entry #3
    db.tamper_modify_entry(3, "HACKED: This was changed!")
    
    report = verifier.verify_full_chain()
    assert report.chain_intact is False
    assert report.tampered_entries > 0
    assert report.first_tamper_point == 3
    
    # Verify the specific entry
    entry_result = report.entries[2]  # Entry #3 (0-indexed)
    assert entry_result.hash_valid is False
    print("  ✓ Modified entry detected correctly")
    cleanup()


# ============================================================
#  Test 8: Deletion Detection
# ============================================================
def test_detect_deletion():
    """Deleted entry must be detected by verification."""
    db, signer, log_mgr, verifier = get_test_components()
    
    for i in range(5):
        log_mgr.add_entry(
            event_type="TRANSACTION", severity="INFO",
            source="test", description=f"Transaction {i+1}"
        )
    
    # Tamper: delete entry #3
    db.tamper_delete_entry(3)
    
    report = verifier.verify_full_chain()
    assert report.chain_intact is False
    assert 3 in report.missing_entries
    print("  ✓ Deleted entry detected correctly")
    cleanup()


# ============================================================
#  Test 9: Reorder Detection
# ============================================================
def test_detect_reorder():
    """Swapped entries must be detected by verification."""
    db, signer, log_mgr, verifier = get_test_components()
    
    for i in range(5):
        log_mgr.add_entry(
            event_type="USER_ACTIVITY", severity="INFO",
            source="test", description=f"Activity {i+1}"
        )
    
    # Tamper: swap entries 2 and 4
    db.tamper_swap_entries(2, 4)
    
    report = verifier.verify_full_chain()
    assert report.chain_intact is False
    assert report.tampered_entries > 0
    print("  ✓ Reordered entries detected correctly")
    cleanup()


# ============================================================
#  Test 10: End-to-End Chain Building
# ============================================================
def test_chain_linkage():
    """Each entry's previous_hash must match the prior entry's current_hash."""
    db, signer, log_mgr, verifier = get_test_components()
    
    entries = []
    for i in range(5):
        e = log_mgr.add_entry(
            event_type="DATA_ACCESS", severity="INFO",
            source="test", description=f"Access {i+1}"
        )
        entries.append(e)
    
    # Verify chain linkage
    assert entries[0]["previous_hash"] == HashEngine.GENESIS_HASH
    for i in range(1, len(entries)):
        assert entries[i]["previous_hash"] == entries[i-1]["current_hash"]
    
    print("  ✓ Chain linkage is correct (each entry links to previous)")
    cleanup()


# ============================================================
#  Run All Tests
# ============================================================
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  TAMPER-EVIDENT LOGGING SYSTEM — Test Suite")
    print("=" * 60 + "\n")
    
    tests = [
        test_canonicalize_deterministic,
        test_hash_consistency,
        test_genesis_hash,
        test_hash_changes_on_modification,
        test_hmac_sign_verify,
        test_valid_chain_verification,
        test_detect_modification,
        test_detect_deletion,
        test_detect_reorder,
        test_chain_linkage,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1
    
    cleanup()
    
    print(f"\n{'=' * 60}")
    print(f"  Results: {passed} passed, {failed} failed, {len(tests)} total")
    print(f"{'=' * 60}\n")
    
    sys.exit(0 if failed == 0 else 1)
