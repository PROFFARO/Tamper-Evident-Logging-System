# Tamper-Evident Logging System — Technical Report

## 1. Introduction

Audit logging forms the backbone of security monitoring in modern enterprise systems. From financial transactions to user authentication events, organisations rely on log records to maintain accountability, comply with regulatory frameworks, and investigate security incidents. However, the value of these logs depends entirely on their integrity. If an attacker can modify, delete, or reorder log entries without detection, the entire audit trail becomes unreliable.

This report describes the design, implementation, and analysis of a tamper-evident logging system that addresses these challenges. The system creates a cryptographic chain between consecutive log entries, making any unauthorised alteration immediately detectable. It draws inspiration from real-world secure audit logging implementations used in SIEM (Security Information and Event Management) platforms and blockchain-based integrity verification mechanisms.

The system was built using Python and Flask for the backend, SQLite for data storage, and a professional web dashboard using HTML, CSS, and JavaScript. The complete solution includes log creation, hash chain verification, tamper simulation capabilities, and comprehensive audit reporting.

## 2. Design Approach

### 2.1 Core Design Principles

The system was designed around four key principles: integrity assurance, authenticity verification, detection granularity, and operational simplicity.

Integrity assurance is achieved through SHA-256 hash chaining. Each log entry contains a hash computed from its own content concatenated with the hash of the previous entry. This creates an unbreakable sequence where modifying any historical entry invalidates all subsequent hashes in the chain, making tampering immediately detectable during verification.

Authenticity verification is implemented using HMAC-SHA256 (Hash-based Message Authentication Code). Beyond hash chaining, each entry receives an HMAC signature generated with a secret key. This prevents a sophisticated attacker from rebuilding a valid hash chain after modification, since they cannot generate correct HMAC signatures without possessing the secret key.

Detection granularity ensures the system can identify not just that tampering occurred, but precisely what type of tampering took place and where in the chain it happened. The verification engine distinguishes between content modifications, entry deletions, and entry reordering through separate detection mechanisms.

Operational simplicity was prioritised to ensure the system remains practical and deployable. The application uses SQLite for zero-configuration storage, requires only Flask as an external dependency, and provides a comprehensive web interface for all operations.

### 2.2 Cryptographic Hash Chain Design

The hash chain follows the principle established in academic literature on tamper-evident logging. For each log entry L_n, the hash H_n is computed as:

```
H_n = SHA-256( canonical(data_n) || H_{n-1} )
```

Where canonical(data_n) represents the deterministic JSON serialisation of the entry's data fields, H_{n-1} is the hash of the previous entry, and the double vertical bar denotes string concatenation. The first entry in the chain uses a genesis hash consisting of 64 zero characters, establishing the foundation of the chain.

Deterministic serialisation is critical for reliable verification. The system uses JSON with sorted keys and consistent separators (no extra whitespace) to ensure that identical data always produces an identical string representation, regardless of dictionary insertion order. Without this canonicalisation step, Python dictionaries with the same key-value pairs but different internal ordering could produce different hashes, leading to false tampering alerts.

### 2.3 HMAC Authentication Layer

The HMAC layer addresses a fundamental limitation of hash chains: if an attacker has full access to the database and knowledge of the hashing algorithm, they could theoretically modify an entry and then recompute all subsequent hashes to rebuild a valid chain. HMAC-SHA256 signatures prevent this attack by requiring possession of a secret key to generate valid authentication codes. The HMAC for each entry is computed as:

```
HMAC_n = HMAC-SHA256( secret_key, H_n )
```

The secret key is generated once when the system is first initialised and stored securely on the filesystem. In a production deployment, this key would be managed through a Hardware Security Module (HSM) or a cloud-based Key Management Service (KMS). The verification process uses constant-time comparison for HMAC checking to prevent timing-based side-channel attacks.

### 2.4 Database Schema

The database uses two primary tables. The log_entries table stores all event records with fields for sequential ID, ISO 8601 timestamp, event type, severity level, source system, description, JSON metadata, previous hash, current hash, and HMAC signature. Indexes are created on timestamp, event type, and severity to support efficient filtering and querying.

The anchors table stores integrity checkpoint records, capturing the hash state at specific points in time. Each anchor records the entry ID, the hash value at that position, the total chain length, and the creation timestamp. Anchors serve as trusted reference points for verifying that the chain state at a given moment matches what was expected.

## 3. Implementation Details

### 3.1 Backend Architecture

The backend follows a modular architecture with clear separation of concerns across five core modules.

The HashEngine module (hash_engine.py) handles all cryptographic operations. It provides methods for deterministic canonicalisation, hash computation, entry hash verification, and extraction of hashable data fields from complete database records. The canonicalisation method uses Python's json.dumps with sort_keys=True and minimal separators to ensure deterministic output. All hash operations use the hashlib library's SHA-256 implementation.

The HMACSigner module (hmac_signer.py) manages HMAC-SHA256 signature generation and verification. It uses Python's hmac library with constant-time comparison (hmac.compare_digest) to prevent timing attacks. The signer accepts a configurable secret key, defaulting to the application's configured key.

The Database module (database.py) provides SQLite connection management with context-managed connections, automatic schema initialisation, and typed query methods. It supports paginated retrieval with filtering by event type, severity, and text search. The module also includes tamper simulation methods that directly manipulate database records for demonstration purposes, bypassing the hash chain to create detectable inconsistencies.

The LogManager module (log_manager.py) orchestrates the creation of new log entries. When a new event is logged, the manager constructs the entry data, retrieves the previous entry's hash, computes the chain hash, generates the HMAC signature, and persists the complete record. It validates event types and severity levels against predefined lists to maintain data consistency.

The Verifier module (verifier.py) implements the comprehensive chain verification engine. It walks the entire chain from the genesis block, performing five checks on each entry: sequential ID continuity (detecting deletions), previous hash pointer validation (detecting chain breaks), hash chain integrity verification (detecting modifications), HMAC signature verification (detecting unauthorised entries), and chronological timestamp ordering (detecting reordering). The verification produces a structured report with per-entry results and aggregate statistics.

### 3.2 REST API Design

The Flask application exposes a RESTful API with endpoints grouped into four categories. The log management endpoints handle creation and retrieval of entries with pagination and filtering support. The verification endpoints trigger full chain verification or single-entry checks. The tamper simulation endpoints allow demonstration of modification, deletion, and reorder attacks. The utility endpoints provide statistics, anchor management, database reset, sample data seeding, and audit report export.

All API responses use JSON format with consistent error handling. Input validation catches missing required fields and invalid event types or severity levels, returning descriptive error messages with appropriate HTTP status codes.

### 3.3 Frontend Dashboard

The web interface was designed to provide a professional experience comparable to enterprise SIEM tools such as Grafana, Kibana, and Splunk. The interface uses a fixed sidebar navigation with organised sections for Monitoring, Security, and Management operations.

The Security Dashboard provides an overview with four stat cards showing total log entries, chain integrity status, security alert count, and integrity anchor count. Below these, three panels display recent activity with colour-coded severity indicators, event type distribution with horizontal bar charts, and severity breakdown.

The Log Explorer offers a data table with pagination, text search, and dropdown filters for event type and severity. Each row displays the entry ID, formatted timestamp, event type badge, severity badge with colour coding, source, truncated description, abbreviated hash, and a details button that opens a modal with full entry information including all hash values.

The Hash Chain Visualiser renders entries as connected blocks showing the previous hash and current hash of each entry, with arrow connectors illustrating the chain linkage. The genesis block receives special highlighting.

The Integrity Verification section features a prominent action button and displays comprehensive results with a colour-coded summary banner (green for intact, red for tampered), aggregate statistics, and per-entry verification results showing pass or fail status for each check category.

The Tamper Simulation Lab presents three attack cards (modification, deletion, reorder), each with input fields and execution buttons, followed by quick-action buttons for verification and database reset.

## 4. Analysis of Results

### 4.1 Verification Testing

The test suite contains ten test cases covering every critical aspect of the system. All tests pass consistently across multiple runs.

The canonicalisation tests confirm that dictionaries with identical key-value pairs but different insertion orders produce identical canonical strings. The hash consistency tests verify that the same input data always produces the same SHA-256 hash. The HMAC tests confirm that signatures verify correctly with the original key and fail with a different key.

The chain verification test creates five entries and confirms that the verifier reports all as valid with zero tampered entries. The modification detection test creates five entries, tampers with entry number three by changing its description directly in the database, and confirms that the verifier identifies the modification at the correct entry. The deletion detection test creates five entries, removes entry number three, and confirms the verifier reports the missing entry ID. The reorder detection test creates five entries, swaps the content of entries two and four, and confirms the verifier identifies the hash mismatches.

### 4.2 Detection Capabilities

The system successfully detects all three categories of tampering required by the specification.

For modifications, when an entry's content is changed without updating its hash, the recomputed hash differs from the stored hash, producing a HASH_MISMATCH error. This detection is reliable because even a single-character change in any data field produces a completely different SHA-256 hash due to the avalanche effect of cryptographic hash functions.

For deletions, the system uses two complementary detection methods. First, sequential ID gaps are identified when the verifier encounters a jump in entry IDs. Second, the chain break is detected because the next remaining entry's previous hash pointer references a hash that no longer exists in the expected position.

For reordering, the system detects both hash chain violations (since swapped content produces different hashes than originally computed) and chronological timestamp violations when entries appear out of temporal order.

### 4.3 Performance Analysis

The verification engine processes entries sequentially, giving it O(n) time complexity where n is the number of log entries. In testing with 25 sample entries, full chain verification completes in under 10 milliseconds. The SHA-256 and HMAC computations are extremely efficient, with Python's hashlib providing native C-optimised implementations.

The SQLite database supports efficient indexed queries for filtering and pagination. Write operations (new entry creation) require only a single INSERT statement after the hash computation, making the logging overhead minimal.

### 4.4 Security Considerations

The system provides tamper evidence rather than tamper proofing. An attacker with full system access could delete the entire database and replace it with a fabricated chain that has valid hash links. The HMAC authentication layer mitigates this by requiring possession of the secret key to generate valid signatures, but if the key is also compromised, this protection fails.

In a production deployment, several additional measures would strengthen the system: storing the HMAC key in a Hardware Security Module, replicating logs to multiple independent systems, periodically publishing anchor hashes to an external immutable ledger, implementing access controls to restrict database write operations, and using TLS for all API communications.

## 5. Conclusion

The tamper-evident logging system successfully implements all functional requirements specified in the task. It provides secure, cryptographically-linked audit logging with reliable detection of modifications, deletions, and reordering of log entries. The professional web dashboard enables intuitive management and verification operations, while the tamper simulation lab allows clear demonstration of the system's detection capabilities. The modular architecture, comprehensive test suite, and detailed documentation ensure the system is maintainable, extensible, and suitable for educational and demonstration purposes.

## References

1. Schneier, B., & Kelsey, J. (1999). Secure Audit Logs to Support Computer Forensics. ACM Transactions on Information and System Security (TISSEC), 2(2), 159-176.
2. Crosby, S. A., & Wallach, D. S. (2009). Efficient Data Structures for Tamper-Evident Logging. Proceedings of the 18th USENIX Security Symposium.
3. National Institute of Standards and Technology. (2015). FIPS PUB 180-4: Secure Hash Standard (SHS).
4. Krawczyk, H., Bellare, M., & Canetti, R. (1997). HMAC: Keyed-Hashing for Message Authentication. RFC 2104.
5. Python Software Foundation. (2024). hashlib — Secure hashes and message digests. Python 3.12 Documentation.
6. Flask Documentation. (2024). Flask Web Development Framework. Pallets Projects.
7. OWASP Foundation. (2023). Logging Cheat Sheet. OWASP Cheat Sheet Series.
