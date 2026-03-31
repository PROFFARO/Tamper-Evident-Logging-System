# 🛡️ Tamper-Evident Logging System

A secure, cryptographically-linked audit logging system that detects modifications, deletions, and reordering of log entries. Built with Python/Flask and a professional SIEM-inspired web dashboard.

## Features

- **SHA-256 Hash Chaining** — Each log entry is cryptographically linked to its predecessor
- **HMAC-SHA256 Authentication** — Prevents chain rebuilding attacks
- **Tamper Detection** — Detects modifications, deletions, and reordering
- **Professional Dashboard** — Grafana/Kibana-inspired dark UI with real-time monitoring
- **Tamper Simulation Lab** — Built-in tools to demonstrate attack detection
- **Integrity Anchors** — Checkpoint hashes for periodic verification
- **Export & Audit Reports** — Downloadable JSON verification reports

## Architecture

```
Log Entry N:
  H_n = SHA-256( canonical(data_n) || H_{n-1} )
  HMAC_n = HMAC-SHA256( secret_key, H_n )
```

Each entry stores: timestamp, event type, severity, source, description, metadata, previous hash, current hash, and HMAC signature.

## Quick Start

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Tamper-Evident-Logging-System.git
cd Tamper-Evident-Logging-System

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Access the Dashboard

Open your browser and navigate to: **http://localhost:5000**

### Seed Sample Data

Click the **"Seed Sample Data"** button on the dashboard to populate the system with 25 realistic log entries.

## Usage

### Adding Log Entries

Navigate to **Management → Add Entry** and fill in:
- **Event Type**: LOGIN_ATTEMPT, TRANSACTION, SECURITY_ALERT, etc.
- **Severity**: INFO, WARNING, ERROR, CRITICAL
- **Source**: Origin system (e.g., auth-service, web-portal)
- **Description**: Human-readable event description
- **Metadata**: Optional JSON key-value data

### Verifying Integrity

Navigate to **Security → Verify Integrity** and click **"Run Full Verification"**. The system checks:
1. Hash chain integrity (SHA-256)
2. HMAC signature authenticity
3. Sequential ID continuity (deletion detection)
4. Chronological ordering (reorder detection)

### Tamper Simulation

Navigate to **Security → Tamper Lab** to simulate attacks:
- **Modification Attack**: Change an entry's description directly in the database
- **Deletion Attack**: Remove an entry, creating a chain gap
- **Reorder Attack**: Swap two entries' content

After any attack, click **"Verify Chain Now"** to see detection results.

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/logs` | Add a new log entry |
| GET | `/api/logs` | List logs (paginated & filterable) |
| GET | `/api/logs/<id>` | Get a single entry |
| GET | `/api/verify` | Run full chain verification |
| GET | `/api/verify/<id>` | Verify a single entry |
| POST | `/api/tamper/modify/<id>` | Simulate modification |
| POST | `/api/tamper/delete/<id>` | Simulate deletion |
| POST | `/api/tamper/reorder` | Simulate reordering |
| GET | `/api/stats` | Get statistics |
| POST | `/api/anchor` | Create integrity anchor |
| GET | `/api/export` | Export audit report |

## Running Tests

```bash
python tests/test_all.py
```

Tests cover: canonicalization, hash consistency, HMAC verification, valid chain verification, modification detection, deletion detection, reorder detection, and chain linkage.

## Tech Stack

- **Backend**: Python 3.10+ / Flask
- **Cryptography**: hashlib (SHA-256), hmac (HMAC-SHA256)
- **Database**: SQLite
- **Frontend**: HTML5, Vanilla CSS, JavaScript
- **Typography**: Inter + JetBrains Mono (Google Fonts)

## Project Structure

```
├── app.py              # Flask application & REST API
├── config.py           # Configuration & secret key management
├── requirements.txt    # Python dependencies
├── core/
│   ├── hash_engine.py  # SHA-256 hash chain engine
│   ├── hmac_signer.py  # HMAC-SHA256 signing module
│   ├── database.py     # SQLite database manager
│   ├── log_manager.py  # High-level log operations
│   └── verifier.py     # Chain integrity verification
├── templates/
│   └── index.html      # Web dashboard template
├── static/
│   ├── css/style.css   # Professional dark theme CSS
│   └── js/app.js       # Frontend application logic
├── tests/
│   └── test_all.py     # Comprehensive test suite
└── docs/
    └── REPORT.md       # Detailed technical report
```

## License

GNU General Public License v3.0
