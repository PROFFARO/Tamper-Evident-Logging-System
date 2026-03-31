# 🛡️ Tamper-Evident Logging System

A secure, cryptographically-linked real-time audit logging system that detects modifications, deletions, and reordering of log entries. Built with Python/Flask and featuring a built-in background agent for active Windows OS and network threat monitoring.

## Features

- **Live Host Monitoring** — Built-in background agent actively monitors actual system events (Windows logins, process creation, and network listeners).
- **SHA-256 Hash Chaining** — Every active log entry is cryptographically linked to its predecessor.
- **HMAC-SHA256 Authentication** — Prevents attackers from forging or rebuilding the chain.
- **Tamper Detection** — Instantly flags any database modifications, row deletions, or temporal reordering.
- **Professional Dashboard** — A sleek, enterprise-grade dark UI for real-time monitoring.
- **Tamper Simulation Lab** — Built-in tools for security teams to demonstrate and test attack detection logic.
- **Integrity Anchors** — Checkpoint hashes for verifying long-term chain state against external or historical backups.

## Cryptographic Architecture

```text
Log Entry N:
  H_n = SHA-256( canonical(data_n) || H_{n-1} )
  HMAC_n = HMAC-SHA256( secret_key, H_n )
```

Each entry stores: `timestamp`, `event_type`, `severity`, `source`, `description`, `metadata`, `previous_hash`, `current_hash`, and an `hmac_signature`.

## Quick Start

### Prerequisites
- Python 3.10+
- `pip`
- *Note: For full OS event monitoring, running on Windows is required. Running as Administrator is recommended to access the Windows Security Event Log.*

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

## Usage

### Real-Time OS Monitoring (The Host Agent)
The dashboard includes an **Agent Status** badge. By default, the SIEM starts a background thread that scans the host machine every 15 seconds for:
- Windows authentication events (Logons/Logoffs)
- New processes and resource utilization warning thresholds
- Suspicious network activity (e.g., active listeners on suspected backdoor ports like 8888 or 4444).
You can toggle this Agent on or off directly from the dashboard.

### Adding Manual Logs
Navigate to the form below the dashboard to inject manual application logs with custom JSON metadata. These will be appended safely to the chain alongside the automated host logs.

### Verifying Integrity
Navigate to the **Integrity Verification** section and click **"Run Full Verification"**. The system checks:
1. Hash chain algorithms verify `SHA-256` integrity.
2. Signatures validate the secret `HMAC-SHA256` keys.
3. ID sequences are verified to detect deleted entries.
4. Timestamps are cross-checked for temporal reordering.

### Tamper Simulation
Navigate to the **Tamper Simulation Lab** to safely break your chain and observe detection behavior:
- **Modification Attack**: Safely alters an entry's payload directly in the database, bypassing the hashing engine.
- **Deletion Attack**: Deletes an entry, creating a physical ID and hash gap.
- **Reorder Attack**: Swaps two entries temporally but leaves them intact.

After any attack run the **Full Verification** to see the system pinpoint the exact location of the tampering.

## API Reference

### Core Logs
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/logs` | Add a new manual log entry |
| GET | `/api/logs` | List logs (paginated & filterable) |
| GET | `/api/logs/<id>` | Get a single entry's full detail |

### Validation & Stats
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/verify` | Run full chain verification |
| GET | `/api/stats` | Get full dashboard statistics |
| POST | `/api/anchor` | Create a cryptographic anchor point |
| GET | `/api/export` | Export the audit report as JSON |

### Host Agent Control
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/agent/status` | Get current agent health and cycle count |
| POST | `/api/agent/start` | Spin up the monitoring thread |
| POST | `/api/agent/stop` | Terminate the monitoring thread |

### Tamper Controls
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/tamper/modify/<id>` | Simulate database payload modification |
| POST | `/api/tamper/delete/<id>` | Simulate hard database deletion |
| POST | `/api/tamper/reorder` | Simulate a swap between two IDs |


## Tech Stack

- **Backend**: Python 3.10+ / Flask / threading
- **Host Monitoring**: `psutil`, `subprocess` (PowerShell queries)
- **Cryptography**: `hashlib` (SHA-256), `hmac` (HMAC-SHA256)
- **Database**: SQLite3 (`data/tamper_evident.db`)
- **Frontend**: HTML5, Vanilla CSS, JS

## Project Structure

```text
├── app.py              # Flask server & thread management
├── config.py           # Configuration & secret key management
├── requirements.txt    # Python dependencies (Flask, psutil)
├── agent/
│   └── host_agent.py   # Background OS monitoring thread
├── core/
│   ├── hash_engine.py  # SHA-256 hash chain calculation
│   ├── hmac_signer.py  # HMAC-SHA256 signing module
│   ├── database.py     # SQLite database connection & migrations
│   ├── log_manager.py  # Thread-safe log operations
│   └── verifier.py     # Complete chain integrity verification logic
├── templates/
│   └── index.html      # Professional UI layout
└── static/
    ├── css/style.css   # Clean, enterprise styling
    └── js/app.js       # Dynamic AJAX API calls
```

## License

GNU General Public License v3.0
