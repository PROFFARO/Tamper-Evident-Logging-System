"""
Tamper-Evident Logging System — Flask Application

A secure logging system with cryptographic hash chaining, HMAC authentication,
and a professional web dashboard for log management and integrity verification.

API Endpoints:
    GET  /                      — Serve the web dashboard
    POST /api/logs              — Add a new log entry
    GET  /api/logs              — List logs (paginated, filterable)
    GET  /api/logs/<id>         — Get a single log entry
    GET  /api/verify            — Run full chain verification
    GET  /api/verify/<id>       — Verify a single entry
    POST /api/tamper/modify/<id>— Simulate modifying an entry
    POST /api/tamper/delete/<id>— Simulate deleting an entry
    POST /api/tamper/reorder    — Simulate reordering entries
    GET  /api/stats             — Get log statistics
    POST /api/anchor            — Create integrity anchor
    GET  /api/anchors           — List all anchors
    POST /api/reset             — Reset database (demo)
    POST /api/seed              — Seed sample data (demo)
    GET  /api/export            — Export verification report
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
import json
import random
from datetime import datetime, timezone, timedelta

from core.log_manager import LogManager
from core.verifier import Verifier
from core.database import Database
from core.hmac_signer import HMACSigner

# Initialize Flask app
app = Flask(__name__, static_folder="static", template_folder="templates")

# Initialize core components
db = Database()
signer = HMACSigner()
log_manager = LogManager(db=db, signer=signer)
verifier = Verifier(db=db, signer=signer)


# ============================================================
#  Page Routes
# ============================================================

@app.route("/")
def index():
    """Serve the web dashboard."""
    return render_template("index.html")


# ============================================================
#  Log Entry API
# ============================================================

@app.route("/api/logs", methods=["POST"])
def add_log():
    """
    Add a new log entry to the chain.
    
    Request JSON:
        event_type: str (required)
        severity: str (required)
        source: str (required)
        description: str (required)
        metadata: dict (optional)
    
    Returns:
        201: Created entry with hash and signature
        400: Validation error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400
        
        required_fields = ["event_type", "severity", "source", "description"]
        missing = [f for f in required_fields if not data.get(f)]
        if missing:
            return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400
        
        entry = log_manager.add_entry(
            event_type=data["event_type"],
            severity=data["severity"],
            source=data["source"],
            description=data["description"],
            metadata=data.get("metadata", {})
        )
        
        return jsonify({"success": True, "entry": entry}), 201
    
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Internal error: {str(e)}"}), 500


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    List log entries with pagination and filtering.
    
    Query params:
        page: int (default 1)
        per_page: int (default 20)
        event_type: str (optional filter)
        severity: str (optional filter)
        search: str (optional text search)
    
    Returns:
        200: Paginated list of entries with metadata
    """
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        event_type = request.args.get("event_type", None)
        severity = request.args.get("severity", None)
        search = request.args.get("search", None)
        
        entries, total = log_manager.get_entries(
            page=page, per_page=per_page,
            event_type=event_type, severity=severity, search=search
        )
        
        return jsonify({
            "entries": entries,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page if per_page > 0 else 0
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logs/<int:entry_id>", methods=["GET"])
def get_log(entry_id):
    """Get a single log entry by ID."""
    entry = log_manager.get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Entry not found"}), 404
    return jsonify({"entry": entry})


# ============================================================
#  Verification API
# ============================================================

@app.route("/api/verify", methods=["GET"])
def verify_chain():
    """
    Run full chain integrity verification.
    
    Checks every entry for:
        - Hash chain integrity
        - HMAC signature validity
        - Sequential ID continuity
        - Chronological ordering
    
    Returns:
        200: Full verification report
    """
    try:
        report = verifier.verify_full_chain()
        return jsonify(report.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/verify/<int:entry_id>", methods=["GET"])
def verify_entry(entry_id):
    """Verify a single entry's integrity."""
    try:
        result = verifier.verify_single_entry(entry_id)
        if not result:
            return jsonify({"error": "Entry not found"}), 404
        return jsonify(result.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
#  Tamper Simulation API (Demo)
# ============================================================

@app.route("/api/tamper/modify/<int:entry_id>", methods=["POST"])
def tamper_modify(entry_id):
    """
    [DEMO] Simulate modifying a log entry.
    
    Directly overwrites the description field in the database,
    bypassing the hash chain. This creates a detectable hash mismatch.
    """
    try:
        data = request.get_json() or {}
        new_description = data.get("description", "[TAMPERED] This entry has been maliciously modified")
        
        success = db.tamper_modify_entry(entry_id, new_description)
        if not success:
            return jsonify({"error": "Entry not found"}), 404
        
        return jsonify({
            "success": True,
            "message": f"Entry {entry_id} has been tampered with (modified). "
                       f"Run verification to detect the tampering.",
            "tamper_type": "MODIFICATION"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tamper/delete/<int:entry_id>", methods=["POST"])
def tamper_delete(entry_id):
    """
    [DEMO] Simulate deleting a log entry.
    
    Removes the entry from the database, creating a gap in the
    sequential IDs and breaking the hash chain.
    """
    try:
        success = db.tamper_delete_entry(entry_id)
        if not success:
            return jsonify({"error": "Entry not found"}), 404
        
        return jsonify({
            "success": True,
            "message": f"Entry {entry_id} has been deleted. "
                       f"Run verification to detect the missing entry.",
            "tamper_type": "DELETION"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tamper/reorder", methods=["POST"])
def tamper_reorder():
    """
    [DEMO] Simulate reordering log entries.
    
    Swaps the content of two entries while keeping their positions,
    creating a timestamp ordering violation.
    """
    try:
        data = request.get_json() or {}
        id_a = data.get("id_a")
        id_b = data.get("id_b")
        
        if not id_a or not id_b:
            return jsonify({"error": "Must provide id_a and id_b"}), 400
        
        success = db.tamper_swap_entries(id_a, id_b)
        if not success:
            return jsonify({"error": "One or both entries not found"}), 404
        
        return jsonify({
            "success": True,
            "message": f"Entries {id_a} and {id_b} have been swapped. "
                       f"Run verification to detect the reordering.",
            "tamper_type": "REORDER"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
#  Statistics & Anchors API
# ============================================================

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get aggregate log statistics."""
    try:
        stats = log_manager.get_statistics()
        stats["chain_length"] = log_manager.get_chain_length()
        stats["event_type_options"] = log_manager.get_event_types()
        stats["severity_options"] = log_manager.get_severity_levels()
        
        # Get latest anchor
        latest_anchor = verifier.get_anchors()
        stats["latest_anchor"] = latest_anchor[0] if latest_anchor else None
        stats["total_anchors"] = len(latest_anchor)
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/anchor", methods=["POST"])
def create_anchor():
    """Create an integrity anchor at the current chain position."""
    try:
        anchor = verifier.create_anchor()
        if not anchor:
            return jsonify({"error": "No entries to anchor"}), 400
        return jsonify({"success": True, "anchor": anchor}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/anchors", methods=["GET"])
def get_anchors():
    """List all integrity anchors."""
    try:
        anchors = verifier.get_anchors()
        return jsonify({"anchors": anchors})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
#  Utility API
# ============================================================

@app.route("/api/reset", methods=["POST"])
def reset_database():
    """[DEMO] Reset the entire database."""
    try:
        db.reset_database()
        return jsonify({"success": True, "message": "Database has been reset"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/seed", methods=["POST"])
def seed_data():
    """
    [DEMO] Seed the database with realistic sample log entries.
    
    Generates a variety of event types, severities, and sources
    to demonstrate the system's capabilities.
    """
    try:
        # Reset first
        db.reset_database()
        
        # Reinitialize components with fresh database
        fresh_log_manager = LogManager(db=db, signer=signer)
        
        sample_events = [
            # Login events
            ("LOGIN_ATTEMPT", "INFO", "auth-service", "User admin@company.com initiated login from 192.168.1.100", {"ip": "192.168.1.100", "user_agent": "Chrome/120.0"}),
            ("LOGIN_SUCCESS", "INFO", "auth-service", "User admin@company.com authenticated successfully via MFA", {"ip": "192.168.1.100", "mfa_method": "TOTP"}),
            ("LOGIN_FAILURE", "WARNING", "auth-service", "Failed login attempt for user john.doe@company.com - invalid password", {"ip": "10.0.0.55", "attempt_count": "3"}),
            ("LOGIN_FAILURE", "WARNING", "auth-service", "Failed login attempt for user john.doe@company.com - account locked", {"ip": "10.0.0.55", "attempt_count": "5"}),
            ("SECURITY_ALERT", "CRITICAL", "ids-sensor", "Brute force attack detected from IP 10.0.0.55 targeting user john.doe", {"ip": "10.0.0.55", "rule": "BF-001"}),
            
            # User activity
            ("USER_ACTIVITY", "INFO", "web-portal", "User admin browsed dashboard at /admin/overview", {"path": "/admin/overview", "session_id": "sess_abc123"}),
            ("DATA_ACCESS", "INFO", "api-gateway", "User admin queried customer records - 150 results returned", {"endpoint": "/api/customers", "result_count": "150"}),
            ("DATA_MODIFICATION", "WARNING", "api-gateway", "User admin updated customer #4521 payment method", {"customer_id": "4521", "field": "payment_method"}),
            ("DATA_ACCESS", "INFO", "api-gateway", "User analyst exported financial report Q4-2025", {"report_type": "financial", "period": "Q4-2025"}),
            
            # Transactions
            ("TRANSACTION", "INFO", "payment-service", "Payment processed: $2,450.00 from account ACC-7891 to ACC-3456", {"amount": "2450.00", "currency": "USD", "tx_id": "TXN-20250331-001"}),
            ("TRANSACTION", "INFO", "payment-service", "Payment processed: $890.50 from account ACC-1234 to ACC-5678", {"amount": "890.50", "currency": "USD", "tx_id": "TXN-20250331-002"}),
            ("TRANSACTION", "ERROR", "payment-service", "Transaction declined: insufficient funds for account ACC-9012", {"amount": "5000.00", "currency": "USD", "reason": "insufficient_funds"}),
            
            # System events
            ("SYSTEM_EVENT", "INFO", "scheduler", "Automated backup completed successfully - 2.3GB archived", {"backup_size": "2.3GB", "duration": "4m32s"}),
            ("SYSTEM_EVENT", "WARNING", "monitor", "High CPU utilization detected on server prod-web-03: 94%", {"server": "prod-web-03", "cpu_percent": "94"}),
            ("CONFIGURATION_CHANGE", "WARNING", "admin-panel", "Firewall rule updated: port 8443 opened for IP range 10.0.0.0/24", {"rule_id": "FW-042", "action": "ALLOW"}),
            ("SYSTEM_EVENT", "INFO", "deployer", "Application version 3.2.1 deployed to production cluster", {"version": "3.2.1", "cluster": "prod-us-east"}),
            
            # Security events
            ("SECURITY_ALERT", "ERROR", "waf", "SQL injection attempt blocked from IP 203.0.113.42", {"ip": "203.0.113.42", "payload": "' OR 1=1--", "rule": "SQLi-001"}),
            ("SECURITY_ALERT", "CRITICAL", "siem", "Privilege escalation detected: user intern01 gained admin access", {"user": "intern01", "previous_role": "intern", "new_role": "admin"}),
            ("DATA_ACCESS", "WARNING", "dlp-agent", "Sensitive data download detected: PII export by user analyst02", {"user": "analyst02", "data_class": "PII", "records": "5000"}),
            ("LOGOUT", "INFO", "auth-service", "User admin@company.com logged out - session duration 2h15m", {"session_duration": "2h15m"}),
            
            # More realistic events
            ("LOGIN_SUCCESS", "INFO", "auth-service", "User sarah.jones@company.com authenticated via SSO", {"ip": "172.16.0.88", "sso_provider": "Okta"}),
            ("USER_ACTIVITY", "INFO", "web-portal", "User sarah.jones ran inventory reconciliation report", {"report": "inventory_reconciliation"}),
            ("ERROR", "ERROR", "api-gateway", "Database connection timeout after 30s on replica db-read-02", {"database": "db-read-02", "timeout": "30s"}),
            ("SYSTEM_EVENT", "INFO", "cert-manager", "SSL certificate renewed for *.company.com - expires 2026-06-30", {"domain": "*.company.com", "expiry": "2026-06-30"}),
            ("TRANSACTION", "INFO", "payment-service", "Refund processed: $150.00 to account ACC-7891 for TXN-20250330-015", {"amount": "150.00", "original_tx": "TXN-20250330-015"}),
        ]
        
        entries_created = []
        for event_type, severity, source, description, metadata in sample_events:
            entry = fresh_log_manager.add_entry(
                event_type=event_type,
                severity=severity,
                source=source,
                description=description,
                metadata=metadata
            )
            entries_created.append(entry["id"])
        
        return jsonify({
            "success": True,
            "message": f"Seeded {len(entries_created)} sample log entries",
            "entry_count": len(entries_created)
        }), 201
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export", methods=["GET"])
def export_report():
    """
    Export a complete verification report as JSON.
    
    Includes all entries, verification results, and system metadata.
    """
    try:
        report = verifier.verify_full_chain()
        stats = log_manager.get_statistics()
        anchors = verifier.get_anchors()
        
        export = {
            "system": "Tamper-Evident Logging System",
            "version": "1.0.0",
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "statistics": stats,
            "anchors": anchors,
            "verification_report": report.to_dict(),
        }
        
        return jsonify(export)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/meta", methods=["GET"])
def get_meta():
    """Get system metadata and configuration info."""
    return jsonify({
        "system_name": "Tamper-Evident Logging System",
        "version": "1.0.0",
        "hash_algorithm": "SHA-256",
        "signing_algorithm": "HMAC-SHA256",
        "database": "SQLite",
        "event_types": log_manager.get_event_types(),
        "severity_levels": log_manager.get_severity_levels(),
    })


# ============================================================
#  Run Application
# ============================================================

if __name__ == "__main__":
    from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG
    
    print("\n" + "=" * 60)
    print("  TAMPER-EVIDENT LOGGING SYSTEM v1.0.0")
    print("=" * 60)
    print(f"  Dashboard:  http://localhost:{FLASK_PORT}")
    print(f"  API Base:   http://localhost:{FLASK_PORT}/api")
    print(f"  Hash Algo:  SHA-256")
    print(f"  Signing:    HMAC-SHA256")
    print("=" * 60 + "\n")
    
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
