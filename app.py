"""
Tamper-Evident Logging System — Flask Application

A secure logging system with cryptographic hash chaining, HMAC authentication,
a real-time host agent for live log collection, and a professional web dashboard.

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
    POST /api/agent/start       — Start the host agent
    POST /api/agent/stop        — Stop the host agent
    GET  /api/agent/status      — Get agent status
    POST /api/reset             — Reset database
    GET  /api/export            — Export verification report
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
import json
import os
import sys
import atexit
from datetime import datetime, timezone

# ============================================================
#  Session Logging Setup
# ============================================================
class LoggerTee:
    """Intercepts terminal output and simultaneously writes it to a log file."""
    def __init__(self, filename, original_stream):
        self.filename = filename
        self.original_stream = original_stream
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        self.log_file = open(self.filename, "a", encoding="utf-8")
        
    def write(self, message):
        self.original_stream.write(message)
        self.log_file.write(message)
        self.log_file.flush()
        
    def flush(self):
        self.original_stream.flush()
        self.log_file.flush()

    def close(self):
        self.log_file.close()

# Start saving everything printed to the terminal into a Session file
session_log_path = os.path.join("logs", f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
sys.stdout = LoggerTee(session_log_path, sys.stdout)
sys.stderr = LoggerTee(session_log_path, sys.stderr)

def cleanup_loggers():
    if hasattr(sys.stdout, 'close'): sys.stdout.close()
    if hasattr(sys.stderr, 'close'): sys.stderr.close()

atexit.register(cleanup_loggers)

from core.log_manager import LogManager
from core.verifier import Verifier
from core.database import Database
from core.hmac_signer import HMACSigner
from agent.host_agent import HostAgent

# Initialize Flask app
app = Flask(__name__, static_folder="static", template_folder="templates")

# Initialize core components
db = Database()
signer = HMACSigner()
log_manager = LogManager(db=db, signer=signer)
verifier = Verifier(db=db, signer=signer)

# Initialize host agent with callback to log_manager
def agent_log_callback(event_type, severity, source, description, metadata):
    """Callback used by the host agent to push events into the chain."""
    try:
        log_manager.add_entry(event_type, severity, source, description, metadata)
        print(f"[SESSION LOG] AGENT EVENT ADDED: {event_type} - {description}")
    except Exception as e:
        print(f"[SESSION LOG] AGENT FAILED: {e}")

host_agent = HostAgent(log_callback=agent_log_callback, interval=15)


@app.route("/")
def index():
    """Serve the web dashboard."""
    return render_template("index.html")


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
        print(f"\n[SESSION LOG] MANUAL EVENT ADDED: {data['event_type']} - {data['description']}")
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
        print(f"\n[SESSION LOG] CHAIN VERIFIED | Status: {'VALID' if report.chain_intact else 'TAMPERED'} | Scanned: {report.valid_entries}")
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
        print(f"\n[SESSION LOG] TAMPER SIMULATION: Modification Attack explicitly executed on ID {entry_id}")
        
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
        print(f"\n[SESSION LOG] TAMPER SIMULATION: Deletion Attack explicitly executed on ID {entry_id}")
        
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
        print(f"\n[SESSION LOG] TAMPER SIMULATION: Reorder Attack explicitly executed between ID {id_a} and ID {id_b}")
        
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


# ============================================================
#  Host Agent API
# ============================================================

@app.route("/api/agent/start", methods=["POST"])
def start_agent():
    """Start the real-time host agent."""
    try:
        data = request.get_json() or {}
        interval = data.get("interval", 15)
        host_agent._interval = max(5, min(300, int(interval)))
        host_agent.start()
        print(f"\n[SESSION LOG] HOST AGENT ACTIVATED | Interval: {host_agent._interval}s")
        return jsonify({"success": True, "message": "Host agent started", "status": host_agent.status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/stop", methods=["POST"])
def stop_agent():
    """Stop the real-time host agent."""
    try:
        host_agent.stop()
        print("\n[SESSION LOG] HOST AGENT DEACTIVATED")
        return jsonify({"success": True, "message": "Host agent stopped", "status": host_agent.status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/status", methods=["GET"])
def agent_status():
    """Get the current agent status."""
    return jsonify(host_agent.status)


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
        "agent": host_agent.status,
    })


# ============================================================
#  Run Application
# ============================================================

if __name__ == "__main__":
    from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG
    import os
    
    print("\n" + "=" * 60)
    print("  TAMPER-EVIDENT LOGGING SYSTEM v1.0.0")
    print("=" * 60)
    print(f"  Dashboard:  http://localhost:{FLASK_PORT}")
    print(f"  API Base:   http://localhost:{FLASK_PORT}/api")
    print(f"  Host Agent: Auto-starting (15s interval)")
    print(f"  Hash Algo:  SHA-256 + HMAC-SHA256")
    print("=" * 60 + "\n")
    
    # Auto-start the host agent (only in the main process, not the reloader)
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not FLASK_DEBUG:
        host_agent.start()
    
    # Disable reloader to prevent duplicate agent instances
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG, use_reloader=False)

