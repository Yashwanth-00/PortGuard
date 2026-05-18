"""
PortGuard - Web Dashboard
Flask app serving real-time monitoring data via REST API + web UI.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import logging
from flask import Flask, render_template, jsonify
from datetime import datetime

logger = logging.getLogger("portguard.dashboard")

app = Flask(__name__)

# These are set by main.py after initializing the engine
_monitor_engine = None
_threat_engine = None
_notifier = None


def init_dashboard(monitor_engine, threat_engine, notifier):
    global _monitor_engine, _threat_engine, _notifier
    _monitor_engine = monitor_engine
    _threat_engine = threat_engine
    _notifier = notifier


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    """System health + uptime."""
    if not _monitor_engine:
        return jsonify({"error": "Engine not initialized"}), 503

    stats = _monitor_engine.stats
    return jsonify({
        "status": "RUNNING" if _monitor_engine.is_running else "STOPPED",
        "uptime": _monitor_engine.uptime,
        "scans_performed": stats["scans_performed"],
        "ports_opened": stats["ports_opened"],
        "ports_closed": stats["ports_closed"],
        "threats_detected": stats["threats_detected"],
        "alerts_sent": _notifier.alert_count if _notifier else 0,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


@app.route("/api/ports")
def api_ports():
    """List all currently active ports."""
    if not _monitor_engine:
        return jsonify([])

    ports = _monitor_engine.current_ports
    result = []
    malicious_db = _threat_engine.malicious_port_list if _threat_engine else {}

    for port_num, port_info in sorted(ports.items()):
        is_malicious = str(port_num) in malicious_db
        entry = {
            **port_info.to_dict(),
            "is_malicious": is_malicious,
            "malicious_info": malicious_db.get(str(port_num)),
        }
        result.append(entry)

    return jsonify(result)


@app.route("/api/threats")
def api_threats():
    """Return all detected threats."""
    if not _threat_engine:
        return jsonify([])

    threats = [t.to_dict() for t in _threat_engine.threat_history]
    return jsonify(threats[::-1])  # Most recent first


@app.route("/api/threats/summary")
def api_threats_summary():
    """Return threat statistics."""
    if not _threat_engine:
        return jsonify({})
    return jsonify(_threat_engine.get_threat_summary())


@app.route("/api/logs")
def api_logs():
    """Return recent log lines from portguard.log."""
    log_path = os.path.join(os.path.dirname(__file__), "..", "logs", "portguard.log")
    lines = []
    try:
        with open(log_path, "r") as f:
            lines = f.readlines()[-100:]
    except Exception:
        pass
    return jsonify({"lines": [l.rstrip() for l in lines]})


if __name__ == "__main__":
    # Standalone mode with mock data for testing the dashboard UI
    from unittest.mock import MagicMock
    mock_engine = MagicMock()
    mock_engine.is_running = True
    mock_engine.uptime = "00:05:12"
    mock_engine.stats = {"scans_performed": 42, "ports_opened": 7, "ports_closed": 2, "threats_detected": 3}
    mock_engine.current_ports = {}

    mock_threat = MagicMock()
    mock_threat.threat_history = []
    mock_threat.malicious_port_list = {}
    mock_threat.get_threat_summary.return_value = {}

    mock_notifier = MagicMock()
    mock_notifier.alert_count = 3

    init_dashboard(mock_engine, mock_threat, mock_notifier)
    app.run(debug=True, port=5000)
