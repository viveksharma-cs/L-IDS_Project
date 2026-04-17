"""
main.py — Flask web application for the L-IDS Dashboard.

Provides a real-time web dashboard showing:
  - Live VM resource metrics (CPU, Memory, Disk I/O, Network)
  - Anomaly score timeline
  - Alert feed with severity levels
  - Detection statistics
  - Attack simulation controls to demonstrate the system
"""

import csv
import io
from flask import Flask, render_template, jsonify, request, send_file

# ... previous imports ...
from flask_socketio import SocketIO
import threading
import json
import argparse

from data_generator import VMMetricsGenerator
from collector_vbox import VBoxCollector
from preprocessor import MetricsPreprocessor
from detector import AnomalyDetector

# ── App Setup ──────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = "lids-secret-key-2025"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ── Core Components ────────────────────────────────────────────────────────

# Parse arguments for mode selection
parser = argparse.ArgumentParser(description="L-IDS Dashboard Server")
parser.add_argument("--mode", type=str, choices=["sim", "real"], default="sim", help="Mode: sim or real")
parser.add_argument("--vm", type=str, default="deta", help="Name of the VirtualBox VM (only for real mode)")
args, unknown = parser.parse_known_args()

# Initialize data source
if args.mode == 'real':
    print(f"[*] Starting in REAL-TIME mode monitoring VM: {args.vm}")
    data_source = VBoxCollector(vm_name=args.vm)
else:
    print("[*] Starting in SIMULATION mode")
    data_source = VMMetricsGenerator(vm_id=args.vm, seed=42)

preprocessor = MetricsPreprocessor(window_size=60)
detector = AnomalyDetector(
    k_warning=2.5,
    k_critical=4.5,
    ema_alpha=0.1,
    calibration_window=60,
    persistence_threshold=3
)

# Monitoring thread control
monitoring_active = False
monitoring_thread = None
sample_interval = 0.8  # seconds between samples


# ── Background Monitoring Loop ─────────────────────────────────────────────

def monitoring_loop():
    """Continuous monitoring loop that generates, processes, and analyzes metrics."""
    global monitoring_active
    while monitoring_active:
        try:
            # Step 1: Data Acquisition — get metrics (from simulator or real VBox)
            raw_sample = data_source.query_metrics() if hasattr(data_source, 'query_metrics') else data_source.generate_sample()

            # Step 2: Preprocessing — normalize and add to sliding window
            normalized = preprocessor.add_sample(raw_sample)

            # Step 3: Feature Engineering — compute windowed features
            features = None
            if preprocessor.is_window_ready():
                features = preprocessor.compute_features()

            # Step 4: Anomaly Detection — analyze and score
            result = detector.analyze(normalized, raw_sample, features)

            # Step 5: Emit results to dashboard via WebSocket
            payload = {
                "mode": args.mode,
                "raw": raw_sample,
                "normalized": {k: round(v, 4) for k, v in normalized.items()},
                "result": result,
                "stats": detector.get_stats(),
                "baselines": detector.get_baselines(),
                "raw_stats": preprocessor.get_raw_stats(),
            }

            socketio.emit("metric_update", payload)

            socketio.sleep(sample_interval)

        except Exception as e:
            print(f"[ERROR] Monitoring loop: {e}")
            socketio.sleep(1)


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    """Serve the main dashboard page."""
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    """Return current detection statistics."""
    return jsonify(detector.get_stats())


@app.route("/api/alerts")
def api_alerts():
    """Return recent alerts."""
    count = request.args.get("count", 20, type=int)
    alerts = detector.get_recent_alerts(count)
    # Serialize safely
    safe_alerts = []
    for a in alerts:
        safe_alerts.append({
            "timestamp": a.get("timestamp", ""),
            "vm_id": a.get("vm_id", ""),
            "severity": a.get("severity", ""),
            "composite_score": a.get("composite_score", 0),
            "description": a.get("description", ""),
            "top_contributor": a.get("top_contributor", ""),
            "attack_label": a.get("attack_label", ""),
        })
    return jsonify(safe_alerts)


@app.route("/api/baselines")
def api_baselines():
    """Return computed baselines."""
    return jsonify(detector.get_baselines() or {})


@app.route("/api/attack", methods=["POST"])
def inject_attack():
    """Inject a simulated attack for demonstration."""
    data = request.get_json()
    attack_type = data.get("type", "dos")
    duration = data.get("duration", 40)
    if hasattr(data_source, 'inject_attack'):
        data_source.inject_attack(attack_type, duration)
    return jsonify({"status": "ok", "attack": attack_type, "duration": duration})


@app.route("/api/stop_attack", methods=["POST"])
def stop_attack():
    """Stop any active attack simulation."""
    if hasattr(data_source, 'stop_attack'):
        data_source.stop_attack()
    return jsonify({"status": "ok"})


@app.route("/api/export_csv")
def export_csv():
    """Export all detected alerts to a CSV file."""
    alerts = detector.get_recent_alerts(500)
    
    # Create an in-memory string buffer for the CSV
    si = io.StringIO()
    cw = csv.writer(si)
    
    # Write header
    cw.writerow(["Timestamp", "VM_ID", "Severity", "Anomaly_Score", "Top_Contributor", "Attack_Label", "Description"])
    
    # Write data
    for a in alerts:
        cw.writerow([
            a.get("timestamp", ""),
            a.get("vm_id", ""),
            a.get("severity", ""),
            a.get("composite_score", 0),
            a.get("top_contributor", ""),
            a.get("attack_label", ""),
            a.get("description", "")
        ])
    
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='lids_security_alerts.csv'
    )


# ── WebSocket Events ───────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    global monitoring_active, monitoring_thread
    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = socketio.start_background_task(monitoring_loop)


@socketio.on("disconnect")
def handle_disconnect():
    pass  # Keep monitoring running for other clients


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  L-IDS: Lightweight Intrusion Detection System")
    print("  Dashboard: http://127.0.0.1:5000")
    print("=" * 60)
    socketio.run(app, host="127.0.0.1", port=5000, debug=False)
