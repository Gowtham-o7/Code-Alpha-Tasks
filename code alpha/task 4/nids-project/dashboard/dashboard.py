#!/usr/bin/env python3
"""
dashboard.py — Lightweight Flask dashboard for Suricata eve.json alerts.

Usage:
    python3 dashboard.py --eve /var/log/suricata/eve.json
Then open http://localhost:5000
"""

import argparse
import json
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template

app = Flask(__name__)
EVE_PATH = Path("/var/log/suricata/eve.json")


def load_alerts():
    alerts = []
    if not EVE_PATH.exists():
        return alerts
    with EVE_PATH.open("r", errors="ignore") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def summary():
    alerts = load_alerts()
    sig_counts = Counter(a.get("alert", {}).get("signature", "unknown") for a in alerts)
    src_counts = Counter(a.get("src_ip", "unknown") for a in alerts)
    severity_counts = Counter(a.get("alert", {}).get("severity", 3) for a in alerts)

    return jsonify({
        "total_alerts": len(alerts),
        "top_signatures": sig_counts.most_common(10),
        "top_sources": src_counts.most_common(10),
        "severity_breakdown": severity_counts.most_common(),
    })


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--eve", default="/var/log/suricata/eve.json")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    EVE_PATH = Path(args.eve)
    app.run(host="0.0.0.0", port=args.port, debug=True)
