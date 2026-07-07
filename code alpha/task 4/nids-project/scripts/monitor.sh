#!/bin/bash
# monitor.sh — live-tail Suricata alerts in a readable format
# Usage: ./monitor.sh [path-to-eve.json]

EVE_LOG="${1:-/var/log/suricata/eve.json}"

if [ ! -f "$EVE_LOG" ]; then
    echo "Log file not found: $EVE_LOG"
    echo "Is Suricata running? Check the path or pass it as an argument."
    exit 1
fi

echo "Monitoring $EVE_LOG for alerts... (Ctrl+C to stop)"
echo "---------------------------------------------------"

tail -F "$EVE_LOG" | jq -c 'select(.event_type=="alert") | {time: .timestamp, src: .src_ip, dst: .dest_ip, sig: .alert.signature, severity: .alert.severity}' --unbuffered 2>/dev/null
