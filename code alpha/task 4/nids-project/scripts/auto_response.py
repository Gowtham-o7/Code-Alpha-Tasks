#!/usr/bin/env python3
"""
auto_response.py — Automated response for Suricata alerts.

Tails Suricata's eve.json log, and for alerts at or above a configured
severity, blocks the offending source IP using iptables and logs the action.

Usage:
    sudo python3 auto_response.py --eve /var/log/suricata/eve.json --max-severity 2

Notes:
- Suricata severity: 1 = high priority, 3 = low priority (lower number = more severe).
- Requires root privileges to modify iptables.
- Designed for LAB / TEST environments. Validate rules before using in production.
"""

import argparse
import ipaddress
import json
import logging
import subprocess
import time
from pathlib import Path

logging.basicConfig(
    filename="auto_response.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

blocked_ips = set()


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def block_ip(ip: str, dry_run: bool):
    if ip in blocked_ips or is_private(ip):
        return
    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    if dry_run:
        print(f"[DRY-RUN] Would block {ip}: {' '.join(cmd)}")
        logging.info("DRY-RUN block %s", ip)
    else:
        try:
            subprocess.run(cmd, check=True)
            print(f"[BLOCKED] {ip}")
            logging.info("Blocked IP %s", ip)
        except subprocess.CalledProcessError as e:
            logging.error("Failed to block %s: %s", ip, e)
            return
    blocked_ips.add(ip)


def follow(path: Path):
    with path.open("r") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    parser = argparse.ArgumentParser(description="Auto-respond to Suricata alerts.")
    parser.add_argument("--eve", default="/var/log/suricata/eve.json", help="Path to eve.json")
    parser.add_argument("--max-severity", type=int, default=2,
                         help="Block IPs for alerts with severity <= this value (1=highest)")
    parser.add_argument("--dry-run", action="store_true", help="Log actions without modifying iptables")
    args = parser.parse_args()

    eve_path = Path(args.eve)
    if not eve_path.exists():
        print(f"Log file not found: {eve_path}")
        return

    print(f"Watching {eve_path} for alerts (severity <= {args.max_severity})...")
    for line in follow(eve_path):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        alert = event.get("alert", {})
        severity = alert.get("severity", 3)
        src_ip = event.get("src_ip")
        sig = alert.get("signature", "unknown")

        if src_ip and severity <= args.max_severity:
            print(f"[ALERT] {sig} from {src_ip} (severity {severity})")
            block_ip(src_ip, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
