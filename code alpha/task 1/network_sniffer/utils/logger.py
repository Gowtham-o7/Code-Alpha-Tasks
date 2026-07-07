"""
Logger Utility
Saves captured packet info to a log file in CSV/text format.
"""

import csv
import sys
from datetime import datetime


class Logger:
    """Logs packet data to a file (CSV format)."""

    CSV_FIELDS = [
        "packet_num", "timestamp", "protocol",
        "src_ip", "src_port", "dst_ip", "dst_port",
        "src_mac", "dst_mac", "length", "ttl",
        "tcp_flags", "icmp_type", "icmp_code",
        "dns_query", "dns_response",
        "http_method", "http_host", "http_path",
        "arp_op", "arp_src_ip", "arp_dst_ip",
        "payload"
    ]

    def __init__(self, filepath=None):
        self._file = None
        self._writer = None

        if filepath:
            try:
                self._file = open(filepath, "w", newline="", encoding="utf-8")
                self._writer = csv.DictWriter(self._file, fieldnames=self.CSV_FIELDS, extrasaction="ignore")
                self._writer.writeheader()
                print(f"[*] Logging packets to: {filepath}")
            except IOError as e:
                print(f"[WARNING] Could not open log file: {e}", file=sys.stderr)

    def log(self, info):
        """Write a PacketInfo to the log file."""
        if self._writer is None:
            return

        row = {field: getattr(info, field, None) for field in self.CSV_FIELDS}
        self._writer.writerow(row)
        self._file.flush()

    def close(self):
        if self._file:
            self._file.close()
            print("[*] Log file saved.")
