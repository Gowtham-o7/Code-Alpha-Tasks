#!/usr/bin/env python3
"""
Offline Demo Script
Simulates network packet capture using crafted Scapy packets.
Useful for testing and demonstration WITHOUT requiring root privileges.

Run with: python3 samples/demo_packets.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
from core.analyzer import PacketAnalyzer
from core.display import PacketDisplay


SAMPLE_PACKETS = [
    # TCP SYN (browser opening connection)
    Ether(src="aa:bb:cc:11:22:33", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="192.168.1.10", dst="142.250.80.46", ttl=64) /
    TCP(sport=54321, dport=443, flags="S", seq=1000, ack=0, window=65535),

    # TCP SYN-ACK (server response)
    Ether(src="ff:ff:ff:ff:ff:ff", dst="aa:bb:cc:11:22:33") /
    IP(src="142.250.80.46", dst="192.168.1.10", ttl=55) /
    TCP(sport=443, dport=54321, flags="SA", seq=5000, ack=1001, window=65535),

    # UDP DNS Query
    Ether(src="aa:bb:cc:11:22:33", dst="dd:ee:ff:00:11:22") /
    IP(src="192.168.1.10", dst="8.8.8.8", ttl=64) /
    UDP(sport=49152, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="github.com")),

    # UDP DNS Response
    Ether(src="dd:ee:ff:00:11:22", dst="aa:bb:cc:11:22:33") /
    IP(src="8.8.8.8", dst="192.168.1.10", ttl=120) /
    UDP(sport=53, dport=49152) /
    DNS(qr=1, aa=1, qd=DNSQR(qname="github.com"),
        an=DNSRR(rrname="github.com", type="A", rdata="140.82.114.4")),

    # ICMP Echo Request (ping)
    Ether(src="aa:bb:cc:11:22:33", dst="dd:ee:ff:00:11:22") /
    IP(src="192.168.1.10", dst="8.8.8.8", ttl=64) /
    ICMP(type=8, code=0),

    # ICMP Echo Reply
    Ether(src="dd:ee:ff:00:11:22", dst="aa:bb:cc:11:22:33") /
    IP(src="8.8.8.8", dst="192.168.1.10", ttl=117) /
    ICMP(type=0, code=0),

    # ARP Request (who has 192.168.1.1?)
    Ether(src="aa:bb:cc:11:22:33", dst="ff:ff:ff:ff:ff:ff") /
    ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1",
        hwsrc="aa:bb:cc:11:22:33"),

    # ARP Reply
    Ether(src="cc:dd:ee:ff:00:11", dst="aa:bb:cc:11:22:33") /
    ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.10",
        hwsrc="cc:dd:ee:ff:00:11"),

    # TCP with HTTP payload
    Ether(src="aa:bb:cc:11:22:33", dst="dd:ee:ff:00:11:22") /
    IP(src="192.168.1.10", dst="93.184.216.34", ttl=64) /
    TCP(sport=55000, dport=80, flags="PA") /
    Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Python\r\n\r\n"),

    # UDP data transfer
    Ether(src="aa:bb:cc:11:22:33", dst="dd:ee:ff:00:11:22") /
    IP(src="192.168.1.10", dst="192.168.1.20", ttl=64) /
    UDP(sport=9000, dport=9001) /
    Raw(load=b"Hello from UDP!"),
]


def main():
    print("\n" + "=" * 70)
    print("  NETWORK SNIFFER - OFFLINE DEMO MODE")
    print("  Replaying pre-crafted packets (no root required)")
    print("=" * 70 + "\n")

    analyzer = PacketAnalyzer()
    display = PacketDisplay(use_color=True, verbose=True)

    header = f"{'#':<6} {'Time':<14} {'Proto':<8} {'Source':<24} {'Destination':<24} {'Info'}"
    print("\033[1m" + header + "\033[0m")
    print("-" * 95)

    for pkt in SAMPLE_PACKETS:
        info = analyzer.analyze(pkt)
        if info:
            display.print_packet(info)

    print()
    display.print_statistics(analyzer.get_statistics())


if __name__ == "__main__":
    main()
