#!/usr/bin/env python3
"""
Network Sniffer - Main Entry Point
Captures and analyzes network packets in real-time.
"""

import argparse
import sys
import signal
from core.capture import PacketCapture
from core.analyzer import PacketAnalyzer
from core.display import PacketDisplay
from utils.logger import Logger


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print("\n\n[!] Stopping packet capture...")
    sys.exit(0)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer - Capture and analyze network packets",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  sudo python3 sniffer.py                          # Capture on default interface
  sudo python3 sniffer.py -i eth0                  # Capture on eth0
  sudo python3 sniffer.py -i eth0 -c 50            # Capture 50 packets
  sudo python3 sniffer.py -f "tcp port 80"         # Filter HTTP traffic
  sudo python3 sniffer.py -o output.log            # Save to file
  sudo python3 sniffer.py --protocol TCP           # Show only TCP packets
  sudo python3 sniffer.py -v                       # Verbose (show payload)
        """
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Network interface to sniff on (default: auto-detect)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited)"
    )
    parser.add_argument(
        "-f", "--filter",
        default=None,
        help="BPF filter string (e.g., 'tcp port 80', 'udp', 'icmp')"
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output log file path"
    )
    parser.add_argument(
        "--protocol",
        choices=["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "ALL"],
        default="ALL",
        help="Filter by protocol (default: ALL)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show packet payload data"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show statistics summary at end"
    )
    return parser.parse_args()


def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_arguments()

    logger = Logger(args.output)
    display = PacketDisplay(use_color=not args.no_color, verbose=args.verbose)
    analyzer = PacketAnalyzer(protocol_filter=args.protocol)
    capture = PacketCapture(
        interface=args.interface,
        packet_filter=args.filter,
        count=args.count
    )

    display.print_banner()
    display.print_config(args)

    try:
        capture.start(
            callback=lambda pkt: process_packet(pkt, analyzer, display, logger),
        )
    except PermissionError:
        print("\n[ERROR] Permission denied. Run with sudo/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
    finally:
        if args.stats:
            display.print_statistics(analyzer.get_statistics())
        logger.close()


def process_packet(packet, analyzer, display, logger):
    """Process a single captured packet."""
    parsed = analyzer.analyze(packet)
    if parsed:
        display.print_packet(parsed)
        logger.log(parsed)


if __name__ == "__main__":
    main()
