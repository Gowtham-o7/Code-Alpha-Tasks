"""
Packet Capture Module
Handles capturing packets from network interfaces using Scapy.
"""

import socket
from scapy.all import sniff, get_if_list, conf


class PacketCapture:
    """
    Manages packet capture from network interfaces.
    Supports BPF filters, interface selection, and packet count limits.
    """

    def __init__(self, interface=None, packet_filter=None, count=0):
        """
        Initialize the packet capture engine.

        Args:
            interface (str): Network interface (e.g., 'eth0', 'wlan0'). Auto-detects if None.
            packet_filter (str): BPF filter string (e.g., 'tcp port 80').
            count (int): Number of packets to capture. 0 = unlimited.
        """
        self.interface = interface or self._get_default_interface()
        self.packet_filter = packet_filter
        self.count = count
        self._packet_count = 0

    def _get_default_interface(self):
        """Auto-detect the default network interface."""
        try:
            # Scapy's default interface
            iface = conf.iface
            if iface:
                return str(iface)
        except Exception:
            pass

        # Fallback: pick first non-loopback interface
        interfaces = get_if_list()
        for iface in interfaces:
            if iface != "lo" and not iface.startswith("loopback"):
                return iface

        return interfaces[0] if interfaces else "eth0"

    def get_available_interfaces(self):
        """Return list of available network interfaces."""
        return get_if_list()

    def start(self, callback):
        """
        Start capturing packets.

        Args:
            callback (callable): Function called for each captured packet.
        """
        print(f"[*] Sniffing on interface: {self.interface}")
        if self.packet_filter:
            print(f"[*] BPF Filter: {self.packet_filter}")
        print(f"[*] Packet limit: {'Unlimited' if self.count == 0 else self.count}")
        print("-" * 70)

        sniff(
            iface=self.interface,
            filter=self.packet_filter,
            count=self.count if self.count > 0 else 0,
            prn=callback,
            store=False   # Don't store packets in memory
        )

    @staticmethod
    def get_hostname(ip):
        """Attempt reverse DNS lookup for an IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None
