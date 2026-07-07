"""
Packet Analyzer Module
Parses raw Scapy packets and extracts structured information.
Supports: Ethernet, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP.
"""

from datetime import datetime
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
)
from scapy.layers.http import HTTPRequest, HTTPResponse


class PacketInfo:
    """Structured container for parsed packet data."""

    def __init__(self):
        self.timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.packet_num = 0
        self.length = 0

        # Layer 2
        self.src_mac = None
        self.dst_mac = None
        self.eth_type = None

        # Layer 3
        self.src_ip = None
        self.dst_ip = None
        self.ttl = None
        self.ip_version = None

        # Layer 4
        self.protocol = "UNKNOWN"
        self.src_port = None
        self.dst_port = None

        # TCP-specific
        self.tcp_flags = None
        self.seq_num = None
        self.ack_num = None
        self.window_size = None

        # ICMP-specific
        self.icmp_type = None
        self.icmp_code = None
        self.icmp_type_name = None

        # ARP-specific
        self.arp_op = None
        self.arp_src_ip = None
        self.arp_dst_ip = None

        # DNS-specific
        self.dns_query = None
        self.dns_response = None
        self.dns_type = None

        # HTTP-specific
        self.http_method = None
        self.http_host = None
        self.http_path = None
        self.http_status = None

        # Payload
        self.payload = None
        self.payload_hex = None


class PacketAnalyzer:
    """
    Analyzes Scapy packets and returns structured PacketInfo objects.
    """

    ICMP_TYPES = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
        12: "Parameter Problem",
    }

    TCP_FLAGS = {
        0x01: "FIN",
        0x02: "SYN",
        0x04: "RST",
        0x08: "PSH",
        0x10: "ACK",
        0x20: "URG",
    }

    def __init__(self, protocol_filter="ALL"):
        self.protocol_filter = protocol_filter.upper()
        self._packet_counter = 0
        self._stats = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "arp": 0,
            "dns": 0,
            "http": 0,
            "other": 0,
            "bytes": 0,
        }

    def analyze(self, packet):
        """
        Parse a Scapy packet into a PacketInfo object.

        Args:
            packet: Raw Scapy packet.

        Returns:
            PacketInfo or None if filtered out.
        """
        self._packet_counter += 1
        info = PacketInfo()
        info.packet_num = self._packet_counter
        info.length = len(packet)

        self._stats["total"] += 1
        self._stats["bytes"] += info.length

        # --- Ethernet Layer ---
        if packet.haslayer(Ether):
            eth = packet[Ether]
            info.src_mac = eth.src
            info.dst_mac = eth.dst

        # --- ARP Layer ---
        if packet.haslayer(ARP):
            self._parse_arp(packet, info)

        # --- IP Layer ---
        elif packet.haslayer(IP):
            ip = packet[IP]
            info.src_ip = ip.src
            info.dst_ip = ip.dst
            info.ttl = ip.ttl
            info.ip_version = 4

            # TCP
            if packet.haslayer(TCP):
                self._parse_tcp(packet, info)
            # UDP
            elif packet.haslayer(UDP):
                self._parse_udp(packet, info)
            # ICMP
            elif packet.haslayer(ICMP):
                self._parse_icmp(packet, info)
            else:
                info.protocol = f"IP (proto={ip.proto})"
                self._stats["other"] += 1

        # --- IPv6 Layer ---
        elif packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            info.src_ip = ipv6.src
            info.dst_ip = ipv6.dst
            info.ip_version = 6
            info.ttl = ipv6.hlim

            if packet.haslayer(TCP):
                self._parse_tcp(packet, info)
            elif packet.haslayer(UDP):
                self._parse_udp(packet, info)
            else:
                info.protocol = "IPv6"
                self._stats["other"] += 1
        else:
            info.protocol = "UNKNOWN"
            self._stats["other"] += 1

        # --- Payload ---
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            info.payload = self._safe_decode(raw_data)
            info.payload_hex = raw_data.hex()

        # Apply protocol filter
        if self.protocol_filter != "ALL":
            if info.protocol.upper() != self.protocol_filter:
                return None

        return info

    # ------------------------------------------------------------------ #
    #  Private parsers                                                     #
    # ------------------------------------------------------------------ #

    def _parse_tcp(self, packet, info):
        tcp = packet[TCP]
        info.src_port = tcp.sport
        info.dst_port = tcp.dport
        info.seq_num = tcp.seq
        info.ack_num = tcp.ack
        info.window_size = tcp.window
        info.tcp_flags = self._decode_tcp_flags(tcp.flags)

        # Check for HTTP
        if packet.haslayer(HTTPRequest):
            self._parse_http_request(packet, info)
        elif packet.haslayer(HTTPResponse):
            self._parse_http_response(packet, info)
        else:
            info.protocol = "TCP"
            self._stats["tcp"] += 1

        # Check for DNS over TCP
        if packet.haslayer(DNS):
            self._parse_dns(packet, info)

    def _parse_udp(self, packet, info):
        udp = packet[UDP]
        info.src_port = udp.sport
        info.dst_port = udp.dport
        info.protocol = "UDP"
        self._stats["udp"] += 1

        # Check for DNS
        if packet.haslayer(DNS):
            self._parse_dns(packet, info)

    def _parse_icmp(self, packet, info):
        icmp = packet[ICMP]
        info.icmp_type = icmp.type
        info.icmp_code = icmp.code
        info.icmp_type_name = self.ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
        info.protocol = "ICMP"
        self._stats["icmp"] += 1

    def _parse_arp(self, packet, info):
        arp = packet[ARP]
        info.arp_op = "Request" if arp.op == 1 else "Reply"
        info.arp_src_ip = arp.psrc
        info.arp_dst_ip = arp.pdst
        info.src_mac = arp.hwsrc
        info.protocol = "ARP"
        self._stats["arp"] += 1

    def _parse_dns(self, packet, info):
        dns = packet[DNS]
        info.protocol = "DNS"
        self._stats["dns"] += 1

        if dns.qr == 0:  # Query
            info.dns_type = "Query"
            if dns.haslayer(DNSQR):
                info.dns_query = dns[DNSQR].qname.decode(errors="replace").rstrip(".")
        else:  # Response
            info.dns_type = "Response"
            if dns.haslayer(DNSRR):
                info.dns_response = dns[DNSRR].rdata

    def _parse_http_request(self, packet, info):
        http = packet[HTTPRequest]
        info.protocol = "HTTP"
        info.http_method = http.Method.decode(errors="replace") if http.Method else None
        info.http_host = http.Host.decode(errors="replace") if http.Host else None
        info.http_path = http.Path.decode(errors="replace") if http.Path else None
        self._stats["http"] += 1

    def _parse_http_response(self, packet, info):
        http = packet[HTTPResponse]
        info.protocol = "HTTP"
        info.http_status = http.Status_Code.decode(errors="replace") if http.Status_Code else None
        self._stats["http"] += 1

    def _decode_tcp_flags(self, flags):
        """Convert TCP flags integer to readable string."""
        active = [name for bit, name in self.TCP_FLAGS.items() if flags & bit]
        return "|".join(active) if active else "NONE"

    @staticmethod
    def _safe_decode(data):
        """Safely decode bytes to printable string."""
        try:
            decoded = data.decode("utf-8", errors="replace")
            printable = "".join(c if c.isprintable() or c in "\n\r\t" else "." for c in decoded)
            return printable[:500]  # Limit length
        except Exception:
            return data.hex()[:100]

    def get_statistics(self):
        """Return captured packet statistics."""
        return dict(self._stats)
