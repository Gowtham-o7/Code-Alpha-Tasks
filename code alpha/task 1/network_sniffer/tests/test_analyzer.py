"""
Unit Tests - PacketAnalyzer
Tests packet parsing for TCP, UDP, ICMP, ARP, DNS packets.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Ether, Raw
from core.analyzer import PacketAnalyzer


def make_eth(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66"):
    return Ether(src=src, dst=dst)


class TestTCPParsing(unittest.TestCase):
    def setUp(self):
        self.analyzer = PacketAnalyzer()

    def test_tcp_syn(self):
        pkt = make_eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")
        info = self.analyzer.analyze(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info.protocol, "TCP")
        self.assertEqual(info.src_ip, "10.0.0.1")
        self.assertEqual(info.dst_ip, "10.0.0.2")
        self.assertEqual(info.src_port, 12345)
        self.assertEqual(info.dst_port, 80)
        self.assertIn("SYN", info.tcp_flags)

    def test_tcp_ack(self):
        pkt = make_eth() / IP(src="192.168.1.1", dst="8.8.8.8") / TCP(sport=443, dport=54321, flags="A")
        info = self.analyzer.analyze(pkt)
        self.assertEqual(info.protocol, "TCP")
        self.assertIn("ACK", info.tcp_flags)

    def test_tcp_fin_ack(self):
        pkt = make_eth() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="FA")
        info = self.analyzer.analyze(pkt)
        self.assertIn("FIN", info.tcp_flags)
        self.assertIn("ACK", info.tcp_flags)

    def test_tcp_with_payload(self):
        pkt = make_eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP() / Raw(load=b"Hello World")
        info = self.analyzer.analyze(pkt)
        self.assertIsNotNone(info.payload)
        self.assertIn("Hello World", info.payload)


class TestUDPParsing(unittest.TestCase):
    def setUp(self):
        self.analyzer = PacketAnalyzer()

    def test_udp_basic(self):
        pkt = make_eth() / IP(src="192.168.0.1", dst="192.168.0.2") / UDP(sport=5000, dport=5001)
        info = self.analyzer.analyze(pkt)
        self.assertEqual(info.protocol, "UDP")
        self.assertEqual(info.src_port, 5000)
        self.assertEqual(info.dst_port, 5001)

    def test_udp_dns_query(self):
        pkt = (make_eth() /
               IP(src="192.168.1.10", dst="8.8.8.8") /
               UDP(sport=54321, dport=53) /
               DNS(rd=1, qd=DNSQR(qname="google.com")))
        info = self.analyzer.analyze(pkt)
        self.assertEqual(info.protocol, "DNS")
        self.assertEqual(info.dns_type, "Query")
        self.assertIn("google.com", info.dns_query)


class TestICMPParsing(unittest.TestCase):
    def setUp(self):
        self.analyzer = PacketAnalyzer()

    def test_icmp_echo_request(self):
        pkt = make_eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0)
        info = self.analyzer.analyze(pkt)
        self.assertEqual(info.protocol, "ICMP")
        self.assertEqual(info.icmp_type, 8)
        self.assertEqual(info.icmp_type_name, "Echo Request")

    def test_icmp_echo_reply(self):
        pkt = make_eth() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0, code=0)
        info = self.analyzer.analyze(pkt)
        self.assertEqual(info.icmp_type_name, "Echo Reply")

    def test_icmp_unreachable(self):
        pkt = make_eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=3, code=1)
        info = self.analyzer.analyze(pkt)
        self.assertEqual(info.icmp_type_name, "Destination Unreachable")


class TestARPParsing(unittest.TestCase):
    def setUp(self):
        self.analyzer = PacketAnalyzer()

    def test_arp_request(self):
        pkt = (make_eth() /
               ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.254",
                   hwsrc="aa:bb:cc:dd:ee:ff"))
        info = self.analyzer.analyze(pkt)
        self.assertEqual(info.protocol, "ARP")
        self.assertEqual(info.arp_op, "Request")
        self.assertEqual(info.arp_src_ip, "192.168.1.1")

    def test_arp_reply(self):
        pkt = (make_eth() /
               ARP(op=2, psrc="192.168.1.254", pdst="192.168.1.1",
                   hwsrc="11:22:33:44:55:66"))
        info = self.analyzer.analyze(pkt)
        self.assertEqual(info.arp_op, "Reply")


class TestProtocolFilter(unittest.TestCase):
    def test_filter_tcp_only(self):
        analyzer = PacketAnalyzer(protocol_filter="TCP")
        tcp_pkt = make_eth() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()
        udp_pkt = make_eth() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP()
        self.assertIsNotNone(analyzer.analyze(tcp_pkt))
        self.assertIsNone(analyzer.analyze(udp_pkt))

    def test_filter_udp_only(self):
        analyzer = PacketAnalyzer(protocol_filter="UDP")
        tcp_pkt = make_eth() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()
        udp_pkt = make_eth() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP()
        self.assertIsNone(analyzer.analyze(tcp_pkt))
        self.assertIsNotNone(analyzer.analyze(udp_pkt))

    def test_filter_all(self):
        analyzer = PacketAnalyzer(protocol_filter="ALL")
        tcp_pkt = make_eth() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()
        self.assertIsNotNone(analyzer.analyze(tcp_pkt))


class TestStatistics(unittest.TestCase):
    def test_stats_increment(self):
        analyzer = PacketAnalyzer()
        for _ in range(3):
            pkt = make_eth() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()
            analyzer.analyze(pkt)
        for _ in range(2):
            pkt = make_eth() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP()
            analyzer.analyze(pkt)

        stats = analyzer.get_statistics()
        self.assertEqual(stats["total"], 5)
        self.assertEqual(stats["tcp"], 3)
        self.assertEqual(stats["udp"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
