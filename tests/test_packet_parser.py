"""
Automated unit tests for packet parsing, protocol detection, and metadata extraction.

All tests utilize synthetic, in-memory Scapy packets and DO NOT rely on live
network traffic or packet capture drivers (Npcap/WinPcap).
"""

import csv
from pathlib import Path
import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from src.config import CSV_FIELDNAMES
from src.exporter import export_to_csv
from src.models import CaptureStats, FilterConfig, PacketMetadata
from src.packet_parser import decode_tcp_flags, detect_protocol, parse_packet


class TestPacketParser:
    """Test suite for packet dissection and safe metadata extraction."""

    def test_tcp_packet_parsing(self):
        """Verify TCP packet parsing with IP addresses, ports, and flags."""
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="192.168.1.100", dst="93.184.216.34")
            / TCP(sport=54321, dport=8080, flags="S", seq=1000)
        )
        meta = parse_packet(pkt)

        assert meta.source_ip == "192.168.1.100"
        assert meta.destination_ip == "93.184.216.34"
        assert meta.ip_version == "IPv4"
        assert meta.source_port == "54321"
        assert meta.destination_port == "8080"
        assert "SYN" in meta.tcp_flags
        assert meta.packet_length == len(pkt)
        assert meta.source_mac == "aa:bb:cc:dd:ee:01"
        assert meta.destination_mac == "aa:bb:cc:dd:ee:02"

    def test_udp_packet_parsing(self):
        """Verify UDP packet parsing with ports and length."""
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="10.0.0.5", dst="10.0.0.1")
            / UDP(sport=12345, dport=9999)
        )
        meta = parse_packet(pkt)

        assert meta.protocol == "UDP"
        assert meta.source_ip == "10.0.0.5"
        assert meta.destination_ip == "10.0.0.1"
        assert meta.source_port == "12345"
        assert meta.destination_port == "9999"
        assert meta.tcp_flags == "N/A"

    def test_icmp_echo_request_parsing(self):
        """Verify ICMP ping request type and code identification."""
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="1.1.1.1")
            / ICMP(type=8, code=0)
        )
        meta = parse_packet(pkt)

        assert meta.protocol == "ICMP"
        assert "Echo Request" in meta.icmp_type
        assert meta.icmp_code == "0"
        assert meta.source_ip == "192.168.1.50"
        assert meta.destination_ip == "1.1.1.1"

    def test_icmp_echo_reply_parsing(self):
        """Verify ICMP ping reply type and code identification."""
        pkt = (
            Ether()
            / IP(src="1.1.1.1", dst="192.168.1.50")
            / ICMP(type=0, code=0)
        )
        meta = parse_packet(pkt)

        assert meta.protocol == "ICMP"
        assert "Echo Reply" in meta.icmp_type
        assert meta.icmp_code == "0"

    def test_dns_query_parsing(self):
        """Verify extraction of DNS queried domain name."""
        pkt = (
            Ether()
            / IP(src="192.168.1.20", dst="8.8.8.8")
            / UDP(sport=53123, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="internship.example.org."))
        )
        meta = parse_packet(pkt)

        assert meta.protocol == "DNS"
        assert meta.dns_query == "internship.example.org"
        assert meta.destination_port == "53"
        assert "internship.example.org" in meta.info

    def test_ipv6_packet_parsing(self):
        """Verify IPv6 address and version detection."""
        pkt = (
            Ether()
            / IPv6(src="2001:db8::1", dst="2606:4700:4700::1111")
            / TCP(sport=49152, dport=443, flags="S")
        )
        meta = parse_packet(pkt)

        assert meta.ip_version == "IPv6"
        assert meta.source_ip == "2001:db8::1"
        assert meta.destination_ip == "2606:4700:4700::1111"
        assert meta.destination_port == "443"

    def test_missing_layers_graceful_handling(self):
        """Verify parser never crashes on packets missing network/transport layers."""
        # Ethernet only packet with raw payload
        raw_pkt = Ether(src="11:22:33:44:55:66", dst="66:55:44:33:22:11") / b"NonStandardPayload"
        meta = parse_packet(raw_pkt)

        assert meta.source_mac == "11:22:33:44:55:66"
        assert meta.destination_mac == "66:55:44:33:22:11"
        assert meta.source_ip == "N/A"
        assert meta.destination_ip == "N/A"
        assert meta.source_port == "N/A"
        assert meta.destination_port == "N/A"
        assert meta.tcp_flags == "N/A"
        assert meta.icmp_type == "N/A"
        assert meta.dns_query == "N/A"
        assert meta.packet_length == len(raw_pkt)

    def test_arp_packet_parsing(self):
        """Verify ARP packet parsing and opcode translation."""
        pkt = Ether() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.100")
        meta = parse_packet(pkt)

        assert meta.protocol == "ARP"
        assert meta.source_ip == "192.168.1.1"
        assert meta.destination_ip == "192.168.1.100"
        assert "ARP" in meta.info

    def test_tcp_flags_decoding(self):
        """Verify decoding of individual and combined TCP flags."""
        assert decode_tcp_flags("S") == "SYN"
        assert "SYN" in decode_tcp_flags("SA") and "ACK" in decode_tcp_flags("SA")
        assert "FIN" in decode_tcp_flags("FA") and "ACK" in decode_tcp_flags("FA")
        assert decode_tcp_flags("R") == "RST"
        assert decode_tcp_flags(None) == "N/A"

    def test_tls_detection(self):
        """Verify detection of TLS traffic via port and record header."""
        # TLS 1.2 Handshake (Client Hello) over port 443
        tls_payload = b"\x16\x03\x03\x00\x10" + b"\x00" * 16
        pkt = Ether() / IP(src="10.0.0.1", dst="1.1.1.1") / TCP(sport=50000, dport=443) / tls_payload
        meta = parse_packet(pkt)

        assert meta.protocol == "TLS"
        assert "TLS" in meta.info

    def test_http_detection(self):
        """Verify detection of plaintext HTTP traffic via method header."""
        http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n"
        pkt = Ether() / IP(src="10.0.0.1", dst="93.184.216.34") / TCP(sport=45000, dport=80) / http_payload
        meta = parse_packet(pkt)

        assert meta.protocol == "HTTP"
        assert "HTTP: GET /index.html" in meta.info


class TestFilteringAndStatistics:
    """Test suite for packet filtering and session statistics."""

    def test_protocol_filtering(self):
        """Verify filter configuration matches target protocols only."""
        tcp_meta = PacketMetadata(protocol="TCP", source_ip="1.1.1.1", destination_ip="2.2.2.2")
        udp_meta = PacketMetadata(protocol="UDP", source_ip="1.1.1.1", destination_ip="2.2.2.2")
        dns_meta = PacketMetadata(protocol="DNS", source_ip="1.1.1.1", destination_ip="2.2.2.2")

        tcp_filter = FilterConfig(protocol="TCP")
        assert tcp_filter.matches(tcp_meta) is True
        assert tcp_filter.matches(udp_meta) is False

        dns_filter = FilterConfig(protocol="DNS")
        assert dns_filter.matches(dns_meta) is True
        assert dns_filter.matches(tcp_meta) is False

    def test_ip_filtering(self):
        """Verify source and destination IP address filtering."""
        meta = PacketMetadata(protocol="TCP", source_ip="192.168.1.100", destination_ip="8.8.8.8")

        src_filter = FilterConfig(source_ip="192.168.1.100")
        assert src_filter.matches(meta) is True

        wrong_src_filter = FilterConfig(source_ip="192.168.1.101")
        assert wrong_src_filter.matches(meta) is False

        dst_filter = FilterConfig(destination_ip="8.8.8.8")
        assert dst_filter.matches(meta) is True

    def test_capture_stats_accumulation(self):
        """Verify statistics counters accurately tally protocol metrics."""
        stats = CaptureStats()

        pkt1 = PacketMetadata(protocol="TCP", ip_version="IPv4", packet_length=100)
        pkt2 = PacketMetadata(protocol="UDP", ip_version="IPv4", packet_length=60)
        pkt3 = PacketMetadata(protocol="DNS", ip_version="IPv4", packet_length=80)
        pkt4 = PacketMetadata(protocol="ICMP", ip_version="IPv4", packet_length=74)
        pkt5 = PacketMetadata(protocol="TCP", ip_version="IPv6", packet_length=120)

        for p in [pkt1, pkt2, pkt3, pkt4, pkt5]:
            stats.update(p)

        assert stats.total_packets == 5
        assert stats.ipv4_count == 4
        assert stats.ipv6_count == 1
        assert stats.tcp_count == 2
        assert stats.udp_count == 2  # 1 UDP + 1 DNS (runs over UDP)
        assert stats.dns_count == 1
        assert stats.icmp_count == 1
        assert stats.total_bytes == 434


class TestCSVExport:
    """Test suite for CSV exporting and schema validation."""

    def test_csv_export_format_and_headers(self, tmp_path: Path):
        """Verify exported CSV file creates correct headers, rows, and structure."""
        out_file = tmp_path / "test_packets.csv"

        packets = [
            PacketMetadata(
                timestamp="2026-09-07 10:00:00.123",
                source_mac="00:11:22:33:44:55",
                destination_mac="66:77:88:99:aa:bb",
                source_ip="192.168.1.100",
                destination_ip="8.8.8.8",
                ip_version="IPv4",
                protocol="DNS",
                source_port="54321",
                destination_port="53",
                packet_length=84,
                tcp_flags="N/A",
                icmp_type="N/A",
                icmp_code="N/A",
                dns_query="internship.edu",
            )
        ]

        success = export_to_csv(packets, out_file)
        assert success is True
        assert out_file.exists()

        # Read back CSV and verify exact schema
        with open(out_file, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)
            assert headers == CSV_FIELDNAMES

            row = next(reader)
            assert row[0] == "2026-09-07 10:00:00.123"
            assert row[3] == "192.168.1.100"
            assert row[4] == "8.8.8.8"
            assert row[6] == "DNS"
            assert row[13] == "internship.edu"
