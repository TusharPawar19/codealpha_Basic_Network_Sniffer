"""
Packet parser and protocol dissection engine for Network Packet Sniffer.

Safely dissects raw Scapy packet structures across Data Link, Network,
Transport, and Application layers. Extracts protocol metadata without
touching or storing sensitive application payloads.
"""

from datetime import datetime
import logging
from typing import Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

# Attempt optional Scapy DNS and TLS layer imports safely
try:
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    DNS = None
    DNSQR = None

try:
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
except (ImportError, Exception):
    TLS = None
    TLSClientHello = None
    TLSServerHello = None

from src.config import ICMP_TYPE_MAP, TCP_FLAGS_MAP, WELL_KNOWN_PORTS
from src.models import PacketMetadata

logger = logging.getLogger(__name__)


def decode_tcp_flags(flags_val: any) -> str:
    """
    Convert Scapy TCP flags into a human-readable comma-separated string.
    
    Examples:
        'S'  -> 'SYN'
        'SA' -> 'SYN, ACK'
        'FA' -> 'FIN, ACK'
        'PA' -> 'PSH, ACK'
    """
    if flags_val is None:
        return "N/A"

    flags_str = str(flags_val).strip()
    names = []
    for char in flags_str:
        if char.upper() in TCP_FLAGS_MAP:
            names.append(TCP_FLAGS_MAP[char.upper()])

    return ", ".join(names) if names else (flags_str or "N/A")


def detect_tls(packet: Packet) -> bool:
    """
    Detect whether a packet contains TLS/HTTPS traffic.
    
    Inspects Scapy TLS layers if available, or analyzes TCP payload headers
    for the standard TLS record header structure (Content Type 20-23, version 0x0301-0x0304),
    or checks well-known HTTPS ports (443, 8443).
    """
    if TLS is not None and packet.haslayer(TLS):
        return True

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        sport = tcp.sport
        dport = tcp.dport

        # Check standard HTTPS ports
        if sport in (443, 8443) or dport in (443, 8443):
            return True

        # Inspect raw bytes for TLS Record Header:
        # Byte 0: Content Type (20: ChangeCipherSpec, 21: Alert, 22: Handshake, 23: App Data)
        # Bytes 1-2: Version (0x0301 TLS 1.0, 0x0302 TLS 1.1, 0x0303 TLS 1.2, 0x0304 TLS 1.3)
        raw_payload = bytes(tcp.payload)
        if len(raw_payload) >= 3:
            content_type = raw_payload[0]
            major_ver = raw_payload[1]
            minor_ver = raw_payload[2]
            if content_type in (20, 21, 22, 23) and major_ver == 3 and minor_ver in (1, 2, 3, 4):
                return True

    return False


def detect_http(packet: Packet) -> bool:
    """
    Detect whether a packet contains plaintext HTTP traffic.
    
    Inspects transport ports (80, 8080) and searches for standard HTTP methods
    or HTTP response status lines in the payload prefix.
    """
    if not packet.haslayer(TCP):
        return False

    tcp = packet[TCP]
    if tcp.sport in (80, 8080) or tcp.dport in (80, 8080):
        return True

    raw_payload = bytes(tcp.payload)
    if len(raw_payload) >= 4:
        methods = (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"HTTP/")
        if any(raw_payload.startswith(m) for m in methods):
            return True

    return False


def detect_protocol(packet: Packet) -> str:
    """
    Identify the highest-level meaningful protocol present in the packet.
    
    Hierarchy:
      Application Layer: TLS, HTTP, DNS
      Transport Layer:   TCP, UDP, ICMP
      Network Layer:     IPv4, IPv6, ARP
      Link Layer:        Ethernet
    """
    try:
        # Application Layer checks
        if DNS is not None and packet.haslayer(DNS):
            return "DNS"

        if detect_tls(packet):
            return "TLS"

        if detect_http(packet):
            return "HTTP"

        # Transport Layer checks
        if packet.haslayer(ICMP):
            return "ICMP"

        if packet.haslayer(TCP):
            return "TCP"

        if packet.haslayer(UDP):
            return "UDP"

        # Network Layer checks
        if packet.haslayer(ARP):
            return "ARP"

        if packet.haslayer(IP):
            return "IPv4"

        if packet.haslayer(IPv6):
            return "IPv6"

        # Link Layer check
        if packet.haslayer(Ether):
            return "Ethernet"

        return "OTHER"
    except Exception as exc:
        logger.debug("Error detecting protocol: %s", exc)
        return "UNKNOWN"


def _extract_safe_http_info(tcp: TCP) -> str:
    """
    Safely extract HTTP request method/line or response code without sensitive headers.
    """
    try:
        raw_payload = bytes(tcp.payload)
        if not raw_payload:
            return "HTTP [Empty]"
        
        # Read only the first line up to \r\n or max 60 bytes
        first_line = raw_payload.split(b"\r\n", 1)[0][:60].decode("ascii", errors="replace").strip()
        if any(first_line.startswith(m) for m in ("GET", "POST", "HEAD", "PUT", "DELETE", "HTTP/")):
            return f"HTTP: {first_line}"
        return "HTTP Data"
    except Exception:
        return "HTTP Traffic"


def _extract_safe_tls_info(tcp: TCP) -> str:
    """
    Safely summarize TLS state without decrypting payload.
    """
    try:
        raw_payload = bytes(tcp.payload)
        if len(raw_payload) >= 5:
            content_type = raw_payload[0]
            type_names = {
                20: "ChangeCipherSpec",
                21: "Alert",
                22: "Handshake",
                23: "Application Data (Encrypted)",
            }
            content_str = type_names.get(content_type, f"Type {content_type}")
            return f"TLS {content_str} [Payload Encrypted]"
        return "TLS Encrypted Traffic"
    except Exception:
        return "TLS Traffic"


def parse_packet(packet: Packet) -> PacketMetadata:
    """
    Safely dissect a Scapy packet and extract metadata into a PacketMetadata model.
    
    Guarantees:
      - Never crashes on incomplete or malformed packets.
      - Returns 'N/A' for any missing layers or fields.
      - Strictly avoids storing sensitive plaintext credentials.
    """
    metadata = PacketMetadata()

    # 1. Timestamp & Packet Length
    try:
        metadata.packet_length = len(packet)
        pkt_time = getattr(packet, "time", None)
        if pkt_time is not None:
            metadata.timestamp = datetime.fromtimestamp(float(pkt_time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        else:
            metadata.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception as exc:
        logger.debug("Failed parsing timestamp/length: %s", exc)
        metadata.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 2. Data Link Layer (Ethernet)
    try:
        if packet.haslayer(Ether):
            eth = packet[Ether]
            metadata.source_mac = getattr(eth, "src", "N/A")
            metadata.destination_mac = getattr(eth, "dst", "N/A")
    except Exception as exc:
        logger.debug("Failed parsing Ethernet layer: %s", exc)

    # 3. Network Layer (IPv4 / IPv6 / ARP)
    try:
        if packet.haslayer(IP):
            ip = packet[IP]
            metadata.source_ip = getattr(ip, "src", "N/A")
            metadata.destination_ip = getattr(ip, "dst", "N/A")
            metadata.ip_version = "IPv4"
        elif packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            metadata.source_ip = getattr(ip6, "src", "N/A")
            metadata.destination_ip = getattr(ip6, "dst", "N/A")
            metadata.ip_version = "IPv6"
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            metadata.source_ip = getattr(arp, "psrc", "N/A")
            metadata.destination_ip = getattr(arp, "pdst", "N/A")
            metadata.ip_version = "N/A (ARP)"
    except Exception as exc:
        logger.debug("Failed parsing Network layer: %s", exc)

    # 4. Protocol Detection
    metadata.protocol = detect_protocol(packet)

    # 5. Transport Layer (TCP / UDP / ICMP)
    info_parts = []
    try:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            metadata.source_port = str(tcp.sport)
            metadata.destination_port = str(tcp.dport)
            metadata.tcp_flags = decode_tcp_flags(tcp.flags)

            # Build info summary
            sport_name = WELL_KNOWN_PORTS.get(tcp.sport, "")
            dport_name = WELL_KNOWN_PORTS.get(tcp.dport, "")
            service_desc = f" [{dport_name or sport_name}]" if (dport_name or sport_name) else ""

            if metadata.protocol == "TLS":
                info_parts.append(_extract_safe_tls_info(tcp))
            elif metadata.protocol == "HTTP":
                info_parts.append(_extract_safe_http_info(tcp))
            else:
                info_parts.append(f"{tcp.sport} -> {tcp.dport}{service_desc} [{metadata.tcp_flags}] Seq={tcp.seq}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            metadata.source_port = str(udp.sport)
            metadata.destination_port = str(udp.dport)
            sport_name = WELL_KNOWN_PORTS.get(udp.sport, "")
            dport_name = WELL_KNOWN_PORTS.get(udp.dport, "")
            service_desc = f" [{dport_name or sport_name}]" if (dport_name or sport_name) else ""
            info_parts.append(f"{udp.sport} -> {udp.dport}{service_desc} Len={udp.len}")

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            metadata.icmp_type = f"{ICMP_TYPE_MAP.get(icmp.type, 'Type')} ({icmp.type})"
            metadata.icmp_code = str(icmp.code)
            info_parts.append(f"ICMP {metadata.icmp_type} Code={icmp.code}")

        elif packet.haslayer(ARP):
            arp = packet[ARP]
            op_desc = "Who has" if arp.op == 1 else "Is at" if arp.op == 2 else f"Op={arp.op}"
            info_parts.append(f"ARP {op_desc} {arp.pdst} tell {arp.psrc}")

    except Exception as exc:
        logger.debug("Failed parsing Transport layer: %s", exc)

    # 6. Application Layer Metadata (DNS)
    try:
        if DNS is not None and packet.haslayer(DNS):
            if packet.haslayer(DNSQR):
                dnsqr = packet[DNSQR]
                qname = getattr(dnsqr, "qname", None)
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                clean_qname = qname.rstrip(".") if qname else "N/A"
                metadata.dns_query = clean_qname
                info_parts.append(f"DNS Query: {clean_qname}")
            else:
                info_parts.append("DNS Message")
    except Exception as exc:
        logger.debug("Failed parsing DNS layer: %s", exc)

    # Fallback info if nothing was populated
    metadata.info = " | ".join(info_parts) if info_parts else f"{metadata.protocol} Packet"

    return metadata
