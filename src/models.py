"""
Data models for network packet representation, session statistics, and filtering.

Uses Python dataclasses for clean, type-annotated, self-documenting data structures.
"""

from dataclasses import dataclass, field
import time
from typing import Any, Dict, Optional


@dataclass
class PacketMetadata:
    """
    Structured metadata extracted safely from a single captured network packet.
    
    Contains protocol header information without extracting sensitive application
    payloads or credentials.
    """
    timestamp: str = "N/A"
    source_mac: str = "N/A"
    destination_mac: str = "N/A"
    source_ip: str = "N/A"
    destination_ip: str = "N/A"
    ip_version: str = "N/A"
    protocol: str = "OTHER"
    source_port: str = "N/A"
    destination_port: str = "N/A"
    packet_length: int = 0
    tcp_flags: str = "N/A"
    icmp_type: str = "N/A"
    icmp_code: str = "N/A"
    dns_query: str = "N/A"
    info: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to a dictionary matching CSV_FIELDNAMES."""
        return {
            "timestamp": self.timestamp,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "ip_version": self.ip_version,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "packet_length": self.packet_length,
            "tcp_flags": self.tcp_flags,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "dns_query": self.dns_query,
        }


@dataclass
class CaptureStats:
    """
    Cumulative statistical counters for a packet capture session.
    """
    total_packets: int = 0
    ipv4_count: int = 0
    ipv6_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    dns_count: int = 0
    http_count: int = 0
    tls_count: int = 0
    arp_count: int = 0
    other_count: int = 0
    total_bytes: int = 0
    start_time: Optional[float] = field(default_factory=time.time)
    end_time: Optional[float] = None

    def update(self, packet: PacketMetadata) -> None:
        """Update counter metrics with a newly parsed packet."""
        self.total_packets += 1
        self.total_bytes += packet.packet_length

        # IP layer accounting
        if packet.ip_version == "IPv4":
            self.ipv4_count += 1
        elif packet.ip_version == "IPv6":
            self.ipv6_count += 1

        # Protocol accounting
        proto = packet.protocol.upper()
        if "TLS" in proto or "HTTPS" in proto:
            self.tls_count += 1
            self.tcp_count += 1  # TLS runs over TCP
        elif "HTTP" in proto:
            self.http_count += 1
            self.tcp_count += 1  # HTTP runs over TCP
        elif proto == "TCP":
            self.tcp_count += 1
        elif "DNS" in proto:
            self.dns_count += 1
            self.udp_count += 1  # Standard DNS queries run over UDP
        elif proto == "UDP":
            self.udp_count += 1
        elif proto == "ICMP":
            self.icmp_count += 1
        elif proto == "ARP":
            self.arp_count += 1
        else:
            self.other_count += 1

    def finalize(self) -> None:
        """Mark completion time of capture."""
        self.end_time = time.time()

    @property
    def duration_seconds(self) -> float:
        """Return total elapsed capture duration in seconds."""
        if self.start_time is None:
            return 0.0
        end = self.end_time if self.end_time is not None else time.time()
        return max(0.0, end - self.start_time)


@dataclass
class FilterConfig:
    """
    Configuration for filtering packets during capture or display.
    """
    protocol: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

    def matches(self, packet: PacketMetadata) -> bool:
        """
        Evaluate whether a packet matches the configured filter criteria.
        Returns True if the packet meets all active filters.
        """
        # Protocol filter
        if self.protocol and self.protocol.upper() != "ALL":
            target_proto = self.protocol.upper()
            packet_proto = packet.protocol.upper()
            if target_proto == "TLS" and ("TLS" in packet_proto or "HTTPS" in packet_proto):
                pass
            elif target_proto == "HTTP" and "HTTP" in packet_proto:
                pass
            elif target_proto == "DNS" and "DNS" in packet_proto:
                pass
            elif target_proto == "TCP" and ("TCP" in packet_proto or "HTTP" in packet_proto or "TLS" in packet_proto):
                pass
            elif target_proto == "UDP" and ("UDP" in packet_proto or "DNS" in packet_proto):
                pass
            elif target_proto != packet_proto:
                return False

        # Source IP filter
        if self.source_ip:
            if self.source_ip.strip() != packet.source_ip.strip():
                return False

        # Destination IP filter
        if self.destination_ip:
            if self.destination_ip.strip() != packet.destination_ip.strip():
                return False

        return True
