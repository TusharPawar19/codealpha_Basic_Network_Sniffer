"""
Configuration and constants for Python Network Packet Sniffer & Traffic Analyzer.

Defines operational defaults, protocol port mappings, TCP flag descriptions,
and ethical boundaries for educational and authorized network analysis.
"""

from pathlib import Path

# Application Metadata
APP_NAME = "Python Network Packet Sniffer & Traffic Analyzer"
APP_VERSION = "1.0.0"
APP_SUBTITLE = "Cybersecurity Internship - Task 1"

# Capture Operational Defaults
DEFAULT_PACKET_COUNT = 50          # Safe default: capture never runs indefinitely
DEFAULT_TIMEOUT = None             # Optional capture timeout in seconds
DEFAULT_OUTPUT_DIR = Path("logs")
DEFAULT_CSV_FILENAME = "captured_packets.csv"
DEFAULT_OUTPUT_PATH = DEFAULT_OUTPUT_DIR / DEFAULT_CSV_FILENAME

# CSV Export Fieldnames (strict standard schema)
CSV_FIELDNAMES = [
    "timestamp",
    "source_mac",
    "destination_mac",
    "source_ip",
    "destination_ip",
    "ip_version",
    "protocol",
    "source_port",
    "destination_port",
    "packet_length",
    "tcp_flags",
    "icmp_type",
    "icmp_code",
    "dns_query",
]

# Standard Well-Known Ports for Port-to-Service Context
WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS/TLS",
    465: "SMTPS",
    587: "SMTP-Submission",
    853: "DNS-over-TLS",
    993: "IMAPS",
    995: "POP3S",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# TCP Control Flag Mappings
TCP_FLAGS_MAP = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

# ICMP Type Mappings for IPv4
ICMP_TYPE_MAP = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

# Supported Protocols for Filtering
SUPPORTED_FILTER_PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "TLS", "ARP", "ALL"]

# Ethical Use Banner Notice
ETHICAL_DISCLAIMER = """
[!] ETHICAL & LEGAL COMPLIANCE NOTICE:
    This tool is designed strictly for educational purposes, authorized
    network diagnostics, and internship evaluation. Capturing network
    traffic on networks without explicit administrative authorization is
    illegal and prohibited. This tool collects packet headers and metadata
    only and strictly avoids sensitive payload extraction.
"""
