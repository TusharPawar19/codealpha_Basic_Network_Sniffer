"""
Terminal presentation and formatting module for Network Packet Sniffer.

Generates professional ASCII banners, real-time live packet streaming rows,
aligned column tables, and post-capture protocol distribution summaries.
"""

import sys
from typing import List, Optional
from src.config import APP_NAME, APP_SUBTITLE, APP_VERSION
from src.models import CaptureStats, PacketMetadata


def print_banner(
    interface: str,
    packet_limit: Optional[int],
    timeout: Optional[int] = None,
    filter_desc: Optional[str] = None,
) -> None:
    """Print the startup banner and operational parameters."""
    limit_str = str(packet_limit) if packet_limit else "Unlimited (Ctrl+C to stop)"
    timeout_str = f"{timeout} seconds" if timeout else "None (Count limit based)"
    filter_str = filter_desc if filter_desc else "None (Capturing all traffic)"

    print("=" * 72)
    print(f"{APP_NAME:^72}")
    print(f"{APP_SUBTITLE} (v{APP_VERSION})".center(72))
    print("=" * 72)
    print(f" Interface      : {interface}")
    print(f" Packet Limit   : {limit_str}")
    print(f" Timeout        : {timeout_str}")
    print(f" Filter Active  : {filter_str}")
    print(f" Capture Status : Running (Safe Metadata Analysis)")
    print("-" * 72)
    # Table header
    header = f"{'No.':<5} {'Source IP':<20} {'Destination IP':<20} {'Protocol':<10} {'Length':<8} {'Info'}"
    print(header)
    print("-" * 72)
    sys.stdout.flush()


def format_packet_row(packet: PacketMetadata, index: int) -> str:
    """
    Format a single captured packet metadata object into an aligned row.
    """
    src_display = packet.source_ip if packet.source_ip != "N/A" else packet.source_mac
    dst_display = packet.destination_ip if packet.destination_ip != "N/A" else packet.destination_mac

    # Truncate extremely long IPv6 addresses if needed to preserve column alignment
    if len(src_display) > 19:
        src_display = src_display[:17] + ".."
    if len(dst_display) > 19:
        dst_display = dst_display[:17] + ".."

    # Provide concise info preview
    info_preview = packet.info if packet.info else f"{packet.protocol} payload"
    if len(info_preview) > 35:
        info_preview = info_preview[:32] + "..."

    row = (
        f"{index:<5} "
        f"{src_display:<20} "
        f"{dst_display:<20} "
        f"{packet.protocol:<10} "
        f"{packet.packet_length:<8} "
        f"{info_preview}"
    )
    return row


def print_packet(packet: PacketMetadata, index: int) -> None:
    """Print formatted packet row to standard output and flush."""
    print(format_packet_row(packet, index))
    sys.stdout.flush()


def print_summary(stats: CaptureStats, output_file: Optional[str] = None) -> None:
    """
    Print the post-capture protocol summary metrics box.
    """
    duration = stats.duration_seconds
    rate = (stats.total_packets / duration) if duration > 0 else 0.0
    kbytes = stats.total_bytes / 1024.0

    print("\n" + "=" * 72)
    print(f"{'CAPTURE SUMMARY':^72}")
    print("=" * 72)
    print(f" Total Packets Captured : {stats.total_packets}")
    print(f" Total Bytes Transferred: {stats.total_bytes:,} bytes ({kbytes:.2f} KB)")
    print(f" Capture Duration       : {duration:.2f} seconds")
    print(f" Average Packet Rate    : {rate:.2f} packets/sec")
    print("-" * 72)
    print(f"{'Protocol Breakdown:':<35}{'Packet Count:':>35}")
    print("-" * 72)
    print(f"   IPv4 Packets         : {stats.ipv4_count:>30}")
    print(f"   IPv6 Packets         : {stats.ipv6_count:>30}")
    print(f"   TCP Packets (Total)  : {stats.tcp_count:>30}")
    print(f"   UDP Packets (Total)  : {stats.udp_count:>30}")
    print(f"   ICMP Packets         : {stats.icmp_count:>30}")
    print(f"   DNS Queries/Answers  : {stats.dns_count:>30}")
    print(f"   HTTP Packets         : {stats.http_count:>30}")
    print(f"   TLS/HTTPS Packets    : {stats.tls_count:>30}")
    print(f"   ARP Packets          : {stats.arp_count:>30}")
    print(f"   Other Protocols      : {stats.other_count:>30}")
    print("=" * 72)
    if output_file:
        print(f" [+] Packet metadata successfully exported to: {output_file}")
        print("=" * 72)
    sys.stdout.flush()


def print_interfaces_table(interfaces: List[dict]) -> None:
    """
    Print an enumeration of available network interfaces for user selection.
    """
    print("\n" + "=" * 72)
    print(f"{'AVAILABLE NETWORK INTERFACES':^72}")
    print("=" * 72)
    print(f"{'Idx':<5} {'Interface Name':<28} {'IP Address':<18} {'MAC Address'}")
    print("-" * 72)
    for idx, iface in enumerate(interfaces, 1):
        name = iface.get("name", "Unknown")
        if len(name) > 27:
            name = name[:25] + ".."
        ip_addr = iface.get("ip", "N/A")
        mac_addr = iface.get("mac", "N/A")
        print(f"{idx:<5} {name:<28} {ip_addr:<18} {mac_addr}")
    print("=" * 72)
    sys.stdout.flush()
