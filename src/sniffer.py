"""
Packet capture engine built on top of Scapy.

Provides live network traffic capture, interface resolution, graceful termination
via Ctrl+C, timeout controls, packet limit enforcement, and platform-specific
permission / driver error handling (e.g., Windows Npcap requirements).
"""

import logging
import platform
import sys
import time
from typing import Callable, List, Optional, Tuple, Union

import scapy.all as scapy
from scapy.packet import Packet

from src.config import DEFAULT_PACKET_COUNT, DEFAULT_TIMEOUT
from src.display import print_packet, print_summary
from src.exporter import export_to_csv
from src.models import CaptureStats, FilterConfig, PacketMetadata
from src.packet_parser import parse_packet

logger = logging.getLogger(__name__)


def get_available_interfaces() -> List[dict]:
    """
    Enumerate and return active or available network interfaces in a clean format.
    
    Returns a list of dicts with keys: 'id', 'name', 'description', 'ip', 'mac', 'raw_iface'.
    """
    interfaces = []
    try:
        ifaces = scapy.conf.ifaces
        seen_names = set()

        for idx, key in enumerate(ifaces):
            iface_obj = ifaces[key]
            name = getattr(iface_obj, "name", str(key))
            description = getattr(iface_obj, "description", name)
            ip_addr = getattr(iface_obj, "ip", "N/A") or "N/A"
            mac_addr = getattr(iface_obj, "mac", "N/A") or "N/A"

            # Filter duplicates or empty virtual miniports if possible
            display_name = description if (description and description != name) else name
            if display_name in seen_names and ip_addr == "N/A":
                continue
            seen_names.add(display_name)

            interfaces.append({
                "index": len(interfaces) + 1,
                "name": display_name,
                "internal_name": name,
                "ip": ip_addr,
                "mac": mac_addr,
                "raw": iface_obj,
            })
    except Exception as exc:
        logger.debug("Failed querying Scapy conf.ifaces: %s", exc)

    # Separate into active (has IP) and inactive
    active_ifaces = []
    other_ifaces = []

    for item in interfaces:
        # Exclude WAN Miniport / QoS filter noise if it has no IP
        name_lower = item["name"].lower()
        if "wan miniport" in name_lower and item["ip"] == "N/A":
            continue
        if "qos packet scheduler" in name_lower and item["ip"] == "N/A":
            continue
        if "filter driver" in name_lower and item["ip"] == "N/A":
            continue
        if "wfp 802.3" in name_lower and item["ip"] == "N/A":
            continue
        if "wfp native" in name_lower and item["ip"] == "N/A":
            continue

        ip = item["ip"]
        if ip != "N/A" and not ip.startswith("169.254"):
            active_ifaces.append(item)
        else:
            other_ifaces.append(item)

    combined = active_ifaces + other_ifaces
    for idx, item in enumerate(combined, 1):
        item["index"] = idx

    return combined


def resolve_interface(interface_spec: Optional[str]) -> Optional[any]:
    """
    Resolve a user-provided interface string (number or name) to a Scapy interface.
    """
    if not interface_spec:
        return None

    all_ifaces = get_available_interfaces()

    # Case 1: Numeric index provided
    if interface_spec.isdigit():
        idx = int(interface_spec)
        for iface in all_ifaces:
            if iface["index"] == idx:
                return iface["raw"]

    # Case 2: Exact or substring match on name or internal_name
    spec_lower = interface_spec.lower().strip()
    for iface in all_ifaces:
        if spec_lower == iface["name"].lower() or spec_lower == iface["internal_name"].lower():
            return iface["raw"]
        if spec_lower in iface["name"].lower() or spec_lower in iface["internal_name"].lower():
            return iface["raw"]

    # Case 3: Return raw string as provided to Scapy
    return interface_spec


def print_driver_requirement_notice() -> None:
    """Print an informative notice when Windows packet capture drivers are missing."""
    is_windows = platform.system().lower() == "windows"
    print("\n" + "=" * 74)
    print(" [!] PACKET CAPTURE PREREQUISITE NOTICE (DRIVER REQUIRED)".center(74))
    print("=" * 74)
    if is_windows:
        print("""
 On Windows, live Layer-2 raw packet capture requires the Npcap driver.
 Without Npcap, Windows kernel policies prevent non-administrative raw socket access.

 HOW TO ENABLE LIVE CAPTURE ON WINDOWS:
  1. Download the official Npcap installer:
     https://npcap.com/#download
  2. During installation, ensure you select:
     [X] "Install Npcap in WinPcap API-compatible Mode"
  3. Restart your PowerShell / Command Prompt terminal.
  4. Run the sniffer again:
     python src/main.py

 DEMONSTRATION & TESTING ALTERNATIVES:
  - Run the automated synthetic unit tests (which run 100% without Npcap):
     pytest tests/ -v
  - Run the built-in synthetic demonstration mode to verify parsing and display:
     python src/main.py --demo
""")
    else:
        print("""
 On Linux/macOS, raw packet capture requires elevated privileges.
 Run the script with sudo:
   sudo python3 src/main.py
""")
    print("=" * 74 + "\n")


class SnifferEngine:
    """
    Core packet capture and processing coordinator.
    """

    def __init__(
        self,
        interface: Optional[any] = None,
        count: int = DEFAULT_PACKET_COUNT,
        timeout: Optional[int] = DEFAULT_TIMEOUT,
        filter_config: Optional[FilterConfig] = None,
        output_file: Optional[str] = None,
    ):
        self.interface = interface
        self.count = count
        self.timeout = timeout
        self.filter_config = filter_config or FilterConfig()
        self.output_file = output_file
        self.captured_packets: List[PacketMetadata] = []
        self.stats = CaptureStats()
        self._matched_count = 0
        self._interrupted = False

    def _packet_handler(self, raw_pkt: Packet) -> None:
        """Internal callback invoked by Scapy for each captured packet."""
        try:
            metadata = parse_packet(raw_pkt)

            # Apply user filtering
            if not self.filter_config.matches(metadata):
                return

            self._matched_count += 1
            self.captured_packets.append(metadata)
            self.stats.update(metadata)

            # Display real-time line in terminal
            print_packet(metadata, self._matched_count)

        except Exception as exc:
            logger.error("Error processing packet: %s", exc)

    def _stop_filter(self, raw_pkt: Packet) -> bool:
        """Predicate to determine if capture should stop."""
        if self._interrupted:
            return True
        if self.count and self._matched_count >= self.count:
            return True
        return False

    def run(self) -> Tuple[List[PacketMetadata], CaptureStats]:
        """
        Execute the packet capture session with error resilience.
        """
        logger.info("Initiating packet capture session on interface: %s", self.interface)

        try:
            sniff_kwargs = {
                "prn": self._packet_handler,
                "stop_filter": self._stop_filter,
                "store": False,  # Memory-safe: do not retain raw packets in Scapy's internal list
            }

            if self.interface is not None:
                sniff_kwargs["iface"] = self.interface

            if self.timeout is not None and self.timeout > 0:
                sniff_kwargs["timeout"] = self.timeout

            # Run Scapy sniffing
            scapy.sniff(**sniff_kwargs)

        except KeyboardInterrupt:
            print("\n\n[*] Capture session interrupted by user (Ctrl+C). Finalizing results...")
            self._interrupted = True
        except (RuntimeError, OSError, PermissionError) as drv_err:
            logger.warning("Packet capture driver/permission error: %s", drv_err)
            print_driver_requirement_notice()
        except Exception as exc:
            logger.error("Unexpected capture error: %s", exc)
            print(f"\n[!] Capture encountered an error: {exc}")
        finally:
            self.stats.finalize()

        # Export to CSV if packets were captured and output path specified
        if self.output_file and self.captured_packets:
            export_to_csv(self.captured_packets, self.output_file)

        # Render summary report
        print_summary(self.stats, self.output_file if self.captured_packets else None)

        return self.captured_packets, self.stats

    def run_demo(self, count: int = 15) -> Tuple[List[PacketMetadata], CaptureStats]:
        """
        Execute an offline demonstration generating synthetic packets.
        
        Allows full pipeline demonstration (parsing, filtering, display, CSV export)
        without requiring Npcap drivers or live network interfaces.
        """
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether

        print("\n[*] Initializing Synthetic Demonstration Mode (Driver-Independent)...")
        time.sleep(0.5)

        synthetic_templates = [
            # 1. DNS Query
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.100", dst="8.8.8.8")
            / UDP(sport=53210, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="www.cybersecurity-internship.edu")),
            # 2. TCP SYN Handshake
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.100", dst="93.184.216.34")
            / TCP(sport=51422, dport=80, flags="S", seq=1000),
            # 3. TCP SYN-ACK Handshake response
            Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
            / IP(src="93.184.216.34", dst="192.168.1.100")
            / TCP(sport=80, dport=51422, flags="SA", seq=5000, ack=1001),
            # 4. TCP ACK Handshake completion
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.100", dst="93.184.216.34")
            / TCP(sport=51422, dport=80, flags="A", seq=1001, ack=5001),
            # 5. HTTP GET Request
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.100", dst="93.184.216.34")
            / TCP(sport=51422, dport=80, flags="PA", seq=1001, ack=5001)
            / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            # 6. TLS Handshake Client Hello (HTTPS)
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.100", dst="142.250.190.46")
            / TCP(sport=58310, dport=443, flags="PA")
            / b"\x16\x03\x03\x00\x95\x01\x00\x00\x91\x03\x03",  # TLS 1.2 Handshake (Client Hello)
            # 7. TLS Encrypted Application Data
            Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
            / IP(src="142.250.190.46", dst="192.168.1.100")
            / TCP(sport=443, dport=58310, flags="PA")
            / (b"\x17\x03\x03\x01\x20" + (b"\xaa" * 288)),  # TLS 1.2 App Data
            # 8. ICMP Echo Request (Ping)
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.100", dst="1.1.1.1")
            / ICMP(type=8, code=0, id=1, seq=1),
            # 9. ICMP Echo Reply (Ping Response)
            Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
            / IP(src="1.1.1.1", dst="192.168.1.100")
            / ICMP(type=0, code=0, id=1, seq=1),
            # 10. IPv6 TCP SYN Packet
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IPv6(src="2001:db8::1", dst="2606:4700:4700::1111")
            / TCP(sport=59200, dport=443, flags="S"),
        ]

        # Replay the synthetic packet stream until requested matched count is satisfied
        max_attempts = count * 15
        attempt = 0
        while self._matched_count < count and attempt < max_attempts:
            pkt_template = synthetic_templates[attempt % len(synthetic_templates)]
            self._packet_handler(pkt_template)
            attempt += 1
            time.sleep(0.05)  # Simulate realistic arrival delay

        self.stats.finalize()

        if self.output_file and self.captured_packets:
            export_to_csv(self.captured_packets, self.output_file)

        print_summary(self.stats, self.output_file if self.captured_packets else None)

        return self.captured_packets, self.stats
