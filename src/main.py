"""
Main CLI entry point for Python Network Packet Sniffer & Traffic Analyzer.

Provides both command-line argument parsing and an interactive prompt mode
for interface selection, filtering, and export configuration.
"""

import argparse
import logging
from pathlib import Path
import sys
from typing import Optional

# Suppress scapy runtime warnings (e.g. no libpcap provider on Windows)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Ensure project root is on sys.path for direct module execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import (
    APP_NAME,
    APP_SUBTITLE,
    APP_VERSION,
    DEFAULT_OUTPUT_PATH,
    DEFAULT_PACKET_COUNT,
    ETHICAL_DISCLAIMER,
    SUPPORTED_FILTER_PROTOCOLS,
)
from src.display import print_banner, print_interfaces_table
from src.models import FilterConfig
from src.sniffer import (
    SnifferEngine,
    get_available_interfaces,
    resolve_interface,
)


def setup_logging(verbose: bool = False) -> None:
    """Configure console logging level and format."""
    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_arguments() -> argparse.Namespace:
    """Configure and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="python src/main.py",
        description=f"{APP_NAME} (v{APP_VERSION}) - Educational packet capture and traffic analysis.",
        epilog="Examples (Windows PowerShell / CMD):\n"
               "  python src/main.py --list-interfaces\n"
               "  python src/main.py --demo\n"
               "  python src/main.py --interface 1 --count 50\n"
               "  python src/main.py --interface \"Wi-Fi\" --protocol DNS --count 20\n"
               "  python src/main.py --interface \"Ethernet\" --output logs/my_packets.csv\n"
               "\nEthical Notice: Use ONLY on networks you own or have permission to analyze.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface name, internal ID, or index number (e.g., '1', 'Wi-Fi', 'Ethernet').",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=DEFAULT_PACKET_COUNT,
        help=f"Maximum number of matching packets to capture (default: {DEFAULT_PACKET_COUNT}).",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=None,
        help="Capture timeout duration in seconds (default: None, terminates on packet count or Ctrl+C).",
    )
    parser.add_argument(
        "-p", "--protocol",
        type=str,
        default=None,
        choices=SUPPORTED_FILTER_PROTOCOLS,
        help="Filter traffic by protocol: TCP, UDP, ICMP, DNS, HTTP, TLS, ARP.",
    )
    parser.add_argument(
        "-s", "--source",
        type=str,
        default=None,
        help="Filter traffic by source IP address (e.g., '192.168.1.10').",
    )
    parser.add_argument(
        "-d", "--destination",
        type=str,
        default=None,
        help="Filter traffic by destination IP address (e.g., '8.8.8.8').",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=str(DEFAULT_OUTPUT_PATH),
        help=f"Filepath to export captured packet metadata as CSV (default: {DEFAULT_OUTPUT_PATH}).",
    )
    parser.add_argument(
        "-l", "--list-interfaces",
        action="store_true",
        help="List all active network interfaces with IP/MAC addresses and exit.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run offline synthetic packet demonstration mode (no driver or root privileges required).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable detailed debug logging.",
    )

    return parser.parse_args()


def interactive_interface_selection() -> Optional[any]:
    """Prompt user interactively to select an available network interface."""
    interfaces = get_available_interfaces()
    if not interfaces:
        print("\n[!] No active network interfaces detected.")
        return None

    print_interfaces_table(interfaces)
    print("\nPlease select an interface number for packet capture:")

    while True:
        try:
            choice = input("Enter interface index (or press Enter for default, 'q' to quit): ").strip()
            if choice.lower() == "q":
                print("Exiting program.")
                sys.exit(0)
            if not choice:
                return interfaces[0]["raw"]

            if choice.isdigit():
                val = int(choice)
                if 1 <= val <= len(interfaces):
                    return interfaces[val - 1]["raw"]

            print(f"[!] Invalid selection '{choice}'. Please enter a number between 1 and {len(interfaces)}.")
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled.")
            sys.exit(0)


def run_interactive_mode() -> None:
    """Guide the user through interactive setup when no CLI arguments are supplied."""
    print("=" * 72)
    print(f"{APP_NAME:^72}")
    print(f"{APP_SUBTITLE}:^72".center(72))
    print("=" * 72)
    print(ETHICAL_DISCLAIMER)

    # 1. Interface selection
    selected_iface = interactive_interface_selection()
    if selected_iface is None:
        return

    # 2. Packet count
    count = DEFAULT_PACKET_COUNT
    count_input = input(f"\nEnter packet capture limit [default: {DEFAULT_PACKET_COUNT}]: ").strip()
    if count_input.isdigit() and int(count_input) > 0:
        count = int(count_input)

    # 3. Timeout
    timeout = None
    timeout_input = input("Enter capture timeout in seconds [default: None / press Enter]: ").strip()
    if timeout_input.isdigit() and int(timeout_input) > 0:
        timeout = int(timeout_input)

    # 4. Protocol filter
    proto_filter = None
    print(f"\nSupported protocol filters: {', '.join(SUPPORTED_FILTER_PROTOCOLS[:-1])}")
    proto_input = input("Filter by protocol [default: All / press Enter]: ").strip().upper()
    if proto_input in SUPPORTED_FILTER_PROTOCOLS and proto_input != "ALL":
        proto_filter = proto_input

    # 5. Output file
    output_path = str(DEFAULT_OUTPUT_PATH)
    out_input = input(f"Output CSV path [default: {DEFAULT_OUTPUT_PATH}]: ").strip()
    if out_input:
        output_path = out_input

    filter_cfg = FilterConfig(protocol=proto_filter)
    filter_desc = f"Protocol={proto_filter}" if proto_filter else "None"

    # Print banner and launch capture
    iface_name = getattr(selected_iface, "description", getattr(selected_iface, "name", str(selected_iface)))
    print_banner(
        interface=iface_name,
        packet_limit=count,
        timeout=timeout,
        filter_desc=filter_desc,
    )

    sniffer = SnifferEngine(
        interface=selected_iface,
        count=count,
        timeout=timeout,
        filter_config=filter_cfg,
        output_file=output_path,
    )
    sniffer.run()


def main() -> None:
    """Main execution function."""
    args = parse_arguments()
    setup_logging(verbose=args.verbose)

    # If --list-interfaces requested
    if args.list_interfaces:
        ifaces = get_available_interfaces()
        print_interfaces_table(ifaces)
        return

    # If --demo mode requested
    if args.demo:
        filter_cfg = FilterConfig(
            protocol=args.protocol,
            source_ip=args.source,
            destination_ip=args.destination,
        )
        filter_desc_parts = []
        if args.protocol:
            filter_desc_parts.append(f"Protocol={args.protocol}")
        if args.source:
            filter_desc_parts.append(f"Src={args.source}")
        if args.destination:
            filter_desc_parts.append(f"Dst={args.destination}")
        filter_desc = ", ".join(filter_desc_parts) if filter_desc_parts else "None"

        print_banner(
            interface="Synthetic Demo Engine",
            packet_limit=args.count,
            timeout=args.timeout,
            filter_desc=filter_desc,
        )
        sniffer = SnifferEngine(
            interface=None,
            count=args.count,
            timeout=args.timeout,
            filter_config=filter_cfg,
            output_file=args.output,
        )
        sniffer.run_demo(count=args.count)
        return

    # If no specific arguments provided and sys.argv was empty (or only default script called)
    if len(sys.argv) == 1:
        run_interactive_mode()
        return

    # CLI mode with explicit arguments
    selected_iface = resolve_interface(args.interface) if args.interface else None
    iface_display = getattr(selected_iface, "description", getattr(selected_iface, "name", str(args.interface or "Default Adapter")))

    filter_cfg = FilterConfig(
        protocol=args.protocol,
        source_ip=args.source,
        destination_ip=args.destination,
    )

    filter_desc_parts = []
    if args.protocol:
        filter_desc_parts.append(f"Protocol={args.protocol}")
    if args.source:
        filter_desc_parts.append(f"Src={args.source}")
    if args.destination:
        filter_desc_parts.append(f"Dst={args.destination}")
    filter_desc = ", ".join(filter_desc_parts) if filter_desc_parts else "None"

    print_banner(
        interface=iface_display,
        packet_limit=args.count,
        timeout=args.timeout,
        filter_desc=filter_desc,
    )

    sniffer = SnifferEngine(
        interface=selected_iface,
        count=args.count,
        timeout=args.timeout,
        filter_config=filter_cfg,
        output_file=args.output,
    )
    sniffer.run()


if __name__ == "__main__":
    main()
