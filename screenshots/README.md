# Internship Screenshot Demonstration Guide

This guide details the **15 required screenshots** for the B.Tech Cybersecurity Internship submission of the **Python Network Packet Sniffer & Traffic Analyzer** project.

Each section outlines the target filename, command to generate the view, what must be visible, and why it is essential for academic and technical evaluation.

---

### Screenshot 1: Project Directory Structure
- **Suggested Filename:** `01_project_structure.png`
- **Command:** `tree /F` (PowerShell/CMD) or VS Code Explorer view
- **What should be visible:** The complete workspace showing `src/`, `tests/`, `logs/`, `screenshots/`, `requirements.txt`, `README.md`, `report_notes.md`, `VIVA_QUESTIONS.md`, and `FINAL_CHECKLIST.md`.
- **Why it matters:** Demonstrates clean, professional modular engineering and separation of concerns according to industry standards.

---

### Screenshot 2: Python Environment Verification
- **Suggested Filename:** `02_python_environment.png`
- **Command:** `python --version` and `python -m pip --version`
- **What should be visible:** Python 3.x runtime and pip package manager details in the terminal.
- **Why it matters:** Proves the application is running in an authentic, modern Python 3 development environment.

---

### Screenshot 3: Dependency Installation (Scapy & Pytest)
- **Suggested Filename:** `03_scapy_installation.png`
- **Command:** `python -m pip install -r requirements.txt`
- **What should be visible:** Successful installation logs of `scapy` and verification that `pytest` is satisfied.
- **Why it matters:** Validates repeatable dependency management and third-party library integration.

---

### Screenshot 4: Network Interface Enumeration
- **Suggested Filename:** `04_network_interfaces.png`
- **Command:** `python src/main.py --list-interfaces`
- **What should be visible:** Formatted ASCII table listing network adapters (e.g., Wi-Fi, Ethernet, Loopback) with their respective Index, Description, IPv4/IPv6 addresses, and MAC addresses.
- **Why it matters:** Confirms OS-level network adapter discovery and Scapy interface bindings.

---

### Screenshot 5: Sniffer Startup & Configuration Banner
- **Suggested Filename:** `05_sniffer_starting.png`
- **Command:** `python src/main.py --demo --count 10`
- **What should be visible:** The top startup banner showing tool title, version, active interface, packet count limit, and ethical compliance notice.
- **Why it matters:** Shows user-friendly CLI design, defensive defaults (packet limit enforced), and prominent ethical disclaimers.

---

### Screenshot 6: Real-Time Live Packet Capture Stream
- **Suggested Filename:** `06_packet_stream.png`
- **Command:** `python src/main.py --demo --count 10`
- **What should be visible:** Real-time rows showing `No.`, `Source IP`, `Destination IP`, `Protocol`, `Length`, and `Info` columns streaming in the console.
- **Why it matters:** Illustrates packet ingestion and dynamic tabular rendering across multiple network flows.

---

### Screenshot 7: TCP Packet Parsing & Flags
- **Suggested Filename:** `07_tcp_packet.png`
- **Command:** `python src/main.py --demo --protocol TCP --count 5`
- **What should be visible:** TCP packets highlighting source/destination ports (e.g., 51422 -> 80) and decoded TCP control flags (`SYN`, `SYN, ACK`, `ACK`, `PSH, ACK`).
- **Why it matters:** Demonstrates Layer 4 Transport Layer dissection and 3-way handshake flag decoding.

---

### Screenshot 8: UDP Packet Dissection
- **Suggested Filename:** `08_udp_packet.png`
- **Command:** `python src/main.py --demo --protocol UDP --count 5`
- **What should be visible:** UDP datagram rows showing source port, destination port, and datagram payload length.
- **Why it matters:** Proves understanding of connectionless transport protocols compared to stateful TCP.

---

### Screenshot 9: DNS Query Inspection
- **Suggested Filename:** `09_dns_packet.png`
- **Command:** `python src/main.py --demo --protocol DNS --count 5`
- **What should be visible:** DNS protocol identification (port 53) and extracted queried domain name (e.g., `www.cybersecurity-internship.edu`).
- **Why it matters:** Validates Application Layer parsing and extraction of safe domain query metadata from DNS question records (`DNSQR`).

---

### Screenshot 10: TLS/HTTPS Metadata Detection
- **Suggested Filename:** `10_tls_metadata.png`
- **Command:** `python src/main.py --demo --protocol TLS --count 5`
- **What should be visible:** TLS rows indicating `TLS Handshake` or `TLS Application Data (Encrypted)` with port 443.
- **Why it matters:** Confirms encrypted protocol recognition and demonstrates strict ethical boundaries (metadata logging without unauthorized decryption).

---

### Screenshot 11: Post-Capture Statistical Summary
- **Suggested Filename:** `11_capture_summary.png`
- **Command:** Displayed automatically upon capture completion
- **What should be visible:** Summary box displaying total packets, total bytes transferred, duration, packet rate, and protocol breakdown (IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS).
- **Why it matters:** Demonstrates aggregated statistical profiling of network traffic patterns.

---

### Screenshot 12: CSV Log Inspection
- **Suggested Filename:** `12_csv_output.png`
- **Command:** Open `logs/captured_packets.csv` in Excel, VS Code, or run `Get-Content logs/captured_packets.csv -Head 10`
- **What should be visible:** Standard CSV header row followed by comma-separated records with properly formatted IPs, MACs, protocols, ports, and flags.
- **Why it matters:** Proves audit logging, structured data export, and integration readiness for SIEM or spreadsheet analysis.

---

### Screenshot 13: Automated Unit Test Suite Execution
- **Suggested Filename:** `13_unit_tests_passing.png`
- **Command:** `python -m pytest tests/ -v`
- **What should be visible:** 15 out of 15 tests marked green `PASSED` in pytest output with execution time.
- **Why it matters:** Verifies software quality, test-driven validation, and independence from live network dependencies through synthetic Scapy packets.

---

### Screenshot 14: Wireshark Live Packet Inspection
- **Suggested Filename:** `14_wireshark_packet.png`
- **Action:** Open Wireshark, select your active adapter (e.g., Wi-Fi), filter by `dns || icmp || tcp.port == 80`, and capture traffic.
- **What should be visible:** Wireshark packet details pane showing frame, Ethernet, IP, and TCP/UDP header fields.
- **Why it matters:** Demonstrates industry-standard reference validation using Wireshark.

---

### Screenshot 15: Side-by-Side Python Sniffer vs. Wireshark Comparison
- **Suggested Filename:** `15_python_vs_wireshark_comparison.png`
- **Action:** Arrange Python sniffer terminal on the left and Wireshark packet list on the right capturing the same event (e.g., ping or DNS query).
- **What should be visible:** Matching Source IP, Destination IP, Protocol, and Length between the Python sniffer row and the Wireshark packet row.
- **Why it matters:** Definitive proof that the custom Python sniffer accurately dissects real network traffic in alignment with Wireshark.
