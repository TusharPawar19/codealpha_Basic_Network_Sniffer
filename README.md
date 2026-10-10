# Python Network Packet Sniffer & Traffic Analyzer

**Cybersecurity Internship — Task 1 Project**  
*A modular, ethical, educational network packet capture and protocol analysis engine built with Python and Scapy.*

---

## Table of Contents
- [Project Overview](#project-overview)
- [Internship Task & Objectives](#internship-task--objectives)
- [Problem Statement](#problem-statement)
- [Core Features](#core-features)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Project Directory Structure](#project-directory-structure)
- [Environment Setup & Installation](#environment-setup--installation)
  - [Windows Setup (PowerShell / CMD)](#windows-setup-powershell--cmd)
  - [Linux / macOS Setup](#linux--macos-setup)
  - [Windows Packet Capture Driver (Npcap)](#windows-packet-capture-driver-npcap)
- [Usage & Execution Modes](#usage--execution-modes)
  - [1. Offline Synthetic Demonstration Mode](#1-offline-synthetic-demonstration-mode)
  - [2. Command-Line Execution](#2-command-line-execution)
  - [3. Interactive Setup Menu](#3-interactive-setup-menu)
- [Command-Line Options](#command-line-options)
- [Supported Protocols & Multi-Layer Dissection](#supported-protocols--multi-layer-dissection)
- [Safe Payload Handling & Ethical Boundaries](#safe-payload-handling--ethical-boundaries)
- [Packet Filtering Engine](#packet-filtering-engine)
- [CSV Export & Reporting](#csv-export--reporting)
- [Automated Testing Suite](#automated-testing-suite)
- [Wireshark Validation Methodology](#wireshark-validation-methodology)
- [Security & Privacy Audit](#security--privacy-audit)
- [Limitations & Future Scope](#limitations--future-scope)
- [Submission Material & Screenshots](#submission-material--screenshots)
- [License & Ethical Disclaimer](#license--ethical-disclaimer)

---

## Project Overview
The **Python Network Packet Sniffer & Traffic Analyzer** is a lightweight, defensive cybersecurity tool developed as part of the B.Tech Cybersecurity Internship (Task 1). It captures network packets traversing host network interfaces, decodes header fields across the TCP/IP stack (Data Link, Network, Transport, and Application layers), formats real-time diagnostic streams in the console, tallies statistical traffic distributions, and safely exports packet metadata to structured CSV logs for forensic review.

---

## Internship Task & Objectives

### Primary Objectives:
1. **Packet Capture:** Ingest raw packets from authorized physical or virtual network adapters.
2. **Protocol Dissection:** Parse and explain the structure of Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS packets.
3. **Data Flow Demonstration:** Illustrate how information traverses network layers and socket boundaries.
4. **Packet Metadata Extraction:** Safely extract source/destination MAC addresses, source/destination IP addresses, port numbers, packet lengths, TCP control flags, ICMP types/codes, and DNS queried domains.
5. **Traffic Filtering:** Implement real-time packet filtering based on protocol family, source IP, or destination IP.
6. **Structured CSV Export:** Persist captured metadata to RFC-compliant CSV files.
7. **Automated Testing:** Implement offline synthetic test suites to ensure 100% deterministic code verification without depending on live network traffic.
8. **Wireshark Parity:** Establish a safe procedure to benchmark and validate custom parser accuracy against Wireshark.

---

## Problem Statement
Network visibility is fundamental to cybersecurity operations, intrusion detection, and network troubleshooting. Security analysts require tools to monitor traffic flows and identify anomalous protocols. However, commercial packet analyzers (such as Wireshark or tcpdump) can be complex or heavy, while basic raw socket scripts often crash on non-standard packets, lack modularity, or introduce privacy risks by dumping sensitive plaintext payloads.

This project addresses these challenges by developing a modular, robust, defensive Python packet analyzer that extracts diagnostic metadata while strictly protecting application privacy and adhering to cybersecurity ethics.

---

## Core Features
- **Multi-Layer Protocol Dissection:** Decodes Ethernet (L2), IPv4/IPv6/ARP (L3), TCP/UDP/ICMP (L4), and DNS/HTTP/TLS (L7).
- **TCP Control Flag Decoding:** Accurately decodes individual and combined flags (`SYN`, `SYN, ACK`, `ACK`, `PSH, ACK`, `FIN, ACK`, `RST`).
- **Application Metadata Extraction:** Safely extracts DNS query hostnames (`DNSQR`) and HTTP request methods without touching sensitive headers.
- **TLS/HTTPS Detection:** Identifies TLS handshake messages (Client Hello) and encrypted application data records over port 443 without attempting unlawful payload decryption.
- **Robust Defensive Parser:** Never crashes on incomplete, malformed, or non-standard packets; unpopulated layers default cleanly to `"N/A"`.
- **Traffic Filtering:** Filter captures by protocol (`--protocol`), source IP (`--source`), and destination IP (`--destination`).
- **Structured CSV Audit Logging:** Automatically exports structured metadata to `logs/captured_packets.csv`.
- **Offline Synthetic Demonstration Mode (`--demo`):** Generates and dissects in-memory packets, allowing instructors and students to evaluate the entire pipeline on systems without administrative privileges or packet-capture drivers.
- **Driver Detection & Graceful Fallbacks:** Detects Windows Npcap requirements and provides clear, actionable remediation guidance instead of raw stack traces.

---

## Technology Stack
- **Programming Language:** Python 3.10+ (tested on Python 3.14)
- **Packet Capture & Dissection:** Scapy 2.7+ (`scapy.layers.inet`, `scapy.layers.inet6`, `scapy.layers.l2`, `scapy.layers.dns`)
- **CLI Framework:** Python Standard Library `argparse`
- **Data Serialization:** Python Standard Library `csv` (`csv.DictWriter`, `csv.QUOTE_MINIMAL`)
- **Data Modeling:** Python Standard Library `dataclasses`
- **Automated Testing:** Pytest 8.0+

---

## System Architecture

```
                       +---------------------------+
                       | Network Interface / Wire |
                       +-------------+-------------+
                                     |
                                     v
                       +---------------------------+
                       |   Scapy Capture Engine    |
                       |       (sniffer.py)        |
                       +-------------+-------------+
                                     |
                                     v
                       +---------------------------+
                       |   Multi-Layer Dissector   |
                       |    (packet_parser.py)     |
                       +-------------+-------------+
                                     |
          +--------------------------+--------------------------+
          |                          |                          |
          v                          v                          v
+-------------------+      +-------------------+      +-------------------+
|  L2 / L3 Parsing  |      |   L4 Dissection   |      |  L7 Safe Metadata |
| Ethernet/IPv4/IPv6|      |   TCP / UDP / ICMP|      |   DNS / HTTP / TLS|
+---------+---------+      +---------+---------+      +---------+---------+
          |                          |                          |
          +--------------------------+--------------------------+
                                     |
                                     v
                       +---------------------------+
                       |     Filtering Engine      |
                       |    (FilterConfig model)   |
                       +-------------+-------------+
                                     |
                    +----------------+----------------+
                    |                                 |
                    v                                 v
      +---------------------------+     +---------------------------+
      | Real-Time Terminal Stream |     |      CSV Audit Logger     |
      |     & Summary Stats       |     |  (logs/captured_packets)  |
      |       (display.py)        |     |       (exporter.py)       |
      +---------------------------+     +---------------------------+
```

---

## Project Directory Structure

```
network_sniffer/
│
├── src/
│   ├── __init__.py           # Package marker & metadata
│   ├── main.py               # CLI entry point & interactive fallback menu
│   ├── sniffer.py            # Capture engine, interface resolution & demo mode
│   ├── packet_parser.py      # Multi-layer packet dissection & safe metadata extraction
│   ├── display.py            # Terminal formatting, stream rows & summary box
│   ├── exporter.py           # RFC-compliant CSV metadata writer
│   ├── config.py             # Constants, port mappings, flag bitmasks & defaults
│   └── models.py             # Dataclasses: PacketMetadata, CaptureStats, FilterConfig
│
├── logs/
│   ├── .gitkeep              # Git directory marker
│   └── captured_packets.csv  # Generated CSV audit file (excluded in .gitignore)
│
├── screenshots/
│   └── README.md             # Guide for capturing all 15 internship evaluation screenshots
│
├── tests/
│   ├── __init__.py           # Test package marker
│   └── test_packet_parser.py # 15 automated synthetic Scapy unit tests
│
├── requirements.txt          # Project dependencies (scapy, pytest)
├── README.md                 # Complete project documentation
├── report_notes.md           # 27-section comprehensive academic internship report
├── VIVA_QUESTIONS.md         # 35 technical viva exam questions & detailed answers
├── FINAL_CHECKLIST.md        # Comprehensive submission audit & verification checklist
├── .gitignore                # Production gitignore (excludes logs, venvs, caches)
└── LICENSE                   # MIT License with educational & ethical disclaimer
```

---

## Environment Setup & Installation

### Windows Setup (PowerShell / CMD)

1. **Verify Python Installation:**
   ```powershell
   python --version
   ```
   Ensure Python 3.10 or higher is installed.

2. **Create and Activate a Virtual Environment:**
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```
   *(If script execution is disabled in PowerShell, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`)*

3. **Install Required Packages:**
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

### Linux / macOS Setup

1. **Create and Activate Virtual Environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install Dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

### Windows Packet Capture Driver (Npcap)
On Microsoft Windows, capturing raw Layer 2 network frames requires the **Npcap** packet capture driver:
1. Download the official installer from: **[https://npcap.com/#download](https://npcap.com/#download)**
2. Run the installer and ensure you check the option:
   **`[X] Install Npcap in WinPcap API-compatible Mode`**
3. Restart your terminal.

> **Note for Non-Administrative Systems:** If running in a university or corporate lab where installing drivers is restricted, you can still execute all automated unit tests (`python -m pytest tests/ -v`) and the full synthetic replay pipeline (`python src/main.py --demo`) without Npcap or administrator privileges.

---

## Usage & Execution Modes

### 1. Offline Synthetic Demonstration Mode
Run the built-in offline demonstration to test packet parsing, filtering, terminal streaming, and CSV export without needing Npcap or live interfaces:
```powershell
python src/main.py --demo --count 10
```

To demonstrate protocol filtering in demo mode:
```powershell
python src/main.py --demo --protocol DNS --count 5
python src/main.py --demo --protocol ICMP --count 5
```

### 2. Command-Line Execution
List all available network adapters:
```powershell
python src/main.py --list-interfaces
```

Capture 50 packets on a specific interface (by index or name):
```powershell
# Capture using interface index number
python src/main.py --interface 2 --count 50

# Capture using interface name
python src/main.py --interface "Wi-Fi" --count 50
```

Capture with protocol filtering:
```powershell
python src/main.py --interface 2 --protocol DNS --count 20
python src/main.py --interface 2 --protocol TCP --count 100
```

Capture with source or destination IP filtering:
```powershell
python src/main.py --interface 2 --source 192.168.1.100 --count 25
python src/main.py --interface 2 --destination 8.8.8.8 --count 25
```

Custom CSV output destination:
```powershell
python src/main.py --interface 2 --count 50 --output logs/session_analysis.csv
```

### 3. Interactive Setup Menu
When launched without CLI arguments, the tool enters an interactive menu guiding you through interface selection, packet limits, and filtering:
```powershell
python src/main.py
```

---

## Command-Line Options

| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--interface` | `-i` | Target network adapter name, internal ID, or index number | Prompts or default |
| `--count` | `-c` | Maximum number of matching packets to capture | `50` |
| `--timeout` | `-t` | Capture timeout duration in seconds | `None` (Count-based) |
| `--protocol` | `-p` | Protocol filter: `TCP`, `UDP`, `ICMP`, `DNS`, `HTTP`, `TLS`, `ARP`, `ALL` | `None` (All traffic) |
| `--source` | `-s` | Filter traffic originating from a specific source IP | `None` |
| `--destination` | `-d` | Filter traffic destined for a specific destination IP | `None` |
| `--output` | `-o` | File path for CSV metadata export | `logs/captured_packets.csv` |
| `--list-interfaces` | `-l` | List all discovered network interfaces and exit | `False` |
| `--demo` | | Run offline synthetic packet replay demonstration | `False` |
| `--verbose` | `-v` | Enable detailed debug logging output | `False` |
| `--help` | `-h` | Display help screen and examples | |

---

## Supported Protocols & Multi-Layer Dissection

| Protocol Layer | Protocol | Decoded Metadata Fields |
| :--- | :--- | :--- |
| **Data Link (Layer 2)** | Ethernet | Source MAC, Destination MAC, EtherType |
| **Network (Layer 3)** | IPv4 | Source IP, Destination IP, Protocol type, Packet length |
| | IPv6 | 128-bit Source IP, Destination IP, Next Header |
| | ARP | Hardware Type, Opcode (Request / Reply), Sender IP/MAC, Target IP/MAC |
| **Transport (Layer 4)** | TCP | Source Port, Destination Port, Sequence Number, Control Flags (`SYN`, `ACK`, `FIN`, `PSH`, `RST`) |
| | UDP | Source Port, Destination Port, Datagram Length |
| | ICMP | ICMP Type (`Echo Request`, `Echo Reply`), ICMP Code |
| **Application (Layer 7)** | DNS | Queried Hostname (`qname` from `DNSQR`), Port 53 |
| | HTTP | Request Verb (`GET`, `POST`), Sanitized URL path |
| | TLS / HTTPS | Record Type (Handshake, Client Hello, Application Data), Port 443 |

---

## Safe Payload Handling & Ethical Boundaries

> [!IMPORTANT]
> **Strict Ethical & Privacy Safeguards:**
> - **Metadata Only:** The application extracts header information, protocol metrics, and safe query hostnames.
> - **No Plaintext Credential Logging:** The tool strictly avoids harvesting passwords, authorization tokens, cookies, session identifiers, or personal data.
> - **No TLS/HTTPS Decryption:** Encrypted payloads are recognized and labeled as `TLS Encrypted Application Data` or `TLS Handshake`. The tool does not perform man-in-the-middle decryption or root certificate tampering.
> - **Defensive Intent:** Contains zero offensive capabilities (no packet injection, no ARP spoofing, no port scanning).

---

## Packet Filtering Engine
Filtering is evaluated in `models.py` via the `FilterConfig` dataclass:
- **Protocol Filter:** Isolates flows for specific protocols (e.g., inspecting DNS requests or TCP handshakes).
- **IP Address Filters:** Isolates traffic to or from a target host (e.g., debugging connectivity with `8.8.8.8`).
- **Evaluation:** Unmatched packets are rejected prior to memory retention or console rendering, optimizing throughput and file size.

---

## CSV Export & Reporting
Captured metadata is automatically serialized to RFC-compliant CSV files (`logs/captured_packets.csv`).

### CSV Schema:
```csv
timestamp,source_mac,destination_mac,source_ip,destination_ip,ip_version,protocol,source_port,destination_port,packet_length,tcp_flags,icmp_type,icmp_code,dns_query
```

### Sample Record:
```csv
2026-09-07 01:13:13.896,00:11:22:33:44:55,66:77:88:99:aa:bb,192.168.1.100,8.8.8.8,IPv4,DNS,53210,53,92,N/A,N/A,N/A,www.cybersecurity-internship.edu
2026-09-07 01:13:13.897,00:11:22:33:44:55,66:77:88:99:aa:bb,192.168.1.100,93.184.216.34,IPv4,HTTP,51422,80,54,SYN,N/A,N/A,N/A
2026-09-07 01:13:13.897,66:77:88:99:aa:bb,00:11:22:33:44:55,93.184.216.34,192.168.1.100,IPv4,HTTP,80,51422,54,"SYN, ACK",N/A,N/A,N/A
```

---

## Automated Testing Suite
Automated unit tests are located in `tests/test_packet_parser.py`. Tests use **synthetic Scapy packets** generated entirely in memory, guaranteeing independence from physical network adapters and live internet traffic.

### Run Unit Tests:
```powershell
python -m pytest tests/ -v
```

### Test Coverage:
1. `test_tcp_packet_parsing`: Verifies IP addresses, ports, sequence numbers, and packet length.
2. `test_udp_packet_parsing`: Verifies UDP port identification and datagram lengths.
3. `test_icmp_echo_request_parsing`: Verifies ICMP Type 8 (Echo Request) and Code 0.
4. `test_icmp_echo_reply_parsing`: Verifies ICMP Type 0 (Echo Reply) and Code 0.
5. `test_dns_query_parsing`: Verifies extraction of queried domain name from `DNSQR`.
6. `test_ipv6_packet_parsing`: Verifies 128-bit IPv6 address and version handling.
7. `test_missing_layers_graceful_handling`: Verifies parser returns `"N/A"` without crashing on raw or partial frames.
8. `test_arp_packet_parsing`: Verifies ARP opcode translation (`Who has ...? tell ...`).
9. `test_tcp_flags_decoding`: Tests multi-flag decoding (`SYN`, `SYN, ACK`, `FIN, ACK`, `PSH, ACK`, `RST`).
10. `test_tls_detection`: Verifies TLS handshake and content-type detection.
11. `test_http_detection`: Verifies HTTP request method detection (`GET`).
12. `test_protocol_filtering`: Verifies protocol isolation logic.
13. `test_ip_filtering`: Verifies source and destination IP matching.
14. `test_capture_stats_accumulation`: Verifies statistical metric accumulation across protocol families.
15. `test_csv_export_format_and_headers`: Verifies CSV schema generation, field ordering, and file write integrity.

---

## Wireshark Validation Methodology
To validate that the custom Python sniffer accurately captures and decodes packets in parity with industry tools, follow this procedure on an authorized interface:

1. **Step 1:** Open Wireshark and select your primary active network adapter (e.g., Wi-Fi).
2. **Step 2:** In Wireshark's display filter bar, apply a filter for harmless diagnostic traffic:
   ```
   dns || icmp || http
   ```
3. **Step 3:** Start packet capture in Wireshark.
4. **Step 4:** Launch the custom Python sniffer in a side-by-side terminal:
   ```powershell
   python src/main.py --interface "Wi-Fi" --count 20
   ```
5. **Step 5:** Generate normal diagnostic traffic on your machine:
   ```powershell
   # In another terminal window:
   ping 1.1.1.1
   nslookup example.com
   ```
6. **Step 6:** Stop both captures.
7. **Step 7:** Cross-reference selected packets between the Python console / CSV and Wireshark:
   - Match **Source IP** and **Destination IP**.
   - Match **Source Port** and **Destination Port**.
   - Match **Frame/Packet Length** (accounting for 14-byte Ethernet header encapsulation).
   - Match **TCP Flags** (`SYN`, `ACK`).
   - Match **DNS Query Hostname**.

---

## Security & Privacy Audit
A comprehensive security review of the codebase confirms:
- **No Hardcoded Credentials:** Zero API keys, passwords, or usernames embedded.
- **Safe Path Handling:** Filepaths are resolved defensively using `pathlib.Path`, preventing path traversal.
- **No Command Injection:** No `subprocess` or `os.system()` invocations with user-controlled input.
- **No Insecure Deserialization:** Packet data is dissected through Scapy's typed layer models without using `pickle` or `eval()`.
- **Resource Protection:** Memory consumption is bounded by enforcing a default packet capture limit (`count=50`) and disabling Scapy's internal packet buffer (`store=False`).

---

## Limitations & Future Scope

### Current Limitations:
- **Throughput:** Designed for network diagnostics and educational inspection; not intended for 10+ Gbps saturating line rates.
- **Encrypted Payload Inspection:** Respects cryptographic boundaries; cannot view plaintext within TLS/HTTPS tunnels.
- **Windows Driver Dependency:** Live Layer 2 capture requires Npcap on Windows.

### Future Scope:
- Real-time web-based visualization dashboard using React and WebSockets.
- Signature-based intrusion detection (e.g., detecting SYN flood spikes or port sweeps).
- Support for reading from and writing to industry-standard `.pcap` files.
- MaxMind GeoIP integration for real-time geographic source IP mapping.

---

## Submission Material & Screenshots
- **Internship Report Notes:** See [report_notes.md](file:///d:/Internship%20all%20document/Task%201'/report_notes.md) for the 27-section comprehensive academic report.
- **Screenshot Plan:** See [screenshots/README.md](file:///d:/Internship%20all%20document/Task%201'/screenshots/README.md) for details on capturing all 15 required screenshots.
- **Viva Voce Exam Preparation:** See [VIVA_QUESTIONS.md](file:///d:/Internship%20all%20document/Task%201'/VIVA_QUESTIONS.md) for 35 detailed questions and answers.
- **Final Audit Checklist:** See [FINAL_CHECKLIST.md](file:///d:/Internship%20all%20document/Task%201'/FINAL_CHECKLIST.md) for verification evidence.

---

## License & Ethical Disclaimer
This project is distributed under the **MIT License**. See [LICENSE](file:///d:/Internship%20all%20document/Task%201'/LICENSE) for full details.

```
ETHICAL COMPLIANCE NOTICE:
This software is intended solely for educational purposes, authorized network diagnostics,
and academic evaluation. Capturing network traffic on networks without explicit administrative
authorization is illegal and unethical. The authors accept no liability for misuse.
```
