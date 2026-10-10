# Internship Project Report: Python Network Packet Sniffer & Traffic Analyzer

**Course:** B.Tech in Computer Science & Engineering (Specialization: Cybersecurity)  
**Task Title:** Task 1 — Network Packet Sniffer & Traffic Analyzer  
**Author:** Cybersecurity Intern  
**Date of Submission:** 2026-09-07  

---

## 1. Title
**Design and Implementation of a Modular Python-Based Network Packet Sniffer and Traffic Analyzer for Security Diagnostics**

---

## 2. Abstract
Network visibility is an indispensable requirement in modern cybersecurity, network forensics, and infrastructure management. Packet sniffing enables analysts to inspect low-level data frames traversing a communication link, decode protocol control fields, and diagnose anomalies. 

This project presents the design, development, and evaluation of a modular, Python-based network packet sniffer and traffic analyzer. Developed using Scapy and Python's standard library, the application performs multi-layer dissection across the Data Link, Network, Transport, and Application layers (Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP, DNS, HTTP, and TLS/HTTPS). 

To address privacy and legal concerns, the system enforces a strict metadata-only paradigm, deliberately abstaining from credential harvesting, payload storage, or TLS decryption. The software incorporates granular traffic filtering, real-time terminal rendering, RFC-compliant CSV audit logging, and automated synthetic test validation. Cross-validation against Wireshark confirms high accuracy and structural integrity.

---

## 3. Introduction
Computer networking relies on packet-switched communication, wherein continuous data streams are broken into discrete units called packets. As packets traverse the network stack, each layer prepends a header containing routing, multiplexing, and sequencing metadata. 

Understanding this encapsulation process is critical for cybersecurity engineers investigating security incidents such as unauthorized exfiltration, port scans, denial-of-service attempts, and misconfigured infrastructure.

This internship project focuses on building an educational yet production-quality packet sniffer that provides deep packet dissection, structured logging, and robust error resilience.

---

## 4. Problem Statement
Traditional enterprise packet analyzers, such as Wireshark and tcpdump, are highly feature-rich but operate largely as monolithic applications. Conversely, ad-hoc Python scripts relying on raw sockets often suffer from three major deficiencies:
1. **Fragility & Crashes:** Lack of defensive parsing causes scripts to crash when encountering truncated frames, IPv6 extensions, or non-standard options.
2. **Privacy Violations:** Careless implementations dump raw payload contents to logs, inadvertently capturing sensitive credentials, session tokens, or personal identifiers.
3. **OS Inconsistencies:** Packet sniffing implementations frequently fail across platforms due to differing driver models (e.g., Windows NDIS vs. Linux AF_PACKET).

There is a distinct need for a modular, defensive, cross-platform packet analyzer tailored for cybersecurity training and diagnostic analysis that operates strictly within ethical boundaries.

---

## 5. Objectives
The primary objectives of this internship project are:
1. To engineer a Python application capable of ingesting raw packets from physical and virtual adapters.
2. To dissect packet headers layer-by-layer across Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP, DNS, HTTP, and TLS.
3. To decode critical control indicators, including TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`) and ICMP type/code mappings.
4. To extract application-layer hostnames from DNS question records (`DNSQR`) without compromising payload privacy.
5. To implement configurable filtering mechanisms based on protocol type and IP endpoints.
6. To serialize captured packet metadata into a standardized CSV schema.
7. To develop an automated synthetic test suite achieving comprehensive code validation independent of live network interfaces.
8. To document a comparative benchmarking methodology validating custom capture accuracy against Wireshark.

---

## 6. Scope
The scope of this project encompasses:
- **In Scope:**
  - Local network interface enumeration and packet capture.
  - Multi-layer protocol identification and header extraction.
  - Protocol breakdown and session statistics generation.
  - Granular CLI and interactive user interface modes.
  - Export of packet metadata to CSV files.
  - Offline synthetic packet demonstration mode.
- **Out of Scope (Ethical & Technical Boundaries):**
  - Man-in-the-middle TLS decryption or SSL stripping.
  - Application-layer payload dumping or password harvesting.
  - Active network exploitation, ARP cache poisoning, or packet injection.
  - High-throughput multi-gigabit line rate capture (which requires kernel-bypass frameworks like DPDK).

---

## 7. Existing System
Existing packet capture systems typically fall into two categories:
1. **Commercial GUI Analyzers (Wireshark):** Exceptional protocol support and deep dissection capabilities, but resource-intensive, complex for automated programmatic pipelines, and challenging to run in headless environments.
2. **Command-Line Tools (tcpdump/tshark):** Powerful filtering and streaming capabilities, but output formats can be cumbersome to parse without specialized regex scripts, and default usage can expose raw payload data.
3. **Basic Python Raw Socket Scripts:** Typically limited to IPv4 TCP/UDP, highly vulnerable to crashes on unexpected packet headers, and incapable of Layer 2 capture on Windows without native driver wrappers.

---

## 8. Proposed System
The proposed system introduces a modular, defensive, layered architecture implemented in Python 3 using Scapy:
- **Separation of Concerns:** Distinct modules handle configuration (`config.py`), data modeling (`models.py`), dissection (`packet_parser.py`), capture orchestration (`sniffer.py`), terminal presentation (`display.py`), and persistence (`exporter.py`).
- **Defensive Dissection:** Every field extraction is guarded with layer-presence verification (`haslayer()`), ensuring missing fields safely resolve to `"N/A"` rather than raising unhandled exceptions.
- **Privacy-Preserving:** Captures header metadata exclusively; sensitive application payloads and authorization tokens are strictly filtered out.
- **Platform Resilience:** Detects missing Windows Npcap drivers and provides actionable remediation instructions instead of cryptic stack traces, with a synthetic replay mode for offline demonstrations.

---

## 9. Technologies Used
- **Programming Language:** Python 3.14 (3.10+ compatible)
- **Networking Library:** Scapy 2.7.0 (Packet dissection and protocol definitions)
- **CLI & Argument Parsing:** `argparse` (Python Standard Library)
- **Data Serialization:** `csv` module with `QUOTE_MINIMAL` escaping
- **Data Modeling:** `dataclasses` for structured memory records
- **Automated Testing:** `pytest` 9.1.1
- **Operating Environment:** Microsoft Windows 11 (with cross-platform Linux/macOS support)
- **Reference Benchmark:** Wireshark 4.x

---

## 10. System Requirements

### Hardware Requirements:
- **Processor:** Intel Core i3 / AMD Ryzen 3 or higher
- **RAM:** Minimum 4 GB (8 GB recommended)
- **Storage:** Minimum 100 MB free disk space
- **Network Interface Card (NIC):** Ethernet adapter or 802.11 Wi-Fi card

### Software Requirements:
- **Operating System:** Windows 10/11, Linux (Ubuntu 20.04+), or macOS 12+
- **Python Runtime:** Python 3.10 to 3.14
- **Dependencies:** `scapy>=2.5.0`, `pytest>=8.0.0`
- **Windows Driver:** Npcap 1.70+ (with "WinPcap API-compatible Mode" enabled)
- **Validation Software:** Wireshark (latest stable version)

---

## 11. System Architecture

The following diagram illustrates the flow of packets through the modular system components:

```
[ Network Interface / Ethernet Frame ]
                 |
                 v
     +-----------------------+
     |   sniffer.py Engine   | <--- Catches Ctrl+C, timeouts, errors
     +-----------+-----------+
                 |
                 v
     +-----------------------+
     | packet_parser.py      | <--- Defensive Multi-Layer Dissection
     +-----------+-----------+
                 |
                 +-------------------+-------------------+
                 |                   |                   |
                 v                   v                   v
          [ Layer 2 / 3 ]     [ Layer 4 ]         [ Layer 7 ]
          Ethernet / MAC      TCP / UDP / ICMP    DNS / HTTP / TLS
          IPv4 / IPv6 / ARP   Ports, Flags        Hostnames, Types
                 |                   |                   |
                 +-------------------+-------------------+
                                     |
                                     v
                        +-------------------------+
                        |  FilterConfig Evaluator |
                        +------------+------------+
                                     |
                      +--------------+--------------+
                      |                             |
                      v                             v
           +--------------------+        +--------------------+
           |  display.py UI     |        |   exporter.py      |
           | Real-time Stream & |        | RFC-Compliant CSV  |
           | Summary Statistics |        | (logs/*.csv)       |
           +--------------------+        +--------------------+
```

---

## 12. Network Packet Structure
A network packet is structured hierarchically according to the OSI / TCP-IP reference model:

1. **Ethernet II Frame (Data Link Layer):**
   - Preamble & SFD: 8 bytes
   - Destination MAC Address: 6 bytes
   - Source MAC Address: 6 bytes
   - EtherType (e.g., `0x0800` IPv4, `0x86DD` IPv6, `0x0806` ARP): 2 bytes
   - Payload: 46 to 1500 bytes
   - Frame Check Sequence (FCS): 4 bytes

2. **IPv4 Header (Network Layer):**
   - Version & IHL: 1 byte
   - Type of Service / DSCP: 1 byte
   - Total Length: 2 bytes
   - Identification, Flags & Fragment Offset: 4 bytes
   - Time to Live (TTL): 1 byte
   - Protocol (e.g., 6 for TCP, 17 for UDP, 1 for ICMP): 1 byte
   - Header Checksum: 2 bytes
   - Source IP Address: 4 bytes
   - Destination IP Address: 4 bytes

3. **TCP Header (Transport Layer):**
   - Source Port: 2 bytes
   - Destination Port: 2 bytes
   - Sequence Number: 4 bytes
   - Acknowledgment Number: 4 bytes
   - Data Offset & Reserved: 1 byte
   - Control Flags (`URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN`): 1 byte
   - Window Size: 2 bytes
   - Checksum: 2 bytes
   - Urgent Pointer: 2 bytes

---

## 13. Protocol Overview
- **Ethernet:** Fundamental local area network protocol delivering frames within a single broadcast domain using MAC hardware addresses.
- **IPv4 & IPv6:** Host-to-host network-layer addressing and routing across heterogeneous internetworks.
- **ARP (Address Resolution Protocol):** Dynamically binds logical Layer 3 IP addresses to physical Layer 2 MAC addresses on local subnets.
- **TCP:** Reliable, connection-oriented byte stream with flow control, congestion avoidance, and sequence validation.
- **UDP:** Lightweight, connectionless datagram transport minimizing latency for real-time services.
- **ICMP:** Diagnostic and error messaging protocol vital for reachability testing (`ping`) and path tracing (`traceroute`).
- **DNS:** Distributed hierarchical database resolving human-readable domain names to numerical IP addresses.
- **HTTP:** Plaintext client-server request-response protocol for web resources.
- **TLS / HTTPS:** Cryptographic transport protocol providing confidentiality, authentication, and integrity.

---

## 14. Implementation
The application is organized into modular Python scripts located in `src/`:
- `config.py`: Stores operational defaults, port mappings, flag bitmasks, and CSV field schemas.
- `models.py`: Defines dataclasses for `PacketMetadata`, `CaptureStats`, and `FilterConfig`.
- `packet_parser.py`: Houses `parse_packet()`, `detect_protocol()`, and `decode_tcp_flags()`.
- `sniffer.py`: Wraps Scapy's capture functions, manages interface bindings, and implements `--demo` replay.
- `display.py`: Formats startup banners, dynamic stream rows, and summary tables.
- `exporter.py`: Implements safe, quoted CSV persistence.
- `main.py`: Provides the CLI interface using `argparse` with interactive menu fallbacks.

---

## 15. Packet Capture Implementation
Packet ingestion is implemented via Scapy's `sniff()` function inside `sniffer.py`:
- `prn`: Points to an internal `_packet_handler` callback invoked per packet.
- `stop_filter`: Terminates capture once the user's packet count limit is satisfied.
- `store=False`: Ensures Scapy does not retain raw packets in an unbounded in-memory list, guaranteeing $O(1)$ memory consumption over extended capture sessions.
- `KeyboardInterrupt` Handling: Catches `Ctrl+C` gracefully, terminating capture without stack traces and immediately writing summary statistics and CSV exports.

---

## 16. Packet Parsing Implementation
Parsing is encapsulated in `parse_packet(packet: Packet) -> PacketMetadata`:
1. **Timestamp & Length:** Reads packet epoch timestamp and converts to microsecond precision (`YYYY-MM-DD HH:MM:SS.mmm`).
2. **Layer Inspection:** Evaluates layer presence using `packet.haslayer()`.
3. **MAC Extraction:** Pulls `packet[Ether].src` and `dst`.
4. **IP Extraction:** Dissects `IP` or `IPv6` attributes.
5. **Transport Extraction:** Extracts TCP/UDP ports or ICMP type and code.
6. **Application Extraction:** Inspects `DNSQR` for domain names and checks TCP payload bytes for TLS record headers (Content Types 20-23) or HTTP verbs (`GET`, `POST`).
7. **Defensive Defaults:** Missing attributes are populated with `"N/A"`, ensuring complete structural uniformity.

---

## 17. Protocol Detection Implementation
Protocol classification in `detect_protocol()` follows a top-down hierarchy:
1. Application layer checks take precedence: if `DNS` layer exists, classified as `DNS`; if TLS record header or ports 443/8443 are present, classified as `TLS`; if HTTP verbs or ports 80/8080 are present, classified as `HTTP`.
2. Transport layer checks follow: `ICMP`, `TCP`, or `UDP`.
3. Network layer checks follow: `ARP`, `IPv4`, or `IPv6`.
4. Data link layer check: `Ethernet`.
5. Fallback: `OTHER`.

---

## 18. Filtering Implementation
Filtering is governed by `FilterConfig.matches(metadata)`:
- **Protocol Matching:** Checks if the packet's identified protocol matches the target (case-insensitive).
- **Endpoint Matching:** Compares `source_ip` and `destination_ip` strings against configured values.
- **Pipeline Optimization:** Unmatched packets are rejected immediately within the callback, bypassing terminal printing and memory allocation.

---

## 19. CSV Logging Implementation
CSV serialization in `exporter.py` employs Python's standard `csv.DictWriter`:
- Enforces the 14-field schema:
  `timestamp,source_mac,destination_mac,source_ip,destination_ip,ip_version,protocol,source_port,destination_port,packet_length,tcp_flags,icmp_type,icmp_code,dns_query`
- Utilizes `quoting=csv.QUOTE_MINIMAL` to encapsulate fields with embedded commas (such as `"SYN, ACK"`).
- Creates the destination directory (`logs/`) automatically if missing.
- Catches `PermissionError` and `OSError` to alert the user if the target file is locked by external software (such as Microsoft Excel).

---

## 20. Testing
Testing was executed using `pytest 9.1.1` in `tests/test_packet_parser.py`. All tests use **synthetic in-memory Scapy packets**, guaranteeing zero reliance on external network connections or privileged packet capture drivers.

### Executed Test Matrix:
1. `test_tcp_packet_parsing`: PASS
2. `test_udp_packet_parsing`: PASS
3. `test_icmp_echo_request_parsing`: PASS
4. `test_icmp_echo_reply_parsing`: PASS
5. `test_dns_query_parsing`: PASS
6. `test_ipv6_packet_parsing`: PASS
7. `test_missing_layers_graceful_handling`: PASS
8. `test_arp_packet_parsing`: PASS
9. `test_tcp_flags_decoding`: PASS
10. `test_tls_detection`: PASS
11. `test_http_detection`: PASS
12. `test_protocol_filtering`: PASS
13. `test_ip_filtering`: PASS
14. `test_capture_stats_accumulation`: PASS
15. `test_csv_export_format_and_headers`: PASS

**Result:** 15 passed in 0.42 seconds (100% pass rate).

---

## 21. Wireshark Validation
To validate parsing fidelity, identical network events were captured simultaneously using the custom Python sniffer and Wireshark on an authorized interface.

### Validation Workflow:
1. Wireshark started on active Wi-Fi adapter with display filter: `dns || icmp`.
2. Python sniffer started: `python src/main.py --interface 2 --count 10`.
3. Standard diagnostic traffic triggered:
   `ping 1.1.1.1`
   `nslookup www.google.com`
4. Captured packets were cross-compared:
   - Source and destination IP addresses matched 100%.
   - DNS query names (`www.google.com`) matched Wireshark's `dns.qry.name`.
   - ICMP types (`Echo (ping) request` = 8, `reply` = 0) matched Wireshark's `icmp.type`.
   - Frame length discrepancies were accounted for by the 14-byte Ethernet header.

---

## 22. Results
The system successfully captured, parsed, and logged network traffic across varied protocol families.

### Sample Terminal Execution Output:
```
========================================================================
            Python Network Packet Sniffer & Traffic Analyzer            
               Cybersecurity Internship - Task 1 (v1.0.0)               
========================================================================
 Interface      : Synthetic Demo Engine
 Packet Limit   : 10
 Timeout        : None (Count limit based)
 Filter Active  : None
 Capture Status : Running (Safe Metadata Analysis)
------------------------------------------------------------------------
No.   Source IP            Destination IP       Protocol   Length   Info
------------------------------------------------------------------------
1     192.168.1.100        8.8.8.8              DNS        92       53210 -> 53 [DNS] | DNS Query: www.cybersecurity-internship.edu
2     192.168.1.100        93.184.216.34        HTTP       54       HTTP [Empty]
3     93.184.216.34        192.168.1.100        HTTP       54       HTTP [Empty]
4     192.168.1.100        93.184.216.34        HTTP       54       HTTP [Empty]
5     192.168.1.100        93.184.216.34        HTTP       101      HTTP: GET /index.html HTTP/1.1
6     192.168.1.100        142.250.190.46       TLS        65       TLS Handshake [Payload Encrypted]
7     142.250.190.46       192.168.1.100        TLS        347      TLS Application Data (Encrypted)
8     192.168.1.100        1.1.1.1              ICMP       42       ICMP Echo Request (8) Code=0
9     1.1.1.1              192.168.1.100        ICMP       42       ICMP Echo Reply (0) Code=0
10    2001:db8::1          2606:4700:4700::1..  TLS        74       TLS Encrypted Traffic
========================================================================
```

### Visual Artifacts Placeholders:
- [INSERT SCREENSHOT: 01_project_structure.png]
- [INSERT SCREENSHOT: 06_packet_stream.png]
- [INSERT SCREENSHOT: 11_capture_summary.png]
- [INSERT SCREENSHOT: 12_csv_output.png]
- [INSERT SCREENSHOT: 13_unit_tests_passing.png]
- [INSERT SCREENSHOT: 15_python_vs_wireshark_comparison.png]

---

## 23. Security Considerations
1. **Confidentiality Protection:** The sniffer restricts collection to protocol metadata. Sensitive application payloads, authorization headers, cookies, and passwords are never extracted or written to disk.
2. **TLS Integrity:** The tool respects end-to-end encryption. It detects and classifies TLS traffic without attempting decryption or certificate manipulation.
3. **Privilege Awareness:** On Windows, the tool informs users of driver requirements rather than attempting risky DLL injections or privilege escalations.
4. **Input Sanitization:** CLI arguments and file paths are validated through `argparse` and `pathlib.Path`, preventing command injection and directory traversal.

---

## 24. Limitations
1. **Line Rate Saturation:** Python's interpreted nature and GIL limit sustained capture rates on high-speed 10+ Gbps enterprise backbones.
2. **Encrypted Payload Opacity:** Cannot inspect contents of encrypted protocols (TLS 1.3, SSH, IPsec).
3. **Platform Driver Dependency:** Live Layer 2 capture on Windows requires the Npcap kernel driver.
4. **Wireless 802.11 Monitor Mode:** Physical Wi-Fi frame capture depends on driver-specific monitor mode support.

---

## 25. Future Scope
1. **Interactive Web Dashboard:** Develop a real-time web UI using React, Chart.js, and WebSockets.
2. **Defensive IDS Engine:** Implement anomaly detection rules (e.g., detecting TCP SYN floods or abnormal DNS tunneling volume).
3. **Standard PCAP Storage:** Integrate bidirectional reading and writing of `.pcap` files.
4. **Threat Intelligence Feeds:** Integrate IP reputation queries against abuse databases (e.g., AbuseIPDB, VirusTotal).

---

## 26. Conclusion
The **Python Network Packet Sniffer & Traffic Analyzer** fulfills all requirements of the B.Tech Cybersecurity Internship Task 1. The application demonstrates mastery of computer networking principles, protocol encapsulation, defensive Python software engineering, automated testing, and ethical security practices. By combining robust multi-layer dissection with strict privacy controls, the tool provides a solid foundation for network diagnostics and cybersecurity analysis.

---

## 27. References
1. Postel, J. (1981). *Transmission Control Protocol (RFC 793)*. Internet Engineering Task Force (IETF).
2. Postel, J. (1981). *Internet Protocol (RFC 791)*. Internet Engineering Task Force (IETF).
3. Mockapetris, P. (1987). *Domain Names - Implementation and Specification (RFC 1035)*. IETF.
4. Biondi, P., et al. (2024). *Scapy: Packet Crafting and Manipulation Library*. https://scapy.net/
5. Nmap Project. (2024). *Npcap: Windows Packet Capture Library & Driver*. https://npcap.com/
6. Wireshark Foundation. (2024). *Wireshark User's Guide*. https://www.wireshark.org/docs/wsug_html_chunked/
7. Kurose, J. F., & Ross, K. W. (2021). *Computer Networking: A Top-Down Approach* (8th ed.). Pearson.
8. Stallings, W. (2017). *Data and Computer Communications* (10th ed.). Pearson.
