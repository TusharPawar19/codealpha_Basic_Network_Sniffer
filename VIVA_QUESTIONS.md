# Cybersecurity Internship — Task 1: Viva Examination Preparation

Comprehensive questions and answers for B.Tech project presentation, viva voce, and technical interviews on the **Python-Based Network Packet Sniffer & Traffic Analyzer**.

---

### Q1: What is a network packet?
**Answer:** A network packet is a formatted unit of data transmitted over a packet-switched network. It consists of two primary components:
1. **Control Information (Header):** Metadata required to deliver and manage the packet (e.g., source and destination IP addresses, MAC addresses, port numbers, error-checking checksums, sequencing numbers).
2. **Payload:** The actual user data or application-layer payload transported across the network.

---

### Q2: What is packet sniffing (packet analysis)?
**Answer:** Packet sniffing is the practice of intercepting, capturing, and decoding data packets as they travel across a computer network. Network administrators and security analysts use packet sniffers for troubleshooting connectivity, diagnosing latency bottlenecks, detecting intrusion attempts, and verifying cryptographic protocols.

---

### Q3: What is Scapy, and why did you choose it for this project?
**Answer:** Scapy is a powerful, flexible Python packet manipulation library. Unlike basic socket programming or traditional sniffing tools, Scapy allows:
- Direct creation, decoding, and dissection of packets across hundreds of network protocols.
- Layer-by-layer inspection (e.g., `packet[IP]`, `packet[TCP]`, `packet[DNS]`).
- Forging synthetic packets in memory for automated testing without requiring live network traffic.
- Platform independence across Windows, Linux, and macOS.

---

### Q4: What is a MAC address, and at which OSI layer does it operate?
**Answer:** A Media Access Control (MAC) address is a unique 48-bit (6-byte) physical identifier permanently or logically assigned to a Network Interface Controller (NIC) by the manufacturer. It operates at **Layer 2 (Data Link Layer)** of the OSI model and enables local frame delivery within the same broadcast domain (local network segment).

---

### Q5: What is an IP address, and how does it differ from a MAC address?
**Answer:** An IP (Internet Protocol) address is a logical network address assigned to a device to enable routing across interconnected networks (Layer 3 — Network Layer). 
- **MAC Address:** Physical, flat, local-hop delivery within an Ethernet segment.
- **IP Address:** Logical, hierarchical, routable globally across multiple intermediate routers and networks.

---

### Q6: What are the key differences between IPv4 and IPv6?
**Answer:**
| Parameter | IPv4 | IPv6 |
| :--- | :--- | :--- |
| **Address Length** | 32 bits (4 bytes) | 128 bits (16 bytes) |
| **Address Space** | $\approx 4.3 \times 10^9$ addresses | $\approx 3.4 \times 10^{38}$ addresses |
| **Notation** | Dotted-decimal (`192.168.1.1`) | Colon-hexadecimal (`2001:db8::1`) |
| **Header Size** | Variable (20 to 60 bytes) | Fixed (40 bytes) |
| **Checksum** | Header checksum present | Checksum removed to accelerate routing |
| **Security** | Optional (IPsec) | Built-in native IPsec architectural support |

---

### Q7: Compare TCP and UDP. When is each protocol used?
**Answer:**
- **TCP (Transmission Control Protocol):** Connection-oriented, reliable, byte-stream protocol. Uses a 3-way handshake, sequencing, acknowledgments, retransmissions, and window-based flow control. Ideal for applications requiring guaranteed delivery (HTTP, HTTPS, SSH, FTP, Email).
- **UDP (User Datagram Protocol):** Connectionless, lightweight, unreliable datagram protocol. Transmits data without prior connection establishment or delivery guarantees, minimizing latency and overhead. Ideal for real-time applications (DNS queries, VoIP, live video streaming, online gaming).

---

### Q8: What is a network port, and what is its role in multiplexing?
**Answer:** A port is a 16-bit unsigned integer (ranging from 0 to 65535) used by Layer 4 protocols (TCP and UDP) to identify specific application processes running on a host. Ports allow a single host with one IP address to concurrently run multiple distinct network services (e.g., Web Server on 80/443, SSH on 22, DNS on 53) through transport-layer multiplexing.

---

### Q9: What is DNS, and how did your sniffer extract DNS query names?
**Answer:** DNS (Domain Name System) is the Internet's directory service, translating human-readable hostnames (e.g., `google.com`) into routable IP addresses. In our project:
1. The packet parser checks if the packet contains Scapy's `DNS` and `DNSQR` (DNS Question Record) layers.
2. It extracts `packet[DNSQR].qname`, decodes the raw byte sequence to UTF-8, strips trailing root dots (`.`), and records the queried domain safely in the metadata model and CSV.

---

### Q10: What is ICMP, and what are its common message types?
**Answer:** ICMP (Internet Control Message Protocol) is a network-layer diagnostic protocol used by network devices to send error messages and operational information. Common types:
- **Type 8, Code 0:** Echo Request (Ping request sent by client).
- **Type 0, Code 0:** Echo Reply (Ping response from target host).
- **Type 3:** Destination Unreachable (Host, port, or network unreachable).
- **Type 11:** Time Exceeded (TTL expired in transit; used by `traceroute`).

---

### Q11: What is HTTP, and how does your sniffer safely detect HTTP traffic?
**Answer:** HTTP (Hypertext Transfer Protocol) is an application-layer protocol for transmitting hypermedia documents. Our sniffer detects HTTP by:
1. Checking transport ports 80 and 8080.
2. Inspecting the initial bytes of the TCP payload for standard HTTP request verbs (`GET`, `POST`, `HEAD`) or response lines (`HTTP/1.1`).
3. For privacy and security, it captures only the request verb and sanitized resource path, strictly excluding cookies, query parameters, authentication tokens, and POST bodies.

---

### Q12: What is TLS/HTTPS, and how does it protect network traffic?
**Answer:** HTTPS is HTTP layered over TLS (Transport Layer Security). TLS provides three core security guarantees:
1. **Confidentiality:** Symmetrically encrypts payload data to prevent eavesdropping.
2. **Integrity:** Uses Message Authentication Codes (MAC / HMAC) to prevent tampering.
3. **Authentication:** Uses X.509 digital certificates to verify server (and optionally client) identity.

---

### Q13: Why does this project NOT decrypt HTTPS/TLS traffic?
**Answer:**
1. **Mathematical Security:** Modern TLS (1.2 and 1.3) uses ephemeral Diffie-Hellman key exchanges (ECDHE) providing **Forward Secrecy**. The symmetric session keys are negotiated securely and never transmitted over the wire.
2. **Ethical & Legal Compliance:** Passive packet sniffers cannot and should not decrypt encrypted traffic without explicit root certificate manipulation (man-in-the-middle proxying). Attempting to bypass encryption without authorization violates cybersecurity laws and ethics.
3. **Internship Boundary:** The tool is designed for passive network metadata monitoring, identifying TLS handshakes, SNI, ports, and sizes safely.

---

### Q14: Explain the TCP 3-Way Handshake and the flags involved.
**Answer:** The 3-way handshake establishes a reliable TCP connection:
1. **SYN (Synchronize):** Client sends a packet with the `SYN` flag set and an initial sequence number ($ISN_c$) to initiate connection.
2. **SYN-ACK:** Server responds with `SYN` and `ACK` flags set, acknowledging the client ($ISN_c + 1$) and offering its own sequence number ($ISN_s$).
3. **ACK (Acknowledge):** Client sends an `ACK` packet with sequence number $ISN_c + 1$ and acknowledgment $ISN_s + 1$. Connection state transitions to `ESTABLISHED`.

---

### Q15: What are TCP control flags, and which ones does your program decode?
**Answer:** TCP flags are 1-bit control fields in the TCP header:
- **SYN (Synchronize):** Initiates a connection.
- **ACK (Acknowledgment):** Confirms data receipt.
- **FIN (Finish):** Initiates graceful connection termination.
- **RST (Reset):** Abruptly tears down an invalid or rejected connection.
- **PSH (Push):** Directs the receiving stack to push data immediately to the application.
- **URG (Urgent):** Indicates urgent pointer field is significant.
- **ECE / CWR:** Explicit Congestion Notification flags.
Our `decode_tcp_flags()` function decodes combinations (e.g., `SYN, ACK`, `PSH, ACK`, `FIN, ACK`).

---

### Q16: What is promiscuous mode in network sniffing?
**Answer:** Normally, a Network Interface Controller (NIC) drops frames whose destination MAC address does not match its own MAC or broadcast/multicast addresses. In **promiscuous mode**, the NIC passes *all* intercepted frames on the physical wire/channel to the operating system kernel and packet capture driver, regardless of intended destination.

---

### Q17: Why are Administrator or Root privileges required for live packet capture?
**Answer:** Capturing raw network frames bypasses the operating system's standard transport-layer socket abstraction. Operating systems restrict raw socket creation (`SOCK_RAW`) and Layer 2 BPF/pcap driver access to privileged users (Admin on Windows, `root` or `CAP_NET_RAW` on Linux) to prevent unauthorized surveillance of host traffic.

---

### Q18: What is Npcap, and why is it necessary on Windows?
**Answer:** Npcap is the modern Windows packet capture and network injection driver developed by the Nmap Project (succeeding the legacy WinPcap). Microsoft Windows does not provide native Layer-2 user-mode packet capture APIs. Npcap installs an NDIS 6 filter driver that hooks into the Windows networking stack, enabling libraries like Scapy and Wireshark to capture raw link-layer frames.

---

### Q19: What is Wireshark, and what role did it play in validating your project?
**Answer:** Wireshark is the industry-standard GUI network packet protocol analyzer. In our project, Wireshark served as the external benchmark:
- We captured simultaneous network traffic (DNS, ICMP, HTTP) on the same interface using both our custom Python sniffer and Wireshark.
- We cross-referenced Source/Destination IP, ports, protocol classifications, frame lengths, and TCP flags to prove our custom parser dissected packets accurately.

---

### Q20: How did you test your application without relying on live network traffic?
**Answer:** We implemented automated unit tests in `tests/test_packet_parser.py` using **synthetic Scapy packets** created entirely in memory:
```python
Ether() / IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="S")
```
This guarantees that unit tests are deterministic, run in milliseconds, require no active network connection, and pass reliably regardless of whether Npcap or root privileges are present.

---

### Q21: What happens if your sniffer captures a packet with missing layers?
**Answer:** The parser uses defensive programming. Every layer check uses `packet.haslayer(LayerClass)`. Missing layers or attributes default to `"N/A"` (e.g., an ARP packet has no TCP flags or ports; a raw Ethernet frame has no IP address). The parser is wrapped in structured `try-except` blocks to ensure it **never crashes** on malformed or non-standard packets.

---

### Q22: Explain how packet filtering was implemented in your project.
**Answer:** Filtering is managed by the `FilterConfig` dataclass and evaluated during the capture loop:
- **Protocol Filter:** Evaluates whether the identified protocol matches the target (`TCP`, `UDP`, `ICMP`, `DNS`, `HTTP`, `TLS`).
- **Source IP Filter:** Compares packet source IP against a specified IP.
- **Destination IP Filter:** Compares packet destination IP against a specified IP.
Unmatched packets are discarded before memory allocation or terminal rendering.

---

### Q23: How does the CSV export mechanism ensure data integrity and security?
**Answer:** 
- Uses Python's standard `csv.DictWriter` with `quoting=csv.QUOTE_MINIMAL` to escape strings containing commas or whitespace (e.g., `"SYN, ACK"`).
- Automatically generates directory structures (`logs/`).
- Writes an exact 14-column header schema.
- Strictly logs metadata fields and deliberately excludes raw packet payload bytes, preventing inadvertent leakage of sensitive data.

---

### Q24: What is the OSI Model, and how does your packet parser traverse it?
**Answer:** The OSI (Open Systems Interconnection) model has 7 layers. Our parser traverses 4 operational layers corresponding to the TCP/IP stack:
1. **Layer 2 (Data Link):** Extracts `Ethernet` source and destination MAC addresses.
2. **Layer 3 (Network):** Dissects `IPv4`, `IPv6`, or `ARP` for source/destination IP and IP version.
3. **Layer 4 (Transport):** Dissects `TCP`, `UDP`, or `ICMP` for ports, flags, sequence numbers, and types.
4. **Layer 7 (Application):** Inspects `DNS`, `TLS`, or `HTTP` for safe high-level metadata.

---

### Q25: What is the difference between passive sniffing and active network scanning?
**Answer:**
- **Passive Sniffing:** Only listens to and reads packets transmitted across the network without transmitting any packets or alerting other devices.
- **Active Scanning (e.g., Nmap):** Actively injects probe packets (SYN scans, UDP probes, ping sweeps) into the network to elicit responses from targets. Active scanning creates detectable network noise and may trigger Intrusion Detection Systems (IDS).

---

### Q26: What is ARP, and what is ARP spoofing/poisoning?
**Answer:**
- **ARP (Address Resolution Protocol):** Resolves known Layer-3 IP addresses to Layer-2 physical MAC addresses on a local subnet.
- **ARP Spoofing:** An attack where an attacker sends falsified ARP replies across a LAN, associating the attacker's MAC address with the IP address of a legitimate host (e.g., Default Gateway). This causes local traffic to be routed through the attacker, facilitating man-in-the-middle eavesdropping.

---

### Q27: What is MTU (Maximum Transmission Unit)?
**Answer:** MTU is the maximum size of a single data frame or packet (in bytes) that can be transmitted across a network layer without fragmentation. For standard Ethernet, the MTU is 1500 bytes. Packets exceeding the path MTU are either fragmented by routers (in IPv4) or dropped with an ICMP "Fragmentation Needed" message (used in Path MTU Discovery).

---

### Q28: What is TTL (Time to Live) in an IPv4 header?
**Answer:** TTL is an 8-bit field that limits the lifetime of an IP packet to prevent persistent routing loops. Each intermediate router decrements the TTL field by at least 1 before forwarding. If TTL reaches 0, the packet is discarded, and the router sends an ICMP "Time Exceeded" (Type 11) message back to the sender.

---

### Q29: What are the primary technical limitations of this project?
**Answer:**
1. **Packet Capture Driver:** Requires Npcap on Windows or `sudo` on Linux for live hardware capture.
2. **High-Throughput Environments:** Python and Scapy are written for ease of use and flexibility, not for multi-gigabit saturating line rates (where C/C++ engines like DPDK, PF_RING, or eBPF are necessary).
3. **Encrypted Payloads:** Safely reports TLS metadata but cannot decrypt ciphertext.
4. **Wireless Monitor Mode:** Passive Wi-Fi monitor mode (802.11 radio frames) requires specialized wireless chipset drivers.

---

### Q30: What ethical responsibilities do network security analysts hold?
**Answer:** Security professionals must adhere to strict ethical codes:
1. Always obtain explicit, documented permission before monitoring network traffic.
2. Protect user confidentiality by avoiding interception or storage of personal payloads, passwords, and private communications.
3. Comply with legal frameworks such as the Information Technology Act (India), Computer Fraud and Abuse Act (USA), and GDPR (EU).
4. Use packet sniffers strictly for defensive verification, academic research, and authorized administration.

---

### Q31: How could this project be extended in the future?
**Answer:**
1. **Web Dashboard:** Build a real-time visualization dashboard using React/Streamlit and WebSockets.
2. **IDS Rule Integration:** Incorporate signature matching against known attack patterns (e.g., SYN flood, port scan detection).
3. **PCAP Import/Export:** Support reading from and writing to industry-standard `.pcap` files.
4. **Geolocation:** Integrate MaxMind GeoIP for IP geolocation mapping.
5. **Database Storage:** Stream packet records into SQLite or PostgreSQL for historical analytics.

---

### Q32: What is the difference between TCP SYN Flood and normal TCP traffic?
**Answer:** In normal traffic, every `SYN` packet is followed by `SYN-ACK` and an `ACK` completing the 3-way handshake. In a **SYN flood attack**, an attacker transmits a deluge of `SYN` packets from spoofed IPs without ever completing the handshake with an `ACK`. This exhausts the server's SYN backlog queue (connection state table), preventing legitimate clients from connecting.

---

### Q33: What is BPF (Berkeley Packet Filter)?
**Answer:** BPF is a kernel-level architecture that provides raw link-layer packet filtering. It compiles filter expressions (e.g., `tcp and port 80`) into bytecode executed directly in the operating system kernel before packets are copied to user space, drastically reducing CPU overhead.

---

### Q34: What is Server Name Indication (SNI) in TLS?
**Answer:** SNI is an extension to the TLS protocol where the client includes the requested hostname in plaintext within the TLS `ClientHello` message during handshake negotiation. This allows a server hosting multiple virtual domains on a single IP address to present the correct SSL/TLS digital certificate.

---

### Q35: Summarize the architecture and modular design of your project.
**Answer:** The project follows a modular, decoupled architecture:
- `config.py`: Centralized operational parameters, port definitions, and CSV schema.
- `models.py`: Immutable dataclasses (`PacketMetadata`, `CaptureStats`, `FilterConfig`).
- `packet_parser.py`: Multi-layer protocol dissection engine with safe metadata extraction.
- `sniffer.py`: Capture coordinator wrapping Scapy with Ctrl+C, timeout, and driver error handling.
- `display.py`: Clean terminal UI rendering real-time streaming rows and post-capture summaries.
- `exporter.py`: RFC-compliant CSV export with robust file exception handling.
- `main.py`: Command-line interface with `argparse` and interactive menu fallback.
