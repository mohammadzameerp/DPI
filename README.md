# DPI Engine - Deep Packet Inspection System

A high-performance C++ & Python system to parse PCAP captures, identify applications via TLS SNI or HTTP Host headers, and apply blocking rules.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** inspects the actual payload of network packets, rather than just headers (like IP addresses and ports).

### Real-World Uses:
- **Bandwidth Management**: ISPs throttling P2P traffic.
- **Content Filtering**: Parental controls or enterprise blocklists.
- **Security**: Intrusion detection and malware prevention.

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Each packet nests headers inside each other:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A network connection is uniquely identified by these five fields:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

### What is SNI?

**Server Name Indication (SNI)** is a plaintext field sent during the TLS/HTTPS handshake.

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

---

## 3. Project Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
│             │     │ - Classify  │     │             │
└─────────────┘     │ - Block     │     └─────────────┘
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `src/main_working.cpp` / `dpi_simple.py` | Learning, small captures |
| Multi-threaded | `src/dpi_mt.cpp` / `dpi_mt.py` | Production, high-throughput captures |

---

## 4. File Structure

```
packet_analyzer/
├── include/                    # Header files (declarations)
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Network protocol parsing
│   ├── sni_extractor.h        # TLS/HTTP inspection
│   ├── types.h                # Data structures (FiveTuple, AppType, etc.)
│   ├── rule_manager.h         # Blocking rules
│   ├── connection_tracker.h   # Flow tracking
│   ├── load_balancer.h        # LB thread
│   ├── fast_path.h            # FP thread
│   ├── thread_safe_queue.h    # Thread-safe queue
│   └── dpi_engine.h           # Main orchestrator
│
├── src/                        # Implementation files
│   ├── pcap_reader.cpp        # PCAP file handling
│   ├── packet_parser.cpp      # Protocol parsing
│   ├── sni_extractor.cpp      # SNI/Host extraction
│   ├── types.cpp              # Helper functions
│   ├── main_working.cpp       # ★ SIMPLE VERSION ★
│   ├── dpi_mt.cpp             # ★ MULTI-THREADED VERSION ★
│   └── [other files]          # Supporting code
│
├── packet_analyzer_python/    # Python Implementation
│   └── dpi_engine/            # Python module folder
│
├── generate_test_pcap.py      # Creates test data
├── test_dpi.pcap              # Sample capture with various traffic
└── README.md                  # This file
```

---

## 5. The Journey of a Packet (Simple Version)

Trace of a single packet through the simple version:

### Step 1: Read PCAP File
```cpp
PcapReader reader;
reader.open("capture.pcap");
```
Reads the 24-byte global header and verifies the format.

```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet
```cpp
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
}
```

### Step 3: Parse Protocol Headers
```cpp
PacketParser::parse(raw, parsed);
```
Extracts MACs, IPs, ports, and protocol type from Ethernet, IP, and TCP/UDP layers.

### Step 4: Track Flow (Five-Tuple)
```cpp
FiveTuple tuple; // populated from parsed packet
Flow& flow = flows[tuple];
```

### Step 5: Extract SNI / HTTP Host
If HTTPS (Port 443) or HTTP (Port 80) is detected:
```cpp
auto sni = SNIExtractor::extract(payload, payload_length);
```

### Step 6: Check Blocking Rules
```cpp
if (rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni)) {
    flow.blocked = true;
}
```

### Step 7: Forward or Drop
Packets belonging to blocked flows are dropped; otherwise, they are written to the output PCAP.

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version implements parallel pipelines to scale processing.

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
 ┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
 │FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
 │(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
 └─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
       │            │              │            │
       └────────────┴──────────────┴────────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │   Output Queue        │
               └───────────┬───────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │  Output Writer Thread │
               │  (writes to PCAP)     │
               └───────────────────────┘
```

### Consistent Hashing
To correctly track connections, packets of the same flow (matching 5-tuple) must route to the same Fast Path (FP) thread.
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):          hash → FP2
Packet 2 (SYN-ACK):      hash → FP2 (Same connection, same FP)
Packet 3 (Client Hello): hash → FP2
```

---

## 7. Deep Dive: Each Component

- **PcapReader**: Parses input binary capture files using PCAP structure definitions.
- **PacketParser**: Converts raw bytes to structured protocol structures, handling Network Byte Order (`ntohs`, `ntohl`).
- **SNIExtractor**: Decodes the TLS Client Hello handshake frame to locate the Server Name Indication hostname.
- **HTTPHostExtractor**: Parses plaintext HTTP headers searching for the `Host: ` field.
- **RuleManager**: Implements lock-protected rules mapping for high-speed multi-threaded checks.
- **ThreadSafeQueue**: A condition-variable and mutex-backed queue implementing the Producer-Consumer pattern.

---

## 8. How SNI Extraction Works

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
```

### TLS Client Hello Structure
1. Validate TLS Handshake Content Type (`0x16`) and Client Hello Handshake Type (`0x01`).
2. Skip past variable-length session parameters, cipher lists, and compression methods.
3. Parse the extensions block to find Extension Type `0x0000` (SNI).
4. Read the hostname from the extension payload.

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source IP |
| App | `YouTube` | All connections classified under YouTube |
| Domain | `tiktok` | Any SNI containing "tiktok" as a substring |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
             FORWARD
```

### Flow-Based Blocking
Once a flow's SNI is detected and matched against a blocklist, the flow state is updated to blocked, dropping all subsequent data packets.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com (Match blocklist!)
                           → Mark flow as BLOCKED & DROP packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
```

---

## 10. Building and Running

### Prerequisites
- C++17 compiler (g++ or MSVC cl)
- Python 3 with launcher support (`py`)

### Compile Commands

**C++ Version (Visual Studio / MSVC)**
Run from Developer Command Prompt or via `vcvars64.bat`:
```cmd
cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_simple.exe src\main_working.cpp src\pcap_reader.cpp src\packet_parser.cpp src\sni_extractor.cpp src\types.cpp

cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_engine.exe src\dpi_mt.cpp src\pcap_reader.cpp src\packet_parser.cpp src\sni_extractor.cpp src\types.cpp src\connection_tracker.cpp src\fast_path.cpp src\load_balancer.cpp src\rule_manager.cpp src\dpi_engine.cpp
```

**C++ Version (GCC)**
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple.exe src/main_working.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

g++ -std=c++17 -pthread -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp src/connection_tracker.cpp src/fast_path.cpp src/load_balancer.cpp src/rule_manager.cpp src/dpi_engine.cpp
```

### Running the Engines

```bash
# Run C++ Multi-threaded Engine
./dpi_engine.exe test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50

# Run Python Simple Engine
py dpi_simple.py test_dpi.pcap output.pcap --block-app YouTube
```

---

## 11. Understanding the Output

### Sample Report Format
```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
╚══════════════════════════════════════════════════════════════╝
```
