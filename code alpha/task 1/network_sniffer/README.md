# 🔍 Basic Network Sniffer

A Python-based network packet capture and analysis tool built with [Scapy](https://scapy.net/). Captures live network traffic and displays structured, color-coded information about each packet — including source/destination IPs, protocols, ports, flags, DNS queries, and payload data.

> ⚠️ **Educational purposes only.** Use only on networks you own or have explicit permission to monitor.

---

## 📋 Features

- **Live packet capture** on any network interface
- **Protocol analysis**: TCP, UDP, ICMP, ARP, DNS, HTTP
- **Color-coded terminal output** for easy reading
- **BPF filter support** (e.g., `tcp port 80`, `icmp`, `host 8.8.8.8`)
- **Protocol filtering** (show only TCP / UDP / DNS etc.)
- **Payload inspection** in verbose mode
- **CSV logging** to save captured packets to file
- **Session statistics** summary
- **Offline demo mode** (no root required for testing)

---

## 🗂️ Project Structure

```
network_sniffer/
├── sniffer.py              # Main entry point
├── requirements.txt        # Dependencies
├── README.md
│
├── core/
│   ├── capture.py          # Packet capture engine (Scapy sniff)
│   ├── analyzer.py         # Packet parser & protocol decoder
│   └── display.py          # Color terminal output & statistics
│
├── utils/
│   └── logger.py           # CSV file logger
│
├── tests/
│   └── test_analyzer.py    # Unit tests (pytest / unittest)
│
└── samples/
    └── demo_packets.py     # Offline demo (no root needed)
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.7+
- Linux / macOS (Windows requires Npcap)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/network-sniffer.git
cd network-sniffer

# 2. Install dependencies
pip install -r requirements.txt

# On Linux, you may also need libpcap:
sudo apt install libpcap-dev   # Debian/Ubuntu
sudo dnf install libpcap-devel # Fedora
```

---

## 🚀 Usage

> **Root/Administrator privileges are required** for live packet capture.

### Basic capture (auto-detect interface)
```bash
sudo python3 sniffer.py
```

### Capture on a specific interface
```bash
sudo python3 sniffer.py -i eth0
sudo python3 sniffer.py -i wlan0
```

### Capture 100 packets then stop
```bash
sudo python3 sniffer.py -c 100
```

### Filter by BPF expression
```bash
sudo python3 sniffer.py -f "tcp port 80"       # HTTP only
sudo python3 sniffer.py -f "udp port 53"       # DNS only
sudo python3 sniffer.py -f "host 8.8.8.8"      # To/from Google DNS
sudo python3 sniffer.py -f "icmp"              # Ping traffic only
```

### Filter by protocol
```bash
sudo python3 sniffer.py --protocol TCP
sudo python3 sniffer.py --protocol DNS
sudo python3 sniffer.py --protocol HTTP
```

### Show payload (verbose mode)
```bash
sudo python3 sniffer.py -v
```

### Save to CSV log file
```bash
sudo python3 sniffer.py -o captured.csv
```

### Show statistics at end
```bash
sudo python3 sniffer.py -c 200 --stats
```

### Combined example
```bash
sudo python3 sniffer.py -i eth0 -c 100 -f "tcp" --protocol TCP -v --stats -o output.csv
```

---

## 🖥️ Sample Output

```
  _   _      _                      _      ____        _  __  __
 | \ | | ___| |___      _____  _ __| | __ / ___| _ __ (_)/ _|/ _| ___ _ __
 ...

[CONFIG]
  Interface : eth0
  Filter    : None
  Protocol  : ALL

#      Time           Proto    Source                 Destination            Info
------------------------------------------------------------------------------------------
1      14:32:01.123   TCP      192.168.1.10:54321     142.250.80.46:443      Flags=SYN Seq=1000 Win=65535 Len=54
2      14:32:01.145   DNS      192.168.1.10:49152     8.8.8.8:53             Query: github.com
3      14:32:01.212   DNS      8.8.8.8:53             192.168.1.10:49152     Response: 140.82.114.4
4      14:32:01.300   ICMP     192.168.1.10           8.8.8.8                Echo Request (type=8 code=0)
5      14:32:01.350   ARP      aa:bb:cc:11:22:33      ff:ff:ff:ff:ff:ff      Request: 192.168.1.10 → 192.168.1.1
```

---

## 🧪 Running Tests

No root required for unit tests:

```bash
# Using unittest
python3 -m pytest tests/ -v

# Or directly
python3 tests/test_analyzer.py
```

Tests cover:
- TCP SYN/ACK/FIN flag parsing
- UDP basic parsing
- DNS query & response parsing
- ICMP echo request/reply
- ARP request/reply
- Protocol filtering
- Statistics tracking

---

## 🎮 Offline Demo (No Root)

Test the tool without capturing live traffic:

```bash
python3 samples/demo_packets.py
```

This replays 10 pre-crafted packets (TCP, UDP, DNS, ICMP, ARP, HTTP) and displays their parsed output with statistics.

---

## 📡 Supported Protocols

| Protocol | Details Extracted |
|----------|-----------------|
| **TCP**  | Src/Dst port, flags (SYN/ACK/FIN/RST/PSH/URG), seq, ack, window size |
| **UDP**  | Src/Dst port, length |
| **ICMP** | Type name (Echo Request/Reply, Unreachable, TTL Exceeded), code |
| **ARP**  | Operation (Request/Reply), sender/target MAC & IP |
| **DNS**  | Query name, response IP |
| **HTTP** | Method, Host, Path (request); Status code (response) |

---

## 🔧 CLI Options

```
usage: sniffer.py [-h] [-i INTERFACE] [-c COUNT] [-f FILTER]
                  [-o OUTPUT] [--protocol {TCP,UDP,ICMP,ARP,DNS,HTTP,ALL}]
                  [-v] [--no-color] [--stats]

Options:
  -i, --interface   Network interface (default: auto-detect)
  -c, --count       Packets to capture (0 = unlimited)
  -f, --filter      BPF filter string
  -o, --output      CSV output file
  --protocol        Show only this protocol
  -v, --verbose     Show packet payloads
  --no-color        Disable ANSI colors
  --stats           Print statistics summary on exit
```

---

## 📚 Learning Objectives

This project demonstrates:

1. **Packet structure** — Ethernet → IP → TCP/UDP layers (OSI model)
2. **Protocol dissection** — How headers encode addressing, routing, and control info
3. **Network flows** — TCP 3-way handshake, DNS resolution, ARP discovery
4. **BPF filtering** — Berkeley Packet Filter expressions used in Wireshark/tcpdump
5. **Python sockets and Scapy** — Low-level network programming

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
