# Network Traffic Analyzer

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Made with Love](https://img.shields.io/badge/Made%20with-Love-red.svg)](https://github.com/yourusername/network-traffic-analyzer)

A Python-based network packet sniffer and analyzer that captures live traffic, replicates core functionality of tools like `tcpdump`, and provides detailed statistics on connections, processes, and DNS queries. This tool leverages low-level packet capture to monitor network activity, associating it with running processes for forensic analysis—ideal for debugging, security monitoring, or performance tuning.

## Background: Linux Network SoftIRQs
In the Linux kernel, **softIRQs** (software interrupts) are a mechanism for deferred processing of hardware interrupts (IRQs) to maintain system responsiveness. Specifically, network softIRQs (e.g., `NET_RX_SOFTIRQ` for incoming packets and `NET_TX_SOFTIRQ` for outgoing) handle packet processing after initial hardware interrupts from network interfaces (NICs). They offload intensive tasks like protocol handling (TCP/IP stack) from real-time interrupt contexts, using techniques like NAPI (New API) for efficient polling under high load.

This script indirectly interacts with the aftermath of these softIRQs by capturing packets at the link layer using raw sockets (`AF_PACKET`). While not directly using eBPF (extended Berkeley Packet Filter) for kernel-level tracing of softIRQ events, it emulates eBPF-like interception by parsing packets post-softIRQ processing. 

I created this program because I love tcpdump, but I wanted a way to visualize and summarize the entire tcpdump when looking for specific one-off IP addresses or anomolies, after becoming 
Frustrated with the lack of real-time support with current protocol analyzers, and lack of real-time stat analysis, overcomplexity and resource inefficiencies from CLI tools like nethogs, I created sockethound with simplicity in mind. This offers real-time analysis and is designed for interoperability on *nix systems
Feel free to tweak it, contribute back if you'd like, or use it in your projects—just keep the spirit of openness alive!

See tcpdump_raw_parser branch for the initial tcpdump based prototype.

## Features
- **Packet Capture and Parsing**: Captures all Ethernet frames (ETH_P_ALL) and parses IPv4, TCP, UDP, ICMP, and DNS packets, replicating `tcpdump` functionality for live traffic inspection.
- **Connection Tracking**: Tracks bidirectional connections by protocol, IP, and port, aggregating bytes transferred and packet counts.
- **Process Association**: Maps connections to running processes by scanning `/proc/net/tcp`, `/proc/net/udp`, and `/proc/[pid]/fd`, identifying apps like browsers or servers consuming bandwidth.
- **Statistics and Reporting**: Generates periodic reports with human-readable stats (e.g., bytes/sec, packet rates), color-coded for quick visualization. Analyzes packet data from softIRQ-handled flows to compute totals, rates, and top connections.
- **DNS Query Tracking**: Parses and logs recent DNS queries/responses, including resolved IPs, for security or debugging (e.g., detecting unusual domains).
- **Filtering and Customization**: Options to exclude local traffic, filter by process name, group by process, and adjust report intervals/counts.
- **Performance-Oriented**: Efficiently handles high-traffic scenarios with deferred reporting via signals, minimizing overhead.

This tool expands on basic packet dumping by providing statistical analysis (e.g., bandwidth coloring based on thresholds like >1MB/s in red) derived from softIRQ-processed packet data, offering insights into network behavior without full eBPF kernel integration.

## Installation
Requires Python 3.6+ and root privileges (for raw socket access). Tested on Linux (e.g., Ubuntu).

1. Clone the repo:

2. Install dependencies (if needed; core script uses standard libraries):
## Usage
Run as root (e.g., with `sudo`) due to raw socket requirements.

sudo python3 sockethound.py [options]


### Options
- `-n, --no-local`: Exclude localhost traffic (127.0.0.0/8).
- `-t, --time <seconds>`: Report interval (default: 10).
- `-c, --count <number>`: Number of connections/processes to display (default: 20).
- `-p, --process <name>`: Filter by process name (e.g., "chrome").
- `-g, --group`: Group connections by process.
- `-d, --dns-count <number>`: Number of recent DNS queries to show (default: 5).

### Sample Output:

![Network Socket Hound Example Output](https://raw.githubusercontent.com/greenfan/shellcode/refs/heads/master/git_ex.png)
