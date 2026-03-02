# UNPA NetHound (`unpa.py`)

UNPA NetHound is a real-time network traffic analyzer focused on fast terminal visibility, live summarization, and practical filtering for anomaly hunting.

## Background: Linux Network SoftIRQs

In the Linux kernel, softIRQs (software interrupts) are a mechanism for deferred processing of hardware interrupts (IRQs) to maintain system responsiveness. Specifically, network softIRQs (for example, `NET_RX_SOFTIRQ` for incoming packets and `NET_TX_SOFTIRQ` for outgoing packets) handle packet processing after initial hardware interrupts from network interfaces (NICs). They offload intensive tasks like protocol handling (TCP/IP stack) from real-time interrupt contexts, using techniques like NAPI (New API) for efficient polling under high load.

This script indirectly interacts with the aftermath of these softIRQs by capturing packets at the link layer using raw sockets (`AF_PACKET` on Linux). While it does not directly use eBPF for kernel-level tracing of softIRQ events, it emulates an eBPF-like interception workflow by parsing packets after softIRQ-driven network stack processing.

I created this program because I love tcpdump, but wanted a way to visualize and summarize the entire stream while hunting one-off IP addresses or anomalies in real time. After frustration with limited real-time stat visibility, unnecessary complexity, and resource overhead in some CLI analyzers, this project was built with simplicity and interoperability in mind for *nix systems.

Feel free to tweak it, contribute back, or use it in your own projects.

See `tcpdump_raw_parser` branch for the initial tcpdump-based prototype.

## Features

- Packet capture and parsing of Ethernet/IPv4, TCP, UDP, ICMP, and DNS.
- Connection tracking by protocol/IP/port with byte and packet aggregation.
- Process association from `/proc/net/*` and `/proc/[pid]/fd` socket mapping.
- Real-time reporting with rates, totals, and colorized traffic intensity.
- DNS query tracking with recent query/answer display and IP name enrichment.
- Flexible filtering (`-n`, `-e`, `-ee`, `-ii`, process filters, grouping, line caps).
- Interactive DNS panel control with `-` (expand/retract to compact mode).
- Platform support for Linux raw sockets and macOS tcpdump-based capture.

## Installation

`unpa.py` uses Python standard library modules only.

Requirements:

- Python 3.8+ (recommended)
- Root/sudo privileges for packet capture



## Synopsis

```bash
sudo python3 unpa.py [options]
```

Startup behavior:

- no arguments -> runs with: `-t 1 -n -e -g -r`
- `-o` only -> runs with: `-t 1 -n -g`
- `-o` with other args -> `-o` is ignored, provided args are used normally

## Command Flags

- `-n`, `--no-local`  
  Exclude localhost-only traffic (`localhost` and `127.0.0.0/24`).

- `-e`, `--exclude-lan`  
  Exclude LAN-to-LAN traffic where both endpoints are in:
  - `192.168.0.0/16`
  - `172.0.0.0/8`
  - `10.0.0.0/8`  
  Note: port 53 traffic bypasses this filter unless `-nodns` is set.

- `-ee IP_OR_CIDR`, `--exclude-extra IP_OR_CIDR`  
  Exclude packets if either endpoint matches additional IP/CIDR filters.  
  Repeatable (example: `-ee 208.10.10.11 -ee 207.10.0.0/16`).

- `-ii IP_CIDR_OR_DOMAIN`, `--include-only IP_CIDR_OR_DOMAIN`  
  Include only packets where either endpoint matches specified IP/CIDR/domain targets.  
  Repeatable. Domains are resolved to current A/AAAA addresses.

- `-nodns`, `--no-dns-bypass`  
  Disable the `-e` port-53 bypass, so DNS traffic is filtered normally by `-e`.

- `-t SECONDS`, `--time SECONDS`  
  Seconds between report refreshes (parser default: `10`).

- `-c COUNT`, `--count COUNT`  
  Maximum number of connections or process groups shown (default: `20`).

- `-p NAME`, `--process NAME`  
  Show only connections whose process name contains this substring.

- `-g`, `--group`  
  Group report output by process instead of flat connection view.

- `-d COUNT`, `--dns-count COUNT`  
  Base number of recent DNS entries to show (default: `5`; panel can expand dynamically).

- `-xx`, `--truncate-output`  
  Limit each report to 60 lines.

- `-r`, `--resolve`  
  Resolve endpoint IPs to names via `/etc/hosts`, captured DNS data, and reverse lookups.

- `-i IFACE`, `--interface IFACE`  
  Capture interface (used for macOS tcpdump capture path; examples: `en0`, `eth0`, `wlan0`).

- `-o`, `--default-no-resolve`  
  Special startup shortcut. If it is the only arg, run with `-t 1 -n -g` (no `-r`).

## Interactive Key

- Press `-` during runtime to toggle DNS panel size:
  - expanded view (more recent queries)
  - compact view (max 5 entries)

## Example Commands

```bash
sudo python3 unpa.py
sudo python3 unpa.py -o
sudo python3 unpa.py -t 2 -g -r
sudo python3 unpa.py -ee 208.10.10.11 -ee 207.10.0.0/16
sudo python3 unpa.py -ii 134.0.0.0/8
sudo python3 unpa.py -ii google.com -g -r
sudo python3 unpa.py -e -nodns
```

## Notes

- Root privileges are required for raw packet capture.
- This tool extends packet dumping with real-time statistical analysis and visual summaries derived from softIRQ-processed network traffic.
