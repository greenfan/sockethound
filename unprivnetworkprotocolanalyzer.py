#!/usr/bin/env python3
import socket
import struct
import time
import sys
import argparse
import signal
from collections import defaultdict, deque
import subprocess
import re
import os
import math
import random
import threading
import platform
import ipaddress
import select
import termios
import tty
import atexit
import io
import contextlib
import shutil
try:
    import psutil
except ImportError:
    psutil = None

# Detect operating system
IS_MACOS = platform.system() == 'Darwin'
IS_LINUX = platform.system() == 'Linux'
ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*m')

def parse_ip_or_cidr(value):
    try:
        if '/' in value:
            return ipaddress.ip_network(value, strict=False)
        ip = ipaddress.ip_address(value)
        suffix = 32 if ip.version == 4 else 128
        return ipaddress.ip_network(f"{ip}/{suffix}", strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid IP or CIDR range: '{value}'. Use values like 208.10.10.11 or 207.10.0.0/16"
        )

def parse_ip_cidr_or_domain(value):
    try:
        return (parse_ip_or_cidr(value),)
    except argparse.ArgumentTypeError:
        pass

    domain = value.rstrip('.')
    if not re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+", domain):
        raise argparse.ArgumentTypeError(
            f"Invalid include target: '{value}'. Use IP, CIDR, or a valid domain like google.com."
        )

    try:
        addr_info = socket.getaddrinfo(domain, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise argparse.ArgumentTypeError(
            f"Invalid include target: '{value}'. Use IP, CIDR, or a resolvable domain (e.g. google.com)."
        )

    networks = []
    seen = set()
    for info in addr_info:
        ip_str = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip_str in seen:
            continue
        seen.add(ip_str)
        suffix = 32 if ip_obj.version == 4 else 128
        networks.append(ipaddress.ip_network(f"{ip_obj}/{suffix}", strict=False))

    if not networks:
        raise argparse.ArgumentTypeError(
            f"Could not resolve '{value}' to a valid IP address."
        )
    return tuple(networks)

parser = argparse.ArgumentParser(
    prog='unpa.py',
    description='UNPA NetHound privileged network traffic analyzer.',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=(
        "Startup behavior:\n"
        "  no arguments      -> runs with: -t 1 -n -e -g -r\n"
        "  -o only           -> runs with: -t 1 -n -g\n"
        "  -o with other args-> -o is ignored; provided args are used as-is\n"
        "\n"
        "Examples:\n"
        "  python3 unpa.py\n"
        "  python3 unpa.py -o\n"
        "  python3 unpa.py -ee 208.10.10.11 -ee 207.10.0.0/16\n"
        "  python3 unpa.py -ii 134.0.0.0/8\n"
        "  python3 unpa.py -ii google.com\n"
    ),
)
parser.add_argument('-n', '--no-local', action='store_true',
                    help='Exclude localhost-only traffic (localhost and 127.0.0.0/24).')
parser.add_argument('-t', '--time', type=int, default=10,
                    help='Seconds between report refreshes (parser default: 10).')
parser.add_argument('-c', '--count', type=int, default=20,
                    help='Maximum number of connections/process groups to display (default: 20).')
parser.add_argument('-p', '--process', type=str,
                    help='Show only connections for process names matching this substring.')
parser.add_argument('-g', '--group', action='store_true',
                    help='Group output by process name instead of a flat connection list.')
parser.add_argument('-d', '--dns-count', type=int, default=5,
                    help='Number of recent DNS query entries shown in report output (default: 5).')
parser.add_argument('-xx', '--truncate-output', action='store_true',
                    help='Limit each report to 60 lines.')
parser.add_argument('-e', '--exclude-lan', action='store_true',
                    help='Exclude LAN-to-LAN traffic in 192.168.0.0/16, 172.0.0.0/8, and 10.0.0.0/8. Port 53 bypass applies unless -nodns is set.')
parser.add_argument('-ee', '--exclude-extra', action='append', default=[], type=parse_ip_or_cidr, metavar='IP_OR_CIDR',
                    help='Exclude additional IP/CIDR targets (repeatable), e.g. -ee 208.10.10.11 or -ee 207.10.0.0/16.')
parser.add_argument('-ii', '--include-only', action='append', default=[], type=parse_ip_cidr_or_domain, metavar='IP_CIDR_OR_DOMAIN',
                    help='Capture only traffic matching these IP/CIDR/domain targets (repeatable). Domains resolve to current A/AAAA addresses.')
parser.add_argument('-o', '--default-no-resolve', action='store_true',
                    help='Special startup switch: if this is the only arg, run -t 1 -n -g (no -r). Ignored when combined with other flags.')
parser.add_argument('-nodns', '--no-dns-bypass', action='store_true',
                    help='Disable the -e port-53 bypass so DNS traffic is filtered like other traffic.')
parser.add_argument('-r', '--resolve', action='store_true',
                    help='Resolve endpoint IPs to names using /etc/hosts, captured DNS, and reverse lookups.')
parser.add_argument('-i', '--interface', type=str, default=None,
                    help='Capture interface (macOS examples: en0/en1; Linux examples: eth0/wlan0).')
parser.add_argument('-m', '--merge-highport-sockets', action='store_true',
                    help='Merge sockets that only differ by high src/dst ports (>35000) when those ports are in a close range (gap <= 9).')

cli_args = sys.argv[1:]
if len(cli_args) == 1 and cli_args[0] in ('-o', '--default-no-resolve'):
    args = parser.parse_args(['-t', '1', '-n', '-g'])
elif len(cli_args) == 1 and cli_args[0] in ('-h', '--help'):
    args = parser.parse_args()
elif len(cli_args) == 0:
    args = parser.parse_args(['-t', '1', '-n', '-e', '-g', '-r'])
else:
    args = parser.parse_args()

args.include_only = tuple(network for group in args.include_only for network in group)

IS_ROOT = (not hasattr(os, "geteuid")) or (os.geteuid() == 0)
RUN_UNPRIVILEGED = False

# Socket creation - platform specific
s = None
if IS_LINUX:
    if IS_ROOT:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except socket.error as e:
            print(f'Socket creation error: {e}')
            print('Note: This script requires root/sudo privileges')
            sys.exit(1)
    else:
        RUN_UNPRIVILEGED = True
elif IS_MACOS:
    # For macOS, use tcpdump in privileged mode and psutil polling in unprivileged mode.
    if IS_ROOT:
        print(f"Running on macOS - using BPF packet capture")
    else:
        RUN_UNPRIVILEGED = True
else:
    print(f"Unsupported operating system: {platform.system()}")
    sys.exit(1)

if RUN_UNPRIVILEGED and psutil is None:
    print("Unprivileged mode requires psutil. Install it with: pip install psutil")
    sys.exit(1)

def format_mac(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def parse_ethernet(packet):
    eth_length = 14
    if len(packet) < eth_length:
        return None, None, None, None
    eth_header = packet[:eth_length]
    eth = struct.unpack('!6s6sH', eth_header)
    dest_mac = format_mac(eth_header[0:6])
    src_mac = format_mac(eth_header[6:12])
    eth_protocol = socket.ntohs(eth[2])
    return eth_protocol, src_mac, dest_mac, packet[eth_length:]

def parse_ip(packet):
    if len(packet) < 20:
        return None, None, None, None, None
    iph = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    total_length = iph[2]
    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])
    return protocol, src_addr, dst_addr, packet[iph_length:], total_length

def parse_tcp(packet):
    if len(packet) < 20:
        return None, None
    tcph = struct.unpack('!HHLLBBHHH', packet[:20])
    return tcph[0], tcph[1]

def parse_udp(packet):
    if len(packet) < 8:
        return None, None
    udph = struct.unpack('!HHHH', packet[:8])
    return udph[0], udph[1]

def parse_dns(packet):
    try:
        if len(packet) < 12:
            return None
        dns_data = packet[8:]
        if len(dns_data) < 12:
            return None
        transaction_id = struct.unpack('!H', dns_data[0:2])[0]
        flags = struct.unpack('!H', dns_data[2:4])[0]
        is_response = (flags & 0x8000) != 0
        question_count = struct.unpack('!H', dns_data[4:6])[0]
        answer_count = struct.unpack('!H', dns_data[6:8])[0]
        query_name, offset = extract_dns_name(dns_data, 12)
        if offset + 4 <= len(dns_data):
            query_type, query_class = struct.unpack('!HH', dns_data[offset:offset+4])
            answers = []
            if is_response and answer_count > 0:
                current_offset = offset + 4
                for _ in range(answer_count):
                    if current_offset + 12 > len(dns_data):
                        break
                    if (dns_data[current_offset] & 0xC0) == 0xC0:
                        current_offset += 2
                    else:
                        _, name_length = extract_dns_name(dns_data, current_offset)
                        current_offset += name_length
                    if current_offset + 10 > len(dns_data):
                        break
                    ans_type, ans_class, ttl, rdlength = struct.unpack(
                        '!HHIH', dns_data[current_offset:current_offset+10]
                    )
                    current_offset += 10
                    if ans_type == 1 and rdlength == 4 and current_offset + rdlength <= len(dns_data):
                        ip_bytes = dns_data[current_offset:current_offset+4]
                        ip_address = socket.inet_ntoa(ip_bytes)
                        answers.append(ip_address)
                    current_offset += rdlength
            return {
                'id': transaction_id,
                'is_response': is_response,
                'query': query_name,
                'answers': answers
            }
    except Exception as e:
        pass
    return None

def extract_dns_name(data, offset):
    name_parts = []
    original_offset = offset
    while True:
        if offset >= len(data):
            return '.'.join(name_parts), offset - original_offset
        length = data[offset]
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                return '.'.join(name_parts), offset - original_offset
            pointer = ((length & 0x3F) << 8) | data[offset+1]
            return '.'.join(name_parts), offset + 2 - original_offset
        if length == 0:
            break
        offset += 1
        if offset + length > len(data):
            break
        label = data[offset:offset+length]
        name_parts.append(label.decode('utf-8', errors='ignore'))
        offset += length
    return '.'.join(name_parts), offset + 1 - original_offset

LOCALHOST_NETWORK = ipaddress.ip_network('127.0.0.0/24')
EXCLUDED_LAN_NETWORKS = (
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('172.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
)

def _is_localhost_addr(addr):
    if not addr:
        return False
    if addr.lower() == 'localhost':
        return True
    try:
        return ipaddress.ip_address(addr) in LOCALHOST_NETWORK
    except ValueError:
        return False

def _is_excluded_lan_addr(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in network for network in EXCLUDED_LAN_NETWORKS)

def is_local_traffic(src_addr, dst_addr):
    return _is_localhost_addr(src_addr) and _is_localhost_addr(dst_addr)

def is_lan_traffic(src_addr, dst_addr):
    return _is_excluded_lan_addr(src_addr) and _is_excluded_lan_addr(dst_addr)

def is_excluded_extra_addr(addr):
    if not args.exclude_extra:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in network for network in args.exclude_extra)

def is_included_only_addr(addr):
    if not args.include_only:
        return True
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in network for network in args.include_only)

def is_include_only_traffic(src_addr, dst_addr):
    return is_included_only_addr(src_addr) or is_included_only_addr(dst_addr)

def is_port_53_traffic(proto, transport_packet):
    if proto == 6:
        src_port, dst_port = parse_tcp(transport_packet)
    elif proto == 17:
        src_port, dst_port = parse_udp(transport_packet)
    else:
        return False
    if src_port is None or dst_port is None:
        return False
    return src_port == 53 or dst_port == 53

def visible_text_len(text):
    return len(ANSI_ESCAPE_RE.sub('', text))

def pad_visible(text, width):
    return text + (' ' * max(0, width - visible_text_len(text)))

def truncate_visible(text, width):
    plain = ANSI_ESCAPE_RE.sub('', text)
    if len(plain) <= width:
        return plain
    if width <= 1:
        return plain[:width]
    return plain[:width - 1] + "…"

def fit_visible(text, width):
    if visible_text_len(text) <= width:
        return pad_visible(text, width)
    return pad_visible(truncate_visible(text, width), width)

def gradient_ansi_text(text, start_code=29, end_code=114):
    if not text:
        return text
    steps = max(1, len(text) - 1)
    pieces = []
    for i, ch in enumerate(text):
        color_code = round(start_code + (end_code - start_code) * (i / steps))
        pieces.append(f"\033[38;5;{color_code}m{ch}")
    pieces.append(Colors.RESET)
    return ''.join(pieces)

def format_bytes(num_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024.0 or unit == 'GB':
            if unit == 'B':
                return f"{num_bytes:6.0f} {unit}"
            return f"{num_bytes:6.2f} {unit}"
        num_bytes /= 1024.0

class Colors:
    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[38;5;151m"
    BLUE = "\033[34m"
    MAGENTA = "\033[38;5;140m"
    CYAN = "\033[97m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"
    BG_DARK_GRAY = "\033[100m"
    GREY = "\033[90m"
    MOSS_GREEN = "\033[38;5;71m"
    SOFT_OLIVE = "\033[38;5;108m"
    HEADER_MOSS = "\033[38;5;65m"
    SPEED_SUNSET = "\033[38;5;215m"

def get_visual_char(kbps):
    if kbps == 0:
        return "·"
    elif kbps < 5:
        return "⣀"
    elif kbps < 400:
        if kbps > 200:
            return Colors.BOLD + "⣤" + Colors.RESET
        return "⣤"
    elif kbps < 1200:
        if kbps > 800:
            return Colors.BOLD + "⣶" + Colors.RESET
        return "⣶"
    elif kbps < 1800:
        if kbps > 1500:
            return Colors.BOLD + "⣾" + Colors.RESET
        return "⣿"
    elif kbps < 7800:
        if kbps > 6000:
            return Colors.BOLD + "⣾" + Colors.RESET
        return "┋"
    elif kbps < 7900:
        return Colors.BOLD + "⣿" + Colors.RESET
    else:
        return "┋"

def get_visual_color(kbps):
    if kbps == 0:
        return Colors.GREY
    elif kbps < 5:
        return Colors.BLUE
    elif kbps < 400:
        if kbps < 100:
            return Colors.SPEED_SUNSET
        elif kbps < 200:
            return random.choice([Colors.SPEED_SUNSET, Colors.YELLOW])
        else:
            return Colors.YELLOW
    elif kbps < 1200:
        if kbps < 600:
            return Colors.YELLOW + Colors.BOLD
        elif kbps < 900:
            return random.choice([Colors.YELLOW + Colors.BOLD, Colors.RED])
        else:
            return Colors.RED
    elif kbps < 1800:
        return Colors.RED + Colors.BOLD
    elif kbps < 7800:
        if kbps < 3000:
            return Colors.RED + Colors.BOLD
        elif kbps < 5000:
            return random.choice([Colors.RED + Colors.BOLD, Colors.WHITE])
        else:
            return Colors.WHITE
    elif kbps < 7900:
        return Colors.WHITE + Colors.BOLD
    else:
        return Colors.WHITE + Colors.BOLD

def get_unpriv_visual_char(pps):
    if pps == 0:
        return "·"
    elif pps < 1:
        return "⣀"
    elif pps < 10:
        if pps > 5:
            return Colors.BOLD + "⣤" + Colors.RESET
        return "⣤"
    elif pps < 20:
        if pps > 15:
            return Colors.BOLD + "⣶" + Colors.RESET
        return "⣶"
    elif pps < 50:
        if pps > 30:
            return Colors.BOLD + "⣾" + Colors.RESET
        return "⣿"
    elif pps < 100:
        if pps > 70:
            return Colors.BOLD + "⣾" + Colors.RESET
        return "┋"
    elif pps < 200:
        return Colors.BOLD + "⣿" + Colors.RESET
    return "┋"

def get_unpriv_visual_color(pps):
    if pps == 0:
        return Colors.GREY
    elif pps < 1:
        return Colors.BLUE
    elif pps < 10:
        if pps < 5:
            return Colors.SPEED_SUNSET
        if pps < 7:
            return random.choice([Colors.SPEED_SUNSET, Colors.YELLOW])
        return Colors.YELLOW
    elif pps < 20:
        if pps < 15:
            return Colors.YELLOW + Colors.BOLD
        return random.choice([Colors.YELLOW + Colors.BOLD, Colors.RED])
    elif pps < 50:
        return Colors.RED + Colors.BOLD
    elif pps < 100:
        if pps < 70:
            return Colors.RED + Colors.BOLD
        if pps < 85:
            return random.choice([Colors.RED + Colors.BOLD, Colors.WHITE])
        return Colors.WHITE
    return Colors.WHITE + Colors.BOLD

def get_protocol_color(proto):
    if proto == 'TCP':
        return Colors.BLUE
    elif proto == 'UDP':
        return Colors.GREEN
    elif proto == 'ICMP':
        return Colors.YELLOW
    elif proto.startswith('IP'):
        return Colors.MAGENTA
    else:
        return Colors.WHITE

class SocketProcessMapper:
    def __init__(self):
        self.socket_to_process = {}
        self.last_refresh = 0
        self.refresh_interval = 5

    def refresh(self):
        current_time = time.time()
        if current_time - self.last_refresh < self.refresh_interval:
            return
        self.last_refresh = current_time
        self.socket_to_process = {}
        
        if IS_LINUX:
            self._refresh_linux()
        elif IS_MACOS:
            self._refresh_macos()

    def _refresh_linux(self):
        try:
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.strip().split()
                    local = parts[1]
                    remote = parts[2]
                    uid = int(parts[7])
                    inode = parts[9]
                    local_ip, local_port = self._hex_to_ip_port(local)
                    remote_ip, remote_port = self._hex_to_ip_port(remote)
                    self.socket_to_process[inode] = {
                        'local': (local_ip, local_port),
                        'remote': (remote_ip, remote_port),
                        'uid': uid,
                        'proto': 'tcp',
                        'pid': None,
                        'process': None
                    }
            with open('/proc/net/udp', 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.strip().split()
                    local = parts[1]
                    remote = parts[2]
                    uid = int(parts[7])
                    inode = parts[9]
                    local_ip, local_port = self._hex_to_ip_port(local)
                    remote_ip, remote_port = self._hex_to_ip_port(remote)
                    self.socket_to_process[inode] = {
                        'local': (local_ip, local_port),
                        'remote': (remote_ip, remote_port),
                        'uid': uid,
                        'proto': 'udp',
                        'pid': None,
                        'process': None
                    }
            for pid in os.listdir('/proc'):
                if not pid.isdigit():
                    continue
                try:
                    fd_dir = f'/proc/{pid}/fd'
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(f'{fd_dir}/{fd}')
                            if 'socket' in link:
                                match = re.search(r'socket:\[(\d+)\]', link)
                                if match:
                                    inode = match.group(1)
                                    if inode in self.socket_to_process:
                                        with open(f'/proc/{pid}/comm', 'r') as f:
                                            process_name = f.read().strip()
                                        self.socket_to_process[inode]['pid'] = pid
                                        self.socket_to_process[inode]['process'] = process_name
                        except (FileNotFoundError, PermissionError):
                            pass
                except (FileNotFoundError, PermissionError):
                    pass
        except Exception as e:
            pass  # Gracefully skip on error

    def _refresh_macos(self):
        """Use lsof to map sockets to processes on macOS"""
        try:
            # Run lsof to get network connections
            # -i: internet connections, -n: no hostname resolution, -P: no port names
            output = subprocess.check_output(
                ['lsof', '-i', '-n', '-P'],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode('utf-8')
            
            for line in output.split('\n')[1:]:  # Skip header
                if not line.strip():
                    continue
                try:
                    parts = line.split()
                    if len(parts) < 9:
                        continue
                    
                    process_name = parts[0]
                    pid = parts[1]
                    proto = parts[7].lower() if len(parts) > 7 else ''
                    
                    if 'TCP' in proto.upper():
                        proto = 'tcp'
                    elif 'UDP' in proto.upper():
                        proto = 'udp'
                    else:
                        continue
                    
                    # Parse connection info (format: host:port->host:port or host:port)
                    connection_info = parts[8] if len(parts) > 8 else ''
                    
                    # Handle different formats
                    if '->' in connection_info:
                        local, remote = connection_info.split('->')
                    else:
                        local = connection_info
                        remote = '*:*'
                    
                    # Parse local address
                    if ':' in local:
                        local_parts = local.rsplit(':', 1)
                        local_ip = local_parts[0].replace('[', '').replace(']', '')
                        local_port = int(local_parts[1]) if local_parts[1].isdigit() else 0
                    else:
                        continue
                    
                    # Parse remote address
                    if ':' in remote and remote != '*:*':
                        remote_parts = remote.rsplit(':', 1)
                        remote_ip = remote_parts[0].replace('[', '').replace(']', '')
                        remote_port = int(remote_parts[1]) if remote_parts[1].isdigit() else 0
                    else:
                        remote_ip = '0.0.0.0'
                        remote_port = 0
                    
                    # Create a unique key for this socket
                    socket_key = f"{proto}:{local_ip}:{local_port}:{remote_ip}:{remote_port}"
                    
                    self.socket_to_process[socket_key] = {
                        'local': (local_ip, local_port),
                        'remote': (remote_ip, remote_port),
                        'proto': proto,
                        'pid': pid,
                        'process': process_name
                    }
                    
                    # Also add a key for listening sockets
                    listening_key = f"{proto}:{local_ip}:{local_port}"
                    self.socket_to_process[listening_key] = {
                        'local': (local_ip, local_port),
                        'remote': ('0.0.0.0', 0),
                        'proto': proto,
                        'pid': pid,
                        'process': process_name
                    }
                    
                except (IndexError, ValueError) as e:
                    continue  # Skip malformed lines
                    
        except subprocess.TimeoutExpired:
            pass  # Gracefully skip on timeout
        except subprocess.CalledProcessError:
            pass  # Gracefully skip if lsof fails
        except FileNotFoundError:
            pass  # lsof not available
        except Exception as e:
            pass  # Gracefully skip on any other error

    def _hex_to_ip_port(self, hex_str):
        ip_hex, port_hex = hex_str.split(':')
        ip_parts = [int(ip_hex[i:i+2], 16) for i in range(6, -2, -2)]
        ip = '.'.join(map(str, ip_parts))
        port = int(port_hex, 16)
        return ip, port

    def get_process_info(self, proto, src_ip, src_port, dst_ip, dst_port):
        self.refresh()
        proto_str = 'tcp' if proto == 6 else 'udp' if proto == 17 else str(proto)
        if proto_str not in ('tcp', 'udp'):
            return None
        
        if IS_MACOS:
            # Try exact match first
            key1 = f"{proto_str}:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
            key2 = f"{proto_str}:{dst_ip}:{dst_port}:{src_ip}:{src_port}"
            
            if key1 in self.socket_to_process:
                return {'process': self.socket_to_process[key1]['process']}
            if key2 in self.socket_to_process:
                return {'process': self.socket_to_process[key2]['process']}
            
            # Try listening socket match
            key3 = f"{proto_str}:{src_ip}:{src_port}"
            key4 = f"{proto_str}:{dst_ip}:{dst_port}"
            
            if key3 in self.socket_to_process:
                return {'process': self.socket_to_process[key3]['process']}
            if key4 in self.socket_to_process:
                return {'process': self.socket_to_process[key4]['process']}
            
            return None
        else:
            # Linux logic
            for socket_info in self.socket_to_process.values():
                if socket_info['proto'] != proto_str:
                    continue
                local_ip, local_port = socket_info['local']
                remote_ip, remote_port = socket_info['remote']
                if ((local_ip == src_ip and local_port == src_port and
                     remote_ip == dst_ip and remote_port == dst_port) or
                    (local_ip == dst_ip and local_port == dst_port and
                     remote_ip == src_ip and remote_port == src_port)):
                    return {'process': socket_info['process']}
                if local_ip == '0.0.0.0' and local_port == src_port:
                    return {'process': socket_info['process']}
            return None

class DnsTracker:
    def __init__(self, max_entries=20):
        self.max_entries = max_entries
        self.queries = {}
        self.recent_dns = deque(maxlen=max_entries)
        self.ip_to_name = {}

    def add_dns_packet(self, src_ip, src_port, dst_ip, dst_port, dns_data):
        if not dns_data:
            return
        if not dns_data['is_response']:
            self.queries[dns_data['id']] = {
                'query': dns_data['query'],
                'time': time.time(),
                'client': src_ip
            }
        else:
            query_info = self.queries.get(dns_data['id'])
            if query_info and query_info['client'] == dst_ip:
                self.recent_dns.appendleft({
                    'query': query_info['query'],
                    'answers': dns_data['answers'],
                    'time': time.time()
                })
                for ip in dns_data['answers']:
                    self.ip_to_name[ip] = query_info['query']
                del self.queries[dns_data['id']]
            elif dns_data['query'] and dns_data['answers']:
                self.recent_dns.appendleft({
                    'query': dns_data['query'],
                    'answers': dns_data['answers'],
                    'time': time.time()
                })
                for ip in dns_data['answers']:
                    self.ip_to_name[ip] = dns_data['query']

    def get_recent_queries(self, count=5):
        return list(self.recent_dns)[:count]

class ConnectionTracker:
    def __init__(self, unprivileged_mode=False):
        self.unprivileged_mode = unprivileged_mode
        self.connections = defaultdict(lambda: [0, 0, None])
        self.start_time = time.time()
        self.process_mapper = SocketProcessMapper()
        self.dns_tracker = DnsTracker()
        self.bytes_snapshot = {}
        self.last_report_time = time.time()
        self.current_bandwidths = {}
        self.bandwidth_history = defaultdict(list)
        self.connections_seen = set()
        self.total_bytes_snapshot = 0
        self.total_packets_snapshot = 0
        self.current_total_bw = 0
        self.current_total_packets_per_sec = 0
        self.peak_total_bw = 0
        self.idle_toggle = defaultdict(int)
        self.ip_cache = {}
        self.expand_dns_queries = True
        self.last_unpriv_poll_time = time.time()
        self.unpriv_prev_io = defaultdict(lambda: (0, 0))
        # On macOS in unprivileged mode, per-process io counters are not reliable
        # for network activity attribution. Use system packet counters instead.
        self.unpriv_has_io_counters = (
            self._check_io_counters_support() if (self.unprivileged_mode and not IS_MACOS) else False
        )
        self.unpriv_prev_net_io = psutil.net_io_counters() if self.unprivileged_mode else None
        self.load_hosts()
        if args.resolve:
            self.resolver_thread = threading.Thread(target=self._resolver_thread, daemon=True)
            self.resolver_thread.start()

    def _check_io_counters_support(self):
        try:
            psutil.Process().io_counters()
            return True
        except (AttributeError, NotImplementedError):
            return False

    def _format_total_metric(self, value):
        if self.unprivileged_mode:
            return f"{int(value):6d} pkts"
        return format_bytes(value)

    def _format_rate_metric(self, value):
        if self.unprivileged_mode:
            return f"{value:6.1f} pps"
        return f"{format_bytes(value)}/s"

    def _metric_color_scale_value(self, value):
        if self.unprivileged_mode:
            return value
        return (value * 8) / 1000

    def _poll_unprivileged(self):
        now = time.time()
        time_delta = now - self.last_unpriv_poll_time
        if time_delta < 0.1:
            return

        try:
            conns = [(conn, conn.pid) for conn in psutil.net_connections(kind='inet')]
        except (psutil.AccessDenied, PermissionError):
            conns = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    for conn in proc.net_connections(kind='inet'):
                        conns.append((conn, proc.info.get('pid')))
                except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, AttributeError):
                    continue

        proc_keys = defaultdict(list)
        all_keys = []
        for conn, conn_pid in conns:
            if not conn.laddr or not conn.raddr:
                continue
            if conn.type == socket.SOCK_STREAM:
                if conn.status != psutil.CONN_ESTABLISHED:
                    continue
                proto = 6
            elif conn.type == socket.SOCK_DGRAM:
                proto = 17
            else:
                continue

            src_addr, src_port = conn.laddr
            dst_addr, dst_port = conn.raddr
            is_port_53 = src_port == 53 or dst_port == 53
            if args.no_local and is_local_traffic(src_addr, dst_addr):
                continue
            if args.exclude_lan and (args.no_dns_bypass or not is_port_53) and is_lan_traffic(src_addr, dst_addr):
                continue
            if args.exclude_extra and (is_excluded_extra_addr(src_addr) or is_excluded_extra_addr(dst_addr)):
                continue
            if args.include_only and not is_include_only_traffic(src_addr, dst_addr):
                continue

            if f"{src_addr}:{src_port}" < f"{dst_addr}:{dst_port}":
                key = (proto, src_addr, src_port, dst_addr, dst_port)
            else:
                key = (proto, dst_addr, dst_port, src_addr, src_port)

            # Ensure connection appears in reports even without PID attribution.
            _ = self.connections[key]
            all_keys.append(key)
            pid = conn_pid
            if pid:
                proc_keys[pid].append(key)
                if self.connections[key][2] is None:
                    try:
                        pname = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                        pname = None
                    if pname:
                        self.connections[key][2] = {'process': pname}
            elif self.connections[key][2] is None:
                self.connections[key][2] = {'process': 'Unknown'}

        if self.unpriv_has_io_counters:
            for pid, keys in proc_keys.items():
                if not keys:
                    continue
                try:
                    io_counters = psutil.Process(pid).io_counters()
                except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, AttributeError):
                    continue
                prev_write, prev_read = self.unpriv_prev_io[pid]
                delta = (io_counters.write_count - prev_write) + (io_counters.read_count - prev_read)
                if delta < 0:
                    delta = 0
                per_conn_packets = delta / len(keys) if keys else 0
                for key in keys:
                    self.connections[key][0] += per_conn_packets
                    self.connections[key][1] += per_conn_packets
                self.unpriv_prev_io[pid] = (io_counters.write_count, io_counters.read_count)
        else:
            net_io = psutil.net_io_counters()
            delta = (net_io.packets_sent - self.unpriv_prev_net_io.packets_sent) + (
                net_io.packets_recv - self.unpriv_prev_net_io.packets_recv
            )
            if delta < 0:
                delta = 0
            if all_keys and delta > 0:
                per_conn_packets = delta / len(all_keys)
                for key in all_keys:
                    self.connections[key][0] += per_conn_packets
                    self.connections[key][1] += per_conn_packets
            self.unpriv_prev_net_io = net_io

        self.last_unpriv_poll_time = now

    def poll(self):
        if self.unprivileged_mode:
            self._poll_unprivileged()

    def _merge_history_display(self, keys):
        width = 18
        merged_speeds = [0.0] * width
        for key in keys:
            history = self.bandwidth_history.get(key, [])
            speeds = [entry[2] for entry in history[-width:]]
            pad = width - len(speeds)
            for idx, speed in enumerate(speeds):
                merged_speeds[pad + idx] += speed

        merged_history = []
        for speed in merged_speeds:
            scaled = self._metric_color_scale_value(speed)
            if scaled == 0:
                merged_history.append((" ", get_unpriv_visual_color(scaled) if self.unprivileged_mode else get_visual_color(scaled), speed))
            else:
                if self.unprivileged_mode:
                    merged_history.append((get_unpriv_visual_char(scaled), get_unpriv_visual_color(scaled), speed))
                else:
                    merged_history.append((get_visual_char(scaled), get_visual_color(scaled), speed))

        return ''.join((color + char + Colors.RESET if color else char) for char, color, _ in merged_history)

    def _build_display_connections(self, filtered_connections):
        display_connections = list(filtered_connections)
        display_current_bandwidths = {}
        display_histories = {}

        if not args.merge_highport_sockets:
            for conn, _ in display_connections:
                display_current_bandwidths[conn] = self.current_bandwidths.get(conn, 0)
                display_histories[conn] = self.get_colored_bandwidth_history(conn)
            return display_connections, display_current_bandwidths, display_histories

        indexed = list(enumerate(display_connections))
        consumed = set()
        merged_output = []

        def process_name_of(stats):
            info = stats[2]
            if info and info.get('process'):
                return info['process']
            return None

        def merge_cluster(item_ids, varied_side):
            members = [display_connections[item_id] for item_id in item_ids]
            base_conn, base_stats = members[0]
            proto, src_ip, src_port, dst_ip, dst_port = base_conn
            if varied_side == 'src':
                merged_conn = (proto, src_ip, "highports", dst_ip, dst_port)
            else:
                merged_conn = (proto, src_ip, src_port, dst_ip, "highports")

            total_metric = sum(stats[0] for _, stats in members)
            total_packets = sum(stats[1] for _, stats in members)
            process_info = base_stats[2]
            merged_stats = [total_metric, total_packets, process_info]
            merged_output.append((merged_conn, merged_stats))
            display_current_bandwidths[merged_conn] = sum(self.current_bandwidths.get(conn, 0) for conn, _ in members)
            display_histories[merged_conn] = self._merge_history_display([conn for conn, _ in members])
            consumed.update(item_ids)

        # Pass 1: merge high source-port variants.
        src_groups = defaultdict(list)
        for idx, (conn, stats) in indexed:
            proto, src_ip, src_port, dst_ip, dst_port = conn
            if idx in consumed or proto not in (6, 17) or not isinstance(src_port, int):
                continue
            if src_port <= 35000:
                continue
            src_groups[(proto, src_ip, dst_ip, dst_port, process_name_of(stats))].append((idx, src_port))

        for _, ports in src_groups.items():
            ports.sort(key=lambda x: x[1])
            cluster = [ports[0][0]] if ports else []
            prev_port = ports[0][1] if ports else None
            for idx, port in ports[1:]:
                if port - prev_port <= 9:
                    cluster.append(idx)
                else:
                    if len(cluster) >= 2:
                        merge_cluster(cluster, 'src')
                    cluster = [idx]
                prev_port = port
            if len(cluster) >= 2:
                merge_cluster(cluster, 'src')

        # Pass 2: merge high destination-port variants among remaining entries.
        dst_groups = defaultdict(list)
        for idx, (conn, stats) in indexed:
            if idx in consumed:
                continue
            proto, src_ip, src_port, dst_ip, dst_port = conn
            if proto not in (6, 17) or not isinstance(dst_port, int):
                continue
            if dst_port <= 35000:
                continue
            dst_groups[(proto, src_ip, src_port, dst_ip, process_name_of(stats))].append((idx, dst_port))

        for _, ports in dst_groups.items():
            ports.sort(key=lambda x: x[1])
            cluster = [ports[0][0]] if ports else []
            prev_port = ports[0][1] if ports else None
            for idx, port in ports[1:]:
                if port - prev_port <= 9:
                    cluster.append(idx)
                else:
                    if len(cluster) >= 2:
                        merge_cluster(cluster, 'dst')
                    cluster = [idx]
                prev_port = port
            if len(cluster) >= 2:
                merge_cluster(cluster, 'dst')

        # Keep all non-merged entries unchanged.
        for idx, (conn, stats) in indexed:
            if idx in consumed:
                continue
            merged_output.append((conn, stats))
            display_current_bandwidths[conn] = self.current_bandwidths.get(conn, 0)
            display_histories[conn] = self.get_colored_bandwidth_history(conn)

        return merged_output, display_current_bandwidths, display_histories

    def load_hosts(self):
        try:
            with open('/etc/hosts', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        ip = parts[0]
                        if len(parts) > 1:
                            self.ip_cache[ip] = parts[1]
        except Exception as e:
            pass  # Gracefully skip

    def get_hostname(self, ip):
        if ip in self.ip_cache:
            cached = self.ip_cache[ip]
            return cached if cached != ip else ip

        if ip in self.dns_tracker.ip_to_name:
            name = self.dns_tracker.ip_to_name[ip]
            self.ip_cache[ip] = name
            return name

        try:
            name = socket.gethostbyaddr(ip)[0]
            self.ip_cache[ip] = name
            return name
        except Exception:
            try:
                resolved = self._resolve_fallback(ip)
                if resolved != ip:
                    self.ip_cache[ip] = resolved
                    return resolved
            except Exception:
                pass
            self.ip_cache[ip] = ip
            return ip

    def _resolve_fallback(self, ip):
        try:
            output = subprocess.check_output(['dig', '-x', ip], timeout=10).decode('utf-8')
            ptr_match = re.search(
                r';; ANSWER SECTION:\n[ \t]*\S+[ \t]+\d+[ \t]+IN[ \t]+PTR[ \t]+(\S+)',
                output,
                re.MULTILINE
            )
            if ptr_match:
                return ptr_match.group(1).rstrip('.')
            soa_match = re.search(
                r';; AUTHORITY SECTION:\n[ \t]*\S+[ \t]+\d+[ \t]+IN[ \t]+SOA[ \t]+(\S+)',
                output,
                re.MULTILINE
            )
            if soa_match:
                return soa_match.group(1).rstrip('.')
            whois_output = subprocess.check_output(['whois', ip], timeout=10).decode('utf-8')
            netname_match = re.search(r'netname:\s*(\S+)', whois_output, re.IGNORECASE)
            orgname_match = re.search(r'org-name:\s*(.+)', whois_output, re.IGNORECASE)
            descr_match = re.search(r'descr:\s*(.+)', whois_output, re.IGNORECASE)
            if netname_match:
                return netname_match.group(1).lower().replace('-', '')
            elif orgname_match:
                return orgname_match.group(1).split()[0].lower()
            elif descr_match:
                return descr_match.group(1).split()[0].lower()
        except Exception:
            pass
        return ip

    def _resolver_thread(self):
        while True:
            unresolved = [ip for ip, name in list(self.ip_cache.items()) if name == ip]
            for ip in unresolved:
                resolved = self._resolve_fallback(ip)
                if resolved != ip:
                    self.ip_cache[ip] = resolved
            time.sleep(60)

    def add_packet(self, proto, src_ip, src_port, dst_ip, dst_port, size, packet_data=None):
        if f"{src_ip}:{src_port}" < f"{dst_ip}:{dst_port}":
            key = (proto, src_ip, src_port, dst_ip, dst_port)
        else:
            key = (proto, dst_ip, dst_port, src_ip, src_port)
        self.connections[key][0] += size
        self.connections[key][1] += 1
        if self.connections[key][2] is None:
            self.connections[key][2] = self.process_mapper.get_process_info(
                proto, src_ip, src_port, dst_ip, dst_port)
        if proto == 17 and (src_port == 53 or dst_port == 53) and packet_data:
            dns_data = parse_dns(packet_data)
            if dns_data:
                self.dns_tracker.add_dns_packet(src_ip, src_port, dst_ip, dst_port, dns_data)

    def _update_bandwidth_measurements(self):
        now = time.time()
        time_delta = now - self.last_report_time
        if time_delta < 0.1:
            return
        updated_connections = set()
        self.current_bandwidths = {}
        total_current_bytes = 0
        total_current_packets = 0
        for key, stats in self.connections.items():
            current_bytes = stats[0]
            current_packets = stats[1]
            total_current_bytes += current_bytes
            total_current_packets += current_packets
            prev_bytes = self.bytes_snapshot.get(key, current_bytes)
            bytes_delta = current_bytes - prev_bytes
            self.connections_seen.add(key)
            updated_connections.add(key)
            if bytes_delta > 0:
                bw = bytes_delta / time_delta
                self.current_bandwidths[key] = bw
            else:
                self.current_bandwidths[key] = 0
            self._update_bandwidth_history(key, self.current_bandwidths[key])
            self.bytes_snapshot[key] = current_bytes
        for key in self.connections_seen - updated_connections:
            if key in self.connections:
                self._update_bandwidth_history(key, 0)
        total_bytes_delta = total_current_bytes - self.total_bytes_snapshot
        self.current_total_bw = total_bytes_delta / time_delta if total_bytes_delta > 0 else 0
        total_packets_delta = total_current_packets - self.total_packets_snapshot
        self.current_total_packets_per_sec = total_packets_delta / time_delta if total_packets_delta > 0 else 0
        self.peak_total_bw = max(self.peak_total_bw, self.current_total_bw)
        self.total_bytes_snapshot = total_current_bytes
        self.total_packets_snapshot = total_current_packets
        self.last_report_time = now

    def _update_bandwidth_history(self, connection_key, bytes_per_sec):
        history = self.bandwidth_history[connection_key]
        smoothing_threshold = 10 if self.unprivileged_mode else (100 * 1024)
        if bytes_per_sec == 0 and history and history[-1][0] != "·" and history[-1][2] > smoothing_threshold:
            prior_speed = history[-1][2]
            effective_speed = (bytes_per_sec + (prior_speed / 3)) / 2
        else:
            effective_speed = bytes_per_sec
        scaled_speed = self._metric_color_scale_value(effective_speed)
        if scaled_speed == 0:
            toggle = self.idle_toggle[connection_key]
            char = " " if toggle == 0 else " "
            self.idle_toggle[connection_key] = 1 - toggle
            color = get_unpriv_visual_color(scaled_speed) if self.unprivileged_mode else get_visual_color(scaled_speed)
        else:
            if self.unprivileged_mode:
                char = get_unpriv_visual_char(scaled_speed)
                color = get_unpriv_visual_color(scaled_speed)
            else:
                char = get_visual_char(scaled_speed)
                color = get_visual_color(scaled_speed)
        history.append((char, color, effective_speed))
        if len(history) > 18:
            history = history[-18:]
        self.bandwidth_history[connection_key] = history

    def get_colored_bandwidth_history(self, connection_key):
        history = self.bandwidth_history.get(connection_key, [])
        padding = 18 - len(history)
        padded_history = [(" ", "", 0)] * padding + history
        display = ''.join(
            (color + char + Colors.RESET if color else char)
            for char, color, _ in padded_history
        )
        return display

    def print_report(self, count=20, process_filter=None, group_by_process=False, dns_count=5, line_limit=None):
        print("\033c", end="")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self._render_report_content(count, process_filter, group_by_process, dns_count, line_limit)
        self._print_framed_output(buffer.getvalue().splitlines())

    def _print_framed_output(self, lines):
        if not lines:
            return
        term_size = shutil.get_terminal_size(fallback=(160, 40))
        # Keep output within viewport so each refresh stays stable and does not scroll.
        # Reserve one terminal row for the bottom footer.
        max_content_rows = max(3, term_size.lines - 3)
        if len(lines) > max_content_rows:
            hidden = len(lines) - (max_content_rows - 1)
            lines = lines[:max_content_rows - 1] + [
                f"{Colors.SOFT_OLIVE}… clipped {hidden} lines to fit terminal height{Colors.RESET}"
            ]
        min_width = 64
        max_width = 148
        content_width = max(visible_text_len(line) for line in lines)
        content_width = max(min_width, min(max_width, content_width))
        border_color = Colors.GREY

        print(f"{border_color}╭{'─' * (content_width + 2)}╮{Colors.RESET}")
        for line in lines:
            print(f"{border_color}│{Colors.RESET} {fit_visible(line, content_width)} {border_color}│{Colors.RESET}")
        print(f"{border_color}╰{'─' * (content_width + 2)}╯{Colors.RESET}")
        self._print_bottom_footer(term_size)

    def _print_bottom_footer(self, term_size):
        footer_plain = " xxx I unpa nethound version 1.2 I xxx "
        footer_width = len(footer_plain)
        if term_size.columns <= 2:
            return
        if footer_width > term_size.columns:
            footer_plain = footer_plain[:term_size.columns]
            footer_width = len(footer_plain)
        left_pad = max(0, (term_size.columns - footer_width) // 2)
        footer_colored = gradient_ansi_text(footer_plain, start_code=22, end_code=114)
        # Move to the last terminal line and draw footer without printing a new line.
        sys.stdout.write(f"\033[{term_size.lines};1H\033[2K{' ' * left_pad}{footer_colored}{Colors.RESET}")
        sys.stdout.flush()

    def _render_report_content(self, count=20, process_filter=None, group_by_process=False, dns_count=5, line_limit=None):
        self._update_bandwidth_measurements()
        duration = time.time() - self.start_time
        filtered_connections = list(self.connections.items())
        if process_filter:
            filtered_connections = [
                (conn, stats) for conn, stats in filtered_connections
                if stats[2] and stats[2]['process'] and process_filter.lower() in stats[2]['process'].lower()
            ]
        display_connections, display_current_bandwidths, display_histories = self._build_display_connections(filtered_connections)
        total_bytes = sum(stats[0] for _, stats in display_connections)
        total_packets = sum(stats[1] for _, stats in display_connections)
        sorted_connections = sorted(
            display_connections,
            key=lambda x: x[1][0],
            reverse=True
        )
        lines_printed = 0
        box_width = 80
        left_inner_width = box_width - 2
        right_panel_width = 42
        title = "UNPA NetHound Unprivileged Traffic Monitor" if self.unprivileged_mode else "UNPA NetHound Privileged Traffic Monitor"
        centered_title = title.center(box_width - 2)
        print(f"{Colors.BOLD}{Colors.HEADER_MOSS}{Colors.UNDERLINE} {centered_title}{Colors.RESET}")
        lines_printed += 1

        # Build left summary box rows
        left_rows = [f"{Colors.BOLD}{Colors.HEADER_MOSS}┌{'─' * (box_width - 2)}┐{Colors.RESET}"]
        platform_str = f"Platform: {Colors.CYAN}{platform.system()} {platform.release()}{Colors.RESET}"
        left_rows.append(f"{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET} {pad_visible(platform_str, left_inner_width - 1)}{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET}")
        duration_str = f"Duration: {Colors.CYAN}{duration:.1f} seconds{Colors.RESET}"
        left_rows.append(f"{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET} {pad_visible(duration_str, left_inner_width - 1)}{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET}")
        total_str = (
            f" Cumulative Total: {Colors.MOSS_GREEN}{self._format_total_metric(total_bytes)}{Colors.RESET} "
            f"in {Colors.MOSS_GREEN}{int(total_packets)}{Colors.RESET} packets"
        )
        left_rows.append(f"{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET}{pad_visible(total_str, left_inner_width)}{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET}")
        current_color = get_unpriv_visual_color(self.current_total_bw) if self.unprivileged_mode else get_visual_color((self.current_total_bw * 8) / 1000)
        peak_color = get_unpriv_visual_color(self.peak_total_bw) if self.unprivileged_mode else get_visual_color((self.peak_total_bw * 8) / 1000)
        rates_str = f" Current: {current_color}{self._format_rate_metric(self.current_total_bw)}{Colors.RESET}"
        left_rows.append(f"{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET}{pad_visible(rates_str, left_inner_width)}{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET}")
        conn_str = (
            f" Sniffed Connections: {Colors.YELLOW}{len(self.connections)}{Colors.RESET}"
            f"  Peak: {peak_color}{self._format_rate_metric(self.peak_total_bw)}{Colors.RESET}"
        )
        left_rows.append(f"{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET}{pad_visible(conn_str, left_inner_width)}{Colors.BOLD}{Colors.HEADER_MOSS}│{Colors.RESET}")
        left_rows.append(f"{Colors.BOLD}{Colors.HEADER_MOSS}└{'─' * (box_width - 2)}┘{Colors.RESET}")

        # Build right DNS panel rows (shown in header area)
        base_header_rows = len(left_rows)
        min_combined_rows = base_header_rows
        panel_query_count = max(dns_count, 12) if self.expand_dns_queries else 5
        recent_queries = self.dns_tracker.get_recent_queries(panel_query_count)
        shown_query_count = min(len(recent_queries), panel_query_count)
        dns_header = f"{Colors.BOLD}{Colors.MOSS_GREEN}Latest DNS Queries{Colors.RESET}"
        if self.expand_dns_queries and shown_query_count > 5:
            dns_header += f" {Colors.SOFT_OLIVE}press \"-\" to show less {Colors.RESET}"
        elif not self.expand_dns_queries:
            dns_header += f" {Colors.SOFT_OLIVE}press \"-\" to expand{Colors.RESET}"
        right_rows = [dns_header]
        if recent_queries:
            for query in recent_queries:
                timestamp = time.strftime("%H:%M:%S", time.localtime(query['time']))
                answer = query['answers'][0] if query['answers'] else "-"
                dns_line = f"{timestamp} {query['query']} -> {answer}"
                right_rows.append(f"{Colors.CYAN}{truncate_visible(dns_line, right_panel_width)}{Colors.RESET}")
        else:
            right_rows.append(f"{Colors.GREY}(no recent DNS queries){Colors.RESET}")
        # Dynamic bump: <5 queries => no bump, 5 => +1, 6 => +2 ... up to 12 => +8.
        extra_rows = max(0, shown_query_count - 4)
        min_combined_rows = base_header_rows + extra_rows

        total_rows = max(len(left_rows), len(right_rows), min_combined_rows)
        for idx in range(total_rows):
            left = left_rows[idx] if idx < len(left_rows) else ""
            left_padded = fit_visible(left, box_width)
            right = right_rows[idx] if idx < len(right_rows) else ""
            right_padded = pad_visible(right, right_panel_width)
            print(f"{left_padded}  {right_padded}")
            lines_printed += 1

        if line_limit and lines_printed >= line_limit:
            return
        if group_by_process:
            self._print_grouped_by_process(
                sorted_connections,
                display_current_bandwidths,
                display_histories,
                count,
                line_limit,
                lines_printed if line_limit else None
            )
        else:
            remaining_lines = self._print_flat_list(
                sorted_connections,
                display_current_bandwidths,
                display_histories,
                count,
                line_limit,
                lines_printed if line_limit else None
            )
            if line_limit and remaining_lines:
                lines_printed = remaining_lines

    def _print_flat_list(self, sorted_connections, display_current_bandwidths, display_histories, count, line_limit=None, lines_printed=0):
        if line_limit:
            lines_printed += 1
            if lines_printed >= line_limit:
                return lines_printed
        displayed = 0
        for conn, stats in sorted_connections:
            if displayed >= count:
                break
            if line_limit and lines_printed >= line_limit:
                break
            proto, src_ip, src_port, dst_ip, dst_port = conn
            endpoint_width = 20
            total_size, packet_count, process_info = stats
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP{proto}")
            proto_color = get_protocol_color(proto_name)
            if process_info and process_info['process']:
                process_name = process_info['process']
                if len(process_name) > 15:
                    process_name = process_name[:12] + "."
                process_display = f"{Colors.MAGENTA}{process_name:<15}{Colors.RESET}"
            else:
                process_display = f"{Colors.MAGENTA}{'-':<15}{Colors.RESET}"
            bytes_display = f"{Colors.YELLOW}{self._format_total_metric(total_size):>11}{Colors.RESET}"
            current_bw = display_current_bandwidths.get(conn, 0)
            current_scale = self._metric_color_scale_value(current_bw)
            current_bw_color = get_unpriv_visual_color(current_scale) if self.unprivileged_mode else get_visual_color(current_scale)
            current_bw_display = f"{current_bw_color}{self._format_rate_metric(current_bw)}{Colors.RESET}"
            colored_history = display_histories.get(conn, self.get_colored_bandwidth_history(conn))
            src_display = self.get_hostname(src_ip) if args.resolve else src_ip
            dst_display = self.get_hostname(dst_ip) if args.resolve else dst_ip
            if args.resolve:
                src_display = src_display[-endpoint_width:]
                dst_display = dst_display[-endpoint_width:]
            else:
                src_display = src_display[:endpoint_width]
                dst_display = dst_display[:endpoint_width]
            if proto in (6, 17):
                print(f"{proto_color}{proto_name:4}{Colors.RESET} Src: {Colors.CYAN}{src_display:20}:{src_port:<9}{Colors.RESET}  ⥄  "
                      f"Dst: {Colors.CYAN}{dst_display:20}:{dst_port:<9}{Colors.RESET}  "
                      f"{process_display} "
                      f"{bytes_display} {current_bw_display} {colored_history}")
            else:
                print(f"{proto_color}{proto_name:4}{Colors.RESET} Src: {Colors.CYAN}{src_display:20}          {Colors.RESET}  ⥄  "
                      f"Dst: {Colors.CYAN}{dst_display:20}          {Colors.RESET}  "
                      f"{process_display} "
                      f"{bytes_display} {current_bw_display} {colored_history}")
            displayed += 1
            if line_limit:
                lines_printed += 1
        return lines_printed if line_limit else None

    def _print_grouped_by_process(self, sorted_connections, display_current_bandwidths, display_histories, count, line_limit=None, lines_printed=0):
        process_groups = defaultdict(list)
        unknown_connections = []
        for conn, stats in sorted_connections:
            process_info = stats[2]
            if process_info and process_info['process']:
                process_groups[process_info['process']].append((conn, stats))
            else:
                unknown_connections.append((conn, stats))
        process_bytes = {
            process: sum(stats[0] for _, stats in connections)
            for process, connections in process_groups.items()
        }
        sorted_processes = sorted(process_bytes.items(), key=lambda x: x[1], reverse=True)
        if lines_printed is None:
            lines_printed = 0
        processes_shown = 0
        for process_name, total_process_bytes in sorted_processes:
            if processes_shown >= count:
                break
            process_connections = process_groups[process_name]
            packet_count = sum(stats[1] for _, stats in process_connections)
            duration = time.time() - self.start_time
            bytes_per_sec = total_process_bytes / duration if duration > 0 else 0
            current_bw = sum(display_current_bandwidths.get(conn, 0) for conn, _ in process_connections)
            bytes_scale = self._metric_color_scale_value(bytes_per_sec)
            current_scale = self._metric_color_scale_value(current_bw)
            bandwidth_color = get_unpriv_visual_color(bytes_scale) if self.unprivileged_mode else get_visual_color(bytes_scale)
            process_bw_color = get_unpriv_visual_color(current_scale) if self.unprivileged_mode else get_visual_color(current_scale)
            bytes_display = f"{bandwidth_color}{self._format_total_metric(total_process_bytes):>16}{Colors.RESET}"
            process_bw_display = f"{process_bw_color}{self._format_rate_metric(current_bw)}{Colors.RESET}"
            sorted_process_connections = sorted(process_connections, key=lambda x: x[1][0], reverse=True)
            connections_to_show = min(5, len(sorted_process_connections))
            if line_limit:
                remaining = line_limit - lines_printed
                if remaining <= 2:
                    break
                connections_to_show = min(connections_to_show, max(0, remaining - 2))
                if connections_to_show == 0:
                    break
            print(f"{Colors.MAGENTA}{Colors.BOLD}[{process_name}]{Colors.RESET} "
                  f"{Colors.SOFT_OLIVE}•{Colors.RESET} "
                  f"Total: {bytes_display} in "
                  f"{Colors.BOLD}{int(packet_count)}{Colors.RESET} packets "
                  f"({bandwidth_color}{self._format_rate_metric(bytes_per_sec)}{Colors.RESET}) {process_bw_display}")
            lines_printed += 1
            for i, (conn, stats) in enumerate(sorted_process_connections):
                if i >= connections_to_show:
                    break
                proto, src_ip, src_port, dst_ip, dst_port = conn
                endpoint_width = 20
                total_size, packet_count, _ = stats
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP{proto}")
                proto_color = get_protocol_color(proto_name)
                bytes_display = f"{Colors.YELLOW}{self._format_total_metric(total_size):>12}{Colors.RESET}"
                current_bw = display_current_bandwidths.get(conn, 0)
                current_scale = self._metric_color_scale_value(current_bw)
                current_bw_color = get_unpriv_visual_color(current_scale) if self.unprivileged_mode else get_visual_color(current_scale)
                current_bw_display = f"{current_bw_color}{self._format_rate_metric(current_bw)}{Colors.RESET}"
                colored_history = display_histories.get(conn, self.get_colored_bandwidth_history(conn))
                src_display = self.get_hostname(src_ip) if args.resolve else src_ip
                dst_display = self.get_hostname(dst_ip) if args.resolve else dst_ip
                if args.resolve:
                    src_display = src_display[-endpoint_width:]
                    dst_display = dst_display[-endpoint_width:]
                else:
                    src_display = src_display[:endpoint_width]
                    dst_display = dst_display[:endpoint_width]
                if proto in (6, 17):
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_display:20}:{src_port:<9}{Colors.RESET}  →  "
                          f"{Colors.CYAN}{dst_display:20}:{dst_port:<9}{Colors.RESET}  "
                          f"{'Pkts' if self.unprivileged_mode else 'Bytes'}: {bytes_display} {current_bw_display} {colored_history}")
                else:
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_display:20}          {Colors.RESET}  →  "
                          f"{Colors.CYAN}{dst_display:20} {Colors.RESET}  "
                          f"{'Pkts' if self.unprivileged_mode else 'Bytes'}: {bytes_display} {current_bw_display} {colored_history}")
                lines_printed += 1
            print()
            lines_printed += 1
            processes_shown += 1
        if processes_shown < count and unknown_connections and (not line_limit or lines_printed < line_limit):
            unknown_bytes = sum(stats[0] for _, stats in unknown_connections)
            unknown_packets = sum(stats[1] for _, stats in unknown_connections)
            duration = time.time() - self.start_time
            bytes_per_sec = unknown_bytes / duration if duration > 0 else 0
            current_bw = sum(display_current_bandwidths.get(conn, 0) for conn, _ in unknown_connections)
            bytes_scale = self._metric_color_scale_value(bytes_per_sec)
            current_scale = self._metric_color_scale_value(current_bw)
            bandwidth_color = get_unpriv_visual_color(bytes_scale) if self.unprivileged_mode else get_visual_color(bytes_scale)
            unknown_bw_color = get_unpriv_visual_color(current_scale) if self.unprivileged_mode else get_visual_color(current_scale)
            bytes_display = f"{bandwidth_color}{self._format_total_metric(unknown_bytes):>16}{Colors.RESET}"
            unknown_bw_display = f"{unknown_bw_color}{self._format_rate_metric(current_bw)}{Colors.RESET}"
            sorted_unknown_connections = sorted(unknown_connections, key=lambda x: x[1][0], reverse=True)
            connections_to_show = min(5, len(sorted_unknown_connections))
            if line_limit:
                remaining = line_limit - lines_printed
                if remaining <= 2:
                    return lines_printed
                connections_to_show = min(connections_to_show, max(0, remaining - 2))
                if connections_to_show == 0:
                    return lines_printed
            print(f"{Colors.RED}{Colors.BOLD}[Unknown Processes]{Colors.RESET} "
                  f"{Colors.SOFT_OLIVE}•{Colors.RESET} "
                  f"Total: {bytes_display} in "
                  f"{Colors.BOLD}{int(unknown_packets)}{Colors.RESET} packets "
                  f"({bandwidth_color}{self._format_rate_metric(bytes_per_sec)}{Colors.RESET}) {unknown_bw_display}")
            lines_printed += 1
            for i, (conn, stats) in enumerate(sorted_unknown_connections):
                if i >= connections_to_show:
                    break
                proto, src_ip, src_port, dst_ip, dst_port = conn
                endpoint_width = 20
                total_size, packet_count, _ = stats
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP{proto}")
                proto_color = get_protocol_color(proto_name)
                bytes_display = f"{Colors.YELLOW}{self._format_total_metric(total_size):>12}{Colors.RESET}"
                current_bw = display_current_bandwidths.get(conn, 0)
                current_scale = self._metric_color_scale_value(current_bw)
                current_bw_color = get_unpriv_visual_color(current_scale) if self.unprivileged_mode else get_visual_color(current_scale)
                current_bw_display = f"{current_bw_color}{self._format_rate_metric(current_bw)}{Colors.RESET}"
                colored_history = display_histories.get(conn, self.get_colored_bandwidth_history(conn))
                src_display = self.get_hostname(src_ip) if args.resolve else src_ip
                dst_display = self.get_hostname(dst_ip) if args.resolve else dst_ip
                if args.resolve:
                    src_display = src_display[-endpoint_width:]
                    dst_display = dst_display[-endpoint_width:]
                else:
                    src_display = src_display[:endpoint_width]
                    dst_display = dst_display[:endpoint_width]
                if proto in (6, 17):
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_display:20}:{src_port:<9}{Colors.RESET}  →  "
                          f"{Colors.CYAN}{dst_display:20}:{dst_port:<9}{Colors.RESET}  "
                          f"{'Pkts' if self.unprivileged_mode else 'Bytes'}: {bytes_display} {current_bw_display} {colored_history}")
                else:
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_display:20}          {Colors.RESET}  →  "
                          f"{Colors.CYAN}{dst_display:20}          {Colors.RESET}  "
                          f"{'Pkts' if self.unprivileged_mode else 'Bytes'}: {bytes_display} {current_bw_display} {colored_history}")
                lines_printed += 1
            print()
            lines_printed += 1
        return lines_printed

def enable_dns_toggle_shortcut(tracker):
    if not sys.stdin.isatty():
        return False
    fd = sys.stdin.fileno()
    try:
        original_mode = termios.tcgetattr(fd)
        tty.setcbreak(fd)
    except Exception:
        return False

    def restore_terminal_mode():
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, original_mode)
        except Exception:
            pass

    atexit.register(restore_terminal_mode)

    def key_listener():
        while True:
            try:
                ready, _, _ = select.select([sys.stdin], [], [], 0.2)
            except Exception:
                break
            if not ready:
                continue
            try:
                key = sys.stdin.read(1)
            except Exception:
                continue
            if key == '-':
                tracker.expand_dns_queries = not tracker.expand_dns_queries

    threading.Thread(target=key_listener, daemon=True).start()
    return True

tracker = ConnectionTracker(unprivileged_mode=RUN_UNPRIVILEGED)
dns_toggle_enabled = enable_dns_toggle_shortcut(tracker)

def print_report(signum=None, frame=None):
    line_limit = 60 if args.truncate_output else None
    tracker.print_report(args.count, args.process, args.group, args.dns_count, line_limit)
    if signum == signal.SIGALRM:
        signal.alarm(args.time)

signal.signal(signal.SIGALRM, print_report)
signal.signal(signal.SIGINT, lambda s, f: (print_report(), sys.exit(0)))

mode_label = "unprivileged" if RUN_UNPRIVILEGED else "privileged"
print(f"{Colors.GREEN}UNPA NetHound {mode_label} monitor - Press Ctrl+C to exit{Colors.RESET}")
print(f"{Colors.CYAN}Running on: {platform.system()} {platform.release()}{Colors.RESET}")
if args.no_local:
    print(f"{Colors.YELLOW}Excluding localhost traffic (localhost and 127.0.0.0/24){Colors.RESET}")
if args.exclude_lan:
    print(f"{Colors.YELLOW}Excluding LAN traffic (192.168.0.0/16 172.0.0.0/8 10.0.0.0/8){Colors.RESET}")
if args.exclude_extra:
    extra_ranges_str = ", ".join(str(network) for network in args.exclude_extra)
    print(f"{Colors.YELLOW}Excluding additional ranges: {extra_ranges_str}{Colors.RESET}")
if args.include_only:
    include_ranges_str = ", ".join(str(network) for network in args.include_only)
    print(f"{Colors.YELLOW}Including only ranges: {include_ranges_str}{Colors.RESET}")
if args.no_dns_bypass:
    print(f"{Colors.YELLOW}DNS port 53 bypass disabled for -e filtering{Colors.RESET}")
if args.truncate_output:
    print(f"{Colors.YELLOW}Output limited to 60 lines{Colors.RESET}")
if args.process:
    print(f"{Colors.YELLOW}Filtering for process: {args.process}{Colors.RESET}")
if args.group:
    print(f"{Colors.YELLOW}Grouping connections by process{Colors.RESET}")
if args.resolve:
    print(f"{Colors.YELLOW}DNS resolution enabled (using /etc/hosts, captured DNS, and reverse lookups){Colors.RESET}")
if args.merge_highport_sockets:
    print(f"{Colors.YELLOW}Merging close-range high-port sockets enabled (-m){Colors.RESET}")
if RUN_UNPRIVILEGED:
    print(f"{Colors.YELLOW}Unprivileged mode enabled: packet counts are used as size surrogates{Colors.RESET}")
if dns_toggle_enabled:
    print(f"{Colors.YELLOW}Press '-' to expand or retract Latest DNS Queries (compact max: 5){Colors.RESET}")
print(f"{Colors.GREEN}Generating reports every {args.time} seconds...{Colors.RESET}")

# Unprivileged polling mode (Linux/macOS userland path)
if RUN_UNPRIVILEGED:
    signal.alarm(args.time)
    try:
        while True:
            tracker.poll()
            time.sleep(1)
    except KeyboardInterrupt:
        pass

# macOS packet capture using tcpdump
elif IS_MACOS:
    # Determine interface
    interface = args.interface
    if not interface:
        # Try to auto-detect active interface
        try:
            route_output = subprocess.check_output(['route', '-n', 'get', 'default']).decode('utf-8')
            interface_match = re.search(r'interface:\s*(\S+)', route_output)
            if interface_match:
                interface = interface_match.group(1)
            else:
                interface = 'en0'  # Default fallback
        except:
            interface = 'en0'  # Default fallback
    
    print(f"{Colors.CYAN}Capturing on interface: {interface}{Colors.RESET}")
    print(f"{Colors.YELLOW}Note: Process mapping uses lsof (may have limited info for some connections){Colors.RESET}")
    
    # Start tcpdump process
    tcpdump_cmd = ['tcpdump', '-i', interface, '-n', '-e', '-xx', '-l']
    tcpdump_process = subprocess.Popen(
        tcpdump_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=1
    )
    
    signal.alarm(args.time)
    
    # Read from tcpdump and parse packets
    packet_buffer = b''
    try:
        for line in iter(tcpdump_process.stdout.readline, b''):
            try:
                line = line.decode('utf-8', errors='ignore').strip()
                
                # Parse hex dump lines (starting with 0x)
                if line.startswith('0x'):
                    hex_part = line.split(':')[1].strip() if ':' in line else line[4:].strip()
                    hex_bytes = hex_part.replace(' ', '')
                    packet_buffer += bytes.fromhex(hex_bytes)
                elif packet_buffer:
                    # Process accumulated packet
                    if len(packet_buffer) >= 14:
                        result = parse_ethernet(packet_buffer)
                        if result[0] is not None:
                            eth_protocol, src_mac, dest_mac, ip_packet = result
                            if eth_protocol == 8 and ip_packet:  # IPv4
                                result = parse_ip(ip_packet)
                                if result[0] is not None:
                                    protocol, src_addr, dst_addr, transport_packet, ip_total_len = result
                                    is_port_53 = is_port_53_traffic(protocol, transport_packet)
                                    if args.no_local and is_local_traffic(src_addr, dst_addr):
                                        packet_buffer = b''
                                        continue
                                    if args.exclude_lan and (args.no_dns_bypass or not is_port_53) and is_lan_traffic(src_addr, dst_addr):
                                        packet_buffer = b''
                                        continue
                                    if args.exclude_extra and (is_excluded_extra_addr(src_addr) or is_excluded_extra_addr(dst_addr)):
                                        packet_buffer = b''
                                        continue
                                    if args.include_only and not is_include_only_traffic(src_addr, dst_addr):
                                        packet_buffer = b''
                                        continue
                                    if protocol == 6:  # TCP
                                        result = parse_tcp(transport_packet)
                                        if result[0] is not None:
                                            src_port, dst_port = result
                                            tracker.add_packet(protocol, src_addr, src_port, dst_addr, dst_port, ip_total_len)
                                    elif protocol == 17:  # UDP
                                        result = parse_udp(transport_packet)
                                        if result[0] is not None:
                                            src_port, dst_port = result
                                            tracker.add_packet(protocol, src_addr, src_port, dst_addr, dst_port, ip_total_len, transport_packet)
                                    else:
                                        tracker.add_packet(protocol, src_addr, 0, dst_addr, 0, ip_total_len)
                    packet_buffer = b''
            except Exception as e:
                packet_buffer = b''
                continue
    except KeyboardInterrupt:
        tcpdump_process.terminate()
        pass
    
else:
    # Linux packet capture
    signal.alarm(args.time)
    try:
        while True:
            packet, addr = s.recvfrom(65535)
            result = parse_ethernet(packet)
            if result[0] is None:
                continue
            eth_protocol, src_mac, dest_mac, ip_packet = result
            if eth_protocol == 8:
                result = parse_ip(ip_packet)
                if result[0] is None:
                    continue
                protocol, src_addr, dst_addr, transport_packet, ip_total_len = result
                is_port_53 = is_port_53_traffic(protocol, transport_packet)
                if args.no_local and is_local_traffic(src_addr, dst_addr):
                    continue
                if args.exclude_lan and (args.no_dns_bypass or not is_port_53) and is_lan_traffic(src_addr, dst_addr):
                    continue
                if args.exclude_extra and (is_excluded_extra_addr(src_addr) or is_excluded_extra_addr(dst_addr)):
                    continue
                if args.include_only and not is_include_only_traffic(src_addr, dst_addr):
                    continue
                if protocol == 6:
                    result = parse_tcp(transport_packet)
                    if result[0] is not None:
                        src_port, dst_port = result
                        tracker.add_packet(protocol, src_addr, src_port, dst_addr, dst_port, ip_total_len)
                elif protocol == 17:
                    result = parse_udp(transport_packet)
                    if result[0] is not None:
                        src_port, dst_port = result
                        tracker.add_packet(protocol, src_addr, src_port, dst_addr, dst_port, ip_total_len, transport_packet)
                else:
                    tracker.add_packet(protocol, src_addr, 0, dst_addr, 0, ip_total_len)
    except KeyboardInterrupt:
        pass

