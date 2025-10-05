#!/usr/bin/env python3
# This code is open and free for you to use, modify, share, and build upon.
# Feel free to tweak it, contribute back if you'd like, or use it in your projectsjust keep the spirit of openness alive!
# If you have questions or ideas, reach out to me directly www.russelldwyer.com
# This program is released under the MIT License - see https://opensource.org/licenses/MIT
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
parser = argparse.ArgumentParser(description='SocketHound Python Protocol Analyzer more at github.com/greenfan written by RND www.russelldwyer.com')
parser.add_argument('-n', '--no-local', action='store_true',
                    help='Exclude local traffic (127.0.0.0/8)')
parser.add_argument('-t', '--time', type=int, default=10,
                    help='Time interval in seconds between reports (default: 10)')
parser.add_argument('-c', '--count', type=int, default=20,
                    help='Number of connections to display (default: 20)')
parser.add_argument('-p', '--process', type=str,
                    help='Filter by process name (e.g., "chrome", "firefox")')
parser.add_argument('-g', '--group', action='store_true',
                    help='Group connections by process')
parser.add_argument('-d', '--dns-count', type=int, default=5,
                    help='Number of recent DNS queries to display (default: 5)')
parser.add_argument('-xx', '--truncate-output', action='store_true',
                    help='Limit output to 60 lines')
parser.add_argument('-e', '--exclude-lan', action='store_true',
                    help='Exclude LAN traffic ')
parser.add_argument('-r', '--resolve', action='store_true',
                    help='Enable DNS resolution for IPs (uses /etc/hosts, captured DNS, and reverse lookups)')
args = parser.parse_args()

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error as e:
    print(f'Socket creation error: {e}')
    print('Note: This script requires root/sudo privileges')
    sys.exit(1)

def format_mac(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def parse_ethernet(packet):
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = struct.unpack('!6s6sH', eth_header)
    dest_mac = format_mac(eth_header[0:6])
    src_mac = format_mac(eth_header[6:12])
    eth_protocol = socket.ntohs(eth[2])
    return eth_protocol, src_mac, dest_mac, packet[eth_length:]

def parse_ip(packet):
    iph = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    total_length = iph[2]  # Total IP packet length
    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])
    return protocol, src_addr, dst_addr, packet[iph_length:], total_length

def parse_tcp(packet):
    tcph = struct.unpack('!HHLLBBHHH', packet[:20])
    return tcph[0], tcph[1]  # src_port, dst_port

def parse_udp(packet):
    udph = struct.unpack('!HHHH', packet[:8])
    return udph[0], udph[1]  # src_port, dst_port
###TODO rework the dns packet scraper...
def parse_dns(packet):
    try:
        dns_data = packet[8:]
        transaction_id = struct.unpack('!H', dns_data[0:2])[0]
        flags = struct.unpack('!H', dns_data[2:4])[0]
        is_response = (flags & 0x8000) != 0
        question_count = struct.unpack('!H', dns_data[4:6])[0]
        answer_count = struct.unpack('!H', dns_data[6:8])[0]
        query_name, offset = extract_dns_name(dns_data, 12)
        if offset + 4 <= len(dns_data):  # Ensure we have enough data
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

def is_local_traffic(src_addr, dst_addr):
    return src_addr.startswith('127.') and dst_addr.startswith('127.')

def is_lan_traffic(src_addr, dst_addr):
    def is_lan_ip(ip):
        return ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.17.')
    return is_lan_ip(src_addr) and is_lan_ip(dst_addr)

def format_bytes(num_bytes):
    #
    # Format bytes to human readble
    #
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024.0 or unit == 'GB':
            if unit == 'B':
                return f"{num_bytes:6.0f} {unit}"
            return f"{num_bytes:6.2f} {unit}"
        num_bytes /= 1024.0
###TODO - Enhance dynamic ranges
#

class Colors:
    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
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


def get_visual_char(kbps):
    if kbps == 0:
        return "�"
    elif kbps < 5:
        return "�"
    elif kbps < 400:
        if kbps > 200:
            return Colors.BOLD + "�" + Colors.RESET
        return "�"
    elif kbps < 1200:
        if kbps > 800:
            return Colors.BOLD + "�" + Colors.RESET  # Bold triple
        return "�"
    elif kbps < 1800:
        if kbps > 1500:
            return Colors.BOLD + "�" + Colors.RESET  # Bold quad
        return "�"
    elif kbps < 7800:
        if kbps > 6000:
            return Colors.BOLD + "�" + Colors.RESET
        return ""  # Regular quad
    elif kbps < 7900:
        return Colors.BOLD + "�" + Colors.RESET
    else:
        return ""  # Very high

def get_visual_color(kbps):
    if kbps == 0:
        return Colors.GREY
    elif kbps < 5:
        return Colors.BLUE
    elif kbps < 400:
        if kbps < 100:
            return Colors.GREEN
        elif kbps < 200:
            return random.choice([Colors.GREEN, Colors.YELLOW])
        else:
            return Colors.YELLOW  # Autumn yellow
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
            return Colors.RED + Colors.BOLD  # Stay in red longer
        elif kbps < 5000:
            return random.choice([Colors.RED + Colors.BOLD, Colors.WHITE])  # Red to white mix
        else:
            return Colors.WHITE  # White
    elif kbps < 7900:
        # White quad dots
        return Colors.WHITE + Colors.BOLD  # Bold white
    else:
        return Colors.WHITE + Colors.BOLD  # Highest white

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

#
#   socket to proc mapping
#
class SocketProcessMapper:
    """Maps socket addresses to process information"""
    def __init__(self):
        self.socket_to_process = {}
        self.last_refresh = 0
        self.refresh_interval = 5  # seconds

    def refresh(self):
        """Refresh the socket-to-process mapping"""
        current_time = time.time()
        if current_time - self.last_refresh < self.refresh_interval:
            return
        self.last_refresh = current_time
        self.socket_to_process = {}
        # For Linux: get TCP socket info
        try:
            # Parse /proc/net/tcp for IPv4 TCP connections
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.strip().split()
                    local = parts[1]
                    remote = parts[2]
                    uid = int(parts[7])
                    inode = parts[9]
                    # Convert hex addresses to decimal
                    local_ip, local_port = self._hex_to_ip_port(local)
                    remote_ip, remote_port = self._hex_to_ip_port(remote)
                    # Store by inode for later process matching
                    self.socket_to_process[inode] = {
                        'local': (local_ip, local_port),
                        'remote': (remote_ip, remote_port),
                        'uid': uid,
                        'proto': 'tcp',
                        'pid': None,
                        'process': None
                    }
            # Parse /proc/net/udp for IPv4 UDP connections
            with open('/proc/net/udp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.strip().split()
                    local = parts[1]
                    remote = parts[2]
                    uid = int(parts[7])
                    inode = parts[9]
                    # Convert hex addresses to decimal
                    local_ip, local_port = self._hex_to_ip_port(local)
                    remote_ip, remote_port = self._hex_to_ip_port(remote)
                    # Store by inode
                    self.socket_to_process[inode] = {
                        'local': (local_ip, local_port),
                        'remote': (remote_ip, remote_port),
                        'uid': uid,
                        'proto': 'udp',
                        'pid': None,
                        'process': None
                    }
            # Find process information by scanning /proc/[pid]/fd
            for pid in os.listdir('/proc'):
                if not pid.isdigit():
                    continue
                try:
                    fd_dir = f'/proc/{pid}/fd'
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(f'{fd_dir}/{fd}')
                            # Check if this is a socket link
                            if 'socket' in link:
                                # Extract socket inode number
                                match = re.search(r'socket:\[(\d+)\]', link)
                                if match:
                                    inode = match.group(1)
                                    if inode in self.socket_to_process:
                                        # Get process name
                                        with open(f'/proc/{pid}/comm', 'r') as f:
                                            process_name = f.read().strip()
                                        self.socket_to_process[inode]['pid'] = pid
                                        self.socket_to_process[inode]['process'] = process_name
                        except (FileNotFoundError, PermissionError):
                            pass
                except (FileNotFoundError, PermissionError):
                    pass
        except Exception as e:
            print(f"Error refreshing socket-to-process mapping: {e}")

    def _hex_to_ip_port(self, hex_str):
        """Convert a hex string like "0100007F:1234" to IP and port"""
        ip_hex, port_hex = hex_str.split(':')
        # Convert hex IP (stored in little-endian) to decimal
        ip_parts = [int(ip_hex[i:i+2], 16) for i in range(6, -2, -2)]
        ip = '.'.join(map(str, ip_parts))
        # Convert hex port to decimal
        port = int(port_hex, 16)
        return ip, port

    def get_process_info(self, proto, src_ip, src_port, dst_ip, dst_port):
        """Try to find process info for a connection"""
        self.refresh()
        # Convert protocol number to string
        proto_str = 'tcp' if proto == 6 else 'udp' if proto == 17 else str(proto)
        if proto_str not in ('tcp', 'udp'):
            return None
        # Try both directions (source�dest and dest�source)
        for socket_info in self.socket_to_process.values():
            if socket_info['proto'] != proto_str:
                continue
            # Check if this socket matches our connection (either direction)
            local_ip, local_port = socket_info['local']
            remote_ip, remote_port = socket_info['remote']
            # Check direct match
            if ((local_ip == src_ip and local_port == src_port and
                 remote_ip == dst_ip and remote_port == dst_port) or
                (local_ip == dst_ip and local_port == dst_port and
                 remote_ip == src_ip and remote_port == src_port)):
                return {
                    'process': socket_info['process']
                }
            # Also check for wildcard matches (0.0.0.0 or any port 0)
            if local_ip == '0.0.0.0' and local_port == src_port:
                return {
                    'process': socket_info['process']
                }
        return None

# DNS tracker
class DnsTracker:
    """Tracks DNS queries and responses"""
    def __init__(self, max_entries=20):
        self.max_entries = max_entries
        self.queries = {}  # id -> query
        self.recent_dns = deque(maxlen=max_entries)  # recent resolved queries
        self.ip_to_name = {}  # Cache from captured DNS: IP -> name (last seen)

    def add_dns_packet(self, src_ip, src_port, dst_ip, dst_port, dns_data):
        if not dns_data:
            return
        # Store query
        if not dns_data['is_response']:
            self.queries[dns_data['id']] = {
                'query': dns_data['query'],
                'time': time.time(),
                'client': src_ip
            }
        # Process response
        else:
            query_info = self.queries.get(dns_data['id'])
            if query_info and query_info['client'] == dst_ip:
                # We have a matching query and response
                self.recent_dns.appendleft({
                    'query': query_info['query'],
                    'answers': dns_data['answers'],
                    'time': time.time()
                })
                # Update IP cache from this response
                for ip in dns_data['answers']:
                    self.ip_to_name[ip] = query_info['query']
                # Remove the query from pending
                del self.queries[dns_data['id']]
            elif dns_data['query'] and dns_data['answers']:
                # We don't have the original query, but we have both name and answers
                self.recent_dns.appendleft({
                    'query': dns_data['query'],
                    'answers': dns_data['answers'],
                    'time': time.time()
                })
                # Update IP cache
                for ip in dns_data['answers']:
                    self.ip_to_name[ip] = dns_data['query']

    def get_recent_queries(self, count=5):
        return list(self.recent_dns)[:count]

class ConnectionTracker:
    def __init__(self):
        # Structure: {(proto, src_ip, src_port, dst_ip, dst_port): [bytes, packet_count, process_info]}
        self.connections = defaultdict(lambda: [0, 0, None])
        self.start_time = time.time()
        self.process_mapper = SocketProcessMapper()
        self.dns_tracker = DnsTracker()
        # Efficient bandwidth tracking
        self.bytes_snapshot = {}  # Most recent snapshot of bytes for each connection
        self.last_report_time = time.time()  # Time of last report
        self.current_bandwidths = {}  # Cache of current bandwidths
        # Bandwidth history tracking: list of (char, color, speed) tuples for smoothing
        self.bandwidth_history = defaultdict(list)  # Stores up to 18 (char, color, speed) for each connection
        self.connections_seen = set()  # Track which connections we've seen for history updates
        # For total bandwidth calculation
        self.total_bytes_snapshot = 0
        self.total_packets_snapshot = 0
        self.current_total_bw = 0
        self.current_total_packets_per_sec = 0
        # For additional stats
        self.peak_total_bw = 0
        # For round-robin idle toggle (0 for space, 1 for dot)
        self.idle_toggle = defaultdict(int)
        # DNS resolution cache (IP -> name or IP if unresolved)
        self.ip_cache = {}
        self.load_hosts()

    def load_hosts(self):
        """Load IP to name mappings from /etc/hosts"""
        try:
            with open('/etc/hosts', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        ip = parts[0]
                        if len(parts) > 1:
                            self.ip_cache[ip] = parts[1]  # Use the first name
        except Exception as e:
            print(f"Error loading /etc/hosts: {e}")

    def get_hostname(self, ip):
        """Get hostname for IP from cache, captured DNS, or reverse lookup"""
        if ip in self.ip_cache:
            cached = self.ip_cache[ip]
            return cached if cached != ip else ip  # If cached as ip, it's unresolved
        # Check captured DNS
        if ip in self.dns_tracker.ip_to_name:
            name = self.dns_tracker.ip_to_name[ip]
            self.ip_cache[ip] = name
            return name
        # Attempt reverse lookup
        try:
            name = socket.gethostbyaddr(ip)[0]
            self.ip_cache[ip] = name
            return name
        except Exception:
            self.ip_cache[ip] = ip  # Cache as IP to avoid retry
            return ip

    def add_packet(self, proto, src_ip, src_port, dst_ip, dst_port, size, packet_data=None):
        # Create bidirectional key
        if f"{src_ip}:{src_port}" < f"{dst_ip}:{dst_port}":
            key = (proto, src_ip, src_port, dst_ip, dst_port)
        else:
            key = (proto, dst_ip, dst_port, src_ip, src_port)
        # Update bytes and packet count
        self.connections[key][0] += size
        self.connections[key][1] += 1
        # Try to identify the process if not already identified
        if self.connections[key][2] is None:
            self.connections[key][2] = self.process_mapper.get_process_info(
                proto, src_ip, src_port, dst_ip, dst_port)
        # Track DNS queries/responses
        if proto == 17 and (src_port == 53 or dst_port == 53) and packet_data:
            dns_data = parse_dns(packet_data)
            if dns_data:
                self.dns_tracker.add_dns_packet(src_ip, src_port, dst_ip, dst_port, dns_data)

    def _update_bandwidth_measurements(self):
        """Efficiently calculate current bandwidth for all connections at once"""
        now = time.time()
        time_delta = now - self.last_report_time
        if time_delta < 0.1:  # Avoid division by very small numbers
            return
        # Track which connections we update in this cycle
        updated_connections = set()
        # Reset bandwidth cache
        self.current_bandwidths = {}
        # Calculate bandwidth for all connections in a single pass
        total_current_bytes = 0
        total_current_packets = 0
        for key, stats in self.connections.items():
            current_bytes = stats[0]
            current_packets = stats[1]
            total_current_bytes += current_bytes
            total_current_packets += current_packets
            # Get previous measurement or use current as initial
            prev_bytes = self.bytes_snapshot.get(key, current_bytes)
            # Calculate bandwidth
            bytes_delta = current_bytes - prev_bytes
            # Record this connection as seen
            self.connections_seen.add(key)
            updated_connections.add(key)
            if bytes_delta > 0:
                bw = bytes_delta / time_delta
                self.current_bandwidths[key] = bw
            else:
                self.current_bandwidths[key] = 0
            # Always update bandwidth history (even for zero bandwidth)
            self._update_bandwidth_history(key, self.current_bandwidths[key])
            # Update snapshot for next time
            self.bytes_snapshot[key] = current_bytes
        # For connections we've seen before but not updated in this cycle,
        # add idle entry to keep the chart moving
        for key in self.connections_seen - updated_connections:
            if key in self.connections:  # Only process if connection still exists
                self._update_bandwidth_history(key, 0)
        # Calculate total current bandwidth (recent rate)
        total_bytes_delta = total_current_bytes - self.total_bytes_snapshot
        self.current_total_bw = total_bytes_delta / time_delta if total_bytes_delta > 0 else 0
        total_packets_delta = total_current_packets - self.total_packets_snapshot
        self.current_total_packets_per_sec = total_packets_delta / time_delta if total_packets_delta > 0 else 0
        # Update peak
        self.peak_total_bw = max(self.peak_total_bw, self.current_total_bw)
        # Update total snapshots
        self.total_bytes_snapshot = total_current_bytes
        self.total_packets_snapshot = total_current_packets
        # Update the timestamp
        self.last_report_time = now

    def _update_bandwidth_history(self, connection_key, bytes_per_sec):
        """Update the bandwidth history visualization for a connection using stacked dots with smoothing"""
        history = self.bandwidth_history[connection_key]
        # Determine the effective (smoothed) speed for visualization
        if bytes_per_sec == 0 and history and history[-1][0] != "�" and history[-1][2] > 100 * 1024:  # Only smooth if current is 0 and prior > 100 KB/s
            prior_speed = history[-1][2]  # Get stored prior effective speed
            effective_speed = (bytes_per_sec + (prior_speed / 3)) / 2
        else:
            effective_speed = bytes_per_sec
        # Convert effective speed to kbps for char and color determination
        kbps = effective_speed * 8 / 1000
        # Get char and color based on congruent logic
        if kbps == 0:
            # Round-robin between " " and "�"
            toggle = self.idle_toggle[connection_key]
            char = " " if toggle == 0 else " "
            self.idle_toggle[connection_key] = 1 - toggle  # Toggle for next time
            color = get_visual_color(kbps)
        else:
            char = get_visual_char(kbps)
            color = get_visual_color(kbps)
        # Append to history: (char, color, effective_speed) and limit to 18
        history.append((char, color, effective_speed))
        if len(history) > 18:
            history = history[-18:]
        self.bandwidth_history[connection_key] = history

    def get_colored_bandwidth_history(self, connection_key):
        """Get the colored bandwidth history string with each character remembering its color/bold"""
        history = self.bandwidth_history.get(connection_key, [])
        # Pad left with plain spaces to make exactly 18 visible characters
        padding = 18 - len(history)
        padded_history = [(" ", "", 0)] * padding + history  # Pad with dummy tuples
        # Build the display string with individual colors (ignore speed here)
        display = ''.join(
            (color + char + Colors.RESET if color else char)
            for char, color, _ in padded_history
        )
        return display

    def print_report(self, count=20, process_filter=None, group_by_process=False, dns_count=5, line_limit=None):
        # Update bandwidth measurements once at the start of the report
        self._update_bandwidth_measurements()
        duration = time.time() - self.start_time
        # Filter connections by process if specified
        filtered_connections = self.connections.items()
        if process_filter:
            filtered_connections = [
                (conn, stats) for conn, stats in filtered_connections
                if stats[2] and stats[2]['process'] and process_filter.lower() in stats[2]['process'].lower()
            ]
        # Calculate totals for the filtered set
        total_bytes = sum(stats[0] for _, stats in filtered_connections)
        total_packets = sum(stats[1] for _, stats in filtered_connections)
        # Sort connections by total bytes (descending)
        sorted_connections = sorted(
            filtered_connections,
            key=lambda x: x[1][0],
            reverse=True
        )
        #
        #
        #
        #   Main table Print statement
        #
        #
        #
        print("\033c", end="")  # Clear screen
        # Initialize line counter for limiting output
        lines_printed = 0
        # Print enhanced summary box with fixed width formatting and proper borders
        box_width = 80
        title = "SocketHound netAF Monitor BY Russell Dwyer"
        centered_title = title.center(box_width - 2)  # -2 for the border characters
        print(f"{Colors.BOLD}{Colors.UNDERLINE} {centered_title}{Colors.RESET}")
        lines_printed += 1
        # Top border with proper corners
        print(f"{Colors.BOLD}{' ' * (box_width - 2)}{Colors.RESET}")
        lines_printed += 1
        # Format duration line with proper padding to maintain fixed width
        duration_str = f"Duration: {Colors.CYAN}{duration:.1f} seconds{Colors.RESET}"
        # Calculate visible length (without ANSI codes)
        visible_length = len(f"Duration: {duration:.1f} seconds")
        print(f"{Colors.BOLD}{Colors.RESET} {duration_str}{' ' * (box_width - visible_length - 3)}{Colors.BOLD}{Colors.RESET}")
        lines_printed += 1
        # Cumulative Total line
        total_color = get_visual_color((total_bytes / duration * 8 / 1000) if duration > 0 else 0)
        # Calculate visible length without ANSI codes
        visible_length = len(f" Cumulative Total: {format_bytes(total_bytes)} in {total_packets} packets")
        total_str = f" Cumulative Total: {total_color}{format_bytes(total_bytes)}{Colors.RESET} in {Colors.BOLD}{total_packets}{Colors.RESET} packets"
        print(f"{Colors.BOLD}{Colors.RESET}{total_str}{' ' * (box_width - visible_length - 3)}{Colors.BOLD} {Colors.RESET}")
        lines_printed += 1
        # Current and Peak Rate line
        current_color = get_visual_color((self.current_total_bw * 8) / 1000)
        peak_color = get_visual_color((self.peak_total_bw * 8) / 1000)
        # Calculate visible length without ANSI codes
        visible_length = len(f" Current: {format_bytes(self.current_total_bw)}/s  Peak: {format_bytes(self.peak_total_bw)}/s")
        rates_str = f" Current: {current_color}{format_bytes(self.current_total_bw)}/s{Colors.RESET}  Peak: {peak_color}{format_bytes(self.peak_total_bw)}/s{Colors.RESET}"
        print(f"{Colors.BOLD}{Colors.RESET}{rates_str}{' ' * (box_width - visible_length - 3)}{Colors.BOLD} {Colors.RESET}")
        lines_printed += 1
        # Active Connections line
        visible_length = len(f" Observed Connections: {len(self.connections)}")
        conn_str = f" Observed Connections: {Colors.YELLOW}{len(self.connections)}{Colors.RESET}"
        print(f"{Colors.BOLD}{Colors.RESET}{conn_str}{' ' * (box_width - visible_length - 3)}{Colors.BOLD} {Colors.RESET}")
        lines_printed += 1
        # Bottom border with proper corners
        print(f"{Colors.BOLD}{' ' * (box_width - 2)}{Colors.RESET}")
        lines_printed += 1
        # Check if we're already at the limit
        if line_limit and lines_printed >= line_limit:
            return
        # Group by process if requested
        if group_by_process:
            self._print_grouped_by_process(sorted_connections, count, line_limit, lines_printed if line_limit else None)
        else:
            remaining_lines = self._print_flat_list(sorted_connections, count, line_limit, lines_printed if line_limit else None)
            if line_limit and remaining_lines:
                lines_printed = remaining_lines
        # Print recent DNS queries if space remains
        if not line_limit or (line_limit and lines_printed < line_limit):
            recent_queries = self.dns_tracker.get_recent_queries(dns_count)
            if recent_queries:
                print(f"\n{Colors.BOLD}{Colors.UNDERLINE}Latest DNS Queries:{Colors.RESET}")
                lines_printed += 2  # Count header and blank line
                # Calculate how many DNS entries we can show
                dns_entries_to_show = min(len(recent_queries),
                                        line_limit - lines_printed if line_limit else len(recent_queries))
                for i, query in enumerate(recent_queries[:dns_entries_to_show]):
                    if line_limit and lines_printed >= line_limit:
                        break
                    timestamp = time.strftime("%H:%M:%S", time.localtime(query['time']))
                    answers_str = ", ".join(query['answers']) if query['answers'] else " "
                    print(f"{Colors.CYAN}[{timestamp}]{Colors.RESET} {Colors.YELLOW}{query['query']}{Colors.RESET} � {Colors.GREEN}{answers_str}{Colors.RESET}")
                    lines_printed += 1

    def _print_flat_list(self, sorted_connections, count, line_limit=None, lines_printed=0):
        print(f"{Colors.YELLOW}{' ' * 100}{Colors.RESET}")
        if line_limit:
            lines_printed += 1  # Count separator
            if lines_printed >= line_limit:
                return lines_printed
        #
        # Print each socket's stats Print statement below.'
        #
        displayed = 0
        for conn, stats in sorted_connections:
            if displayed >= count:
                break
            if line_limit and lines_printed >= line_limit:
                break
            proto, src_ip, src_port, dst_ip, dst_port = conn
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
            bytes_display = f"{Colors.YELLOW}{format_bytes(total_size):>9}{Colors.RESET}"
            current_bw = self.current_bandwidths.get(conn, 0)
            current_kbps = (current_bw * 8) / 1000
            current_bw_color = get_visual_color(current_kbps)
            current_bw_display = f"{current_bw_color}{format_bytes(current_bw)}/s{Colors.RESET}"
            colored_history = self.get_colored_bandwidth_history(conn)
            # Resolve IPs if -r is enabled
            src_display = self.get_hostname(src_ip) if args.resolve else src_ip
            dst_display = self.get_hostname(dst_ip) if args.resolve else dst_ip
            # Truncate to 15 chars for formatting
            src_display = src_display[:19]
            dst_display = dst_display[:19]
            if proto in (6, 17):  # TCP or UDP
                print(f"{proto_color}{proto_name:4}{Colors.RESET} Src: {Colors.CYAN}{src_display:21}:{src_port:<6}{Colors.RESET} � "
                      f"Dst: {Colors.CYAN}{dst_display:21}:{dst_port:<6}{Colors.RESET} "
                      f"{process_display} "
                      f"{bytes_display} {current_bw_display} {colored_history}")
            else:
                print(f"{proto_color}{proto_name:4}{Colors.RESET} Src: {Colors.CYAN}{src_display:21}       {Colors.RESET} � "
                      f"Dst: {Colors.CYAN}{dst_display:21}       {Colors.RESET} "
                      f"Bytes: {process_display} "
                      f"Proc: {bytes_display} {current_bw_display} {colored_history}")
            displayed += 1
            if line_limit:
                lines_printed += 1
        return lines_printed if line_limit else None

        #
        #          Print Grouped process
        #
    def _print_grouped_by_process(self, sorted_connections, count, line_limit=None, lines_printed=0):
        process_groups = defaultdict(list)
        unknown_connections = []
        for conn, stats in sorted_connections:
            process_info = stats[2]
            if process_info and process_info['process']:
                process_groups[process_info['process']].append((conn, stats))
            else:
                unknown_connections.append((conn, stats))
        # Sort processes by total bytes
        process_bytes = {
            process: sum(stats[0] for _, stats in connections)
            for process, connections in process_groups.items()
        }
        sorted_processes = sorted(process_bytes.items(), key=lambda x: x[1], reverse=True)
        print(f"{Colors.YELLOW}{'P' * 100}{Colors.RESET}")
        if line_limit:
            if lines_printed is None:
                lines_printed = 0
            lines_printed += 2  # Count header and separator
            if lines_printed >= line_limit:
                return lines_printed
        # Print each process group
        processes_shown = 0
        for process_name, total_process_bytes in sorted_processes:
            if processes_shown >= count:
                break
            if line_limit and lines_printed + 3 > line_limit:  # Need at least 3 lines for process header
                break
            process_connections = process_groups[process_name]
            packet_count = sum(stats[1] for _, stats in process_connections)
            # Print process summary
            duration = time.time() - self.start_time
            bytes_per_sec = total_process_bytes / duration if duration > 0 else 0
            # Calculate current bandwidth for process (sum of all connections, raw)
            current_bw = sum(self.current_bandwidths.get(conn, 0) for conn, _ in process_connections)
            current_kbps = (current_bw * 8) / 1000
            # Use visual color for summaries
            bandwidth_color = get_visual_color((bytes_per_sec * 8) / 1000)
            process_bw_color = get_visual_color(current_kbps)
            # Format bytes with consistent width
            bytes_display = f"{bandwidth_color}{format_bytes(total_process_bytes):>16}{Colors.RESET}"
            # Display current bandwidth with visual color
            process_bw_display = f"{process_bw_color}{format_bytes(current_bw)}/s{Colors.RESET}"
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}[{process_name}]{Colors.RESET} "
                  f"Total: {bytes_display} in "
                  f"{Colors.BOLD}{packet_count}{Colors.RESET} packets "
                  f"({bandwidth_color}{format_bytes(bytes_per_sec)}/s{Colors.RESET}) {process_bw_display}")
            print(f"{Colors.YELLOW}{' ' * 100}{Colors.RESET}")
            if lines_printed is None:
                lines_printed = 0
            lines_printed += 2
            # Print top connections for this process
            connections_to_show = min(5, len(process_connections))
            if line_limit and lines_printed + connections_to_show > line_limit:
                connections_to_show = line_limit - lines_printed
            for i, (conn, stats) in enumerate(sorted(process_connections, key=lambda x: x[1][0], reverse=True)):
                if i >= connections_to_show:
                    break
                proto, src_ip, src_port, dst_ip, dst_port = conn
                total_size, packet_count, _ = stats
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP{proto}")
                proto_color = get_protocol_color(proto_name)
                # Format the bytes column with consistent width
                bytes_display = f"{Colors.YELLOW}{format_bytes(total_size):>10}{Colors.RESET}"
                # Get current bandwidth from cache (raw)
                current_bw = self.current_bandwidths.get(conn, 0)
                current_kbps = (current_bw * 8) / 1000
                # Display current bandwidth with visual color
                current_bw_color = get_visual_color(current_kbps)
                current_bw_display = f"{current_bw_color}{format_bytes(current_bw)}/s{Colors.RESET}"
                # Get colored bandwidth history with per-character memory
                colored_history = self.get_colored_bandwidth_history(conn)
                # Resolve IPs if -r is enabled
                src_display = self.get_hostname(src_ip) if args.resolve else src_ip
                dst_display = self.get_hostname(dst_ip) if args.resolve else dst_ip
                if args.resolve:
                    src_display = src_display[-21:]
                    dst_display = dst_display[-21:]
                else:
                    src_display = src_display[:19]
                    dst_display = dst_display[:19]
                if proto in (6, 17):  # TCP or UDP
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_display:21}:{src_port:<6}{Colors.RESET} � "
                          f"{Colors.CYAN}{dst_display:21}:{dst_port:<6}{Colors.RESET} "
                          f"Bytes: {bytes_display} {current_bw_display} {colored_history}")
                else:
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_display:21}       {Colors.RESET} � "
                          f"{Colors.CYAN}{dst_display:21} {Colors.RESET} "
                          f"Bytes: {bytes_display} {current_bw_display} {colored_history}")
                lines_printed += 1
            processes_shown += 1
        # If space remains, show unidentified connections
        if processes_shown < count and unknown_connections and (not line_limit or lines_printed < line_limit):
            if line_limit and lines_printed + 3 > line_limit:  # Need at least 3 lines for unknown header
                return lines_printed
            unknown_bytes = sum(stats[0] for _, stats in unknown_connections)
            unknown_packets = sum(stats[1] for _, stats in unknown_connections)
            duration = time.time() - self.start_time
            bytes_per_sec = unknown_bytes / duration if duration > 0 else 0
            current_bw = sum(self.current_bandwidths.get(conn, 0) for conn, _ in unknown_connections)
            current_kbps = (current_bw * 8) / 1000
            bandwidth_color = get_visual_color((bytes_per_sec * 8) / 1000)
            unknown_bw_color = get_visual_color(current_kbps)
            # Format bytes with consistent width
            bytes_display = f"{bandwidth_color}{format_bytes(unknown_bytes):>16}{Colors.RESET}"
            # Display current bandwidth with visual color
            unknown_bw_display = f"{unknown_bw_color}{format_bytes(current_bw)}/s{Colors.RESET}"
            print(f"\n{Colors.RED}{Colors.BOLD}[Unknown Processes]{Colors.RESET} "
                  f"Total: {bytes_display} in "
                  f"{Colors.BOLD}{unknown_packets}{Colors.RESET} packets "
                  f"({bandwidth_color}{format_bytes(bytes_per_sec)}/s{Colors.RESET}) {unknown_bw_display}")
            print(f"{Colors.YELLOW}{' ' * 100}{Colors.RESET}")
            lines_printed += 2
            # Print top unknown connections
            connections_to_show = min(5, len(unknown_connections))
            if line_limit and lines_printed + connections_to_show > line_limit:
                connections_to_show = line_limit - lines_printed
            for i, (conn, stats) in enumerate(sorted(unknown_connections, key=lambda x: x[1][0], reverse=True)):
                if i >= connections_to_show:
                    break
                proto, src_ip, src_port, dst_ip, dst_port = conn
                total_size, packet_count, _ = stats
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP{proto}")
                proto_color = get_protocol_color(proto_name)
                # Format the bytes column with consistent width
                bytes_display = f"{Colors.YELLOW}{format_bytes(total_size):>10}{Colors.RESET}"
                # Get current bandwidth from cache (raw)
                current_bw = self.current_bandwidths.get(conn, 0)
                current_kbps = (current_bw * 8) / 1000
                # Display current bandwidth with visual color
                current_bw_color = get_visual_color(current_kbps)
                current_bw_display = f"{current_bw_color}{format_bytes(current_bw)}/s{Colors.RESET}"
                # Get colored bandwidth history with per-character memory
                colored_history = self.get_colored_bandwidth_history(conn)
                # Resolve IPs if -r is enabled
                src_display = self.get_hostname(src_ip) if args.resolve else src_ip
                dst_display = self.get_hostname(dst_ip) if args.resolve else dst_ip
                # Truncate to 15 chars for formatting
                src_display = src_display[:19]
                dst_display = dst_display[:19]
                if proto in (6, 17):  # TCP or UDP
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_display:21}:{src_port:<6}{Colors.RESET} � "
                          f"{Colors.CYAN}{dst_display:21}:{dst_port:<6}{Colors.RESET} "
                          f"Bytes: {bytes_display} {current_bw_display} {colored_history}")
                else:
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_display:21}       {Colors.RESET} � "
                          f"{Colors.CYAN}{dst_display:21}       {Colors.RESET} "
                          f"Bytes: {bytes_display} {current_bw_display} {colored_history}")
                if lines_printed is None:
                    lines_printed = 0
                lines_printed += 1
        return lines_printed

# Set up the connection tracker
tracker = ConnectionTracker()

# Handle periodic reporting with signal
def print_report(signum=None, frame=None):
    line_limit = 60 if args.truncate_output else None
    tracker.print_report(args.count, args.process, args.group, args.dns_count, line_limit)
    # Set up the next alarm if not triggered by Ctrl+C
    if signum == signal.SIGALRM:
        signal.alarm(args.time)

# Set up signal handlers
signal.signal(signal.SIGALRM, print_report)
signal.signal(signal.SIGINT, lambda s, f: (print_report(), sys.exit(0)))

print(f"{Colors.GREEN}Network Traffic Analyzer with Process Information - Press Ctrl+C to exit{Colors.RESET}")
if args.no_local:
    print(f"{Colors.YELLOW}Excluding localhost traffic (127.0.0.0/8){Colors.RESET}")
if args.exclude_lan:
    print(f"{Colors.YELLOW}Excluding LAN traffic (192.168.0.0/16 172.17.0.0/16 10.0.0.0/8){Colors.RESET}")
if args.truncate_output:
    print(f"{Colors.YELLOW}Output limited to 60 lines{Colors.RESET}")
if args.process:
    print(f"{Colors.YELLOW}Filtering for process: {args.process}{Colors.RESET}")
if args.group:
    print(f"{Colors.YELLOW}Grouping connections by process{Colors.RESET}")
if args.resolve:
    print(f"{Colors.YELLOW}DNS resolution enabled (using /etc/hosts, captured DNS, and reverse lookups){Colors.RESET}")
print(f"{Colors.GREEN}Generating reports every {args.time} seconds...{Colors.RESET}")

# Start the first timer
signal.alarm(args.time)

try:
    while True:
        packet, addr = s.recvfrom(65535)
        # Parse Ethernet header
        eth_protocol, src_mac, dest_mac, ip_packet = parse_ethernet(packet)
        # Handle IPv4 packets (type 0x0800)
        if eth_protocol == 8:  # IPv4
            protocol, src_addr, dst_addr, transport_packet, ip_total_len = parse_ip(ip_packet)
            # Skip localhost traffic if --no-local is specified
            if args.no_local and is_local_traffic(src_addr, dst_addr):
                continue
            # Skip LAN traffic if --exclude-lan is specified
            if args.exclude_lan and is_lan_traffic(src_addr, dst_addr):
                continue
            # TCP or UDP: Get port information
            if protocol == 6:  # TCP
                src_port, dst_port = parse_tcp(transport_packet)
                tracker.add_packet(protocol, src_addr, src_port, dst_addr, dst_port, ip_total_len)
            elif protocol == 17:  # UDP
                src_port, dst_port = parse_udp(transport_packet)
                tracker.add_packet(protocol, src_addr, src_port, dst_addr, dst_port, ip_total_len, transport_packet)
            else:  # ICMP or other IP protocols
                tracker.add_packet(protocol, src_addr, 0, dst_addr, 0, ip_total_len)
except KeyboardInterrupt:
    # Handler will print report and exit
    pass
 
