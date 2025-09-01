#!/usr/bin/env python3

# This code is open and free for you to use, modify, share, and build upon.
# Feel free to tweak it, contribute back if you'd like, or use it in your projects—just keep the spirit of openness alive!
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

# ANSI color codes
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

# Parse command line arguments
parser = argparse.ArgumentParser(description='Network Traffic Analyzer with Process Information')
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
args = parser.parse_args()

# Create a raw socket
try:
    # ETH_P_ALL (0x0003) to capture all packets
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

def parse_dns(packet):
    """Parse a DNS packet and extract query and response information"""
    try:
        # Skip UDP header (8 bytes)
        dns_data = packet[8:]
        
        # Parse DNS header
        transaction_id = struct.unpack('!H', dns_data[0:2])[0]
        flags = struct.unpack('!H', dns_data[2:4])[0]
        is_response = (flags & 0x8000) != 0
        question_count = struct.unpack('!H', dns_data[4:6])[0]
        answer_count = struct.unpack('!H', dns_data[6:8])[0]
        
        # Parse query section
        query_name, offset = extract_dns_name(dns_data, 12)
        
        if offset + 4 <= len(dns_data):  # Ensure we have enough data
            query_type, query_class = struct.unpack('!HH', dns_data[offset:offset+4])
            
            # For responses, try to extract answer
            answers = []
            if is_response and answer_count > 0:
                current_offset = offset + 4  # Skip type and class
                
                # Try to extract answers
                for _ in range(answer_count):
                    if current_offset + 12 > len(dns_data):
                        break
                        
                    # For answer records, the first 2 bytes are either a pointer or a name
                    if (dns_data[current_offset] & 0xC0) == 0xC0:  # Compressed name pointer
                        current_offset += 2  # Skip pointer
                    else:
                        # Skip name field
                        _, name_length = extract_dns_name(dns_data, current_offset)
                        current_offset += name_length
                    
                    if current_offset + 10 > len(dns_data):
                        break
                        
                    ans_type, ans_class, ttl, rdlength = struct.unpack(
                        '!HHIH', dns_data[current_offset:current_offset+10]
                    )
                    current_offset += 10
                    
                    # Handle A records (IPv4 addresses)
                    if ans_type == 1 and rdlength == 4 and current_offset + rdlength <= len(dns_data):
                        ip_bytes = dns_data[current_offset:current_offset+4]
                        ip_address = socket.inet_ntoa(ip_bytes)
                        answers.append(ip_address)
                    
                    # Skip to next record
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
    """Extract a DNS name starting at the given offset"""
    name_parts = []
    original_offset = offset
    
    while True:
        if offset >= len(data):
            return '.'.join(name_parts), offset - original_offset
            
        length = data[offset]
        
        # Check for compression pointer
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset+1]
            # For a pointer, we don't recursively follow it in this simple implementation
            return '.'.join(name_parts), offset + 2 - original_offset
            
        # Check for end of name
        if length == 0:
            break
            
        # Extract this label
        offset += 1
        if offset + length > len(data):
            break
            
        label = data[offset:offset+length]
        name_parts.append(label.decode('utf-8', errors='ignore'))
        offset += length
    
    return '.'.join(name_parts), offset + 1 - original_offset

def is_local_traffic(src_addr, dst_addr):
    """Check if traffic is between localhost addresses (127.0.0.0/8)"""
    return src_addr.startswith('127.') and dst_addr.startswith('127.')

def format_bytes(num_bytes):
    """Format bytes into human-readable format (B, KB, MB, GB)"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024.0 or unit == 'GB':
            if unit == 'B':
                return f"{num_bytes:6.0f} {unit}"
            return f"{num_bytes:6.2f} {unit}"
        num_bytes /= 1024.0

def get_bandwidth_color(bytes_per_sec):
    """Return color based on bandwidth level"""
    if bytes_per_sec > 1024*1024:  # > 1MB/s
        return Colors.RED + Colors.BOLD
    elif bytes_per_sec > 100*1024:  # > 100KB/s
        return Colors.YELLOW + Colors.BOLD
    elif bytes_per_sec > 10*1024:   # > 10KB/s
        return Colors.GREEN + Colors.BOLD
    else:
        return Colors.CYAN

def get_protocol_color(proto):
    """Return color based on protocol"""
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
            
        # Try both directions (source→dest and dest→source)
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
                    'pid': socket_info['pid'],
                    'process': socket_info['process']
                }
                
            # Also check for wildcard matches (0.0.0.0 or any port 0)
            if local_ip == '0.0.0.0' and local_port == src_port:
                return {
                    'pid': socket_info['pid'],
                    'process': socket_info['process']
                }
                
        return None

class DnsTracker:
    """Tracks DNS queries and responses"""
    def __init__(self, max_entries=20):
        self.max_entries = max_entries
        self.queries = {}  # id -> query
        self.recent_dns = deque(maxlen=max_entries)  # recent resolved queries
    
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
                # Remove the query from pending
                del self.queries[dns_data['id']]
            elif dns_data['query'] and dns_data['answers']:
                # We don't have the original query, but we have both name and answers
                self.recent_dns.appendleft({
                    'query': dns_data['query'],
                    'answers': dns_data['answers'],
                    'time': time.time()
                })
    
    def get_recent_queries(self, count=5):
        return list(self.recent_dns)[:count]

class ConnectionTracker:
    def __init__(self):
        # Structure: {(proto, src_ip, src_port, dst_ip, dst_port): [bytes, packet_count, process_info]}
        self.connections = defaultdict(lambda: [0, 0, None])
        self.start_time = time.time()
        self.process_mapper = SocketProcessMapper()
        self.dns_tracker = DnsTracker()
    
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
    
    def print_report(self, count=20, process_filter=None, group_by_process=False, dns_count=5):
        duration = time.time() - self.start_time
        
        # Filter connections by process if specified
        filtered_connections = self.connections.items()
        if process_filter:
            filtered_connections = [
                (conn, stats) for conn, stats in filtered_connections
                if stats[2] and stats[2]['process'] and process_filter.lower() in stats[2]['process'].lower()
            ]
        
        # Calculate totals for the filtered set
        total_bytes = sum(conn[0] for _, conn in filtered_connections)
        total_packets = sum(conn[1] for _, conn in filtered_connections)
        bytes_per_second = total_bytes / duration if duration > 0 else 0
        
        # Sort connections by total bytes (descending)
        sorted_connections = sorted(
            filtered_connections, 
            key=lambda x: x[1][0], 
            reverse=True
        )
        
        # Clear screen and print header
        print("\033c", end="")  # Clear screen
        
        # Print fancy header
        print(f"{Colors.BOLD}{Colors.UNDERLINE}Network Traffic Summary{Colors.RESET}")
        print(f"Duration: {Colors.CYAN}{duration:.1f} seconds{Colors.RESET}")
        
        # Print total stats with color based on bandwidth
        bandwidth_color = get_bandwidth_color(bytes_per_second)
        print(f"Total: {bandwidth_color}{format_bytes(total_bytes)}{Colors.RESET} in {Colors.BOLD}{total_packets}{Colors.RESET} packets")
        print(f"Rate: {bandwidth_color}{format_bytes(bytes_per_second)}/s{Colors.RESET} ({Colors.BOLD}{total_packets/duration:.1f}{Colors.RESET} packets/sec)")
        
        # Group by process if requested
        if group_by_process:
            self._print_grouped_by_process(sorted_connections, count)
        else:
            self._print_flat_list(sorted_connections, count)
            
        # Print recent DNS queries
        recent_queries = self.dns_tracker.get_recent_queries(dns_count)
        if recent_queries:
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}Latest DNS Queries:{Colors.RESET}")
            for i, query in enumerate(recent_queries):
                timestamp = time.strftime("%H:%M:%S", time.localtime(query['time']))
                answers_str = ", ".join(query['answers']) if query['answers'] else "No answer"
                print(f"{Colors.CYAN}[{timestamp}]{Colors.RESET} {Colors.YELLOW}{query['query']}{Colors.RESET} → {Colors.GREEN}{answers_str}{Colors.RESET}")
    
    def _print_flat_list(self, sorted_connections, count):
        """Print a flat list of connections sorted by bytes"""
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}Active Network Sockets (sorted by total bytes):{Colors.RESET}")
        print(f"{Colors.YELLOW}{'─' * 100}{Colors.RESET}")
        
        # Print each connection's stats
        displayed = 0
        for conn, stats in sorted_connections:
            if displayed >= count:
                break
                
            proto, src_ip, src_port, dst_ip, dst_port = conn
            total_size, packet_count, process_info = stats
            
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP{proto}")
            proto_color = get_protocol_color(proto_name)
            process_name = f"{Colors.MAGENTA}[{process_info['process']}]{Colors.RESET}" if process_info and process_info['process'] else ""
            
            if proto in (6, 17):  # TCP or UDP
                print(f"{proto_color}{proto_name:4}{Colors.RESET} Src: {Colors.CYAN}{src_ip:15}:{src_port:<6}{Colors.RESET} → "
                      f"Dst: {Colors.CYAN}{dst_ip:15}:{dst_port:<6}{Colors.RESET} "
                      f"Bytes: {Colors.YELLOW}{format_bytes(total_size)}{Colors.RESET} "
                      f"Count: {Colors.GREEN}{packet_count:6}{Colors.RESET} {process_name}")
            else:
                print(f"{proto_color}{proto_name:4}{Colors.RESET} Src: {Colors.CYAN}{src_ip:15}       {Colors.RESET} → "
                      f"Dst: {Colors.CYAN}{dst_ip:15}       {Colors.RESET} "
                      f"Bytes: {Colors.YELLOW}{format_bytes(total_size)}{Colors.RESET} "
                      f"Count: {Colors.GREEN}{packet_count:6}{Colors.RESET} {process_name}")
            
            displayed += 1
    
    def _print_grouped_by_process(self, sorted_connections, count):
        """Print connections grouped by process with summaries"""
        # Group connections by process
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
        
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}Network Connections by Process (sorted by total bytes):{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 100}{Colors.RESET}")
        
        # Print each process group
        processes_shown = 0
        for process_name, total_process_bytes in sorted_processes:
            if processes_shown >= count:
                break
                
            process_connections = process_groups[process_name]
            packet_count = sum(stats[1] for _, stats in process_connections)
            
            # Print process summary
            bytes_per_sec = total_process_bytes / duration if duration > 0 else 0
            bandwidth_color = get_bandwidth_color(bytes_per_sec)
            
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}[{process_name}]{Colors.RESET} "
                  f"Total: {bandwidth_color}{format_bytes(total_process_bytes)}{Colors.RESET} in "
                  f"{Colors.BOLD}{packet_count}{Colors.RESET} packets "
                  f"({bandwidth_color}{format_bytes(bytes_per_sec)}/s{Colors.RESET})")
            print(f"{Colors.YELLOW}{'─' * 100}{Colors.RESET}")
            
            # Print top 5 connections for this process
            for conn, stats in sorted(process_connections, key=lambda x: x[1][0], reverse=True)[:5]:
                proto, src_ip, src_port, dst_ip, dst_port = conn
                total_size, packet_count, _ = stats
                
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP{proto}")
                proto_color = get_protocol_color(proto_name)
                
                if proto in (6, 17):  # TCP or UDP
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_ip:15}:{src_port:<6}{Colors.RESET} → "
                          f"{Colors.CYAN}{dst_ip:15}:{dst_port:<6}{Colors.RESET} "
                          f"Bytes: {Colors.YELLOW}{format_bytes(total_size)}{Colors.RESET} "
                          f"Count: {Colors.GREEN}{packet_count:6}{Colors.RESET}")
                else:
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_ip:15}       {Colors.RESET} → "
                          f"{Colors.CYAN}{dst_ip:15}       {Colors.RESET} "
                          f"Bytes: {Colors.YELLOW}{format_bytes(total_size)}{Colors.RESET} "
                          f"Count: {Colors.GREEN}{packet_count:6}{Colors.RESET}")
            
            processes_shown += 1
        
        # If space remains, show unidentified connections
        if processes_shown < count and unknown_connections:
            unknown_bytes = sum(stats[0] for _, stats in unknown_connections)
            unknown_packets = sum(stats[1] for _, stats in unknown_connections)
            bytes_per_sec = unknown_bytes / duration if duration > 0 else 0
            bandwidth_color = get_bandwidth_color(bytes_per_sec)
            
            print(f"\n{Colors.RED}{Colors.BOLD}[Unknown Processes]{Colors.RESET} "
                  f"Total: {bandwidth_color}{format_bytes(unknown_bytes)}{Colors.RESET} in "
                  f"{Colors.BOLD}{unknown_packets}{Colors.RESET} packets "
                  f"({bandwidth_color}{format_bytes(bytes_per_sec)}/s{Colors.RESET})")
            print(f"{Colors.YELLOW}{'─' * 100}{Colors.RESET}")
            
            # Print top 5 unknown connections
            for conn, stats in sorted(unknown_connections, key=lambda x: x[1][0], reverse=True)[:5]:
                proto, src_ip, src_port, dst_ip, dst_port = conn
                total_size, packet_count, _ = stats
                
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP{proto}")
                proto_color = get_protocol_color(proto_name)
                
                if proto in (6, 17):  # TCP or UDP
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_ip:15}:{src_port:<6}{Colors.RESET} → "
                          f"{Colors.CYAN}{dst_ip:15}:{dst_port:<6}{Colors.RESET} "
                          f"Bytes: {Colors.YELLOW}{format_bytes(total_size)}{Colors.RESET} "
                          f"Count: {Colors.GREEN}{packet_count:6}{Colors.RESET}")
                else:
                    print(f"  {proto_color}{proto_name:4}{Colors.RESET} {Colors.CYAN}{src_ip:15}       {Colors.RESET} → "
                          f"{Colors.CYAN}{dst_ip:15}       {Colors.RESET} "
                          f"Bytes: {Colors.YELLOW}{format_bytes(total_size)}{Colors.RESET} "
                          f"Count: {Colors.GREEN}{packet_count:6}{Colors.RESET}")

# Set up the connection tracker
tracker = ConnectionTracker()

# Handle periodic reporting with signal
def print_report(signum=None, frame=None):
    tracker.print_report(args.count, args.process, args.group, args.dns_count)
    # Set up the next alarm if not triggered by Ctrl+C
    if signum == signal.SIGALRM:
        signal.alarm(args.time)

# Set up signal handlers
signal.signal(signal.SIGALRM, print_report)
signal.signal(signal.SIGINT, lambda s, f: (print_report(), sys.exit(0)))

print(f"{Colors.GREEN}Network Traffic Analyzer with Process Information - Press Ctrl+C to exit{Colors.RESET}")
if args.no_local:
    print(f"{Colors.YELLOW}Excluding localhost traffic (127.0.0.0/8){Colors.RESET}")
if args.process:
    print(f"{Colors.YELLOW}Filtering for process: {args.process}{Colors.RESET}")
if args.group:
    print(f"{Colors.YELLOW}Grouping connections by process{Colors.RESET}")
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
