#!/usr/bin/env python3
#
## TODO: fix arrows make nodes be placed farther apart. fix networkx graphing or replace entirely.
###
import asyncio
import os
import sys
from collections import deque, defaultdict
from typing import Deque, Tuple, Dict, List
from dataclasses import dataclass
import re
from subprocess import Popen, PIPE
import threading
import subprocess  # For running shell command
import math  # For arrow calculations
import random  # For slight position offsets to reduce overlaps

# New imports for visualization
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import networkx as nx  # For network graph

# Constants
DUMP_FILE = "/tmp/hound_dump.pcap"
BUFFER_SIZE = 65536
OUTPUT_INTERVAL_SEC = 5
HIGH_PORT_THRESHOLD = 10900

# Global shared data for visuals (updated every 5s)
latest_data = []
data_lock = threading.Lock()  # For thread safety

# Global set of local IPs
local_ips = set()

# Global cached positions for stable layout
cached_pos = {}

@dataclass
class Config:
    interface: str = 'any'
    resolve_mode: bool = False
    show_fd: bool = False
    use_local_replacement: bool = True  # Default to on for Local_Box_IP replacement

async def setup_tcpdump(cmd: str) -> asyncio.subprocess.Process:
    if os.path.exists(DUMP_FILE):
        os.remove(DUMP_FILE)
    with open(DUMP_FILE, 'w') as f:
        pass  # this will Create an empty file
    os.chmod(DUMP_FILE, 0o666)

    return await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

async def read_dump_file(queue: Deque[str]):
    position = 0
    remainder = b''
    while True:
        try:
            with open(DUMP_FILE, 'rb') as f:
                f.seek(position)
                chunk = f.read(BUFFER_SIZE)
                if chunk:
                    data = remainder + chunk
                    text = data.decode('utf-8', errors='ignore')
                    lines = text.splitlines(keepends=False)
                    if not text.endswith('\n'):
                        remainder = data[data.rfind(b'\n') + 1:] if b'\n' in data else data
                        lines = lines[:-1]
                    else:
                        remainder = b''
                    for line in lines:
                        if line.strip():
                            queue.append(line)
                    position = f.tell()
                    await asyncio.sleep(0.01)
                else:
                    await asyncio.sleep(0.1)
        except FileNotFoundError:
            await asyncio.sleep(0.1)
        except Exception as e:
            print(f"Error reading dump file: {e}")
            await asyncio.sleep(0.1)

def humanbytes(B: float, no_color: bool = False) -> str:
    B = float(B)
    KB, MB, GB, TB = 1024.0, 1024**2, 1024**3, 1024**4
    RED, YELLOW, GREEN, BLUE, ENDC = '\033[91m', '\033[93m', '\033[92m', '\033[94m', '\033[0m'

    color = RED if B >= GB else YELLOW if B >= 100 * MB else GREEN if B >= MB else BLUE

    if B < KB:
        unit = 'Byte' if B == 1 else 'Bytes'
        formatted = f'{int(B)} {unit}'
    elif B < MB:
        formatted = f'{B/KB:.2f} KB'
    elif B < GB:
        formatted = f'{B/MB:.2f} MB'
    elif B < TB:
        formatted = f'{B/GB:.2f} GB'
    else:
        formatted = f'{B/TB:.2f} TB'

    if no_color:
        return f"{formatted:>10}"
    else:
        return f"{color}{formatted:>10}{ENDC}"

def opt_parse_rawip(rawip: str) -> Dict[str, any] | None:
    try:
        if 'IP ' not in rawip or 'IP6 ' in rawip:  # Skip IPv6 for now
            return None
        ip_part = rawip.split('IP ')[1]
        src, remainder = ip_part.split(' > ')
        dst, proto_length = remainder.split(': ', 1)
        src_ip, src_port = src.rsplit('.', 1)
        dst_ip, dst_port = dst.rsplit('.', 1)
        length = int(proto_length.split()[-1])
        return {"SRC": src_ip, "s_port": src_port, "DST": dst_ip, "d_port": dst_port, "Length": length}
    except Exception:
        return None

async def process_queue(queue: Deque[str], output_data: Dict[Tuple[str, str, str, str], Tuple[int, int, str, str, str, str]]):
    while True:
        if queue:
            line = queue.popleft()
            data = opt_parse_rawip(line)
            if data:
                key = (data["SRC"], data["s_port"], data["DST"], data["d_port"])
                total_bytes, count, *extra = output_data.get(key, (0, 0, "~", "~", "~", "~"))
                output_data[key] = (total_bytes + data["Length"], count + 1, *extra)
        else:
            await asyncio.sleep(0.01)

def sock_table():
    lsof_data = Popen(
        ["lsof", "-i", "-n", "-P"],
        stdout=PIPE,
        stderr=PIPE,
        universal_newlines=True
    ).communicate()[0]
    sock_dicts = []
    for line in lsof_data.splitlines():
        parts = line.split()
        if len(parts) < 9:
            continue
        proc = parts[0]
        pid = parts[1]
        fd = parts[3]
        proto = parts[7]
        connection = " ".join(parts[8:])
        match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+\.\d+\.\d+\.\d+):(\d+)', connection)
        if not match:
            continue
        source, s_port, dest, d_port = match.groups()
        sock_dict = {
            'proc': proc,
            'pid': pid,
            'fd': fd,
            'proto': proto,
            'source': source,
            's_port': int(s_port),
            'dest': dest,
            'd_port': int(d_port)
        }
        sock_dicts.append(sock_dict)
    return sock_dicts

def update_with_sock_info(output_data: Dict[Tuple[str, str, str, str], Tuple[int, int, str, str, str, str]]):
    sock_infos = sock_table()
    sock_dict = {
        (info['source'], str(info['s_port']), info['dest'], str(info['d_port'])): (info['proc'], info['pid'], info['fd'], info['proto'])
        for info in sock_infos
    }
    reverse_sock_dict = {
        (info['dest'], str(info['d_port']), info['source'], str(info['s_port'])): (info['proc'], info['pid'], info['fd'], info['proto'])
        for info in sock_infos
    }
    for key in output_data:
        matched_info = sock_dict.get(key) or reverse_sock_dict.get(key) or ("~", "~", "~", "~")
        total_bytes, count, *_ = output_data[key]
        output_data[key] = (total_bytes, count, *matched_info)

def consolidate_entries(entries: List[Tuple[Tuple[str, str, str, str], Tuple[int, int, str, str, str, str]]]) \
        -> List[Tuple[Tuple[str, str, str, str], Tuple[int, int, str, str, str, str]]]:
    consolidated: List[Tuple[Tuple[str, str, str, str], Tuple[int, int, str, str, str, str]]] = []
    groups: Dict[Tuple[str, str, str, str], List[Tuple[Tuple[str, str, str, str], Tuple[int, int, str, str, str, str]]]] = defaultdict(list)

    for entry in entries:
        key, value = entry
        src_ip, src_port, dst_ip, dst_port = key
        merged = False

        if src_port.isdigit() and int(src_port) > HIGH_PORT_THRESHOLD and dst_port.isdigit() and int(dst_port) <= HIGH_PORT_THRESHOLD:
            group_key = (src_ip, 'HIGH', dst_ip, dst_port)
            groups[group_key].append(entry)
            merged = True
        elif dst_port.isdigit() and int(dst_port) > HIGH_PORT_THRESHOLD and src_port.isdigit() and int(src_port) <= HIGH_PORT_THRESHOLD:
            group_key = (src_ip, src_port, dst_ip, 'HIGH')
            groups[group_key].append(entry)
            merged = True

        if not merged:
            consolidated.append(entry)

    for group_key, entry_list in groups.items():
        if len(entry_list) > 1:
            total_bytes = sum(v[0] for _, v in entry_list)
            total_count = sum(v[1] for _, v in entry_list)
            proc = pid = fd = proto = "~"
            for _, v in entry_list:
                if proc == "~" and v[2] != "~":
                    proc = v[2]
                if pid == "~" and v[3] != "~":
                    pid = v[3]
                if fd == "~" and v[4] != "~":
                    fd = v[4]
                if proto == "~" and v[5] != "~":
                    proto = v[5]
            consolidated.append((group_key, (total_bytes, total_count, proc, pid, fd, proto)))
        else:
            consolidated.append(entry_list[0])

    consolidated.sort(key=lambda item: item[1][0], reverse=True)
    return consolidated

async def output_report(output_data: Dict[Tuple[str, str, str, str], Tuple[int, int, str, str, str, str]], config: Config):
    global latest_data
    while True:
        await asyncio.sleep(OUTPUT_INTERVAL_SEC)
        if output_data:
            update_with_sock_info(output_data)
            sorted_data = sorted(output_data.items(), key=lambda item: item[1][0], reverse=True)
            consolidated_data = consolidate_entries(sorted_data)
            total_lines = len(consolidated_data)
            print(f"\nActive Network Sockets (sorted by total bytes, total: {total_lines}):")
            for entry in consolidated_data:
                print_formatted_entry(entry, config)
            print('--- End of Report ---\n')

            # Update shared data for visuals
            with data_lock:
                latest_data = consolidated_data

def print_formatted_entry(entry: Tuple[Tuple[str, str, str, str], Tuple[int, int, str, str, str, str]], config: Config):
    (src_ip, src_port, dst_ip, dst_port), (total_bytes, count, proc, pid, fd, proto) = entry
    # Replace local IPs for display (only if feature enabled via local_ips set)
    src_display = "Local_Box_IP" if src_ip in local_ips else src_ip
    dst_display = "Local_Box_IP" if dst_ip in local_ips else dst_ip
    bytes_formatted = humanbytes(total_bytes)
    base = (
        f"Src: {src_display:>15}:{src_port:<5} -> "
        f"Dst: {dst_display:>15}:{dst_port:<5} "
        f"Bytes: {bytes_formatted} "
        f"Count: {count:>6} "
        f"Proc: {proc:<15}"
    )
    if config.show_fd:
        print(base + f" pid: {pid:<6} FD: {fd:<4} Proto: {proto:<4}")
    else:
        print(base + f" pid: {pid:<6}")

def parse_args() -> Config:
    config = Config()
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '-R':
            config.resolve_mode = True
        elif arg.lower() in ('-i', '-I'):
            if i + 1 < len(sys.argv):
                config.interface = sys.argv[i + 1]
                i += 1
            else:
                print("Error: Interface name must be specified after -i/-I")
                sys.exit(1)
        elif arg == '-fd':
            config.show_fd = True
        elif arg == '-nolocal':  # Flag to disable Local_Box_IP replacement
            config.use_local_replacement = False
        i += 1
    return config

# --- Visualization Functions ---

def is_local_node(node: str) -> bool:
    """Check if node label represents a local IP (e.g., 192.168., 172., 10.)."""
    if node.startswith('Local_Box_IP'):
        return True
    ip = node.split(':')[0] if ':' in node else node
    return ip.startswith(('192.168.', '172.', '10.'))

def generate_network_graph(data):
    global cached_pos
    if not data:
        return go.Figure().update_layout(title="No data available")

    # Create a directed graph
    G = nx.DiGraph()

    # Temporary dict to detect bidirectional pairs
    flow_dict = defaultdict(lambda: {'bytes': 0, 'count': 0, 'proc': '~', 'bidir': False, 'rev_bytes': 0, 'rev_count': 0})

    for (src_ip, src_port, dst_ip, dst_port), (total_bytes, count, proc, _, _, _) in data[:20]:  # Top 20 to avoid clutter
        src = "Local_Box_IP" if src_ip in local_ips else f"{src_ip}:{src_port}"
        dst = "Local_Box_IP" if dst_ip in local_ips else f"{dst_ip}:{dst_port}"
        key = (src, dst)
        flow_dict[key]['bytes'] += total_bytes
        flow_dict[key]['count'] += count
        if flow_dict[key]['proc'] == '~':
            flow_dict[key]['proc'] = proc

    # Post-process to merge bidirectional flows
    processed = set()
    for key in list(flow_dict):
        if key in processed:
            continue
        src, dst = key
        rev_key = (dst, src)
        if rev_key in flow_dict:
            flow_dict[key]['bidir'] = True
            flow_dict[key]['rev_bytes'] = flow_dict[rev_key]['bytes']
            flow_dict[key]['rev_count'] = flow_dict[rev_key]['count']
            if flow_dict[key]['proc'] == '~':
                flow_dict[key]['proc'] = flow_dict[rev_key]['proc']
            del flow_dict[rev_key]
            processed.add(rev_key)
        processed.add(key)

    # Add nodes and edges to graph
    for (src, dst), info in flow_dict.items():
        G.add_node(src)
        G.add_node(dst)
        G.add_edge(src, dst, weight=info['bytes'], count=info['count'], proc=info['proc'],
                   bidir=info['bidir'], rev_weight=info['rev_bytes'], rev_count=info['rev_count'])

    # Stable layout with caching
    current_nodes = set(G.nodes())
    new_nodes = current_nodes - set(cached_pos.keys())

    # Assign initial positions for new nodes
    center = (0, 0)  # Default center
    local_center = cached_pos.get('Local_Box_IP', center) if 'Local_Box_IP' in cached_pos else center
    for node in new_nodes:
        if is_local_node(node):
            # Place local nodes near Local_Box_IP or center
            cached_pos[node] = (local_center[0] + random.uniform(-0.2, 0.2),
                                local_center[1] + random.uniform(-0.2, 0.2))
        else:
            # Place non-local near center with slight offset
            cached_pos[node] = (center[0] + random.uniform(-0.5, 0.5),
                                center[1] + random.uniform(-0.5, 0.5))

    # Compute layout: Fix existing positions, layout only new nodes
    fixed_nodes = list(set(cached_pos.keys()) - new_nodes)
    pos = nx.spring_layout(G, pos=cached_pos, fixed=fixed_nodes, k=1.0, iterations=20, seed=42)

    # Update cache with new positions
    cached_pos.update(pos)

    # Create traces for edges and arrows
    edge_traces = []
    for edge in G.edges(data=True):
        src, dst, info = edge
        x0, y0 = pos[src]
        x1, y1 = pos[dst]
        weight = info['weight']
        rev_weight = info.get('rev_weight', 0)
        total_weight = weight + rev_weight
        color_idx = int(min(total_weight / 1e6, 9))  # Scale to MB
        color = px.colors.sequential.Viridis[color_idx]
        line_width = min(30, max(2, total_weight / 1e3))  # More aggressive scaling for wider lines

        # Hover template
        if info['bidir']:
            hovertemplate = (
                "Bidirectional<br>"
                "%{customdata[0]} -> %{customdata[1]}<br>"
                "Bytes: %{customdata[2]}<br>Count: %{customdata[3]}<br>"
                "%{customdata[1]} -> %{customdata[0]}<br>"
                "Bytes: %{customdata[4]}<br>Count: %{customdata[5]}<br>"
                "Proc: %{customdata[6]}<extra></extra>"
            )
            customdata = [src, dst, humanbytes(weight, no_color=True), info['count'],
                          humanbytes(rev_weight, no_color=True), info['rev_count'], info['proc']]
        else:
            hovertemplate = (
                "%{customdata[0]} -> %{customdata[1]}<br>"
                "Bytes: %{customdata[2]}<br>Count: %{customdata[3]}<br>"
                "Proc: %{customdata[4]}<extra></extra>"
            )
            customdata = [src, dst, humanbytes(weight, no_color=True), info['count'], info['proc']]

        # Main line with dynamic width
        edge_traces.append(go.Scatter(
            x=[x0, x1], y=[y0, y1],
            line=dict(width=line_width, color=color),
            mode='lines',
            hovertemplate=hovertemplate,
            customdata=[customdata],  # Repeated for both points if needed
            showlegend=False
        ))

        # Arrowhead(s) with scaled size
        dx = x1 - x0
        dy = y1 - y0
        length = math.sqrt(dx**2 + dy**2)
        arrow_size = 6 + (line_width / 2)  # Scale arrow size with line width
        if length > 0:
            ux = dx / length
            uy = dy / length
            angle = math.atan2(dy, dx) * 180 / math.pi

            # Arrow near dst
            arrow_pos_x = x1 - ux * 0.1 * length
            arrow_pos_y = y1 - uy * 0.1 * length
            edge_traces.append(go.Scatter(
                x=[arrow_pos_x], y=[arrow_pos_y],
                mode='markers',
                marker=dict(symbol='triangle-up', size=arrow_size, color=color, angle=angle),
                hoverinfo='skip',
                showlegend=False
            ))

            if info['bidir']:
                # Reverse arrow near src
                rev_angle = angle + 180
                rev_arrow_pos_x = x0 + ux * 0.1 * length
                rev_arrow_pos_y = y0 + uy * 0.1 * length
                edge_traces.append(go.Scatter(
                    x=[rev_arrow_pos_x], y=[rev_arrow_pos_y],
                    mode='markers',
                    marker=dict(symbol='triangle-up', size=arrow_size, color=color, angle=rev_angle),
                    hoverinfo='skip',
                    showlegend=False
                ))

    # Node traces with hover (full labels)
    node_x, node_y, node_text, node_size, node_hover = [], [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        total_traffic = sum(d.get('weight', 0) + d.get('rev_weight', 0) for _, _, d in G.edges(node, data=True))
        node_size.append(max(.5, total_traffic / 1e7))  # Less aggressive node scaling to focus on arrows
        node_text.append(node)  # Full label
        node_hover.append(f"Node: {node}<br>Total Traffic: {humanbytes(total_traffic, no_color=True)}")

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=node_text,
        textposition='middle right',  # Shift right for pseudo-padding
        textfont=dict(size=12),  # Smaller font to reduce overlap risk
        marker=dict(size=node_size, color='lightblue', line_width=2),
        hovertemplate="%{text}<extra></extra>",
        #text2=node_hover,  # Use text for hovertemplate
        showlegend=False
    )

    # Figure assembly with smaller canvas
    fig = go.Figure(data=edge_traces + [node_trace],
                    layout=go.Layout(
                        title=dict(
                            text="Network Traffic Flows (Directional & Bidirectional)",
                            font=dict(size=16)
                        ),
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20, l=5, r=5, t=40),
                        annotations=[dict(text="Arrows show direction; thickness = bytes; hover for details", showarrow=False, xref="paper", yref="paper", x=0.005, y=-0.002)],
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        template='plotly_dark',
                        height=700,  # Smaller height
                        width=1000   # Smaller width
                    ))
    fig.update_layout(transition_duration=500)  # Subtle animation
    return fig

def generate_pie_chart(data):
    if not data:
        return px.pie(title="No data available")
    proc_bytes = defaultdict(int)
    for _, (total_bytes, _, proc, _, _, _) in data:
        proc_bytes[proc] += total_bytes
    df = pd.DataFrame(list(proc_bytes.items()), columns=['Process', 'Bytes'])
    fig = px.pie(df, names='Process', values='Bytes', title="Bytes Distribution by Process")
    fig.update_layout(template='plotly_dark')
    return fig

def generate_table(data):
    if not data:
        return html.Div("No data available")
    rows = []
    for (src_ip, src_port, dst_ip, dst_port), (total_bytes, count, proc, pid, fd, proto) in data:
        src_display = "Local_Box_IP" if src_ip in local_ips else src_ip
        dst_display = "Local_Box_IP" if dst_ip in local_ips else dst_ip
        rows.append(html.Tr([
            html.Td(f"{src_display}:{src_port}"),
            html.Td(f"{dst_display}:{dst_port}"),
            html.Td(humanbytes(total_bytes, no_color=True).strip()),
            html.Td(count),
            html.Td(proc),
            html.Td(pid),
            html.Td(fd),
            html.Td(proto)
        ]))
    table = html.Table([
        html.Thead(html.Tr([
            html.Th("Src"), html.Th("Dst"), html.Th("Bytes"), html.Th("Count"),
            html.Th("Proc"), html.Th("PID"), html.Th("FD"), html.Th("Proto")
        ])),
        html.Tbody(rows)
    ], style={'width': '100%', 'overflow': 'auto'})
    return table

# --- Dash App Setup ---

app = dash.Dash(__name__)

app.layout = html.Div(style={'backgroundColor': '#111', 'color': 'white', 'padding': '20px'}, children=[
    html.H1("Network Analyzer Dashboard", style={'textAlign': 'center'}),
    dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0),  # Update every 5s
    dcc.Graph(id='network-graph'),  # Replaced bar-chart with network-graph
    dcc.Graph(id='pie-chart'),
    html.H3("Detailed Table"),
    html.Div(id='table')
])

@app.callback(
    [Output('network-graph', 'figure'),  # Updated to network-graph
     Output('pie-chart', 'figure'),
     Output('table', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_visuals(n):
    with data_lock:
        data = latest_data.copy()  # Safe copy
    return generate_network_graph(data), generate_pie_chart(data), generate_table(data)

def run_dash_server():
    app.run(debug=False, port=8050)

async def main():
    global local_ips
    config = parse_args()
    queue: Deque[str] = deque()
    output_data: Dict[Tuple[str, str, str, str], Tuple[int, int, str, str, str, str]] = defaultdict(lambda: (0, 0, "~", "~", "~", "~"))

    # Prompt for interface
    if config.interface == 'any':
        interface_input = input(f"Enter network interface to sniff (default: {config.interface}): ").strip() or config.interface
    else:
        interface_input = input(f"Enter network interface to sniff (current: {config.interface}): ").strip() or config.interface
    config.interface = interface_input

    # Prompt to confirm/toggle Local_Box_IP replacement (respects -nolocal flag as default)
    local_replacement_input = input(f"Use Local_Box_IP replacement for local IPs? (y/n, default: {'y' if config.use_local_replacement else 'n'}): ").strip().lower()
    if local_replacement_input in ('y', 'n'):
        config.use_local_replacement = local_replacement_input == 'y'

    # Fetch local IPs only if enabled
    if config.use_local_replacement:
        local_ips_cmd = "ip a | grep -i inet | awk '{ print $2 }' | sed 's/.[0-9]*$//g'"
        try:
            local_ips_output = subprocess.check_output(local_ips_cmd, shell=True).decode().strip()
            local_ips = set(local_ips_output.splitlines())
            print(f"Detected local IPs: {', '.join(local_ips)}")
        except Exception as e:
            print(f"Error fetching local IPs: {e}")
            local_ips = set()
    else:
        local_ips = set()  # Empty set disables replacement checks
        print("Local_Box_IP replacement disabled.")

    resolve_flag = '-nn' if not config.resolve_mode else ''
    cmd = (
        f"doas tcpdump -i {config.interface} {resolve_flag} "
        f"not arp and not host 127.0.0.1 and "
        f"not host ::1 -ql > {DUMP_FILE}"
    )

    print(f"\nProposed tcpdump command:\n{cmd}")
    confirm = input("Proceed with this command? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Aborted by user.")
        sys.exit(0)

    print(f"\nInitiating command: {cmd}")
    print(f"Dump file location: {DUMP_FILE}")
    print("Web Dashboard: http://127.0.0.1:8050/ (opens in browser)")

    tcpdump_process = await setup_tcpdump(cmd)
    try:
        # Start Dash in a thread
        dash_thread = threading.Thread(target=run_dash_server, daemon=True)
        dash_thread.start()

        reader = asyncio.create_task(read_dump_file(queue))
        processor = asyncio.create_task(process_queue(queue, output_data))
        reporter = asyncio.create_task(output_report(output_data, config))
        await asyncio.gather(reader, processor, reporter)
    except asyncio.CancelledError:
        print("\nShutting down...")
    except KeyboardInterrupt:
        print("\nProgram terminated by user")
    finally:
        tcpdump_process.terminate()
        await tcpdump_process.wait()
        if os.path.exists(DUMP_FILE):
            os.remove(DUMP_FILE)

if __name__ == '__main__':
    asyncio.run(main())
