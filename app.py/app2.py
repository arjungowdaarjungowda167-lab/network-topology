# ============================================================
# Project: Automated Network Topology Mapper (v2 - Enhanced)
# Description: Discovers network devices and visualizes topology
# Technology: Python, Streamlit, NetworkX, Matplotlib
#
# FIXES & IMPROVEMENTS over v1:
#   - Added subprocess timeout to prevent ping hangs
#   - Fixed ARP race condition (ping-first → then ARP)
#   - Added TCP port scanning for ICMP-blocked hosts
#   - Added common-port service fingerprinting
#   - Resolved hostname via socket with enforced timeout
#   - Topology now differentiates switches/printers/unknown
#   - Robust error handling for permission errors
#   - Live device table updates during scan
#   - Color-coded topology by device type
#   - Summary metrics dashboard
# ============================================================

import streamlit as st
import socket
import ipaddress
import platform
import subprocess
import re
import concurrent.futures
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
SCAN_TIMEOUT   = 1       # seconds per ping / port probe
MAX_WORKERS    = 100     # concurrent threads
COMMON_PORTS   = [22, 23, 80, 443, 8080, 8443, 445, 139, 3389, 21]

# ─────────────────────────────────────────────
# INPUT VALIDATION
# ─────────────────────────────────────────────
def validate_network(ip_input: str):
    """Returns (True, IPv4Network) or (False, error_string)."""
    try:
        net = ipaddress.IPv4Network(ip_input.strip(), strict=False)
        if net.num_addresses > 1024:
            return False, "Network too large (max /22 = 1022 hosts). Use a smaller CIDR."
        return True, net
    except Exception as exc:
        return False, str(exc)

# ─────────────────────────────────────────────
# HOST ALIVE — ping with timeout (FIX #1)
# ─────────────────────────────────────────────
def ping_host(ip: str) -> bool:
    """Returns True if the host responds to ICMP ping."""
    try:
        param = ["-n", "1", "-w", "1000"] if platform.system().lower() == "windows" \
                else ["-c", "1", "-W", "1"]
        result = subprocess.run(
            ["ping"] + param + [ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SCAN_TIMEOUT + 1      # FIX #1: hard timeout prevents hangs
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return False

# ─────────────────────────────────────────────
# TCP PORT PROBE — catches ICMP-blocked hosts (FIX #3)
# ─────────────────────────────────────────────
def tcp_probe(ip: str) -> tuple[bool, list[int]]:
    """
    Probes common TCP ports.
    Returns (is_alive, [open_ports]).
    A host that blocks ping may still respond on TCP.
    """
    open_ports = []
    for port in COMMON_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SCAN_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except (socket.error, OSError):
            pass
    return bool(open_ports), open_ports

# ─────────────────────────────────────────────
# SERVICE FINGERPRINTING from open ports (NEW)
# ─────────────────────────────────────────────
PORT_SERVICE_MAP = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    80:   "HTTP",
    139:  "SMB",
    443:  "HTTPS",
    445:  "SMB",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

def fingerprint_services(open_ports: list[int]) -> str:
    services = [PORT_SERVICE_MAP.get(p, str(p)) for p in open_ports]
    return ", ".join(services) if services else "—"

# ─────────────────────────────────────────────
# HOSTNAME RESOLUTION — with timeout (FIX #7)
# ─────────────────────────────────────────────
def resolve_hostname(ip: str) -> str:
    """Resolves PTR record; enforces a hard timeout via a thread."""
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            return fut.result(timeout=2)[0]   # FIX #7: 2 s cap
    except Exception:
        return "Unknown"

# ─────────────────────────────────────────────
# MAC ADDRESS — only after confirmed alive (FIX #2)
# ─────────────────────────────────────────────
def get_mac_address(ip: str) -> str:
    """
    Reads ARP cache AFTER we know the host is alive.
    Avoids the v1 race condition where ARP had not populated yet.
    """
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(
                ["arp", "-a", ip], text=True, timeout=3
            )
        else:
            output = subprocess.check_output(
                ["arp", ip], text=True, timeout=3
            )
        match = re.search(r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", output)
        return match.group(0) if match else "Unknown"
    except Exception:
        return "Unknown"

# ─────────────────────────────────────────────
# DEVICE TYPE INFERENCE (NEW)
# ─────────────────────────────────────────────
def infer_device_type(ip: str, gateway_ip: str | None, open_ports: list[int]) -> str:
    if ip == gateway_ip:
        return "Router / Gateway"
    if 3389 in open_ports:
        return "Windows PC"
    if 22 in open_ports and 80 not in open_ports:
        return "Linux / Server"
    if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
        return "Web Server / IoT"
    if 445 in open_ports or 139 in open_ports:
        return "File Server / NAS"
    if 23 in open_ports:
        return "Switch / AP (Telnet)"
    return "Host"

# ─────────────────────────────────────────────
# DEFAULT GATEWAY
# ─────────────────────────────────────────────
def get_default_gateway() -> str | None:
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output("ipconfig", shell=True, text=True, timeout=5)
            match = re.search(r"Default Gateway.*?:\s*([\d.]+)", output)
        else:
            output = subprocess.check_output(["ip", "route"], text=True, timeout=5)
            match = re.search(r"default via ([\d.]+)", output)
        return match.group(1) if match else None
    except Exception:
        return None

# ─────────────────────────────────────────────
# SINGLE HOST SCAN  (combines ping + tcp)
# ─────────────────────────────────────────────
def scan_host(ip: str, gateway_ip: str | None) -> dict | None:
    ip = str(ip)

    # Step 1 — ICMP ping
    alive = ping_host(ip)

    # Step 2 — TCP fallback for ICMP-blocked hosts (FIX #3)
    if not alive:
        alive, open_ports = tcp_probe(ip)
        if not alive:
            return None
    else:
        _, open_ports = tcp_probe(ip)   # still gather port info

    # Step 3 — resolve metadata now that host is confirmed alive
    hostname   = resolve_hostname(ip)
    mac        = get_mac_address(ip)
    dev_type   = infer_device_type(ip, gateway_ip, open_ports)
    services   = fingerprint_services(open_ports)

    return {
        "IP Address":   ip,
        "Hostname":     hostname,
        "MAC Address":  mac,
        "Device Type":  dev_type,
        "Open Ports":   ", ".join(str(p) for p in open_ports) if open_ports else "—",
        "Services":     services,
        "Timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

# ─────────────────────────────────────────────
# NETWORK SCAN — parallel with live progress
# ─────────────────────────────────────────────
def scan_network(network, progress_bar, status_text, live_placeholder):
    devices    = []
    gateway_ip = get_default_gateway()
    hosts      = list(network.hosts())
    total      = len(hosts)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(scan_host, ip, gateway_ip): ip for ip in hosts}

        completed = 0
        for future in as_completed(futures):
            completed += 1
            progress_bar.progress(completed / total)
            status_text.text(f"Probing… {completed}/{total} hosts | Found: {len(devices)} active")

            result = future.result()
            if result:
                devices.append(result)
                # live table refresh
                live_placeholder.dataframe(
                    pd.DataFrame(devices).sort_values("IP Address"),
                    use_container_width=True
                )

    return devices, gateway_ip

# ─────────────────────────────────────────────
# TOPOLOGY GRAPH BUILDER
# ─────────────────────────────────────────────
def build_topology(devices: list[dict], gateway_ip: str | None) -> nx.Graph:
    G = nx.Graph()
    if gateway_ip:
        G.add_node(gateway_ip, type="Router / Gateway")

    for d in devices:
        ip = d["IP Address"]
        G.add_node(ip, type=d["Device Type"])
        if gateway_ip and ip != gateway_ip:
            G.add_edge(gateway_ip, ip)

    return G

# ─────────────────────────────────────────────
# TOPOLOGY VISUALIZATION — color-coded by type
# ─────────────────────────────────────────────
TYPE_COLORS = {
    "Router / Gateway":    "#EF4444",   # red
    "Windows PC":          "#3B82F6",   # blue
    "Linux / Server":      "#8B5CF6",   # purple
    "Web Server / IoT":    "#F59E0B",   # amber
    "File Server / NAS":   "#10B981",   # emerald
    "Switch / AP (Telnet)":"#EC4899",   # pink
    "Host":                "#60A5FA",   # light blue
}

def draw_topology(G: nx.Graph):
    if G.number_of_nodes() == 0:
        st.info("No nodes to display.")
        return

    fig, ax = plt.subplots(figsize=(14, 9))
    fig.patch.set_facecolor("#0F172A")
    ax.set_facecolor("#0F172A")

    # Layout: shell puts gateway in center if present
    try:
        pos = nx.spring_layout(G, seed=42, k=2.5)
    except Exception:
        pos = nx.random_layout(G)

    colors = [TYPE_COLORS.get(G.nodes[n].get("type", "Host"), "#60A5FA") for n in G.nodes]
    sizes  = [3500 if G.nodes[n].get("type") == "Router / Gateway" else 1800 for n in G.nodes]

    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#334155", width=1.5, alpha=0.7)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=colors, node_size=sizes, alpha=0.95)
    nx.draw_networkx_labels(G, pos, ax=ax, font_color="white", font_size=7, font_weight="bold")

    # Legend
    legend_handles = [
        mpatches.Patch(color=c, label=t)
        for t, c in TYPE_COLORS.items()
        if t in nx.get_node_attributes(G, "type").values()
    ]
    ax.legend(handles=legend_handles, loc="upper left",
              facecolor="#1E293B", edgecolor="#334155",
              labelcolor="white", fontsize=8)

    ax.axis("off")
    plt.tight_layout()
    st.pyplot(fig)
    plt.close(fig)

# ─────────────────────────────────────────────
# SUMMARY METRICS
# ─────────────────────────────────────────────
def show_metrics(devices: list[dict], gateway_ip: str | None):
    df = pd.DataFrame(devices)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🖥️ Total Active", len(devices))
    col2.metric("🌐 Gateway", gateway_ip or "Not detected")
    col3.metric("🔓 Open Port Hosts",
                int((df["Open Ports"] != "—").sum()))
    col4.metric("🔎 Device Types",
                df["Device Type"].nunique())

# ════════════════════════════════════════════════════════════
# STREAMLIT UI
# ════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="Network Topology Mapper",
    page_icon="🌐",
    layout="wide"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Sora:wght@400;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Sora', sans-serif;
        background-color: #0F172A;
        color: #E2E8F0;
    }
    .stButton > button {
        background: linear-gradient(135deg, #3B82F6, #8B5CF6);
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 0.5rem 2rem;
        transition: opacity 0.2s;
    }
    .stButton > button:hover { opacity: 0.85; }
    .stTextInput > div > div > input {
        background: #1E293B;
        border: 1px solid #334155;
        border-radius: 8px;
        color: #E2E8F0;
        font-family: 'JetBrains Mono', monospace;
    }
    [data-testid="metric-container"] {
        background: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 1rem;
    }
    .stDataFrame { border-radius: 10px; overflow: hidden; }
    .stAlert { border-radius: 8px; }
</style>
""", unsafe_allow_html=True)

# ── Header ──────────────────────────────────
st.markdown("""
<div style="text-align:center; padding: 1.5rem 0 0.5rem">
    <h1 style="font-family:'Sora',sans-serif; font-size:2.2rem; font-weight:700;
               background:linear-gradient(90deg,#3B82F6,#8B5CF6,#EC4899);
               -webkit-background-clip:text; -webkit-text-fill-color:transparent;">
        🌐 Network Topology Mapper
    </h1>
    <p style="color:#94A3B8; font-size:0.95rem; margin-top:-0.4rem;">
        Discovers active devices via ICMP + TCP probing &amp; visualizes your network topology
    </p>
</div>
""", unsafe_allow_html=True)

st.divider()

# ── Sidebar: help & config ───────────────────
with st.sidebar:
    st.markdown("### ⚙️ Scan Configuration")
    custom_timeout = st.slider("Probe Timeout (s)", 0.5, 3.0, float(SCAN_TIMEOUT), 0.5)
    custom_workers = st.slider("Max Threads", 10, 200, MAX_WORKERS, 10)
    st.markdown("---")
    st.markdown("""
**Detection Methods**
- ✅ ICMP Ping
- ✅ TCP Port Scan (fallback)
- ✅ ARP MAC lookup
- ✅ PTR hostname resolution
- ✅ Service fingerprinting

**Color Legend**
🔴 Router / Gateway  
🔵 Windows PC  
🟣 Linux / Server  
🟡 Web Server / IoT  
🟢 File Server / NAS  
🩷 Switch / AP  
💙 Unknown Host  
""")
    st.caption("v2.0 — Enhanced Edition")

SCAN_TIMEOUT = custom_timeout
MAX_WORKERS  = custom_workers

# ── Main Input ──────────────────────────────
col_input, col_btn = st.columns([3, 1])
with col_input:
    ip_input = st.text_input(
        "Network Range (CIDR)",
        placeholder="e.g. 192.168.1.0/24",
        label_visibility="collapsed"
    )
with col_btn:
    scan_btn = st.button("🔍 Start Scan", use_container_width=True)

# ── Execution ───────────────────────────────
if scan_btn:
    if not ip_input:
        st.error("⚠️ Please enter a network range (e.g. 192.168.1.0/24)")
    else:
        valid, result = validate_network(ip_input)
        if not valid:
            st.error(f"❌ Invalid network: {result}")
        else:
            network = result
            host_count = network.num_addresses - 2

            st.info(f"🔍 Scanning **{network}** — up to **{host_count}** hosts using ICMP + TCP probing…")

            progress_bar   = st.progress(0)
            status_text    = st.empty()
            live_placeholder = st.empty()

            try:
                devices, gateway_ip = scan_network(
                    network, progress_bar, status_text, live_placeholder
                )
            except PermissionError:
                st.error("❌ Permission denied. Try running with elevated privileges (sudo).")
                st.stop()

            progress_bar.empty()
            status_text.empty()
            live_placeholder.empty()

            # ── Results ──────────────────────────────
            if devices:
                df = pd.DataFrame(devices).sort_values("IP Address").reset_index(drop=True)

                st.success(f"✅ Scan complete — **{len(devices)} active device(s)** found on {network}")
                show_metrics(devices, gateway_ip)

                st.markdown("### 📊 Discovered Devices")
                st.dataframe(
                    df.style.apply(
                        lambda col: [
                            "background-color: #1E3A5F" if v == "Router / Gateway"
                            else "background-color: #1E293B"
                            for v in col
                        ] if col.name == "Device Type" else [""] * len(col),
                        axis=0
                    ),
                    use_container_width=True,
                    height=min(400, 45 + 35 * len(df))
                )

                st.markdown("### 🗺️ Network Topology Map")
                graph = build_topology(devices, gateway_ip)
                draw_topology(graph)

                # ── Download ─────────────────────────
                st.divider()
                csv = df.to_csv(index=False)
                st.download_button(
                    label="⬇️ Download Report (CSV)",
                    data=csv,
                    file_name=f"topology_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

            else:
                st.warning("⚠️ No active devices found. Check the network range or your permissions.")

# ── Footer ──────────────────────────────────
st.markdown("---")
st.caption("🌐 Network Topology Mapper v2.0 | ICMP + TCP dual-probe engine")
import streamlit as st

st.set_page_config(
    page_title="Automated Network Topology Mapper",
    layout="wide",
    initial_sidebar_state="expanded"
)

