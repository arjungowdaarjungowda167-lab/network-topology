# ==========================================================
# Project: Automated Network Topology Mapper
# ==========================================================

import streamlit as st
import socket
import ipaddress
import platform
import subprocess
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

# ----------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------

COMMON_PORTS = [21, 22, 23, 53, 80, 443, 445, 3389, 8080, 8443]

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP Alt",
    8443: "HTTPS Alt"
}

# ----------------------------------------------------------
# NETWORK SCANNER CLASS
# ----------------------------------------------------------

class NetworkTopologyMapper:

    @staticmethod
    def validate_network(ip_input):
        try:
            net = ipaddress.IPv4Network(ip_input, strict=False)
            return True, net
        except Exception as e:
            return False, f"Invalid Network: {e}"

    @staticmethod
    def ping_host(ip):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", param, "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1
            )
            return result.returncode == 0
        except:
            return False

    @staticmethod
    def get_hostname(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"

    @staticmethod
    def get_mac(ip):
        try:
            cmd = ["arp", "-a", ip] if platform.system().lower() == "windows" else ["arp", "-n", ip]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
            match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", result.stdout)
            return match.group(0).upper() if match else "Not Available"
        except:
            return "Not Available"

    @staticmethod
    def get_gateway():
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output("ipconfig", shell=True, text=True)
                match = re.search(r"Default Gateway.*?:\s([\d.]+)", output)
                return match.group(1)
            else:
                output = subprocess.check_output("ip route", shell=True, text=True)
                match = re.search(r"default via ([\d.]+)", output)
                return match.group(1)
        except:
            return None

    @staticmethod
    def scan_ports(ip):
        open_ports = []
        for port in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(f"{port} ({PORT_SERVICES.get(port,'Unknown')})")
                sock.close()
            except:
                pass
        return ", ".join(open_ports) if open_ports else "None"

    @staticmethod
    def scan_device(ip):
        if not NetworkTopologyMapper.ping_host(ip):
            return None
        return {
            "IP Address": ip,
            "Hostname": NetworkTopologyMapper.get_hostname(ip),
            "MAC Address": NetworkTopologyMapper.get_mac(ip),
            "Open Ports": NetworkTopologyMapper.scan_ports(ip),
            "Scan Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    @staticmethod
    def scan_network(network, progress_bar, status_text):
        devices = []
        hosts = list(network.hosts())
        total = len(hosts)

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(NetworkTopologyMapper.scan_device, str(ip)) for ip in hosts]

            for i, future in enumerate(as_completed(futures), 1):
                progress_bar.progress(i / total)
                status_text.text(f"Scanning {i}/{total}")
                result = future.result()
                if result:
                    devices.append(result)

        return devices


# ----------------------------------------------------------
# STREAMLIT UI
# ----------------------------------------------------------

st.set_page_config(
    page_title="Automated Network Topology Mapper",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# custom CSS for a more polished look
st.markdown(
    """
    <style>
    /* change background of main content area */
    .reportview-container .main {
        background-color: #f0f2f6;
    }
    /* card-like styling for markdown sections */
    .stMarkdown {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    /* style dataframe header */
    .stDataFrame table {
        border-collapse: collapse;
    }
    .stDataFrame th {
        background-color: #1f77b4;
        color: white;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --- header ---
cols = st.columns([1, 3, 1])
with cols[1]:
    st.image("https://raw.githubusercontent.com/streamlit/brand/master/streamlit-mark-color.png", width=60)
    st.title("Automated Network Topology Mapper")
    st.markdown("<small>Discover and visualise your network effortlessly.</small>", unsafe_allow_html=True)

st.markdown("---")

# --- sidebar inputs ---
with st.sidebar:
    st.header("Scan Settings")
    ip_input = st.text_input("Network (CIDR)", value="192.168.1.0/24", help="e.g. 192.168.0.0/24")
    scan_btn = st.button("🔍 Start Scan")
    st.markdown("---")
    st.caption("© 2026 Network Tools Inc.")

# default session state
if "devices" not in st.session_state:
    st.session_state.devices = []

if "devices" not in st.session_state:
    st.session_state.devices = []

if scan_btn:
    valid, net = NetworkTopologyMapper.validate_network(ip_input)

    if not valid:
        st.error(net)
    else:
        # perform scan with spinner and progress updates
        with st.spinner("Scanning network, please wait..."):
            bar = st.progress(0)
            txt = st.empty()
            st.session_state.devices = NetworkTopologyMapper.scan_network(net, bar, txt)
            bar.empty()
            txt.empty()
        st.success(f"Scan complete: {len(st.session_state.devices)} devices found")

# ----------------------------------------------------------
# DISPLAY RESULTS
# ----------------------------------------------------------

if st.session_state.devices:

    df = pd.DataFrame(st.session_state.devices)

    # top metrics
    mcols = st.columns([1,1,1])
    mcols[0].metric("Total Devices", len(df))
    mcols[1].metric("Network", ip_input)
    mcols[2].metric("Scan Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    st.markdown("---")

    # table with download
    st.subheader("Discovered Devices")
    st.dataframe(df, use_container_width=True)
    st.download_button(
        "⬇ Download CSV Report",
        df.to_csv(index=False),
        "network_topology_report.csv",
        "text/csv",
        key="download"
    )

    st.markdown("---")

    # topology graph
    st.subheader("Network Topology Map")
    gateway = NetworkTopologyMapper.get_gateway()
    G = nx.Graph()
    if gateway:
        G.add_node(gateway, role="Router")
    for device in st.session_state.devices:
        ip = device["IP Address"]
        G.add_node(ip, role="Host")
        if gateway:
            G.add_edge(gateway, ip)
    plt.figure(figsize=(10, 6))
    pos = nx.spring_layout(G)
    colors = [
        "red" if G.nodes[n].get("role") == "Router"
        else "skyblue"
        for n in G.nodes
    ]
    nx.draw(G, pos,
            with_labels=True,
            node_color=colors,
            node_size=2000,
            font_size=8)
    st.pyplot(plt)

    st.markdown("---")

    # device details expanders
    st.subheader("Device Details")
    for device in st.session_state.devices:
        with st.expander(f"{device['IP Address']} ({device['Hostname']})"):
            st.write(f"**MAC Address:** {device['MAC Address']}")
            st.write(f"**Open Ports:** {device['Open Ports']}")
            st.write(f"**Scan Time:** {device['Scan Time']}")

st.caption("Academic Project – Automated Network Topology Mapper")
