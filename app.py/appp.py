# ============================================================
# Project: Automated Network Topology Mapper
# ============================================================

import streamlit as st
import socket
import ipaddress
import platform
import subprocess
import re
from datetime import datetime
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

# -------------------- CONFIG --------------------
MAX_HOSTS = 256

# -------------------- VALIDATION --------------------
def validate_network(ip_input):
    try:
        net = ipaddress.IPv4Network(ip_input, strict=False)
        return True, net
    except Exception as e:
        return False, str(e)

# -------------------- NETWORK UTILITIES --------------------
def ping_host(ip):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", param, "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except:
        return "Unknown"

def get_mac(ip):
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output(f"arp -a {ip}", shell=True, text=True)
        else:
            out = subprocess.check_output(f"arp {ip}", shell=True, text=True)

        match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", out)
        return match.group(0) if match else "Unknown"
    except:
        return "Unknown"

def get_gateway():
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output("ipconfig", shell=True, text=True)
            match = re.search(r"Default Gateway.*?:\s([\d.]+)", out)
            return match.group(1)
        else:
            out = subprocess.check_output("ip route", shell=True, text=True)
            match = re.search(r"default via ([\d.]+)", out)
            return match.group(1)
    except:
        return None

# -------------------- SCANNING --------------------
def scan_network(network, progress):
    devices = []
    gateway = get_gateway()
    hosts = list(network.hosts())[:MAX_HOSTS]
    total = len(hosts)

    for i, ip in enumerate(hosts):
        progress.progress((i + 1) / total)

        if ping_host(ip):
            devices.append({
                "IP Address": str(ip),
                "Hostname": get_hostname(ip),
                "MAC Address": get_mac(ip),
                "Device Type": "Router" if str(ip) == gateway else "Host",
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

    return devices, gateway

# -------------------- TOPOLOGY --------------------
def build_graph(devices, gateway):
    G = nx.Graph()

    if gateway:
        G.add_node(gateway, role="Router")

    for d in devices:
        ip = d["IP Address"]
        G.add_node(ip, role=d["Device Type"])
        if gateway and ip != gateway:
            G.add_edge(gateway, ip)

    return G

def draw_graph(G):
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

# ============================================================
# STREAMLIT UI
# ============================================================

st.set_page_config(
    page_title="Automated Network Topology Mapper",
    layout="wide"
)

st.title("🌐 Automated Network Topology Mapper")
st.write("Automatically discovers network devices and visualizes topology")

ip_input = st.text_input(
    "Enter Network Range (CIDR)",
    placeholder="Example: 192.168.1.0/24"
)

if st.button("Start Scan"):

    valid, result = validate_network(ip_input)

    if not valid:
        st.error(result)
    else:
        network = result
        st.info("Scanning network...")
        progress = st.progress(0)

        devices, gateway = scan_network(network, progress)
        progress.empty()

        if devices:
            df = pd.DataFrame(devices)

            st.subheader("📊 Discovered Devices")
            st.dataframe(df, use_container_width=True)

            st.subheader("🗺 Network Topology")
            graph = build_graph(devices, gateway)
            draw_graph(graph)

            st.download_button(
                "Download CSV Report",
                df.to_csv(index=False),
                "network_topology_report.csv",
                "text/csv"
            )
        else:
            st.warning("No active devices found")

st.markdown("---")
st.caption("Automated Network Topology Mapper | Academic Project")
