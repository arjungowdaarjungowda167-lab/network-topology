# ============================================================
# Project: Automated Network Topology Mapper
# Description: Discovers network devices and visualizes topology
# Technology: Python, Streamlit, NetworkX, Matplotlib
# ============================================================

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

# -------------------- CONFIGURATION --------------------
SCAN_TIMEOUT = 1
MAX_WORKERS = 50

# -------------------- INPUT VALIDATION --------------------
def validate_network(ip_input):
    try:
        return True, ipaddress.IPv4Network(ip_input, strict=False)
    except Exception as e:
        return False, str(e)

# -------------------- DEVICE DISCOVERY --------------------
def check_host_alive(ip):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", param, "1", ip],
            stdout=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_mac_address(ip):
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(f"arp -a {ip}", shell=True, text=True)
        else:
            output = subprocess.check_output(f"arp {ip}", shell=True, text=True)

        match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", output)
        return match.group(0) if match else "Unknown"
    except:
        return "Unknown"

# -------------------- ROUTER DETECTION --------------------
def get_default_gateway():
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output("ipconfig", shell=True, text=True)
            match = re.search(r"Default Gateway.*?:\s([\d.]+)", output)
            return match.group(1) if match else None
        else:
            output = subprocess.check_output("ip route", shell=True, text=True)
            match = re.search(r"default via ([\d.]+)", output)
            return match.group(1) if match else None
    except:
        return None

# -------------------- SINGLE HOST SCAN --------------------
def scan_host(ip, gateway_ip):

    ip = str(ip)

    if not check_host_alive(ip):
        return None

    return {
        "IP Address": ip,
        "Hostname": resolve_hostname(ip),
        "MAC Address": get_mac_address(ip),
        "Device Type": "Router" if ip == gateway_ip else "Host",
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# -------------------- NETWORK SCAN --------------------
def scan_network(network, progress_bar):

    devices = []
    gateway_ip = get_default_gateway()

    hosts = list(network.hosts())
    total = len(hosts)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        futures = {
            executor.submit(scan_host, ip, gateway_ip): ip
            for ip in hosts
        }

        completed = 0
        for future in as_completed(futures):

            completed += 1
            progress_bar.progress(completed / total)

            result = future.result()
            if result:
                devices.append(result)

    return devices, gateway_ip

# -------------------- TOPOLOGY CREATION --------------------
def build_topology(devices, gateway_ip):

    graph = nx.Graph()

    if gateway_ip:
        graph.add_node(gateway_ip, type="Router")

    for device in devices:

        ip = device["IP Address"]
        graph.add_node(ip, type=device["Device Type"])

        if gateway_ip and ip != gateway_ip:
            graph.add_edge(gateway_ip, ip)

    return graph

# -------------------- TOPOLOGY VISUALIZATION --------------------
def draw_topology(graph):

    plt.figure(figsize=(10, 7))
    pos = nx.spring_layout(graph)

    colors = [
        "red" if graph.nodes[n].get("type") == "Router"
        else "skyblue"
        for n in graph.nodes
    ]

    nx.draw(graph, pos, with_labels=True,
            node_color=colors,
            node_size=2000,
            font_size=8)

    st.pyplot(plt)

# ============================================================
# STREAMLIT USER INTERFACE
# ============================================================

st.set_page_config(
    page_title="Automated Network Topology Mapper",
    layout="wide"
)

st.title("🌐 Automated Network Topology Mapper")
st.write("Discovers network devices and maps logical topology automatically")

# -------------------- USER INPUT --------------------
ip_input = st.text_input(
    "Enter Network Range (CIDR)",
    placeholder="Example: 192.168.1.0/24"
)

scan_btn = st.button("Start Scan")

# -------------------- EXECUTION --------------------
if scan_btn:

    if not ip_input:
        st.error("Please enter network range")
    else:

        valid, result = validate_network(ip_input)

        if not valid:
            st.error(result)

        else:

            network = result

            st.info("Scanning Network...")
            progress_bar = st.progress(0)

            devices, gateway_ip = scan_network(network, progress_bar)

            progress_bar.empty()

            # -------------------- RESULTS --------------------
            if devices:

                df = pd.DataFrame(devices)

                st.subheader("📊 Discovered Devices")
                st.dataframe(df, use_container_width=True)

                st.subheader("🗺 Network Topology Map")
                graph = build_topology(devices, gateway_ip)
                draw_topology(graph)

                # Download Option
                csv = df.to_csv(index=False)
                st.download_button(
                    "Download Report",
                    csv,
                    "topology_report.csv",
                    "text/csv"
                )

            else:
                st.warning("No active devices found")

# -------------------- FOOTER --------------------
st.markdown("---")
st.caption("Automated Network Topology Mapper | Academic Project")
