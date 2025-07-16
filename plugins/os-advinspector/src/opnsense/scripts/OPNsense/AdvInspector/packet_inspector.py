#!/usr/local/bin/python3

import pcapy
import ipaddress
import struct
import signal
import sys
import socket
import json
import subprocess
import threading
import time
from collections import defaultdict
from rule_engine import evaluate_packet
from logger import log_alert, log_packet
from settings_loader import (
    load_inspection_mode,
    load_enabled,
    load_promiscuous_mode,
    load_interfaces,
    load_home_networks,
    load_verbosity,
    load_ips_mode,
)

# Costanti
SOCKET_PATH = "/var/run/netzones.sock"
PF_ANCHOR_PATH = "/usr/local/etc/ips_block.conf"
PF_ANCHOR_NAME = "ips_block"
RULES_FILE = "/usr/local/etc/advinspector/rules.json"

# Tabelle per futuri usi (rate limiting, counter)
rate_table = defaultdict(list)
alert_count = defaultdict(int)
block_count = defaultdict(int)

# Thread safety
packet_lock = threading.Lock()
running = True

def signal_handler(signum, frame):
    global running
    running = False
    print("\n[*] Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def should_log(level):
    levels = ["default", "v", "vv", "vvv", "vvvv", "vvvvv"]
    try:
        current_level = load_verbosity()
        return levels.index(current_level) >= levels.index(level)
    except Exception:
        return False


def get_protocol_info(port, ip_protocol):
    """
    Get protocol information with both layer 4 and application layer info
    Returns: (base_protocol, application_protocol, port)
    """
    # Base protocol from IP header
    if ip_protocol == 6:
        base_protocol = "tcp"
    elif ip_protocol == 17:
        base_protocol = "udp"
    elif ip_protocol == 1:
        base_protocol = "icmp"
    else:
        base_protocol = "other"
    
    # Application protocol mapping (only for well-known ports)
    app_protocol_map = {
        # Standard protocols
        80: "http",
        443: "https", 
        22: "ssh",
        21: "ftp",
        53: "dns",
        67: "dhcp",
        68: "dhcp",
        
        # Industrial protocols
        502: "modbus_tcp",
        4840: "opcua",
        1883: "mqtt",
        8883: "mqtt",
        47808: "bacnet",
        20000: "dnp3",
        102: "s7comm",
        2404: "iec104",
        34962: "profinet",
        34963: "profinet", 
        34964: "profinet"
    }
    
    # For NetZones, use the base protocol (tcp/udp/icmp)
    # This avoids confusion in policy evaluation
    application_protocol = app_protocol_map.get(port, base_protocol)
    
    return base_protocol, application_protocol, port


def ip_in_networks(ip, networks):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in ipaddress.ip_network(net, strict=False) for net in networks)
    except ValueError:
        return False


def parse_ipv4_packet(pkt_data):
    """Parsing più robusto dei pacchetti IPv4"""
    if len(pkt_data) < 34:
        return None

    # Verifica tipo Ethernet
    eth_proto = struct.unpack('!H', pkt_data[12:14])[0]
    if eth_proto != 0x0800:  # IPv4
        return None

    # Header IP - gestisce lunghezza variabile
    ip_header_start = 14
    version_ihl = pkt_data[ip_header_start]
    version = (version_ihl >> 4) & 0xF
    if version != 4:
        return None
    
    ihl = (version_ihl & 0xF) * 4  # Lunghezza header IP in bytes
    if len(pkt_data) < ip_header_start + ihl + 4:
        return None

    # Estrai header IP
    ip_header = pkt_data[ip_header_start:ip_header_start + ihl]
    if len(ip_header) < 20:
        return None

    iph = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])
    ip_protocol = iph[6]  # Protocol field from IP header
    src_ip = ipaddress.ip_address(iph[8])
    dst_ip = ipaddress.ip_address(iph[9])

    # Header trasporto
    transport_start = ip_header_start + ihl
    if len(pkt_data) < transport_start + 4:
        return None

    transport_header = pkt_data[transport_start:transport_start + 4]
    
    if ip_protocol in (6, 17):  # TCP o UDP
        src_port, dst_port = struct.unpack('!HH', transport_header)
    else:
        # Per altri protocolli, usa porta 0
        src_port = dst_port = 0

    # Get protocol information
    base_protocol, app_protocol, port = get_protocol_info(dst_port, ip_protocol)

    return {
        "src": str(src_ip),
        "dst": str(dst_ip),
        "src_port": src_port,
        "dst_port": dst_port,
        "port": dst_port,  # Destination port
        "protocol": base_protocol,  # Use base protocol for NetZones (tcp/udp/icmp)
        "application_protocol": app_protocol,  # Application layer protocol for logging
        "ip_protocol": ip_protocol,  # IP protocol number
        "protocol_info": {
            "base": base_protocol,
            "application": app_protocol,
            "ip_protocol_num": ip_protocol
        }
    }


def block_with_pf(src, dst, port):
    """Blocco con PF migliorato"""
    rule = f"block in quick from {src} to {dst} port = {port}\n"
    try:
        with open(PF_ANCHOR_PATH, "a") as f:
            f.write(rule)
        result = subprocess.run(
            ["pfctl", "-a", PF_ANCHOR_NAME, "-f", PF_ANCHOR_PATH], 
            check=True, capture_output=True, text=True
        )
        if should_log("vv"):
            print(f"[+] Blocked via pf: {src} → {dst}:{port}")
        with packet_lock:
            block_count[f"{src}->{dst}:{port}"] += 1
    except subprocess.CalledProcessError as e:
        if should_log("v"):
            print(f"[!] pf block failed: {e.stderr}")
    except Exception as e:
        if should_log("v"):
            print(f"[!] pf block failed: {e}")


def query_netzones_decision(packet):
    """Query netzones con protocollo corretto"""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)  # Timeout di 5 secondi
            s.connect(SOCKET_PATH)
            
            # Send the base protocol (tcp/udp/icmp) to NetZones
            # This ensures consistent policy evaluation
            query = {
                "src": packet["src"],
                "dst": packet["dst"],
                "port": packet["port"],
                "protocol": packet["protocol"],  # Base protocol (tcp/udp/icmp)
                # Include additional context for logging/analysis
                "meta": {
                    "application_protocol": packet.get("application_protocol", ""),
                    "ip_protocol": packet.get("ip_protocol", 0),
                    "interface": packet.get("interface", "unknown")
                }
            }
            
            s.sendall(json.dumps(query).encode())
            response_data = s.recv(4096)
            
            if response_data:
                response = json.loads(response_data.decode())
                if should_log("vvv"):
                    app_proto = packet.get("application_protocol", "")
                    if app_proto != packet["protocol"]:
                        print(f"[+] Netzones decision for {packet['protocol']}:{packet['port']} ({app_proto}): {response.get('decision', 'unknown')}")
                    else:
                        print(f"[+] Netzones decision for {packet['protocol']}:{packet['port']}: {response.get('decision', 'unknown')}")
                return response
            
    except socket.timeout:
        if should_log("v"):
            print("[!] Netzones query timeout")
    except FileNotFoundError:
        if should_log("v"):
            print("[!] Netzones socket not found")
    except Exception as e:
        if should_log("v"):
            print(f"[!] Netzones query failed: {e}")
    
    return None


def inspect_packet(packet, interface):
    """Ispezione pacchetto con integrazione netzones migliorata"""
    packet["interface"] = interface

    if not load_enabled():
        return "disabled"

    homenets = load_home_networks()
    if homenets and not ip_in_networks(packet.get("src", ""), homenets):
        if should_log("vvv"):
            print(f"[-] Skipped packet from {packet['src']} not in homenet")
        return "homenet_skipped"

    # Valutazione regole locali
    local_action = evaluate_packet(packet)
    
    # Query netzones per decisione basata su zone
    netzones_response = query_netzones_decision(packet)
    netzones_decision = None
    if netzones_response:
        netzones_decision = netzones_response.get("decision", "allow")

    # Logica di decisione combinata
    final_action = local_action
    if netzones_decision == "deny" or netzones_decision == "block":
        final_action = "block"
    elif netzones_decision == "allow" and local_action == "block":
        # Netzones permette ma regole locali bloccano
        final_action = "alert"  # Degradare a alert per evitare falsi positivi

    mode = load_inspection_mode()
    
    # Enhanced logging with protocol details
    protocol_desc = packet["protocol"]
    if packet.get("application_protocol") and packet["application_protocol"] != packet["protocol"]:
        protocol_desc = f"{packet['protocol']}:{packet['port']} ({packet['application_protocol']})"

    if final_action == "block":
        log_packet(packet, reason=f"Rule matched — {protocol_desc} blocked (local: {local_action}, netzones: {netzones_decision})")
        log_alert(packet, reason=f"Rule matched: action=block for {protocol_desc} (local: {local_action}, netzones: {netzones_decision})")
        
        if load_ips_mode() and mode in ["stateful", "both"]:
            block_with_pf(packet["src"], packet["dst"], packet["port"])
        return "blocked"
        
    elif final_action == "alert":
        log_packet(packet, reason=f"Rule matched — {protocol_desc} alert only (local: {local_action}, netzones: {netzones_decision})")
        log_alert(packet, reason=f"Rule matched: action=alert for {protocol_desc} (local: {local_action}, netzones: {netzones_decision})")
        
        with packet_lock:
            alert_count[f"{packet['src']}->{packet['dst']}:{packet['port']}"] += 1
    else:
        log_packet(packet, reason=f"No rules matched — {protocol_desc} allowed (local: {local_action}, netzones: {netzones_decision})")
        if should_log("vvv"):
            print(f"[~] Allowed: {packet['src']} → {packet['dst']}:{packet['port']} ({protocol_desc})")

    return "inspected"


def sniff_interface(interface):
    """Sniffing per singola interfaccia (thread-safe)"""
    promisc = load_promiscuous_mode()
    
    try:
        cap = pcapy.open_live(interface, 65536, promisc, 100)
        if should_log("v"):
            print(f"[*] Started sniffing on {interface} (promisc={promisc})")

        def handler(header, data):
            if not running:
                return
            
            pkt = parse_ipv4_packet(data)
            if pkt:
                pkt["raw"] = data.hex()
                pkt["timestamp"] = time.time()
                inspect_packet(pkt, interface)

        # Loop non bloccante con controllo running
        while running:
            try:
                cap.dispatch(100, handler)  # Processa fino a 100 pacchetti per volta
                time.sleep(0.01)  # Breve pausa per evitare CPU al 100%
            except Exception as e:
                if running:  # Solo se non stiamo terminando
                    if should_log("v"):
                        print(f"[!] Error processing packets on {interface}: {e}")
                    time.sleep(1)  # Pausa più lunga in caso di errore
                    
    except Exception as e:
        if should_log("default"):
            print(f"[!] Failed to sniff on {interface}: {e}")


def run_sniffer():
    """Sniffer multi-interfaccia con threading"""
    interfaces = load_interfaces()
    
    if not interfaces:
        print("[!] No interfaces configured for inspection.")
        return

    threads = []
    
    # Avvia un thread per ogni interfaccia
    for iface in interfaces:
        thread = threading.Thread(target=sniff_interface, args=(iface,))
        thread.daemon = True
        threads.append(thread)
        thread.start()

    if should_log("default"):
        print(f"[*] Sniffing started on {len(interfaces)} interfaces: {', '.join(interfaces)}")
        print(f"[*] Protocol detection: base protocol for policies, application protocol for logging")
        print(f"[*] Protocol detection: base protocol for policies, application protocol for logging")

    # Attendi che tutti i thread terminino
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\n[*] Received interrupt signal, stopping...")
        global running
        running = False


if __name__ == "__main__":
    print("[*] Advanced Network Inspector starting...")
    print("[*] Enhanced protocol detection enabled")
    run_sniffer()