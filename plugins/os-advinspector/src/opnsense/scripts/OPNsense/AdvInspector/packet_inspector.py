#!/usr/local/bin/python3

"""
packet_inspector.py - OPNsense Advanced Inspector Main Engine

This is the core packet inspection engine for the OPNsense Advanced Inspector
plugin. It provides real-time packet capture, analysis, and security policy
enforcement with support for industrial protocols and NetZones integration.

Author: Pierpaolo Casati
Version: 2.0
License: BSD 2-Clause

Features:
- Multi-interface packet capture
- Industrial protocol detection (Modbus, DNP3, OPC UA, etc.)
- Integration with NetZones for policy decisions
- IPS mode with PF firewall integration
- Comprehensive logging and alerting
- Thread-safe operation
"""

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
import logging
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from rule_engine import RuleEngine
from logger import InspectorLogger
from settings_loader import SettingsLoader, InspectorSettings

@dataclass
class InspectorConfig:
    """Configuration for the packet inspector."""
    socket_path: str = "/var/run/netzones.sock"
    pf_anchor_path: str = "/usr/local/etc/ips_block.conf"
    pf_anchor_name: str = "ips_block"
    rules_file: str = "/usr/local/etc/advinspector/rules.json"
    socket_timeout: float = 5.0
    capture_timeout: int = 100
    batch_size: int = 100


@dataclass
class PacketInfo:
    """Represents parsed packet information."""
    src: str
    dst: str
    src_port: int
    dst_port: int
    port: int  # Usually dst_port
    protocol: str  # Base protocol (tcp/udp/icmp)
    application_protocol: str = ""
    ip_protocol: int = 0
    interface: str = ""
    raw: str = ""
    timestamp: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for compatibility."""
        return {
            "src": self.src,
            "dst": self.dst,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "port": self.port,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "ip_protocol": self.ip_protocol,
            "interface": self.interface,
            "raw": self.raw,
            "timestamp": self.timestamp
        }


class ProtocolDetector:
    """Handles protocol detection and classification."""
    
    # Application protocol mapping (only for well-known ports)
    APP_PROTOCOL_MAP = {
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
    
    @classmethod
    def get_protocol_info(cls, port: int, ip_protocol: int) -> Tuple[str, str, int]:
        """
        Get protocol information with both layer 4 and application layer info.
        
        Args:
            port: Port number
            ip_protocol: IP protocol number
            
        Returns:
            Tuple of (base_protocol, application_protocol, port)
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
        
        # For NetZones, use the base protocol (tcp/udp/icmp)
        # This avoids confusion in policy evaluation
        application_protocol = cls.APP_PROTOCOL_MAP.get(port, base_protocol)
        
        return base_protocol, application_protocol, port


class PacketParser:
    """Handles packet parsing and extraction."""
    
    def __init__(self):
        self.protocol_detector = ProtocolDetector()
    
    def ip_in_networks(self, ip: str, networks: List[str]) -> bool:
        """
        Check if IP is in any of the specified networks.
        
        Args:
            ip: IP address to check
            networks: List of network CIDR strings
            
        Returns:
            True if IP is in any network, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in ipaddress.ip_network(net, strict=False) for net in networks)
        except ValueError:
            return False
    
    def parse_ipv4_packet(self, pkt_data: bytes) -> Optional[PacketInfo]:
        """
        Parse IPv4 packet data into PacketInfo object.
        
        Args:
            pkt_data: Raw packet data
            
        Returns:
            PacketInfo object or None if parsing fails
        """
        if len(pkt_data) < 34:
            return None

        # Verify Ethernet type
        eth_proto = struct.unpack('!H', pkt_data[12:14])[0]
        if eth_proto != 0x0800:  # IPv4
            return None

        # IP header - handles variable length
        ip_header_start = 14
        version_ihl = pkt_data[ip_header_start]
        version = (version_ihl >> 4) & 0xF
        if version != 4:
            return None
        
        ihl = (version_ihl & 0xF) * 4  # IP header length in bytes
        if len(pkt_data) < ip_header_start + ihl + 4:
            return None

        # Extract IP header
        ip_header = pkt_data[ip_header_start:ip_header_start + ihl]
        if len(ip_header) < 20:
            return None

        iph = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])
        ip_protocol = iph[6]  # Protocol field from IP header
        src_ip = ipaddress.ip_address(iph[8])
        dst_ip = ipaddress.ip_address(iph[9])

        # Transport header
        transport_start = ip_header_start + ihl
        if len(pkt_data) < transport_start + 4:
            return None

        transport_header = pkt_data[transport_start:transport_start + 4]
        
        if ip_protocol in (6, 17):  # TCP or UDP
            src_port, dst_port = struct.unpack('!HH', transport_header)
        else:
            # For other protocols, use port 0
            src_port = dst_port = 0

        # Get protocol information
        base_protocol, app_protocol, port = self.protocol_detector.get_protocol_info(dst_port, ip_protocol)

        return PacketInfo(
            src=str(src_ip),
            dst=str(dst_ip),
            src_port=src_port,
            dst_port=dst_port,
            port=dst_port,  # Destination port
            protocol=base_protocol,  # Use base protocol for NetZones (tcp/udp/icmp)
            application_protocol=app_protocol,  # Application layer protocol for logging
            ip_protocol=ip_protocol,  # IP protocol number
            timestamp=time.time()
        )


# Global state for signal handling (will be moved to class later)
_running = True
_packet_lock = threading.Lock()

# Statistics (will be moved to class later)  
_rate_table = defaultdict(list)
_alert_count = defaultdict(int)
_block_count = defaultdict(int)

def signal_handler(signum, frame):
    global _running
    _running = False
    print("\n[*] Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


class NetZonesIntegration:
    """Handles integration with NetZones policy engine."""
    
    def __init__(self, socket_path: str, socket_timeout: float = 5.0):
        self.socket_path = socket_path
        self.socket_timeout = socket_timeout
        self.logger = logging.getLogger('netzones_integration')
    
    def query_decision(self, packet: PacketInfo) -> Optional[Dict[str, Any]]:
        """
        Query NetZones for policy decision.
        
        Args:
            packet: Packet information to query
            
        Returns:
            NetZones response dictionary or None if failed
        """
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.socket_timeout)
                s.connect(self.socket_path)
                
                # Send the base protocol (tcp/udp/icmp) to NetZones
                # This ensures consistent policy evaluation
                query = {
                    "src": packet.src,
                    "dst": packet.dst,
                    "port": packet.port,
                    "protocol": packet.protocol,  # Base protocol (tcp/udp/icmp)
                    # Include additional context for logging/analysis
                    "meta": {
                        "application_protocol": packet.application_protocol,
                        "ip_protocol": packet.ip_protocol,
                        "interface": packet.interface
                    }
                }
                
                s.sendall(json.dumps(query).encode())
                response_data = s.recv(4096)
                
                if response_data:
                    response = json.loads(response_data.decode())
                    self.logger.debug(f"NetZones decision for {packet.protocol}:{packet.port}: {response.get('decision', 'unknown')}")
                    return response
                
        except socket.timeout:
            self.logger.warning("NetZones query timeout")
        except FileNotFoundError:
            self.logger.warning("NetZones socket not found")
        except Exception as e:
            self.logger.warning(f"NetZones query failed: {e}")
        
        return None


class FirewallManager:
    """Handles PF firewall integration for IPS mode."""
    
    def __init__(self, anchor_path: str, anchor_name: str):
        self.anchor_path = Path(anchor_path)
        self.anchor_name = anchor_name
        self.logger = logging.getLogger('firewall_manager')
        self._block_stats = defaultdict(int)
        self._lock = threading.Lock()
    
    def block_traffic(self, src: str, dst: str, port: int) -> bool:
        """
        Block traffic using PF firewall rules.
        
        Args:
            src: Source IP address
            dst: Destination IP address  
            port: Port number
            
        Returns:
            True if block succeeded, False otherwise
        """
        rule = f"block in quick from {src} to {dst} port = {port}\\n"
        
        try:
            # Append rule to anchor file
            with open(self.anchor_path, "a") as f:
                f.write(rule)
            
            # Reload PF rules
            result = subprocess.run(
                ["pfctl", "-a", self.anchor_name, "-f", str(self.anchor_path)], 
                check=True, capture_output=True, text=True
            )
            
            # Update statistics
            with self._lock:
                self._block_stats[f"{src}->{dst}:{port}"] += 1
            
            self.logger.info(f"Blocked via pf: {src} → {dst}:{port}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"PF block failed: {e.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"PF block failed: {e}")
            return False
    
    def get_block_statistics(self) -> Dict[str, int]:
        """Get blocking statistics."""
        with self._lock:
            return dict(self._block_stats)


def should_log(level):
    """Legacy function for backward compatibility."""
    levels = ["default", "v", "vv", "vvv", "vvvv", "vvvvv"]
    try:
        # Use legacy function for now
        from settings_loader import load_verbosity
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