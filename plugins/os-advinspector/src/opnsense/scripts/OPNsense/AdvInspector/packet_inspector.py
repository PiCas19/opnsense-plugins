#!/usr/local/bin/python3

"""
Advanced Network Inspector - Properly Integrated Object-Oriented Version

A comprehensive network packet inspection system that integrates with NetZones
for zone-based security policies and provides intrusion prevention capabilities.

This version properly integrates with the refactored OOP modules:
- RuleEngine for rule evaluation
- NetworkLogger for structured logging  
- ConfigurationManager for settings
- Enhanced error handling and performance

Author: System Administrator
Version: 1.0
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
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

# Import the refactored OOP modules
from rule_engine import get_rule_engine, RuleEngine
from logger import get_logger, NetworkLogger, log_system_event
from settings_loader import get_config_manager, ConfigurationManager, AdvancedInspectorConfig


class InspectionAction(Enum):
    """Enumeration of possible packet inspection actions."""
    ALLOW = "allow"
    BLOCK = "block"
    ALERT = "alert"
    DROP = "drop"


class LogLevel(Enum):
    """Enumeration of logging verbosity levels."""
    DEFAULT = "default"
    VERBOSE = "v"
    VERY_VERBOSE = "vv"
    DEBUG = "vvv"
    TRACE = "vvvv"
    ULTRA_TRACE = "vvvvv"


@dataclass
class ProtocolInfo:
    """Container for protocol information at different layers."""
    base: str              # Transport layer protocol (tcp/udp/icmp)
    application: str       # Application layer protocol (http/ssh/etc)
    ip_protocol_num: int   # IP protocol number from header
    port: int             # Destination port number


@dataclass
class PacketData:
    """Structured representation of a network packet."""
    src: str
    dst: str
    src_port: int
    dst_port: int
    port: int  # Destination port for convenience
    protocol: str  # Base protocol for NetZones compatibility
    application_protocol: str
    ip_protocol: int
    protocol_info: ProtocolInfo
    interface: str = ""
    timestamp: float = field(default_factory=time.time)
    raw: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet data to dictionary for JSON serialization."""
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
            "timestamp": self.timestamp,
            "raw": self.raw,
            "protocol_info": {
                "base": self.protocol_info.base,
                "application": self.protocol_info.application,
                "ip_protocol_num": self.protocol_info.ip_protocol_num
            }
        }


class ProtocolDetector:
    """Handles protocol detection for network packets."""
    
    # Well-known application protocol mappings
    APP_PROTOCOLS = {
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
    def detect_protocol(cls, port: int, ip_protocol: int) -> ProtocolInfo:
        """
        Detect protocol information from port and IP protocol number.
        
        Args:
            port: Destination port number
            ip_protocol: IP protocol number from packet header
            
        Returns:
            ProtocolInfo object with detected protocol information
        """
        # Determine base transport protocol
        if ip_protocol == 6:
            base_protocol = "tcp"
        elif ip_protocol == 17:
            base_protocol = "udp"
        elif ip_protocol == 1:
            base_protocol = "icmp"
        else:
            base_protocol = "other"
        
        # Detect application protocol from well-known ports
        application_protocol = cls.APP_PROTOCOLS.get(port, base_protocol)
        
        return ProtocolInfo(
            base=base_protocol,
            application=application_protocol,
            ip_protocol_num=ip_protocol,
            port=port
        )


class PacketParser:
    """Handles parsing of raw network packets."""
    
    MIN_PACKET_SIZE = 34
    ETH_IPV4_TYPE = 0x0800
    IPV4_VERSION = 4
    
    @classmethod
    def parse_ipv4_packet(cls, pkt_data: bytes) -> Optional[PacketData]:
        """
        Parse raw packet data into structured PacketData object.
        
        Args:
            pkt_data: Raw packet bytes from network interface
            
        Returns:
            PacketData object if parsing successful, None otherwise
        """
        if len(pkt_data) < cls.MIN_PACKET_SIZE:
            return None

        # Verify Ethernet frame type (IPv4)
        eth_proto = struct.unpack('!H', pkt_data[12:14])[0]
        if eth_proto != cls.ETH_IPV4_TYPE:
            return None

        # Parse IP header with variable length support
        ip_header_start = 14
        version_ihl = pkt_data[ip_header_start]
        version = (version_ihl >> 4) & 0xF
        
        if version != cls.IPV4_VERSION:
            return None
        
        # Calculate IP header length
        ihl = (version_ihl & 0xF) * 4
        if len(pkt_data) < ip_header_start + ihl + 4:
            return None

        # Extract IP header fields
        ip_header = pkt_data[ip_header_start:ip_header_start + ihl]
        if len(ip_header) < 20:
            return None

        iph = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])
        ip_protocol = iph[6]
        src_ip = ipaddress.ip_address(iph[8])
        dst_ip = ipaddress.ip_address(iph[9])

        # Parse transport layer header
        transport_start = ip_header_start + ihl
        if len(pkt_data) < transport_start + 4:
            return None

        transport_header = pkt_data[transport_start:transport_start + 4]
        
        # Extract port information for TCP/UDP
        if ip_protocol in (6, 17):  # TCP or UDP
            src_port, dst_port = struct.unpack('!HH', transport_header)
        else:
            src_port = dst_port = 0

        # Detect protocol information
        protocol_info = ProtocolDetector.detect_protocol(dst_port, ip_protocol)

        return PacketData(
            src=str(src_ip),
            dst=str(dst_ip),
            src_port=src_port,
            dst_port=dst_port,
            port=dst_port,
            protocol=protocol_info.base,
            application_protocol=protocol_info.application,
            ip_protocol=ip_protocol,
            protocol_info=protocol_info,
            raw=pkt_data.hex()
        )


class NetworkFilter:
    """Handles network-based filtering operations."""
    
    @staticmethod
    def ip_in_networks(ip: str, networks: List[str]) -> bool:
        """
        Check if IP address belongs to any of the specified networks.
        
        Args:
            ip: IP address to check
            networks: List of network CIDR blocks
            
        Returns:
            True if IP is in any network, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in ipaddress.ip_network(net, strict=False) 
                      for net in networks)
        except ValueError:
            return False


class VerbosityLogger:
    """Logging wrapper that integrates with configuration system."""
    
    LEVEL_HIERARCHY = [
        LogLevel.DEFAULT,
        LogLevel.VERBOSE,
        LogLevel.VERY_VERBOSE,
        LogLevel.DEBUG,
        LogLevel.TRACE,
        LogLevel.ULTRA_TRACE
    ]
    
    def __init__(self, config_manager: ConfigurationManager):
        """
        Initialize verbosity logger.
        
        Args:
            config_manager: Configuration manager for verbosity settings
        """
        self.config_manager = config_manager
    
    def should_log(self, level: LogLevel) -> bool:
        """
        Determine if message should be logged based on current verbosity.
        
        Args:
            level: Minimum log level required for message
            
        Returns:
            True if message should be logged, False otherwise
        """
        try:
            config = self.config_manager.get_config()
            current_level = config.verbosity
            current_index = self.LEVEL_HIERARCHY.index(LogLevel(current_level.value))
            required_index = self.LEVEL_HIERARCHY.index(level)
            return current_index >= required_index
        except Exception:
            return False
    
    def log(self, level: LogLevel, message: str) -> None:
        """
        Log message if verbosity level permits.
        
        Args:
            level: Log level for this message
            message: Message to log
        """
        if self.should_log(level):
            print(message)


class FirewallIntegration(ABC):
    """Abstract base class for firewall integration."""
    
    @abstractmethod
    def block_traffic(self, src: str, dst: str, port: int) -> bool:
        """
        Block traffic from source to destination on specified port.
        
        Args:
            src: Source IP address
            dst: Destination IP address
            port: Port number to block
            
        Returns:
            True if blocking was successful, False otherwise
        """
        pass


class PfFirewall(FirewallIntegration):
    """PF (Packet Filter) firewall integration."""
    
    def __init__(self, 
                 verbosity_logger: VerbosityLogger,
                 anchor_path: str = "/usr/local/etc/ips_block.conf",
                 anchor_name: str = "ips_block"):
        """
        Initialize PF firewall integration.
        
        Args:
            verbosity_logger: Logger for verbose output
            anchor_path: Path to PF anchor configuration file
            anchor_name: Name of PF anchor for IPS rules
        """
        self.verbosity_logger = verbosity_logger
        self.anchor_path = anchor_path
        self.anchor_name = anchor_name
        self.block_count = defaultdict(int)
        self.block_lock = threading.Lock()
    
    def block_traffic(self, src: str, dst: str, port: int) -> bool:
        """
        Add blocking rule to PF firewall.
        
        Args:
            src: Source IP address to block
            dst: Destination IP address
            port: Port number to block
            
        Returns:
            True if rule was added successfully, False otherwise
        """
        rule = f"block in quick from {src} to {dst} port = {port}\n"
        
        try:
            # Append rule to anchor file
            with open(self.anchor_path, "a") as f:
                f.write(rule)
            
            # Reload PF rules
            result = subprocess.run(
                ["pfctl", "-a", self.anchor_name, "-f", self.anchor_path], 
                check=True, capture_output=True, text=True
            )
            
            # Update statistics
            with self.block_lock:
                block_key = f"{src}->{dst}:{port}"
                self.block_count[block_key] += 1
            
            self.verbosity_logger.log(LogLevel.VERY_VERBOSE, 
                                    f"[+] Blocked via pf: {src} → {dst}:{port}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.verbosity_logger.log(LogLevel.VERBOSE, f"[!] pf block failed: {e.stderr}")
            return False
        except Exception as e:
            self.verbosity_logger.log(LogLevel.VERBOSE, f"[!] pf block failed: {e}")
            return False
    
    def get_block_stats(self) -> Dict[str, int]:
        """Get blocking statistics."""
        with self.block_lock:
            return dict(self.block_count)


class NetZonesClient:
    """Client for communicating with NetZones policy engine."""
    
    def __init__(self, 
                 verbosity_logger: VerbosityLogger,
                 socket_path: str = "/var/run/netzones.sock", 
                 timeout: float = 5.0):
        """
        Initialize NetZones client.
        
        Args:
            verbosity_logger: Logger for verbose output
            socket_path: Path to NetZones Unix socket
            timeout: Connection timeout in seconds
        """
        self.verbosity_logger = verbosity_logger
        self.socket_path = socket_path
        self.timeout = timeout
    
    def query_decision(self, packet: PacketData) -> Optional[str]:
        """
        Query NetZones for policy decision on packet.
        
        Args:
            packet: Packet data to evaluate
            
        Returns:
            Policy decision string ("allow"/"deny"/"block") or None if query failed
        """
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.socket_path)
                
                # Send packet data as JSON query
                query_data = packet.to_dict()
                s.sendall(json.dumps(query_data).encode())
                
                # Receive response
                response_data = s.recv(4096)
                if response_data:
                    response = json.loads(response_data.decode())
                    decision = response.get('decision', 'allow')
                    
                    # Log decision if debugging enabled
                    if self.verbosity_logger.should_log(LogLevel.DEBUG):
                        protocol_desc = self._get_protocol_description(packet)
                        self.verbosity_logger.log(LogLevel.DEBUG, 
                                                f"[+] NetZones decision for {protocol_desc}: {decision}")
                    
                    return decision
                    
        except socket.timeout:
            self.verbosity_logger.log(LogLevel.VERBOSE, "[!] NetZones query timeout")
        except FileNotFoundError:
            self.verbosity_logger.log(LogLevel.VERBOSE, "[!] NetZones socket not found")
        except Exception as e:
            self.verbosity_logger.log(LogLevel.VERBOSE, f"[!] NetZones query failed: {e}")
        
        return None
    
    def _get_protocol_description(self, packet: PacketData) -> str:
        """Generate human-readable protocol description."""
        if (packet.application_protocol and 
            packet.application_protocol != packet.protocol):
            return f"{packet.protocol}:{packet.port} ({packet.application_protocol})"
        return f"{packet.protocol}:{packet.port}"


class PacketInspector:
    """Main packet inspection engine with rule evaluation and policy integration."""
    
    def __init__(self, 
                 config_manager: ConfigurationManager,
                 rule_engine: RuleEngine,
                 network_logger: NetworkLogger,
                 verbosity_logger: VerbosityLogger,
                 firewall: FirewallIntegration, 
                 netzones_client: NetZonesClient):
        """
        Initialize packet inspector with all dependencies.
        
        Args:
            config_manager: Configuration manager instance
            rule_engine: Rule evaluation engine
            network_logger: Structured network logger
            verbosity_logger: Verbosity-aware console logger
            firewall: Firewall integration instance
            netzones_client: NetZones client for policy queries
        """
        self.config_manager = config_manager
        self.rule_engine = rule_engine
        self.network_logger = network_logger
        self.verbosity_logger = verbosity_logger
        self.firewall = firewall
        self.netzones_client = netzones_client
        self.alert_count = defaultdict(int)
        self.alert_lock = threading.Lock()
    
    def inspect_packet(self, packet: PacketData) -> str:
        """
        Perform comprehensive packet inspection with policy evaluation.
        
        Args:
            packet: Parsed packet data to inspect
            
        Returns:
            String describing inspection result
        """
        # Get current configuration
        config = self.config_manager.get_config()
        
        # Check if inspection is enabled
        if not config.enabled:
            return "disabled"

        # Apply home network filtering
        if (config.home_networks and 
            not NetworkFilter.ip_in_networks(packet.src, config.home_networks)):
            self.verbosity_logger.log(LogLevel.DEBUG, 
                                    f"[-] Skipped packet from {packet.src} not in homenet")
            return "homenet_skipped"

        # Evaluate local rules using rule engine
        local_action = self.rule_engine.evaluate_packet(packet.to_dict())
        
        # Query NetZones for policy decision
        netzones_decision = self.netzones_client.query_decision(packet)
        
        # Determine final action based on combined policies
        final_action = self._determine_final_action(local_action, netzones_decision)
        
        # Execute action and log results
        return self._execute_action(packet, final_action, local_action, netzones_decision, config)
    
    def _determine_final_action(self, local_action: str, 
                              netzones_decision: Optional[str]) -> InspectionAction:
        """
        Combine local rules and NetZones policy to determine final action.
        
        Args:
            local_action: Action determined by local rules
            netzones_decision: Decision from NetZones policy engine
            
        Returns:
            Final action to take on packet
        """
        # NetZones takes precedence for blocking
        if netzones_decision in ("deny", "block"):
            return InspectionAction.BLOCK
        
        # If NetZones allows but local rules block, degrade to alert
        if netzones_decision == "allow" and local_action == "block":
            return InspectionAction.ALERT
        
        # Default to local action
        try:
            return InspectionAction(local_action)
        except ValueError:
            return InspectionAction.ALLOW
    
    def _execute_action(self, packet: PacketData, action: InspectionAction,
                       local_action: str, netzones_decision: Optional[str],
                       config: AdvancedInspectorConfig) -> str:
        """
        Execute the determined action and perform logging.
        
        Args:
            packet: Packet being processed
            action: Final action to execute
            local_action: Original local rule action
            netzones_decision: NetZones policy decision
            config: Current system configuration
            
        Returns:
            String describing the result
        """
        protocol_desc = self._get_protocol_description(packet)
        decision_context = f"(local: {local_action}, netzones: {netzones_decision})"
        
        if action == InspectionAction.BLOCK:
            reason = f"Rule matched — {protocol_desc} blocked {decision_context}"
            
            # Log to structured logger
            self.network_logger.log_packet(packet.to_dict(), reason=reason)
            self.network_logger.log_alert(packet.to_dict(), 
                                        reason=f"Rule matched: action=block for {protocol_desc} {decision_context}")
            
            # Execute blocking if IPS mode is enabled
            if config.ips_mode and config.inspection_mode.value in ("stateful", "both"):
                self.firewall.block_traffic(packet.src, packet.dst, packet.port)
            
            return "blocked"
        
        elif action == InspectionAction.ALERT:
            reason = f"Rule matched — {protocol_desc} alert only {decision_context}"
            
            # Log to structured logger
            self.network_logger.log_packet(packet.to_dict(), reason=reason)
            self.network_logger.log_alert(packet.to_dict(),
                                        reason=f"Rule matched: action=alert for {protocol_desc} {decision_context}")
            
            # Update alert statistics
            with self.alert_lock:
                alert_key = f"{packet.src}->{packet.dst}:{packet.port}"
                self.alert_count[alert_key] += 1
            
            return "alerted"
        
        else:
            reason = f"No rules matched — {protocol_desc} allowed {decision_context}"
            
            # Log to structured logger
            self.network_logger.log_packet(packet.to_dict(), reason=reason)
            
            # Console log for debugging
            self.verbosity_logger.log(LogLevel.DEBUG,
                                    f"[~] Allowed: {packet.src} → {packet.dst}:{packet.port} ({protocol_desc})")
            
            return "allowed"
    
    def _get_protocol_description(self, packet: PacketData) -> str:
        """Generate human-readable protocol description for logging."""
        if (packet.application_protocol and 
            packet.application_protocol != packet.protocol):
            return f"{packet.protocol}:{packet.port} ({packet.application_protocol})"
        return packet.protocol
    
    def get_alert_stats(self) -> Dict[str, int]:
        """Get alert statistics."""
        with self.alert_lock:
            return dict(self.alert_count)


class InterfaceSniffer:
    """Handles packet sniffing on a single network interface."""
    
    def __init__(self, 
                 interface: str, 
                 inspector: PacketInspector,
                 config_manager: ConfigurationManager,
                 verbosity_logger: VerbosityLogger):
        """
        Initialize interface sniffer.
        
        Args:
            interface: Network interface name to monitor
            inspector: Packet inspector instance for processing packets
            config_manager: Configuration manager for settings
            verbosity_logger: Logger for verbose output
        """
        self.interface = interface
        self.inspector = inspector
        self.config_manager = config_manager
        self.verbosity_logger = verbosity_logger
        self.running = False
        self._capture_handle = None
    
    def start_sniffing(self) -> None:
        """Start packet capture on the interface."""
        config = self.config_manager.get_config()
        
        try:
            # Open capture handle with specified parameters
            self._capture_handle = pcapy.open_live(
                self.interface, 65536, config.promiscuous_mode, 100
            )
            
            self.verbosity_logger.log(LogLevel.VERBOSE,
                                    f"[*] Started sniffing on {self.interface} (promisc={config.promiscuous_mode})")
            
            self.running = True
            self._capture_loop()
            
        except Exception as e:
            self.verbosity_logger.log(LogLevel.DEFAULT,
                                    f"[!] Failed to start sniffing on {self.interface}: {e}")
    
    def stop_sniffing(self) -> None:
        """Stop packet capture."""
        self.running = False
    
    def _capture_loop(self) -> None:
        """Main packet capture loop."""
        def packet_handler(header, data):
            """Handle captured packet."""
            if not self.running:
                return
            
            # Parse packet data
            packet = PacketParser.parse_ipv4_packet(data)
            if packet:
                packet.interface = self.interface
                packet.timestamp = time.time()
                
                # Inspect packet
                self.inspector.inspect_packet(packet)
        
        # Non-blocking capture loop with running check
        while self.running:
            try:
                if self._capture_handle:
                    self._capture_handle.dispatch(100, packet_handler)
                time.sleep(0.01)  # Brief pause to prevent 100% CPU usage
            except Exception as e:
                if self.running:  # Only log if not shutting down
                    self.verbosity_logger.log(LogLevel.VERBOSE,
                                            f"[!] Error processing packets on {self.interface}: {e}")
                    time.sleep(1)  # Longer pause on error


class NetworkInspectorService:
    """Main service class orchestrating the network inspection system."""
    
    def __init__(self):
        """Initialize the network inspector service with all dependencies."""
        self.running = False
        self.sniffers: List[InterfaceSniffer] = []
        self.threads: List[threading.Thread] = []
        
        # Initialize core components using OOP modules
        self.config_manager = get_config_manager()
        self.rule_engine = get_rule_engine()
        self.network_logger = get_logger()
        self.verbosity_logger = VerbosityLogger(self.config_manager)
        
        # Initialize service components
        self.firewall = PfFirewall(self.verbosity_logger)
        self.netzones_client = NetZonesClient(self.verbosity_logger)
        self.inspector = PacketInspector(
            self.config_manager,
            self.rule_engine,
            self.network_logger,
            self.verbosity_logger,
            self.firewall,
            self.netzones_client
        )
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Log system startup
        log_system_event("startup", "Network Inspector Service initializing", {
            "version": "2.0",
            "components": ["rule_engine", "network_logger", "config_manager", "firewall", "netzones"]
        })
    
    def start(self) -> None:
        """Start the network inspection service."""
        config = self.config_manager.get_config()
        
        self.verbosity_logger.log(LogLevel.DEFAULT, "[*] Advanced Network Inspector starting...")
        self.verbosity_logger.log(LogLevel.DEFAULT, "[*] Enhanced protocol detection enabled")
        
        # Get interface list from configuration
        physical_interfaces = config.get_physical_interface_names()
        
        if not physical_interfaces:
            self.verbosity_logger.log(LogLevel.DEFAULT, "[!] No interfaces configured for inspection.")
            return
        
        # Validate configuration
        validation = self.config_manager.validate_config()
        if validation["errors"]:
            self.verbosity_logger.log(LogLevel.DEFAULT, f"[!] Configuration errors: {validation['errors']}")
            return
        
        if validation["warnings"]:
            for warning in validation["warnings"]:
                self.verbosity_logger.log(LogLevel.VERBOSE, f"[WARN] {warning}")
        
        # Create sniffers for each interface
        for interface in physical_interfaces:
            sniffer = InterfaceSniffer(
                interface, 
                self.inspector, 
                self.config_manager,
                self.verbosity_logger
            )
            self.sniffers.append(sniffer)
            
            # Start sniffer in separate thread
            thread = threading.Thread(target=sniffer.start_sniffing)
            thread.daemon = True
            self.threads.append(thread)
            thread.start()
        
        self.running = True
        self.verbosity_logger.log(LogLevel.DEFAULT,
                                f"[*] Sniffing started on {len(physical_interfaces)} interfaces: {', '.join(physical_interfaces)}")
        self.verbosity_logger.log(LogLevel.DEFAULT,
                                "[*] Protocol detection: base protocol for policies, application protocol for logging")
        
        # Log successful startup
        log_system_event("startup_complete", "Network Inspector Service started successfully", {
            "interfaces": physical_interfaces,
            "inspection_mode": config.inspection_mode.value,
            "ips_mode": config.ips_mode
        })
        
        # Wait for threads to complete
        self._wait_for_completion()
    
    def stop(self) -> None:
        """Stop the network inspection service gracefully."""
        self.verbosity_logger.log(LogLevel.DEFAULT, "\n[*] Shutting down gracefully...")
        
        self.running = False
        
        # Stop all sniffers
        for sniffer in self.sniffers:
            sniffer.stop_sniffing()
        
        # Wait for threads with timeout
        for thread in self.threads:
            thread.join(timeout=2.0)
        
        # Log shutdown
        log_system_event("shutdown", "Network Inspector Service stopped", {
            "uptime_seconds": time.time()  # Could track actual uptime
        })
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive service statistics."""
        return {
            "config_stats": self.config_manager.get_statistics(),
            "rule_engine_stats": self.rule_engine.get_statistics(),
            "logger_stats": self.network_logger.get_log_stats(),
            "alert_stats": self.inspector.get_alert_stats(),
            "block_stats": self.firewall.get_block_stats(),
            "service_stats": {
                "running": self.running,
                "active_interfaces": len(self.sniffers),
                "active_threads": len([t for t in self.threads if t.is_alive()])
            }
        }
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        self.stop()
        sys.exit(0)
    
    def _wait_for_completion(self) -> None:
        """Wait for all threads to complete."""
        try:
            for thread in self.threads:
                thread.join()
        except KeyboardInterrupt:
            self.stop()


def main():
    """Main entry point for the application."""
    try:
        service = NetworkInspectorService()
        service.start()
    except Exception as e:
        print(f"[FATAL] Failed to start Network Inspector Service: {e}")
        log_system_event("startup_failed", "Service startup failed", {"error": str(e)})
        sys.exit(1)


if __name__ == "__main__":
    main()