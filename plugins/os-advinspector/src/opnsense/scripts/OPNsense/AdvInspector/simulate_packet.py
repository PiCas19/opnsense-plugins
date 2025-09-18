#!/usr/local/bin/python3
"""
simulate_packet.py - OPNsense Advanced Inspector Packet Simulation Tool

This module provides a command-line tool for simulating packet inspection
without actual network traffic. It's useful for testing rules, debugging
configurations, and validating inspector behavior.

Author: Pierpaolo Casati
Version: 2.0
License: BSD 2-Clause

Usage:
    # Via command line argument
    python3 simulate_packet.py '{"src":"192.168.1.100","dst":"192.168.1.1","port":80,"protocol":"tcp","interface":"lan"}'
    
    # Via stdin
    echo '{"src":"192.168.1.100","dst":"192.168.1.1","port":80,"protocol":"tcp","interface":"lan"}' | python3 simulate_packet.py
    
    # Using the PacketSimulator class
    from simulate_packet import PacketSimulator
    simulator = PacketSimulator()
    result = simulator.simulate_packet({...})
"""

import json
import sys
import argparse
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from pathlib import Path
from packet_inspector import inspect_packet


@dataclass
class SimulationResult:
    """Result of packet simulation."""
    success: bool
    action: str
    packet: Dict[str, Any]
    execution_time: float
    rule_matched: Optional[str] = None
    error: Optional[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class PacketSimulator:
    """
    Packet simulation tool for testing the Advanced Inspector.
    
    This class provides functionality to simulate packet inspection
    without actual network traffic, useful for testing and debugging.
    """
    
    # Required fields for packet simulation
    REQUIRED_FIELDS = ["src", "dst", "port", "protocol", "interface"]
    
    # Optional fields with default values
    DEFAULT_VALUES = {
        "src_port": 0,
        "dst_port": 0,
        "ip_protocol": 6,  # TCP
        "application_protocol": "",
        "raw": "",
        "timestamp": 0
    }
    
    def __init__(self, verbose: bool = False):
        """
        Initialize packet simulator.
        
        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        """
        Set up logging for the simulator.
        
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger('packet_simulator')
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        logger.setLevel(logging.DEBUG if self.verbose else logging.WARNING)
        return logger
    
    def validate_packet(self, packet: Dict[str, Any]) -> List[str]:
        """
        Validate packet data for simulation.
        
        Args:
            packet: Packet data to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check required fields
        missing_fields = [field for field in self.REQUIRED_FIELDS if field not in packet]
        if missing_fields:
            errors.append(f"Missing required field(s): {', '.join(missing_fields)}")
        
        # Validate IP addresses
        for ip_field in ['src', 'dst']:
            if ip_field in packet:
                ip_value = packet[ip_field]
                if not self._is_valid_ip(ip_value):
                    errors.append(f"Invalid IP address in field '{ip_field}': {ip_value}")
        
        # Validate port numbers
        for port_field in ['port', 'src_port', 'dst_port']:
            if port_field in packet:
                try:
                    port_value = int(packet[port_field])
                    if not (0 <= port_value <= 65535):
                        errors.append(f"Port {port_field} must be between 0 and 65535: {port_value}")
                except (ValueError, TypeError):
                    errors.append(f"Invalid port number in field '{port_field}': {packet[port_field]}")
        
        # Validate protocol
        if 'protocol' in packet:
            valid_protocols = [
                'tcp', 'udp', 'icmp', 'modbus_tcp', 'dnp3', 'iec104', 'iec61850',
                'profinet', 'ethercat', 'opcua', 'mqtt', 'bacnet', 's7comm'
            ]
            if packet['protocol'].lower() not in valid_protocols:
                errors.append(f"Invalid protocol: {packet['protocol']}")
        
        return errors
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """
        Check if string is a valid IP address.
        
        Args:
            ip_str: IP address string to validate
            
        Returns:
            True if valid IP, False otherwise
        """
        try:
            import ipaddress
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def prepare_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare packet data with default values.
        
        Args:
            packet_data: Raw packet data
            
        Returns:
            Packet data with all required fields
        """
        prepared_packet = packet_data.copy()
        
        # Add default values for missing optional fields
        for field, default_value in self.DEFAULT_VALUES.items():
            if field not in prepared_packet:
                prepared_packet[field] = default_value
        
        # Ensure destination port matches port if not specified
        if 'dst_port' not in prepared_packet and 'port' in prepared_packet:
            prepared_packet['dst_port'] = prepared_packet['port']
        
        # Set timestamp if not provided
        if prepared_packet.get('timestamp', 0) == 0:
            import time
            prepared_packet['timestamp'] = time.time()
        
        return prepared_packet
    
    def simulate_packet(self, packet_data: Dict[str, Any]) -> SimulationResult:
        """
        Simulate packet inspection.
        
        Args:
            packet_data: Packet data to simulate
            
        Returns:
            SimulationResult with inspection outcome
        """
        import time
        start_time = time.time()
        
        try:
            self.logger.debug(f"Starting packet simulation: {packet_data}")
            
            # Validate packet data
            validation_errors = self.validate_packet(packet_data)
            if validation_errors:
                return SimulationResult(
                    success=False,
                    action="validation_failed",
                    packet=packet_data,
                    execution_time=time.time() - start_time,
                    error="Validation failed: " + "; ".join(validation_errors)
                )
            
            # Prepare packet with defaults
            prepared_packet = self.prepare_packet(packet_data)
            
            # Run inspection
            interface = prepared_packet['interface']
            result = inspect_packet(prepared_packet, interface)
            
            execution_time = time.time() - start_time
            
            self.logger.debug(f"Simulation completed in {execution_time:.4f}s: {result}")
            
            return SimulationResult(
                success=True,
                action=result,
                packet=prepared_packet,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Simulation failed: {e}")
            
            return SimulationResult(
                success=False,
                action="error",
                packet=packet_data,
                execution_time=execution_time,
                error=str(e)
            )
    
    def simulate_batch(self, packets: List[Dict[str, Any]]) -> List[SimulationResult]:
        """
        Simulate multiple packets.
        
        Args:
            packets: List of packet data to simulate
            
        Returns:
            List of simulation results
        """
        results = []
        
        for i, packet in enumerate(packets):
            self.logger.debug(f"Simulating packet {i+1}/{len(packets)}")
            result = self.simulate_packet(packet)
            results.append(result)
        
        return results


class PacketSimulatorCLI:
    """
    Command-line interface for the packet simulator.
    """
    
    def __init__(self):
        self.simulator = None
        
    def read_packet_input(self, args) -> Dict[str, Any]:
        """
        Read packet input from various sources.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            Packet data dictionary
            
        Raises:
            ValueError: If no valid input provided
        """
        # Try command line argument first
        if args.packet:
            return json.loads(args.packet)
        
        # Try input file
        if args.file:
            with open(args.file, 'r') as f:
                return json.load(f)
        
        # Try stdin (only if not a TTY)
        if not sys.stdin.isatty():
            return json.load(sys.stdin)
        
        raise ValueError("No packet input provided. Use --packet, --file, or pipe JSON to stdin.")
    
    def create_sample_packet(self) -> Dict[str, Any]:
        """
        Create a sample packet for demonstration.
        
        Returns:
            Sample packet data
        """
        return {
            "src": "192.168.1.100",
            "dst": "192.168.1.1", 
            "port": 80,
            "protocol": "tcp",
            "interface": "lan",
            "description": "Sample HTTP packet for testing"
        }
    
    def format_result(self, result: SimulationResult, format_type: str = "json") -> str:
        """
        Format simulation result for output.
        
        Args:
            result: Simulation result to format
            format_type: Output format ('json', 'text')
            
        Returns:
            Formatted result string
        """
        if format_type == "json":
            output = {
                "success": result.success,
                "action": result.action,
                "execution_time": result.execution_time,
                "packet": result.packet
            }
            
            if result.error:
                output["error"] = result.error
            if result.warnings:
                output["warnings"] = result.warnings
            if result.rule_matched:
                output["rule_matched"] = result.rule_matched
                
            return json.dumps(output, indent=2, ensure_ascii=False)
        
        elif format_type == "text":
            lines = []
            lines.append(f"Simulation Result: {'SUCCESS' if result.success else 'FAILED'}")
            lines.append(f"Action: {result.action}")
            lines.append(f"Execution Time: {result.execution_time:.4f}s")
            
            if result.error:
                lines.append(f"Error: {result.error}")
            
            if result.warnings:
                lines.append("Warnings:")
                for warning in result.warnings:
                    lines.append(f"  - {warning}")
            
            if result.rule_matched:
                lines.append(f"Rule Matched: {result.rule_matched}")
                
            lines.append("\nPacket Details:")
            for key, value in result.packet.items():
                lines.append(f"  {key}: {value}")
                
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unknown format type: {format_type}")
    
    def run(self) -> int:
        """
        Run the CLI application.
        
        Returns:
            Exit code (0 for success, 1 for error)
        """
        parser = argparse.ArgumentParser(
            description="Simulate packet inspection for OPNsense Advanced Inspector",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""Examples:
  %(prog)s --packet '{"src":"192.168.1.100","dst":"192.168.1.1","port":80,"protocol":"tcp","interface":"lan"}'
  %(prog)s --file packet.json
  echo '{"src":"192.168.1.100","dst":"192.168.1.1","port":80,"protocol":"tcp","interface":"lan"}' | %(prog)s
  %(prog)s --sample"""
        )
        
        parser.add_argument('--packet', '-p', help='Packet data as JSON string')
        parser.add_argument('--file', '-f', help='Read packet data from JSON file')
        parser.add_argument('--sample', action='store_true', help='Use sample packet data')
        parser.add_argument('--format', choices=['json', 'text'], default='json',
                          help='Output format (default: json)')
        parser.add_argument('--verbose', '-v', action='store_true',
                          help='Enable verbose output')
        
        args = parser.parse_args()
        
        try:
            # Initialize simulator
            self.simulator = PacketSimulator(verbose=args.verbose)
            
            # Get packet data
            if args.sample:
                packet_data = self.create_sample_packet()
            else:
                packet_data = self.read_packet_input(args)
            
            # Run simulation
            result = self.simulator.simulate_packet(packet_data)
            
            # Output result
            formatted_result = self.format_result(result, args.format)
            print(formatted_result)
            
            return 0 if result.success else 1
            
        except Exception as e:
            error_result = {
                "success": False,
                "error": str(e)
            }
            print(json.dumps(error_result, indent=2))
            return 1


# Legacy functions for backward compatibility
def validate_packet(packet):
    """Legacy function - use PacketSimulator.validate_packet() instead."""
    simulator = PacketSimulator()
    errors = simulator.validate_packet(packet)
    if errors:
        raise ValueError(errors[0])


def read_packet_input():
    """Legacy function - use PacketSimulatorCLI.read_packet_input() instead."""
    if len(sys.argv) == 2:
        return json.loads(sys.argv[1])
    elif not sys.stdin.isatty():
        return json.load(sys.stdin)
    else:
        raise ValueError("No packet input provided. Use CLI arg or pipe JSON to stdin.")


def main():
    """Legacy main function for backward compatibility."""
    try:
        packet = read_packet_input()
        validate_packet(packet)
        result = inspect_packet(packet, packet["interface"])
        print(json.dumps({
            "success": True,
            "result": result
        }))
    except Exception as e:
        print(json.dumps({
            "success": False,
            "error": str(e)
        }))
        sys.exit(1)


if __name__ == "__main__":
    # Use new CLI if possible, fall back to legacy for compatibility
    try:
        cli = PacketSimulatorCLI()
        sys.exit(cli.run())
    except Exception:
        # Fall back to legacy behavior
        main()