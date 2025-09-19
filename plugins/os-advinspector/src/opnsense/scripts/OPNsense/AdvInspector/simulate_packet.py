#!/usr/local/bin/python3

"""
Packet Tester Module for Advanced Network Inspector

Command-line testing utility for packet inspection engine. Supports multiple
input formats, comprehensive validation, detailed output formatting, and
batch processing capabilities for security rule testing and development.

Features:
- Multiple input methods (CLI args, stdin, file)
- Comprehensive packet validation
- Structured JSON output with detailed results
- Batch processing for multiple packets
- Performance timing and statistics
- Flexible output formatting options

Author: System Administrator
Version: 1.0
"""

import json
import sys
import argparse
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, TextIO
from enum import Enum
import ipaddress


class InputSource(Enum):
    """Enumeration of available input sources."""
    CLI_ARGUMENT = "cli_argument"
    STDIN = "stdin"
    FILE = "file"


class OutputFormat(Enum):
    """Enumeration of available output formats."""
    JSON = "json"
    YAML = "yaml"
    TABLE = "table"
    SUMMARY = "summary"


@dataclass
class PacketValidationResult:
    """Result of packet validation operation."""
    valid: bool
    errors: List[str]
    warnings: List[str]
    normalized_packet: Optional[Dict[str, Any]] = None


@dataclass
class InspectionResult:
    """Result of packet inspection operation."""
    success: bool
    action: str
    execution_time: float
    packet_data: Dict[str, Any]
    error_message: Optional[str] = None
    rule_matches: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class TestSession:
    """Complete test session results."""
    total_packets: int
    successful_tests: int
    failed_tests: int
    total_execution_time: float
    results: List[InspectionResult]
    start_time: float
    end_time: float


class PacketValidationError(Exception):
    """Custom exception for packet validation errors."""
    pass


class InputProcessingError(Exception):
    """Custom exception for input processing errors."""
    pass


class PacketValidator:
    """
    Comprehensive packet validator with field validation and normalization.
    """
    
    # Required fields for basic packet inspection
    REQUIRED_FIELDS = {
        "src": str,      # Source IP address
        "dst": str,      # Destination IP address
        "port": int,     # Destination port
        "interface": str # Network interface
    }
    
    # Optional fields with expected types
    OPTIONAL_FIELDS = {
        "src_port": int,
        "dst_port": int,
        "protocol": str,
        "application_protocol": str,
        "ip_protocol": int,
        "timestamp": float,
        "raw": str,
        "metadata": dict
    }
    
    def __init__(self):
        """Initialize packet validator."""
        self.validation_stats = {
            "total_validations": 0,
            "successful_validations": 0,
            "validation_errors": 0
        }
    
    def validate_packet(self, packet: Dict[str, Any]) -> PacketValidationResult:
        """
        Comprehensive packet validation with normalization.
        
        Args:
            packet: Raw packet data dictionary
            
        Returns:
            PacketValidationResult with validation status and normalized data
        """
        self.validation_stats["total_validations"] += 1
        
        errors = []
        warnings = []
        normalized_packet = packet.copy()
        
        try:
            # Check required fields
            missing_fields = self._check_required_fields(packet)
            if missing_fields:
                errors.extend([f"Missing required field: {field}" for field in missing_fields])
            
            # Validate field types and values
            type_errors = self._validate_field_types(packet)
            errors.extend(type_errors)
            
            # Validate IP addresses
            ip_errors, ip_warnings = self._validate_ip_addresses(packet)
            errors.extend(ip_errors)
            warnings.extend(ip_warnings)
            
            # Validate ports
            port_errors = self._validate_ports(packet)
            errors.extend(port_errors)
            
            # Normalize packet data
            if not errors:
                normalized_packet = self._normalize_packet(packet)
                self.validation_stats["successful_validations"] += 1
            else:
                self.validation_stats["validation_errors"] += 1
            
            return PacketValidationResult(
                valid=len(errors) == 0,
                errors=errors,
                warnings=warnings,
                normalized_packet=normalized_packet if not errors else None
            )
            
        except Exception as e:
            self.validation_stats["validation_errors"] += 1
            return PacketValidationResult(
                valid=False,
                errors=[f"Validation exception: {str(e)}"],
                warnings=[],
                normalized_packet=None
            )
    
    def _check_required_fields(self, packet: Dict[str, Any]) -> List[str]:
        """Check for missing required fields."""
        return [field for field in self.REQUIRED_FIELDS.keys() if field not in packet]
    
    def _validate_field_types(self, packet: Dict[str, Any]) -> List[str]:
        """Validate field types against expected types."""
        errors = []
        
        # Check required field types
        for field, expected_type in self.REQUIRED_FIELDS.items():
            if field in packet:
                value = packet[field]
                if not isinstance(value, expected_type):
                    # Try to convert common cases
                    if expected_type == int and isinstance(value, str):
                        try:
                            int(value)
                            continue  # Conversion possible
                        except ValueError:
                            pass
                    
                    errors.append(f"Field '{field}' must be of type {expected_type.__name__}, got {type(value).__name__}")
        
        # Check optional field types
        for field, expected_type in self.OPTIONAL_FIELDS.items():
            if field in packet:
                value = packet[field]
                if not isinstance(value, expected_type):
                    errors.append(f"Optional field '{field}' must be of type {expected_type.__name__}, got {type(value).__name__}")
        
        return errors
    
    def _validate_ip_addresses(self, packet: Dict[str, Any]) -> tuple[List[str], List[str]]:
        """Validate IP address fields."""
        errors = []
        warnings = []
        
        for field in ["src", "dst"]:
            if field in packet:
                try:
                    ip = ipaddress.ip_address(packet[field])
                    
                    # Check for private/public address warnings
                    if ip.is_private:
                        warnings.append(f"Field '{field}' contains private IP address: {ip}")
                    if ip.is_loopback:
                        warnings.append(f"Field '{field}' contains loopback address: {ip}")
                    if ip.is_multicast:
                        warnings.append(f"Field '{field}' contains multicast address: {ip}")
                        
                except ValueError as e:
                    errors.append(f"Invalid IP address in field '{field}': {e}")
        
        return errors, warnings
    
    def _validate_ports(self, packet: Dict[str, Any]) -> List[str]:
        """Validate port number fields."""
        errors = []
        
        port_fields = ["port", "src_port", "dst_port"]
        
        for field in port_fields:
            if field in packet:
                try:
                    port = int(packet[field])
                    if not (1 <= port <= 65535):
                        errors.append(f"Port '{field}' must be between 1 and 65535, got {port}")
                except (ValueError, TypeError):
                    errors.append(f"Port '{field}' must be a valid integer")
        
        return errors
    
    def _normalize_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize packet data to standard format."""
        normalized = packet.copy()
        
        # Ensure port fields are integers
        for port_field in ["port", "src_port", "dst_port"]:
            if port_field in normalized:
                normalized[port_field] = int(normalized[port_field])
        
        # Normalize protocol names to lowercase
        if "protocol" in normalized:
            normalized["protocol"] = normalized["protocol"].lower().strip()
        
        if "application_protocol" in normalized:
            normalized["application_protocol"] = normalized["application_protocol"].lower().strip()
        
        # Add timestamp if not present
        if "timestamp" not in normalized:
            normalized["timestamp"] = time.time()
        
        # Ensure dst_port matches port if not specified
        if "dst_port" not in normalized and "port" in normalized:
            normalized["dst_port"] = normalized["port"]
        
        return normalized
    
    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        stats = self.validation_stats.copy()
        if stats["total_validations"] > 0:
            stats["success_rate"] = stats["successful_validations"] / stats["total_validations"] * 100
        else:
            stats["success_rate"] = 0
        return stats


class InputReader(ABC):
    """Abstract base class for packet input readers."""
    
    @abstractmethod
    def read_packets(self) -> List[Dict[str, Any]]:
        """
        Read packet data from input source.
        
        Returns:
            List of packet dictionaries
            
        Raises:
            InputProcessingError: If input reading fails
        """
        pass


class CLIArgumentReader(InputReader):
    """Read packet data from command line arguments."""
    
    def __init__(self, json_string: str):
        """
        Initialize CLI argument reader.
        
        Args:
            json_string: JSON string containing packet data
        """
        self.json_string = json_string
    
    def read_packets(self) -> List[Dict[str, Any]]:
        """Read packet from CLI argument JSON string."""
        try:
            data = json.loads(self.json_string)
            
            # Handle both single packet and list of packets
            if isinstance(data, dict):
                return [data]
            elif isinstance(data, list):
                return data
            else:
                raise InputProcessingError("Input must be a JSON object or array")
                
        except json.JSONDecodeError as e:
            raise InputProcessingError(f"Invalid JSON in CLI argument: {e}")


class StdinReader(InputReader):
    """Read packet data from standard input."""
    
    def __init__(self, stdin: TextIO = sys.stdin):
        """
        Initialize stdin reader.
        
        Args:
            stdin: Input stream (defaults to sys.stdin)
        """
        self.stdin = stdin
    
    def read_packets(self) -> List[Dict[str, Any]]:
        """Read packet data from stdin."""
        try:
            if self.stdin.isatty():
                raise InputProcessingError("No input data provided via stdin")
            
            data = json.load(self.stdin)
            
            # Handle both single packet and list of packets
            if isinstance(data, dict):
                return [data]
            elif isinstance(data, list):
                return data
            else:
                raise InputProcessingError("Input must be a JSON object or array")
                
        except json.JSONDecodeError as e:
            raise InputProcessingError(f"Invalid JSON in stdin: {e}")


class FileReader(InputReader):
    """Read packet data from file."""
    
    def __init__(self, file_path: Path):
        """
        Initialize file reader.
        
        Args:
            file_path: Path to input file
        """
        self.file_path = file_path
    
    def read_packets(self) -> List[Dict[str, Any]]:
        """Read packet data from file."""
        try:
            if not self.file_path.exists():
                raise InputProcessingError(f"Input file not found: {self.file_path}")
            
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle both single packet and list of packets
            if isinstance(data, dict):
                return [data]
            elif isinstance(data, list):
                return data
            else:
                raise InputProcessingError("File must contain a JSON object or array")
                
        except json.JSONDecodeError as e:
            raise InputProcessingError(f"Invalid JSON in file {self.file_path}: {e}")
        except Exception as e:
            raise InputProcessingError(f"Error reading file {self.file_path}: {e}")


class PacketInspectionTester:
    """
    Main packet inspection testing engine with comprehensive testing capabilities.
    """
    
    def __init__(self, validator: Optional[PacketValidator] = None):
        """
        Initialize packet inspection tester.
        
        Args:
            validator: Packet validator instance (defaults to PacketValidator)
        """
        self.validator = validator or PacketValidator()
        self.session_stats = {
            "sessions_run": 0,
            "total_packets_tested": 0,
            "total_execution_time": 0.0
        }
    
    def test_packet(self, packet: Dict[str, Any]) -> InspectionResult:
        """
        Test a single packet through the inspection engine.
        
        Args:
            packet: Packet data to test
            
        Returns:
            InspectionResult with test outcomes
        """
        start_time = time.time()
        
        try:
            # Validate packet first
            validation_result = self.validator.validate_packet(packet)
            
            if not validation_result.valid:
                return InspectionResult(
                    success=False,
                    action="validation_failed",
                    execution_time=time.time() - start_time,
                    packet_data=packet,
                    error_message=f"Validation errors: {', '.join(validation_result.errors)}"
                )
            
            # Import here to avoid circular imports
            from packet_inspector import inspect_packet
            
            # Use normalized packet for inspection
            normalized_packet = validation_result.normalized_packet
            interface = normalized_packet["interface"]
            
            # Perform inspection
            inspection_result = inspect_packet(normalized_packet, interface)
            
            execution_time = time.time() - start_time
            
            return InspectionResult(
                success=True,
                action=inspection_result,
                execution_time=execution_time,
                packet_data=normalized_packet,
                metadata={
                    "validation_warnings": validation_result.warnings,
                    "original_packet": packet
                }
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            logging.error(f"Packet inspection test failed: {e}")
            
            return InspectionResult(
                success=False,
                action="inspection_error",
                execution_time=execution_time,
                packet_data=packet,
                error_message=str(e)
            )
    
    def test_packets(self, packets: List[Dict[str, Any]]) -> TestSession:
        """
        Test multiple packets and return comprehensive session results.
        
        Args:
            packets: List of packet dictionaries to test
            
        Returns:
            TestSession with complete results
        """
        session_start = time.time()
        results = []
        successful_tests = 0
        failed_tests = 0
        
        for packet in packets:
            result = self.test_packet(packet)
            results.append(result)
            
            if result.success:
                successful_tests += 1
            else:
                failed_tests += 1
        
        session_end = time.time()
        total_execution_time = session_end - session_start
        
        # Update global stats
        self.session_stats["sessions_run"] += 1
        self.session_stats["total_packets_tested"] += len(packets)
        self.session_stats["total_execution_time"] += total_execution_time
        
        return TestSession(
            total_packets=len(packets),
            successful_tests=successful_tests,
            failed_tests=failed_tests,
            total_execution_time=total_execution_time,
            results=results,
            start_time=session_start,
            end_time=session_end
        )
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get testing session statistics."""
        stats = self.session_stats.copy()
        if stats["total_packets_tested"] > 0:
            stats["average_execution_time"] = stats["total_execution_time"] / stats["total_packets_tested"]
        else:
            stats["average_execution_time"] = 0
        return stats


class OutputFormatter(ABC):
    """Abstract base class for output formatters."""
    
    @abstractmethod
    def format_result(self, result: Union[InspectionResult, TestSession]) -> str:
        """
        Format inspection result or test session for output.
        
        Args:
            result: Result to format
            
        Returns:
            Formatted output string
        """
        pass


class JSONOutputFormatter(OutputFormatter):
    """JSON output formatter with structured data."""
    
    def __init__(self, pretty: bool = True):
        """
        Initialize JSON formatter.
        
        Args:
            pretty: Whether to use pretty printing
        """
        self.pretty = pretty
    
    def format_result(self, result: Union[InspectionResult, TestSession]) -> str:
        """Format result as JSON."""
        if isinstance(result, InspectionResult):
            output_data = {
                "success": result.success,
                "action": result.action,
                "execution_time": result.execution_time,
                "packet": result.packet_data
            }
            
            if result.error_message:
                output_data["error"] = result.error_message
            
            if result.metadata:
                output_data["metadata"] = result.metadata
                
        elif isinstance(result, TestSession):
            output_data = {
                "session_summary": {
                    "total_packets": result.total_packets,
                    "successful_tests": result.successful_tests,
                    "failed_tests": result.failed_tests,
                    "success_rate": (result.successful_tests / result.total_packets * 100) if result.total_packets > 0 else 0,
                    "total_execution_time": result.total_execution_time,
                    "average_execution_time": result.total_execution_time / result.total_packets if result.total_packets > 0 else 0
                },
                "results": [asdict(r) for r in result.results]
            }
        else:
            output_data = {"error": "Unknown result type"}
        
        if self.pretty:
            return json.dumps(output_data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(output_data, ensure_ascii=False)


class SummaryOutputFormatter(OutputFormatter):
    """Human-readable summary formatter."""
    
    def format_result(self, result: Union[InspectionResult, TestSession]) -> str:
        """Format result as human-readable summary."""
        if isinstance(result, InspectionResult):
            lines = []
            lines.append(f"✓ Packet Test Result: {'SUCCESS' if result.success else 'FAILED'}")
            lines.append(f"  Action: {result.action}")
            lines.append(f"  Execution Time: {result.execution_time:.6f}s")
            lines.append(f"  Source: {result.packet_data.get('src', 'unknown')}")
            lines.append(f"  Destination: {result.packet_data.get('dst', 'unknown')}:{result.packet_data.get('port', 'unknown')}")
            lines.append(f"  Protocol: {result.packet_data.get('protocol', 'unknown')}")
            
            if result.error_message:
                lines.append(f"  Error: {result.error_message}")
            
            return '\n'.join(lines)
            
        elif isinstance(result, TestSession):
            lines = []
            lines.append("Test Session Summary")
            lines.append(f"  Total Packets: {result.total_packets}")
            lines.append(f"  Successful: {result.successful_tests}")
            lines.append(f"  Failed: {result.failed_tests}")
            
            if result.total_packets > 0:
                success_rate = result.successful_tests / result.total_packets * 100
                lines.append(f"  Success Rate: {success_rate:.1f}%")
            
            lines.append(f"  Total Time: {result.total_execution_time:.6f}s")
            
            if result.total_packets > 0:
                avg_time = result.total_execution_time / result.total_packets
                lines.append(f"  Average Time: {avg_time:.6f}s per packet")
            
            return '\n'.join(lines)
        
        return "Unknown result type"


class PacketTestCLI:
    """
    Command-line interface for packet testing with comprehensive argument support.
    """
    
    def __init__(self):
        """Initialize CLI interface."""
        self.tester = PacketInspectionTester()
        self.setup_argument_parser()
    
    def setup_argument_parser(self) -> None:
        """Setup command line argument parser."""
        self.parser = argparse.ArgumentParser(
            description="Advanced Network Inspector Packet Tester",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s '{"src":"192.168.1.1","dst":"10.0.1.1","port":80,"interface":"eth0"}'
  echo '{"src":"192.168.1.1","dst":"10.0.1.1","port":80,"interface":"eth0"}' | %(prog)s
  %(prog)s --file packets.json --output-format summary
  %(prog)s --stdin --verbose
            """
        )
        
        # Input options (mutually exclusive)
        input_group = self.parser.add_mutually_exclusive_group(required=True)
        input_group.add_argument(
            "packet_json", nargs='?',
            help="JSON string containing packet data"
        )
        input_group.add_argument(
            "--stdin", action="store_true",
            help="Read packet data from stdin"
        )
        input_group.add_argument(
            "--file", type=Path,
            help="Read packet data from file"
        )
        
        # Output options
        self.parser.add_argument(
            "--output-format", choices=["json", "summary"], default="json",
            help="Output format (default: json)"
        )
        self.parser.add_argument(
            "--pretty", action="store_true", default=True,
            help="Pretty-print JSON output (default: True)"
        )
        self.parser.add_argument(
            "--verbose", "-v", action="store_true",
            help="Enable verbose output"
        )
        
        # Testing options
        self.parser.add_argument(
            "--validate-only", action="store_true",
            help="Only validate packets without running inspection"
        )
    
    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Run the CLI application.
        
        Args:
            args: Command line arguments (defaults to sys.argv)
            
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        try:
            parsed_args = self.parser.parse_args(args)
            
            # Setup logging
            if parsed_args.verbose:
                logging.basicConfig(level=logging.DEBUG)
            else:
                logging.basicConfig(level=logging.WARNING)
            
            # Read input
            packets = self._read_input(parsed_args)
            
            # Process packets
            if parsed_args.validate_only:
                results = self._validate_only(packets)
            else:
                results = self.tester.test_packets(packets)
            
            # Format and output results
            formatted_output = self._format_output(results, parsed_args)
            print(formatted_output)
            
            # Return appropriate exit code
            if isinstance(results, TestSession):
                return 0 if results.failed_tests == 0 else 1
            else:
                return 0
                
        except Exception as e:
            error_output = {
                "success": False,
                "error": str(e)
            }
            print(json.dumps(error_output, indent=2))
            return 1
    
    def _read_input(self, args) -> List[Dict[str, Any]]:
        """Read input based on command line arguments."""
        if args.packet_json:
            reader = CLIArgumentReader(args.packet_json)
        elif args.stdin:
            reader = StdinReader()
        elif args.file:
            reader = FileReader(args.file)
        else:
            raise InputProcessingError("No input method specified")
        
        return reader.read_packets()
    
    def _validate_only(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform validation-only processing."""
        results = []
        
        for packet in packets:
            validation_result = self.tester.validator.validate_packet(packet)
            results.append({
                "packet": packet,
                "valid": validation_result.valid,
                "errors": validation_result.errors,
                "warnings": validation_result.warnings
            })
        
        return {
            "validation_summary": {
                "total_packets": len(packets),
                "valid_packets": sum(1 for r in results if r["valid"]),
                "invalid_packets": sum(1 for r in results if not r["valid"])
            },
            "results": results
        }
    
    def _format_output(self, results: Union[TestSession, Dict[str, Any]], args) -> str:
        """Format output based on command line arguments."""
        if args.output_format == "json":
            formatter = JSONOutputFormatter(pretty=args.pretty)
        else:  # summary
            formatter = SummaryOutputFormatter()
        
        if isinstance(results, dict):  # Validation-only results
            if args.output_format == "json":
                return json.dumps(results, indent=2 if args.pretty else None)
            else:
                # Create summary for validation results
                summary = results["validation_summary"]
                lines = [
                    "Validation Results",
                    f"  Total Packets: {summary['total_packets']}",
                    f"  Valid: {summary['valid_packets']}",
                    f"  Invalid: {summary['invalid_packets']}"
                ]
                return '\n'.join(lines)
        else:
            return formatter.format_result(results)


def main():
    """Main entry point for command line execution."""
    cli = PacketTestCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())