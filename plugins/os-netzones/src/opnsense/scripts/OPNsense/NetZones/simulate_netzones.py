#!/usr/local/bin/python3

import sys
import json
import socket
import os
import argparse

# Add the NetZones scripts path to import modules
sys.path.insert(0, '/usr/local/opnsense/scripts/OPNsense/NetZones')

try:
    from settings_loader import get_zone_by_ip, get_zone_config
    from netzones_decisions_engine import evaluate_policy
except ImportError as e:
    print(json.dumps({
        "success": False,
        "error": f"Failed to import NetZones modules: {e}",
        "help": "Ensure NetZones is properly installed"
    }, indent=2))
    sys.exit(1)

SOCKET_PATH = "/var/run/netzones.sock"
REQUIRED_FIELDS = ["src", "dst", "port"]

def validate_packet(data):
    """Validate packet data structure"""
    if not isinstance(data, dict):
        raise ValueError("Input must be a JSON object")
    
    missing = [field for field in REQUIRED_FIELDS if field not in data]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")
    
    # Validate IP addresses
    import ipaddress
    try:
        ipaddress.ip_address(data["src"])
        ipaddress.ip_address(data["dst"])
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {e}")
    
    # Validate port
    try:
        port = int(data["port"])
        if not (0 <= port <= 65535):
            raise ValueError(f"Port must be between 0-65535, got: {port}")
        data["port"] = port
    except (ValueError, TypeError):
        raise ValueError("Port must be an integer or convertible to int")
    
    return data

def simulate_via_socket(packet_data):
    """Simulate via socket connection to running evaluator"""
    try:
        if not os.path.exists(SOCKET_PATH):
            raise ConnectionError(f"NetZones socket not found at {SOCKET_PATH}. Is the service running?")
        
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(10.0)
            sock.connect(SOCKET_PATH)
            
            # Send request
            request = json.dumps(packet_data)
            sock.sendall(request.encode())
            
            # Receive response
            response_data = sock.recv(4096)
            response = json.loads(response_data.decode())
            
            return {
                "success": True,
                "method": "socket",
                "decision": response.get("decision", "unknown"),
                "details": response.get("details", {}),
                "evaluator_response": response
            }
            
    except Exception as e:
        raise ConnectionError(f"Socket communication failed: {e}")

def simulate_direct(packet_data):
    """Simulate via direct module calls (fallback)"""
    try:
        src_ip = packet_data["src"]
        dst_ip = packet_data["dst"]
        port = packet_data["port"]
        protocol = packet_data.get("protocol", "tcp")  # Use provided protocol or default to tcp
        
        # Get zones
        src_zone = get_zone_by_ip(src_ip)
        dst_zone = get_zone_by_ip(dst_ip)
        
        # Get zone configurations
        src_config = get_zone_config(src_zone) if src_zone != "UNKNOWN" else None
        dst_config = get_zone_config(dst_zone) if dst_zone != "UNKNOWN" else None
        
        # Evaluate policy
        decision = evaluate_policy(src_zone, dst_zone, protocol, port)
        
        return {
            "success": True,
            "method": "direct",
            "decision": decision,
            "details": {
                "source_zone": src_zone,
                "destination_zone": dst_zone,
                "protocol": protocol,
                "source_config": {
                    "exists": src_config is not None,
                    "security_level": src_config.get("security_level", "unknown") if src_config else None,
                    "isolation_level": src_config.get("isolation_level", "unknown") if src_config else None
                } if src_zone != "UNKNOWN" else None,
                "destination_config": {
                    "exists": dst_config is not None,
                    "security_level": dst_config.get("security_level", "unknown") if dst_config else None,
                    "isolation_level": dst_config.get("isolation_level", "unknown") if dst_config else None
                } if dst_zone != "UNKNOWN" else None
            }
        }
        
    except Exception as e:
        raise RuntimeError(f"Direct evaluation failed: {e}")

def read_input():
    """Read input from various sources"""
    if len(sys.argv) >= 2:
        # Try to parse as JSON from command line
        arg = sys.argv[1]
        if arg.startswith('{') and arg.endswith('}'):
            return json.loads(arg)
        else:
            # Treat as file path
            if os.path.isfile(arg):
                with open(arg, 'r') as f:
                    return json.load(f)
            else:
                raise ValueError(f"File not found: {arg}")
    elif not sys.stdin.isatty():
        # Read from stdin
        return json.load(sys.stdin)
    else:
        raise ValueError("No input provided. Use: JSON string, file path, or pipe JSON to stdin.")

def create_sample_packets():
    """Create sample packets for testing"""
    return [
        {
            "name": "Corporate to DMZ (HTTP)",
            "src": "192.168.1.100",
            "dst": "192.168.2.50",
            "port": 80,
            "protocol": "http"
        },
        {
            "name": "DMZ to Internet (HTTPS)",
            "src": "192.168.2.10",
            "dst": "8.8.8.8",
            "port": 443,
            "protocol": "https"
        },
        {
            "name": "OT Network Modbus",
            "src": "10.0.1.50",
            "dst": "10.0.1.100",
            "port": 502,
            "protocol": "modbus_tcp"
        },
        {
            "name": "Management SSH",
            "src": "192.168.100.5",
            "dst": "192.168.1.1",
            "port": 22,
            "protocol": "ssh"
        },
        {
            "name": "Guest to Corporate (blocked)",
            "src": "192.168.50.100",
            "dst": "192.168.1.50",
            "port": 445,
            "protocol": "smb"
        }
    ]

def run_batch_test():
    """Run batch test with sample packets"""
    samples = create_sample_packets()
    results = []
    
    print("=== NetZones Batch Simulation ===\n")
    
    for i, packet in enumerate(samples, 1):
        name = packet.pop("name", f"Test {i}")
        print(f"[{i}/{len(samples)}] {name}")
        print(f"    {packet['src']}:{packet['port']} -> {packet['dst']} ({packet.get('protocol', 'auto')})")
        
        try:
            # Try socket first, fallback to direct
            try:
                result = simulate_via_socket(packet)
            except (ConnectionError, FileNotFoundError):
                print("    Socket unavailable, using direct evaluation...")
                result = simulate_direct(packet)
            
            decision = result["decision"]
            method = result["method"]
            
            print(f"    Decision: {decision.upper()} (via {method})")
            
            if "details" in result:
                details = result["details"]
                if "source_zone" in details:
                    print(f"    Zones: {details['source_zone']} -> {details['destination_zone']}")
            
            results.append({
                "test": name,
                "packet": packet,
                "result": result
            })
            print()
            
        except Exception as e:
            print(f"    ERROR: {e}\n")
            results.append({
                "test": name,
                "packet": packet,
                "error": str(e)
            })
    
    return results

def main():
    """Main simulation function"""
    parser = argparse.ArgumentParser(description='NetZones Traffic Simulator')
    parser.add_argument('input', nargs='?', help='JSON packet data, file path, or stdin')
    parser.add_argument('--batch', action='store_true', help='Run batch test with sample packets')
    parser.add_argument('--socket-only', action='store_true', help='Use only socket method')
    parser.add_argument('--direct-only', action='store_true', help='Use only direct method')
    parser.add_argument('--output', '-o', help='Output file for results')
    
    args = parser.parse_args()
    
    try:
        if args.batch:
            results = run_batch_test()
            output = {
                "success": True,
                "type": "batch_test",
                "results": results,
                "summary": {
                    "total_tests": len(results),
                    "successful": len([r for r in results if "result" in r]),
                    "failed": len([r for r in results if "error" in r])
                }
            }
        else:
            # Single packet simulation
            packet = read_input()
            packet = validate_packet(packet)
            
            # Choose simulation method
            if args.socket_only:
                output = simulate_via_socket(packet)
            elif args.direct_only:
                output = simulate_direct(packet)
            else:
                # Try socket first, fallback to direct
                try:
                    output = simulate_via_socket(packet)
                except (ConnectionError, FileNotFoundError):
                    output = simulate_direct(packet)
                    output["fallback"] = "Socket unavailable, used direct evaluation"
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            print(json.dumps(output, indent=2))
            
    except Exception as e:
        error_output = {
            "success": False,
            "error": str(e),
            "help": {
                "usage": "Provide JSON packet with src, dst, port fields",
                "example": '{"src": "192.168.1.100", "dst": "192.168.2.50", "port": 80}',
                "batch_test": "Use --batch flag to run sample tests",
                "service_check": "Ensure NetZones service is running for socket method"
            }
        }
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(error_output, f, indent=2)
        else:
            print(json.dumps(error_output, indent=2))
        
        sys.exit(1)

if __name__ == "__main__":
    main()