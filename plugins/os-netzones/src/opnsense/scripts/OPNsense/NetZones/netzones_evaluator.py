#!/usr/local/bin/python3

# netzones_policy_evaluator.py - NetZones Policy Evaluation Server for OPNsense
#
# This script implements a high-performance Unix socket server for real-time policy evaluation
# between network zones. It integrates with the NetZones decision engine, provides caching for
# performance, maintains comprehensive statistics, and supports integration with advanced inspectors.
# The server aligns with OPNsense's XML-based zone and policy model, supporting actions like "pass",
# "block", and "reject". It handles concurrent client connections and provides detailed logging
# and monitoring for dashboard integration.
#
# Key Features:
# - Unix socket listener for low-latency IPC
# - LRU-style caching with TTL for decision reuse
# - Thread-safe statistics collection
# - Graceful shutdown and periodic maintenance
# - Integration with settings_loader for zone/policy data
# - Fail-open policy for safety (defaults to "pass" on errors)

# Author: Pierpaolo Casati
# Version: 1.0.0
#

import socket
import json
import ipaddress
import time
import os
import signal
import sys
import threading
from collections import defaultdict, deque
from settings_loader import (
    get_zone_by_ip, get_zone_config, get_policy_between_zones,
    load_zone_subnet_map, cache_config, get_system_stats
)
from netzones_decisions_engine import evaluate_policy, get_policy_stats, log_decision

# Configuration constants
LOG_FILE = "/var/log/netzones_decisions.log"  # Path for decision and activity logs
SOCKET_PATH = "/var/run/netzones.sock"       # Unix socket for client connections
STATS_FILE = "/var/run/netzones_stats.json"  # JSON file for service statistics export
INSPECTOR_SOCKET = "/var/run/advinspector.sock"  # Socket for advanced inspector integration

# Service state - Global statistics tracking (thread-safe via locks if needed)
running = True  # Service runtime flag for graceful shutdown
service_stats = {
    "start_time": time.time(),                          # Server startup timestamp
    "requests_processed": 0,                            # Total requests handled
    "decisions_pass": 0,                                # Count of "pass" decisions (XML model alignment)
    "decisions_block": 0,                               # Count of "block" decisions (XML model alignment)
    "decisions_reject": 0,                              # Count of "reject" decisions (XML model alignment)
    "cache_hits": 0,                                    # Cache hit counter
    "cache_misses": 0,                                  # Cache miss counter
    "avg_processing_time": 0.0,                         # Running average of request processing time (ms)
    "recent_activities": deque(maxlen=1000),            # Rolling buffer of recent activities (max 1000)
    "protocol_stats": defaultdict(int),                 # Protocol-specific decision counts
    "zone_pair_stats": defaultdict(int),                # Zone pair traffic counts (e.g., "LAN->DMZ")
    "hourly_stats": defaultdict(int)                    # Hourly request volume for trends
}

# Performance cache - In-memory decision storage with TTL
decision_cache = {}  # Dict of {cache_key: {"decision": str, "timestamp": float}}
CACHE_TTL = 300      # Cache entry expiration time (5 minutes)
cache_stats = {"hits": 0, "misses": 0}  # Cache performance metrics

def signal_handler(signum, frame):
    """
    Graceful shutdown handler for SIGTERM and SIGINT signals.

    Ensures statistics are saved, socket is cleaned up, and the service exits cleanly.

    Args:
        signum (int): Signal number
        frame (frame): Current stack frame

    Returns:
        None
    """
    global running
    running = False  # Set shutdown flag
    print("\n[*] NetZones evaluator shutting down...")  # Log shutdown initiation
    save_service_stats()  # Persist final statistics
    try:
        os.unlink(SOCKET_PATH)  # Remove Unix socket file
    except FileNotFoundError:
        pass  # Ignore if socket doesn't exist
    sys.exit(0)  # Exit with success code

# Register signal handlers for graceful shutdown
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

def save_service_stats():
    """
    Save comprehensive service statistics to JSON file for dashboard consumption.

    Combines service stats, policy stats, system stats, and cache metrics into a single exportable structure.

    Returns:
        None
    """
    try:
        # Retrieve system statistics from settings_loader module
        system_stats = get_system_stats()
        
        # Retrieve policy statistics from decision engine
        policy_stats = get_policy_stats()
        
        # Aggregate all statistics into a comprehensive structure
        stats_data = {
            **service_stats,  # Include core service stats
            "uptime": time.time() - service_stats["start_time"],  # Calculate uptime in seconds
            "cache_hits": cache_stats["hits"],                    # Direct cache hit count
            "cache_misses": cache_stats["misses"],                # Direct cache miss count
            "recent_activities": list(service_stats["recent_activities"]),  # Convert deque to list
            "protocol_stats": dict(service_stats["protocol_stats"]),        # Convert defaultdict to dict
            "zone_pair_stats": dict(service_stats["zone_pair_stats"]),      # Convert defaultdict to dict
            "hourly_stats": dict(service_stats["hourly_stats"]),            # Convert defaultdict to dict
            "last_updated": time.time(),  # Timestamp for data freshness
            
            # Integrate system statistics from settings_loader
            "system_stats": system_stats,
            
            # Integrate policy statistics from decision engine
            "policy_stats": policy_stats,
            
            # Include zone-to-subnet mapping for reference
            "zone_subnet_mapping": load_zone_subnet_map(),
            
            # Calculate and include cache efficiency metrics
            "cache_efficiency": {
                "hit_rate": (cache_stats["hits"] / max(1, cache_stats["hits"] + cache_stats["misses"])) * 100,  # Percentage hit rate
                "total_entries": len(decision_cache),          # Current cache size
                "cache_size_limit": 10000                       # Maximum allowed cache entries
            }
        }
        
        # Write statistics to JSON file with indentation for readability
        with open(STATS_FILE, 'w') as f:
            json.dump(stats_data, f, indent=2)
            
    except Exception as e:
        # Log error if stats export fails (non-fatal)
        print(f"[!] Failed to save service stats: {e}")

def get_cache_key(src_ip, dst_ip, port, protocol):
    """
    Generate a unique cache key for policy decisions.

    The key format ensures uniqueness for IP pairs, ports, and protocols.

    Args:
        src_ip (str): Source IP address
        dst_ip (str): Destination IP address
        port (int): Port number
        protocol (str): Protocol identifier (e.g., "tcp")

    Returns:
        str: Cache key in format "src_ip:dst_ip:port:protocol"
    """
    return f"{src_ip}:{dst_ip}:{port}:{protocol}"

def is_cache_valid(entry):
    """
    Check if a cache entry is still valid based on TTL.

    Args:
        entry (dict): Cache entry with "timestamp" key

    Returns:
        bool: True if entry is within TTL, False otherwise
    """
    return time.time() - entry["timestamp"] < CACHE_TTL  # Compare current time against entry age

def update_stats(decision, processing_time, src_zone, dst_zone, protocol, cached=False):
    """
    Update service statistics counters and averages (aligned with XML model actions: pass, block, reject).

    This function is thread-safe for concurrent updates and maintains running averages.

    Args:
        decision (str): Decision outcome ("pass", "block", "reject")
        processing_time (float): Processing time in milliseconds
        src_zone (str): Source zone identifier
        dst_zone (str): Destination zone identifier
        protocol (str): Protocol of the request
        cached (bool): True if decision was from cache (hit)

    Returns:
        None
    """
    global service_stats
    
    service_stats["requests_processed"] += 1  # Increment total request counter
    
    # Update decision-specific counters (XML model alignment: pass/block/reject)
    decision_key = f"decisions_{decision.lower()}"
    if decision_key in service_stats:
        service_stats[decision_key] += 1  # Increment appropriate decision type
    
    # Update cache performance metrics
    if cached:
        service_stats["cache_hits"] += 1      # Local service stat update
        cache_stats["hits"] += 1              # Global cache stat update
    else:
        service_stats["cache_misses"] += 1    # Local service stat update
        cache_stats["misses"] += 1            # Global cache stat update
    
    # Update running average processing time (weighted average formula)
    total_requests = service_stats["requests_processed"]
    current_avg = service_stats["avg_processing_time"]
    service_stats["avg_processing_time"] = (
        (current_avg * (total_requests - 1) + processing_time) / total_requests
    )
    
    # Update protocol-specific statistics
    service_stats["protocol_stats"][protocol] += 1
    
    # Update zone pair statistics (format: "LAN->DMZ")
    zone_pair = f"{src_zone}->{dst_zone}"
    service_stats["zone_pair_stats"][zone_pair] += 1
    
    # Update hourly request volume for trend analysis
    current_hour = time.strftime("%Y-%m-%d %H:00:00")
    service_stats["hourly_stats"][current_hour] += 1
    
    # Log recent activity to rolling buffer
    activity = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "protocol": protocol,
        "decision": decision,
        "processing_time": processing_time,
        "cached": cached
    }
    service_stats["recent_activities"].append(activity)

def validate_request(data):
    """
    Enhanced request validation with comprehensive error checking.

    Validates JSON structure, required fields, IP formats, and port ranges.

    Args:
        data (dict): Incoming request data

    Returns:
        tuple: (src_ip, dst_ip, port) if valid, raises ValueError otherwise
    """
    if not isinstance(data, dict):
        raise ValueError("Request must be a JSON object")
    
    # Check for required fields
    required_fields = ["src", "dst", "port"]
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")
    
    # Validate IP addresses using ipaddress module
    try:
        ipaddress.ip_address(data["src"])
        ipaddress.ip_address(data["dst"])
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {e}")
    
    # Validate port number (0-65535 range)
    try:
        port = int(data["port"])
        if not (0 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port}")
    except (ValueError, TypeError):
        raise ValueError(f"Invalid port: {data['port']}")
    
    return data["src"], data["dst"], port

def handle_netzones_request(data):
    """
    Handle a NetZones policy evaluation request with caching and detailed response.

    This is the core request handler: validates input, checks cache, evaluates policy,
    logs decisions, updates stats, and returns enriched response data.

    Args:
        data (dict): Request data with "src", "dst", "port", "protocol" fields

    Returns:
        dict: Response with decision, details (zones, processing time, policies), and metadata
    """
    start_time = time.time()  # Start timing for performance metrics
    
    try:
        # Validate input parameters
        src_ip, dst_ip, port = validate_request(data)
        
        # Default to TCP if protocol not specified
        protocol = data.get("protocol", "tcp")
        
        # Check cache for existing decision (performance optimization)
        cache_key = get_cache_key(src_ip, dst_ip, port, protocol)
        if cache_key in decision_cache:
            cached_entry = decision_cache[cache_key]
            if is_cache_valid(cached_entry):
                processing_time = (time.time() - start_time) * 1000  # Calculate processing time (ms)
                
                # Resolve zones for stats (even on cache hit)
                src_zone = get_zone_by_ip(src_ip)
                dst_zone = get_zone_by_ip(dst_ip)
                
                # Update statistics for cache hit
                update_stats(
                    cached_entry["decision"], 
                    processing_time, 
                    src_zone, 
                    dst_zone, 
                    protocol, 
                    cached=True
                )
                
                # Return cached response with metadata
                response = {
                    "decision": cached_entry["decision"],
                    "details": {
                        "source_zone": src_zone,
                        "destination_zone": dst_zone,
                        "protocol": protocol,
                        "cached": True,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }
                }
                return response
        
        # Resolve zones using efficient IP-to-zone mapping
        src_zone = get_zone_by_ip(src_ip)
        dst_zone = get_zone_by_ip(dst_ip)
        
        # Retrieve zone configurations for validation and response enrichment
        src_config = get_zone_config(src_zone) if src_zone != "UNKNOWN" else None
        dst_config = get_zone_config(dst_zone) if dst_zone != "UNKNOWN" else None
        
        # Evaluate policy using the decision engine
        decision = evaluate_policy(src_zone, dst_zone, protocol, port)
        
        processing_time = (time.time() - start_time) * 1000  # Final processing time (ms)
        
        # Determine detailed reason based on zone availability
        reason = "Policy evaluation completed"
        if not src_config and src_zone != "UNKNOWN":
            reason = f"Source zone {src_zone} configuration not found"
        elif not dst_config and dst_zone != "UNKNOWN":
            reason = f"Destination zone {dst_zone} configuration not found"
        elif src_zone == "UNKNOWN" or dst_zone == "UNKNOWN":
            reason = "Unknown zone detected"
        
        # Log decision with optional metadata from request
        extra_data = data.get("meta", {})
        log_decision(src_zone, dst_zone, protocol, port, decision, reason, extra_data)
        
        # Cache the new decision for future reuse
        decision_cache[cache_key] = {
            "decision": decision,
            "timestamp": time.time()
        }
        
        # Enforce cache size limit and clean if exceeded
        if len(decision_cache) > 10000:
            clean_cache()
        
        # Update statistics for cache miss
        update_stats(decision, processing_time, src_zone, dst_zone, protocol, cached=False)
        
        # Retrieve policies between zones for response enrichment
        policies_between_zones = get_policy_between_zones(src_zone, dst_zone)
        
        # Build detailed response structure (XML model alignment: zone configs, policies)
        response = {
            "decision": decision,
            "details": {
                "source_zone": src_zone,
                "destination_zone": dst_zone,
                "protocol": protocol,
                "processing_time_ms": processing_time,
                "cached": False,
                "policies_evaluated": len(policies_between_zones),  # Number of policies checked
                "source_zone_config": {  # Source zone details (if available)
                    "exists": src_config is not None,
                    "default_action": src_config.get("default_action", "unknown") if src_config else "unknown",
                    "log_traffic": src_config.get("log_traffic", False) if src_config else False
                } if src_zone != "UNKNOWN" else None,
                "destination_zone_config": {  # Destination zone details (if available)
                    "exists": dst_config is not None,
                    "default_action": dst_config.get("default_action", "unknown") if dst_config else "unknown",
                    "log_traffic": dst_config.get("log_traffic", False) if dst_config else False
                } if dst_zone != "UNKNOWN" else None,
                "applied_policies": [  # Top 3 policies for debugging (with priority)
                    {
                        "name": p.get("name", "unnamed"),
                        "action": p.get("action", "unknown"),
                        "priority": p.get("priority", 999)
                    } for p in policies_between_zones[:3]
                ],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        }
        
        return response
        
    except ValueError as e:
        # Handle validation errors (non-fatal, fail-open policy)
        error_msg = f"Validation error: {str(e)}"
        print(f"[!] {error_msg}")
        return {"error": error_msg, "decision": "pass"}  # XML model fail-open: default to "pass"
        
    except Exception as e:
        # Handle unexpected errors (non-fatal, fail-open policy)
        error_msg = f"Processing error: {str(e)}"
        print(f"[!] {error_msg}")
        return {"error": error_msg, "decision": "pass"}  # XML model fail-open: default to "pass"

def handle_inspector_packet(packet_data):
    """
    Handle packet data from advanced inspector integration.

    Converts inspector-specific format to NetZones request format and forces logging for threats.

    Args:
        packet_data (dict): Inspector packet data (src_ip, dst_ip, dst_port, protocol, etc.)

    Returns:
        dict: Processed response from handle_netzones_request
    """
    try:
        # Map inspector fields to NetZones request format
        netzones_request = {
            "src": packet_data.get("src_ip", ""),
            "dst": packet_data.get("dst_ip", ""),
            "port": packet_data.get("dst_port", packet_data.get("port", 0)),  # Prefer dst_port
            "protocol": packet_data.get("protocol", "tcp").lower(),
            "inspector_session": packet_data.get("session_id", ""),  # Session tracking
            "request_id": packet_data.get("packet_id", "")           # Packet uniqueness
        }
        
        # Add inspector-specific metadata if present
        if packet_data.get("signature_id"):
            netzones_request["signature_id"] = packet_data["signature_id"]
        
        if packet_data.get("threat_level"):
            netzones_request["threat_level"] = packet_data["threat_level"]
            
        # Force detailed logging for high/critical threat levels
        if packet_data.get("threat_level", "low") in ["high", "critical"]:
            netzones_request["force_log"] = True
        
        # Delegate to main request handler
        return handle_netzones_request(netzones_request)
        
    except Exception as e:
        # Log inspector handling errors (non-fatal)
        print(f"[!] Error handling inspector packet: {e}")
        return {"error": str(e), "decision": "pass"}  # Fail-open policy

def clean_cache():
    """
    Remove expired entries from the decision cache to manage memory usage.

    Iterates through cache and deletes entries older than TTL.

    Returns:
        None
    """
    global decision_cache
    current_time = time.time()
    
    # Identify expired entries
    expired_keys = [
        key for key, entry in decision_cache.items()
        if current_time - entry["timestamp"] > CACHE_TTL
    ]
    
    # Remove expired entries
    for key in expired_keys:
        del decision_cache[key]
    
    # Log cleanup activity
    print(f"[*] Cleaned {len(expired_keys)} expired cache entries")

def handle_client(conn, addr):
    """
    Handle individual client connection with timeout and error recovery.

    Processes multiple requests per connection in a loop, with JSON parsing and response sending.

    Args:
        conn (socket.socket): Client socket connection
        addr (tuple): Client address (for logging)

    Returns:
        None
    """
    try:
        conn.settimeout(10.0)  # 10-second timeout per request
        
        while running:  # Loop until shutdown or connection closes
            try:
                # Receive up to 4KB of data
                data = conn.recv(4096)
                if not data:
                    break  # Client disconnected
                
                # Parse incoming JSON request
                try:
                    request = json.loads(data.decode('utf-8'))
                except json.JSONDecodeError as e:
                    # Respond to invalid JSON with error
                    error_response = {
                        "error": f"Invalid JSON: {str(e)}",
                        "decision": "pass"  # Fail-open
                    }
                    conn.sendall(json.dumps(error_response).encode())
                    continue
                
                # Route based on request type (inspector vs standard)
                if request.get("type") == "inspector_packet":
                    response = handle_inspector_packet(request.get("data", {}))
                else:
                    response = handle_netzones_request(request)
                
                # Send JSON response
                response_json = json.dumps(response)
                conn.sendall(response_json.encode())
                
            except socket.timeout:
                print("[!] Client connection timeout")  # Handle read timeout
                break
            except ConnectionResetError:
                print("[!] Client connection reset")  # Handle abrupt disconnect
                break
            except Exception as e:
                # Handle other request errors
                print(f"[!] Error handling client: {e}")
                error_response = {
                    "error": f"Server error: {str(e)}",
                    "decision": "pass"  # Fail-open
                }
                try:
                    conn.sendall(json.dumps(error_response).encode())
                except:
                    pass  # Ignore send errors on error path
                break
                
    except Exception as e:
        # Top-level client handler error
        print(f"[!] Client handler error: {e}")
    finally:
        # Ensure connection cleanup
        try:
            conn.close()
        except:
            pass  # Ignore close errors

def ensure_socket_permissions():
    """
    Set appropriate permissions on the Unix socket (0666 for broad access).

    Ensures clients can connect without permission issues.

    Returns:
        None
    """
    try:
        if os.path.exists(SOCKET_PATH):
            os.chmod(SOCKET_PATH, 0o666)  # World-readable/writable for socket
    except Exception as e:
        print(f"[!] Could not set socket permissions: {e}")

def periodic_maintenance():
    """
    Background thread for periodic tasks: stats export, cache cleaning, config refresh.

    Runs every 60 seconds, with cache cleaning every 10 minutes.

    Returns:
        None
    """
    while running:  # Loop until shutdown
        try:
            time.sleep(60)  # Wait 1 minute between cycles
            
            # Export statistics to file
            save_service_stats()
            
            # Clean cache every 10 minutes (600 seconds)
            if int(time.time()) % 600 == 0:
                clean_cache()
                
                # Log maintenance summary
                print(f"[*] Periodic maintenance completed")
                print(f"    - Cache entries: {len(decision_cache)}")
                print(f"    - Requests processed: {service_stats['requests_processed']}")
                
                # Log system health from settings_loader
                sys_stats = get_system_stats()
                print(f"    - Active zones: {sys_stats.get('zones', {}).get('active', 0)}")
                print(f"    - Active policies: {sys_stats.get('policies', {}).get('active', 0)}")
            
            # Refresh configuration cache from settings_loader
            cache_config()
            
        except Exception as e:
            # Log maintenance errors (non-fatal)
            print(f"[!] Maintenance error: {e}")

def get_status_info():
    """
    Retrieve comprehensive status information for monitoring and health checks.

    Aggregates service, cache, zone, policy, and recent activity data.

    Returns:
        dict: Status object with service metrics, cache stats, zone/policy counts, and recent activities
    """
    try:
        # Gather system statistics
        sys_stats = get_system_stats()
        
        # Gather policy statistics
        pol_stats = get_policy_stats()
        
        # Gather zone mapping
        zone_mapping = load_zone_subnet_map()
        
        # Build status response
        status = {
            "service": {  # Core service metrics
                "running": True,
                "uptime": time.time() - service_stats["start_time"],
                "requests_processed": service_stats["requests_processed"],
                "avg_processing_time": service_stats["avg_processing_time"]
            },
            "cache": {  # Cache performance
                "entries": len(decision_cache),
                "hits": cache_stats["hits"],
                "misses": cache_stats["misses"],
                "hit_rate": (cache_stats["hits"] / max(1, cache_stats["hits"] + cache_stats["misses"])) * 100
            },
            "zones": {  # Zone configuration summary
                "configured": len(zone_mapping),
                "active": sys_stats.get("zones", {}).get("active", 0),
                "total": sys_stats.get("zones", {}).get("total", 0)
            },
            "policies": {  # Policy configuration summary
                "active": sys_stats.get("policies", {}).get("active", 0),
                "total": sys_stats.get("policies", {}).get("total", 0),
                "decisions": pol_stats.get("total_decisions", 0)
            },
            "recent_activity": list(service_stats["recent_activities"])[-10:]  # Last 10 activities
        }
        
        return status
        
    except Exception as e:
        # Log status retrieval errors
        print(f"[!] Error getting status info: {e}")
        return {"error": str(e)}

def run_server():
    """
    Main server loop: sets up Unix socket, handles connections, and manages threads.

    Listens for up to 20 concurrent connections with 1-second accept timeout.

    Returns:
        None
    """
    # Cleanup any existing socket file
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass  # Normal if no prior socket
    except Exception as e:
        print(f"[!] Error removing old socket: {e}")
    
    # Ensure socket directory exists
    socket_dir = os.path.dirname(SOCKET_PATH)
    if socket_dir and not os.path.exists(socket_dir):
        try:
            os.makedirs(socket_dir, mode=0o755)  # Standard directory permissions
        except Exception as e:
            print(f"[!] Could not create socket directory: {e}")
            return
    
    # Start background maintenance thread (daemon: exits with main thread)
    maintenance_thread = threading.Thread(target=periodic_maintenance)
    maintenance_thread.daemon = True
    maintenance_thread.start()
    
    # Main server setup and loop
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(SOCKET_PATH)  # Bind to Unix socket
            ensure_socket_permissions()  # Set broad access permissions
            
            server.listen(20)  # Allow up to 20 queued connections
            print(f"[*] NetZones policy evaluator listening on {SOCKET_PATH}")
            print(f"[*] Service statistics will be saved to {STATS_FILE}")
            print(f"[*] Decision logs will be written to {LOG_FILE}")
            
            while running:  # Accept loop until shutdown
                try:
                    server.settimeout(1.0)  # 1-second timeout for non-blocking accept
                    conn, addr = server.accept()
                    print(f"[+] New client connection")  # Log new connection
                    
                    # Spawn client handler in daemon thread
                    client_thread = threading.Thread(
                        target=handle_client, 
                        args=(conn, addr)
                    )
                    client_thread.daemon = True  # Auto-cleanup on shutdown
                    client_thread.start()
                    
                except socket.timeout:
                    continue  # Timeout: check shutdown flag and retry
                except Exception as e:
                    if running:  # Only log if not shutting down
                        print(f"[!] Error accepting connections: {e}")
                        time.sleep(1)  # Brief pause on error
                    
    except Exception as e:
        # Log server startup/runtime errors
        print(f"[!] Server error: {e}")
    finally:
        # Cleanup socket on exit
        try:
            os.unlink(SOCKET_PATH)
        except:
            pass

def test_evaluator():
    """
    Comprehensive test suite for the policy evaluator.

    Tests zone resolution, policy evaluation, statistics, and cache performance with sample data.

    Returns:
        None (prints results to stdout)
    """
    print("=== NetZones Policy Evaluator Test ===")
    
    # Section 1: System and configuration information
    print("\n--- System Information ---")
    sys_stats = get_system_stats()
    print(f"System Stats: {sys_stats}")
    
    zone_mapping = load_zone_subnet_map()
    print(f"Zone Mappings: {zone_mapping}")
    
    policy_stats = get_policy_stats()
    print(f"Policy Stats: {policy_stats}")
    
    # Section 2: Policy evaluation test cases
    test_cases = [
        {
            "src": "192.168.1.100",  # LAN example
            "dst": "192.168.2.50",   # DMZ example
            "port": 502,             # Modbus (industrial)
            "protocol": "tcp"
        },
        {
            "src": "10.0.0.10",      # Internal example
            "dst": "192.168.1.1",    # LAN gateway
            "port": 80,              # HTTP
            "protocol": "tcp"
        },
        {
            "src": "192.168.1.5",    # LAN client
            "dst": "8.8.8.8",        # External DNS
            "port": 443,             # HTTPS
            "protocol": "tcp"
        }
    ]
    
    print("\n--- Policy Evaluation Tests ---")
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        
        # Test zone resolution
        src_zone = get_zone_by_ip(test_case["src"])
        dst_zone = get_zone_by_ip(test_case["dst"])
        print(f"Source IP {test_case['src']} -> Zone: {src_zone}")
        print(f"Destination IP {test_case['dst']} -> Zone: {dst_zone}")
        
        # Test zone configurations
        if src_zone != "UNKNOWN":
            src_config = get_zone_config(src_zone)
            if src_config:
                print(f"Source zone config: {src_config['default_action']}")
        
        if dst_zone != "UNKNOWN":
            dst_config = get_zone_config(dst_zone)
            if dst_config:
                print(f"Destination zone config: {dst_config['default_action']}")
        
        # Test policy retrieval
        policies = get_policy_between_zones(src_zone, dst_zone)
        print(f"Policies between zones: {len(policies)}")
        for policy in policies[:2]:  # Limit to first 2 for brevity
            print(f"  - {policy.get('name', 'unnamed')}: {policy.get('action', 'unknown')}")
        
        # Execute evaluation
        result = handle_netzones_request(test_case)
        print(f"Request: {test_case}")
        print(f"Decision: {result['decision']}")
        print(f"Details: {result.get('details', {})}")
    
    # Section 3: Final statistics and performance
    print(f"\n--- Final Service Statistics ---")
    save_service_stats()  # Persist test stats
    
    status = get_status_info()
    print(f"Service Status: {status}")
    
    print(f"\n--- Cache Performance ---")
    print(f"Cache entries: {len(decision_cache)}")
    print(f"Cache hits: {cache_stats['hits']}")
    print(f"Cache misses: {cache_stats['misses']}")
    if cache_stats['hits'] + cache_stats['misses'] > 0:
        hit_rate = (cache_stats['hits'] / (cache_stats['hits'] + cache_stats['misses'])) * 100
        print(f"Hit rate: {hit_rate:.2f}%")

if __name__ == "__main__":
    # Entry point: test mode vs production server mode
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_evaluator()  # Run comprehensive test suite
    else:
        print("[*] Starting NetZones policy evaluator...")
        print("[*] Integration with advinspector enabled")  # Note inspector support
        run_server()  # Start production server