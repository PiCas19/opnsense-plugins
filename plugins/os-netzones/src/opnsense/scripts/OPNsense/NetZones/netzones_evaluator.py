#!/usr/local/bin/python3

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

# Configuration
LOG_FILE = "/var/log/netzones_decisions.log"
SOCKET_PATH = "/var/run/netzones.sock"
STATS_FILE = "/var/run/netzones_stats.json"
INSPECTOR_SOCKET = "/var/run/advinspector.sock"

# Service state
running = True
service_stats = {
    "start_time": time.time(),
    "requests_processed": 0,
    "decisions_pass": 0,   # Allineato al modello XML (pass invece di allow)
    "decisions_block": 0,
    "decisions_reject": 0, # Aggiunto reject dal modello XML
    "cache_hits": 0,
    "cache_misses": 0,
    "avg_processing_time": 0.0,
    "recent_activities": deque(maxlen=1000),
    "protocol_stats": defaultdict(int),
    "zone_pair_stats": defaultdict(int),
    "hourly_stats": defaultdict(int)
}

# Performance cache
decision_cache = {}
CACHE_TTL = 300  # 5 minutes
cache_stats = {"hits": 0, "misses": 0}


def signal_handler(signum, frame):
    """Graceful shutdown handler"""
    global running
    running = False
    print("\n[*] NetZones evaluator shutting down...")
    save_service_stats()
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass
    sys.exit(0)


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def save_service_stats():
    """Save service statistics to file for dashboard"""
    try:
        # Get system stats from settings_loader
        system_stats = get_system_stats()
        
        # Get policy stats from netzones_decision_engine
        policy_stats = get_policy_stats()
        
        # Combine all statistics
        stats_data = {
            **service_stats,
            "uptime": time.time() - service_stats["start_time"],
            "cache_hits": cache_stats["hits"],
            "cache_misses": cache_stats["misses"],
            "recent_activities": list(service_stats["recent_activities"]),
            "protocol_stats": dict(service_stats["protocol_stats"]),
            "zone_pair_stats": dict(service_stats["zone_pair_stats"]),
            "hourly_stats": dict(service_stats["hourly_stats"]),
            "last_updated": time.time(),
            
            # Add system stats from settings_loader
            "system_stats": system_stats,
            
            # Add policy stats from netzones_decision_engine  
            "policy_stats": policy_stats,
            
            # Add zone mapping info
            "zone_subnet_mapping": load_zone_subnet_map(),
            
            # Add cache efficiency metrics
            "cache_efficiency": {
                "hit_rate": (cache_stats["hits"] / max(1, cache_stats["hits"] + cache_stats["misses"])) * 100,
                "total_entries": len(decision_cache),
                "cache_size_limit": 10000
            }
        }
        
        with open(STATS_FILE, 'w') as f:
            json.dump(stats_data, f, indent=2)
            
    except Exception as e:
        print(f"[!] Failed to save service stats: {e}")


def get_cache_key(src_ip, dst_ip, port, protocol):
    """Generate cache key for decision"""
    return f"{src_ip}:{dst_ip}:{port}:{protocol}"


def is_cache_valid(entry):
    """Check if cache entry is still valid"""
    return time.time() - entry["timestamp"] < CACHE_TTL


def update_stats(decision, processing_time, src_zone, dst_zone, protocol, cached=False):
    """Update service statistics (allineato alle azioni del modello XML)"""
    global service_stats
    
    service_stats["requests_processed"] += 1
    
    # Decision counts - allineato al modello XML (pass, block, reject)
    decision_key = f"decisions_{decision.lower()}"
    if decision_key in service_stats:
        service_stats[decision_key] += 1
    
    # Cache stats
    if cached:
        service_stats["cache_hits"] += 1
        cache_stats["hits"] += 1
    else:
        service_stats["cache_misses"] += 1
        cache_stats["misses"] += 1
    
    # Update average processing time
    total_requests = service_stats["requests_processed"]
    current_avg = service_stats["avg_processing_time"]
    service_stats["avg_processing_time"] = (
        (current_avg * (total_requests - 1) + processing_time) / total_requests
    )
    
    # Protocol and zone pair statistics
    service_stats["protocol_stats"][protocol] += 1
    zone_pair = f"{src_zone}->{dst_zone}"
    service_stats["zone_pair_stats"][zone_pair] += 1
    
    # Hourly statistics
    current_hour = time.strftime("%Y-%m-%d %H:00:00")
    service_stats["hourly_stats"][current_hour] += 1
    
    # Recent activities
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
    """Enhanced request validation"""
    if not isinstance(data, dict):
        raise ValueError("Request must be a JSON object")
    
    required_fields = ["src", "dst", "port"]
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")
    
    # Validate IP addresses
    try:
        ipaddress.ip_address(data["src"])
        ipaddress.ip_address(data["dst"])
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {e}")
    
    # Validate port
    try:
        port = int(data["port"])
        if not (0 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port}")
    except (ValueError, TypeError):
        raise ValueError(f"Invalid port: {data['port']}")
    
    return data["src"], data["dst"], port


def handle_netzones_request(data):
    """Handle NetZones policy evaluation request"""
    start_time = time.time()
    
    try:
        # Validate input
        src_ip, dst_ip, port = validate_request(data)
        
        # Use the original protocol from the request
        protocol = data.get("protocol", "tcp")
        
        # Check cache first
        cache_key = get_cache_key(src_ip, dst_ip, port, protocol)
        if cache_key in decision_cache:
            cached_entry = decision_cache[cache_key]
            if is_cache_valid(cached_entry):
                processing_time = (time.time() - start_time) * 1000
                
                # Get zones
                src_zone = get_zone_by_ip(src_ip)
                dst_zone = get_zone_by_ip(dst_ip)
                
                update_stats(
                    cached_entry["decision"], 
                    processing_time, 
                    src_zone, 
                    dst_zone, 
                    protocol, 
                    cached=True
                )
                
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
        
        # Get zones using efficient mapping
        src_zone = get_zone_by_ip(src_ip)
        dst_zone = get_zone_by_ip(dst_ip)
        
        # Get zone configurations for enhanced validation
        src_config = get_zone_config(src_zone) if src_zone != "UNKNOWN" else None
        dst_config = get_zone_config(dst_zone) if dst_zone != "UNKNOWN" else None
        
        # Evaluate policy using netzones_decision_engine
        decision = evaluate_policy(src_zone, dst_zone, protocol, port)
        
        processing_time = (time.time() - start_time) * 1000
        
        # Enhanced reason based on zone configs
        reason = "Policy evaluation completed"
        if not src_config and src_zone != "UNKNOWN":
            reason = f"Source zone {src_zone} configuration not found"
        elif not dst_config and dst_zone != "UNKNOWN":
            reason = f"Destination zone {dst_zone} configuration not found"
        elif src_zone == "UNKNOWN" or dst_zone == "UNKNOWN":
            reason = "Unknown zone detected"
        
        # Log decision with extra metadata
        extra_data = data.get("meta", {})
        log_decision(src_zone, dst_zone, protocol, port, decision, reason, extra_data)
        
        # Cache the decision
        decision_cache[cache_key] = {
            "decision": decision,
            "timestamp": time.time()
        }
        
        # Clean old cache entries periodically
        if len(decision_cache) > 10000:
            clean_cache()
        
        # Update statistics
        update_stats(decision, processing_time, src_zone, dst_zone, protocol, cached=False)
        
        # Get policy details for response
        policies_between_zones = get_policy_between_zones(src_zone, dst_zone)
        
        # Response structure with zone config details (allineato al modello XML)
        response = {
            "decision": decision,
            "details": {
                "source_zone": src_zone,
                "destination_zone": dst_zone,
                "protocol": protocol,
                "processing_time_ms": processing_time,
                "cached": False,
                "policies_evaluated": len(policies_between_zones),
                "source_zone_config": {
                    "exists": src_config is not None,
                    "default_action": src_config.get("default_action", "unknown") if src_config else "unknown",
                    "log_traffic": src_config.get("log_traffic", False) if src_config else False
                } if src_zone != "UNKNOWN" else None,
                "destination_zone_config": {
                    "exists": dst_config is not None,
                    "default_action": dst_config.get("default_action", "unknown") if dst_config else "unknown",
                    "log_traffic": dst_config.get("log_traffic", False) if dst_config else False
                } if dst_zone != "UNKNOWN" else None,
                "applied_policies": [
                    {
                        "name": p.get("name", "unnamed"),
                        "action": p.get("action", "unknown"),
                        "priority": p.get("priority", 999)
                    } for p in policies_between_zones[:3]  # Include top 3 policies
                ],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        }
        
        return response
        
    except ValueError as e:
        error_msg = f"Validation error: {str(e)}"
        print(f"[!] {error_msg}")
        return {"error": error_msg, "decision": "pass"}  # Fail-open con azione del modello XML
        
    except Exception as e:
        error_msg = f"Processing error: {str(e)}"
        print(f"[!] {error_msg}")
        return {"error": error_msg, "decision": "pass"}  # Fail-open con azione del modello XML


def handle_inspector_packet(packet_data):
    """Handle packet from advinspector integration"""
    try:
        # Convert inspector packet format to NetZones format
        netzones_request = {
            "src": packet_data.get("src_ip", ""),
            "dst": packet_data.get("dst_ip", ""),
            "port": packet_data.get("dst_port", packet_data.get("port", 0)),
            "protocol": packet_data.get("protocol", "tcp").lower(),
            "inspector_session": packet_data.get("session_id", ""),
            "request_id": packet_data.get("packet_id", "")
        }
        
        # Add inspector-specific fields
        if packet_data.get("signature_id"):
            netzones_request["signature_id"] = packet_data["signature_id"]
        
        if packet_data.get("threat_level"):
            netzones_request["threat_level"] = packet_data["threat_level"]
            
        # Force logging for suspicious packets
        if packet_data.get("threat_level", "low") in ["high", "critical"]:
            netzones_request["force_log"] = True
        
        return handle_netzones_request(netzones_request)
        
    except Exception as e:
        print(f"[!] Error handling inspector packet: {e}")
        return {"error": str(e), "decision": "pass"}


def clean_cache():
    """Remove expired entries from cache"""
    global decision_cache
    current_time = time.time()
    
    expired_keys = [
        key for key, entry in decision_cache.items()
        if current_time - entry["timestamp"] > CACHE_TTL
    ]
    
    for key in expired_keys:
        del decision_cache[key]
    
    print(f"[*] Cleaned {len(expired_keys)} expired cache entries")


def handle_client(conn, addr):
    """Handle client connection with enhanced error handling"""
    try:
        conn.settimeout(10.0)
        
        while running:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                
                # Parse JSON request
                try:
                    request = json.loads(data.decode('utf-8'))
                except json.JSONDecodeError as e:
                    error_response = {
                        "error": f"Invalid JSON: {str(e)}",
                        "decision": "pass"
                    }
                    conn.sendall(json.dumps(error_response).encode())
                    continue
                
                # Determine request type and handle accordingly
                if request.get("type") == "inspector_packet":
                    response = handle_inspector_packet(request.get("data", {}))
                else:
                    response = handle_netzones_request(request)
                
                # Send response
                response_json = json.dumps(response)
                conn.sendall(response_json.encode())
                
            except socket.timeout:
                print("[!] Client connection timeout")
                break
            except ConnectionResetError:
                print("[!] Client connection reset")
                break
            except Exception as e:
                print(f"[!] Error handling client: {e}")
                error_response = {
                    "error": f"Server error: {str(e)}",
                    "decision": "pass"
                }
                try:
                    conn.sendall(json.dumps(error_response).encode())
                except:
                    pass
                break
                
    except Exception as e:
        print(f"[!] Client handler error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass


def ensure_socket_permissions():
    """Ensure socket has correct permissions"""
    try:
        if os.path.exists(SOCKET_PATH):
            os.chmod(SOCKET_PATH, 0o666)
    except Exception as e:
        print(f"[!] Could not set socket permissions: {e}")


def periodic_maintenance():
    """Periodic maintenance tasks"""
    while running:
        try:
            time.sleep(60)  # Run every minute
            
            # Save statistics
            save_service_stats()
            
            # Clean cache every 10 minutes
            if int(time.time()) % 600 == 0:
                clean_cache()
                
                # Log maintenance activity
                print(f"[*] Periodic maintenance completed")
                print(f"    - Cache entries: {len(decision_cache)}")
                print(f"    - Requests processed: {service_stats['requests_processed']}")
                
                # Get current system stats for monitoring
                sys_stats = get_system_stats()
                print(f"    - Active zones: {sys_stats.get('zones', {}).get('active', 0)}")
                print(f"    - Active policies: {sys_stats.get('policies', {}).get('active', 0)}")
            
            # Refresh configuration cache from settings_loader
            cache_config()
            
        except Exception as e:
            print(f"[!] Maintenance error: {e}")


def get_status_info():
    """Get comprehensive status information for monitoring"""
    try:
        # Get system statistics
        sys_stats = get_system_stats()
        
        # Get policy statistics  
        pol_stats = get_policy_stats()
        
        # Get zone mapping
        zone_mapping = load_zone_subnet_map()
        
        status = {
            "service": {
                "running": True,
                "uptime": time.time() - service_stats["start_time"],
                "requests_processed": service_stats["requests_processed"],
                "avg_processing_time": service_stats["avg_processing_time"]
            },
            "cache": {
                "entries": len(decision_cache),
                "hits": cache_stats["hits"],
                "misses": cache_stats["misses"],
                "hit_rate": (cache_stats["hits"] / max(1, cache_stats["hits"] + cache_stats["misses"])) * 100
            },
            "zones": {
                "configured": len(zone_mapping),
                "active": sys_stats.get("zones", {}).get("active", 0),
                "total": sys_stats.get("zones", {}).get("total", 0)
            },
            "policies": {
                "active": sys_stats.get("policies", {}).get("active", 0),
                "total": sys_stats.get("policies", {}).get("total", 0),
                "decisions": pol_stats.get("total_decisions", 0)
            },
            "recent_activity": list(service_stats["recent_activities"])[-10:]  # Last 10 activities
        }
        
        return status
        
    except Exception as e:
        print(f"[!] Error getting status info: {e}")
        return {"error": str(e)}


def run_server():
    """Main server with enhanced features"""
    # Remove existing socket
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[!] Error removing old socket: {e}")
    
    # Create directory if needed
    socket_dir = os.path.dirname(SOCKET_PATH)
    if socket_dir and not os.path.exists(socket_dir):
        try:
            os.makedirs(socket_dir, mode=0o755)
        except Exception as e:
            print(f"[!] Could not create socket directory: {e}")
            return
    
    # Start maintenance thread
    maintenance_thread = threading.Thread(target=periodic_maintenance)
    maintenance_thread.daemon = True
    maintenance_thread.start()
    
    # Start main server
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(SOCKET_PATH)
            ensure_socket_permissions()
            
            server.listen(20)
            print(f"[*] NetZones policy evaluator listening on {SOCKET_PATH}")
            print(f"[*] Service statistics will be saved to {STATS_FILE}")
            print(f"[*] Decision logs will be written to {LOG_FILE}")
            
            while running:
                try:
                    server.settimeout(1.0)
                    conn, addr = server.accept()
                    print(f"[+] New client connection")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=handle_client, 
                        args=(conn, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if running:
                        print(f"[!] Error accepting connections: {e}")
                        time.sleep(1)
                    
    except Exception as e:
        print(f"[!] Server error: {e}")
    finally:
        try:
            os.unlink(SOCKET_PATH)
        except:
            pass


def test_evaluator():
    """Test the evaluator with sample data"""
    print("=== NetZones Policy Evaluator Test ===")
    
    # First, show system status using imported functions
    print("\n--- System Information ---")
    sys_stats = get_system_stats()
    print(f"System Stats: {sys_stats}")
    
    zone_mapping = load_zone_subnet_map()
    print(f"Zone Mappings: {zone_mapping}")
    
    policy_stats = get_policy_stats()
    print(f"Policy Stats: {policy_stats}")
    
    test_cases = [
        {
            "src": "192.168.1.100",
            "dst": "192.168.2.50", 
            "port": 502,
            "protocol": "tcp"
        },
        {
            "src": "10.0.0.10",
            "dst": "192.168.1.1",
            "port": 80,
            "protocol": "tcp"
        },
        {
            "src": "192.168.1.5",
            "dst": "8.8.8.8",
            "port": 443,
            "protocol": "tcp"
        }
    ]
    
    print("\n--- Policy Evaluation Tests ---")
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        
        # Show zone resolution
        src_zone = get_zone_by_ip(test_case["src"])
        dst_zone = get_zone_by_ip(test_case["dst"])
        print(f"Source IP {test_case['src']} -> Zone: {src_zone}")
        print(f"Destination IP {test_case['dst']} -> Zone: {dst_zone}")
        
        # Show zone configurations if available
        if src_zone != "UNKNOWN":
            src_config = get_zone_config(src_zone)
            if src_config:
                print(f"Source zone config: {src_config['default_action']}")
        
        if dst_zone != "UNKNOWN":
            dst_config = get_zone_config(dst_zone)
            if dst_config:
                print(f"Destination zone config: {dst_config['default_action']}")
        
        # Show policies between zones
        policies = get_policy_between_zones(src_zone, dst_zone)
        print(f"Policies between zones: {len(policies)}")
        for policy in policies[:2]:  # Show first 2 policies
            print(f"  - {policy.get('name', 'unnamed')}: {policy.get('action', 'unknown')}")
        
        # Evaluate request
        result = handle_netzones_request(test_case)
        print(f"Request: {test_case}")
        print(f"Decision: {result['decision']}")
        print(f"Details: {result.get('details', {})}")
    
    # Show final statistics
    print(f"\n--- Final Service Statistics ---")
    save_service_stats()
    
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
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_evaluator()
    else:
        print("[*] Starting NetZones policy evaluator...")
        print("[*] Integration with advinspector enabled")
        run_server()