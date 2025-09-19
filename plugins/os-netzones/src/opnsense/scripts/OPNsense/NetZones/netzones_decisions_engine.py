#!/usr/local/bin/python3

import json
import os
import sys
from settings_loader import get_policy_between_zones, get_zone_config

DEFAULT_ACTION = "block"
LOG_FILE = "/var/log/netzones_decisions.log"

def check_port_match(port_rule, port):
    """
    Verifica se una porta corrisponde a una regola porta (allineato ai campi del modello XML)
    """
    if not port_rule:
        return True  # Nessuna restrizione porta
    
    try:
        port = int(port)
        port_rule = str(port_rule).strip()
        
        if '-' in port_rule:
            # Range di porte (es. "1000-2000")
            start, end = map(int, port_rule.split('-', 1))
            return start <= port <= end
        elif ',' in port_rule:
            # Lista di porte (es. "80,443,8080")
            ports = [int(p.strip()) for p in port_rule.split(',')]
            return port in ports
        else:
            # Porta singola
            return int(port_rule) == port
    except (ValueError, TypeError):
        return False

def check_protocol_match(policy_protocol, requested_protocol):
    """
    Verifica se un protocollo corrisponde (allineato al modello XML - singolo protocollo per policy)
    """
    if not policy_protocol:
        return True  # Nessuna restrizione protocollo
    
    policy_protocol = policy_protocol.lower().strip()
    requested_protocol = requested_protocol.lower().strip()
    
    # Confronto diretto
    if policy_protocol == requested_protocol:
        return True
    
    # Protocolli speciali
    if policy_protocol == "any":
        return True
    
    # Normalizzazione protocolli comuni
    protocol_aliases = {
        'http': 'tcp',
        'https': 'tcp', 
        'ssh': 'tcp',
        'ftp': 'tcp',
        'dns': 'udp',
        'dhcp': 'udp'
    }
    
    normalized_policy = protocol_aliases.get(policy_protocol, policy_protocol)
    normalized_requested = protocol_aliases.get(requested_protocol, requested_protocol)
    
    return normalized_policy == normalized_requested

def evaluate_policy(source_zone, destination_zone, protocol, port):
    """
    Valuta se la comunicazione tra zone è ammessa (allineato al modello XML semplificato)
    """
    
    # Ottieni configurazione zone
    src_config = get_zone_config(source_zone)
    dst_config = get_zone_config(destination_zone)
    
    # Se una delle zone non esiste o è disabilitata, blocca
    if not src_config or not dst_config:
        log_decision(source_zone, destination_zone, protocol, port, "block", 
                    "Zone not found or disabled")
        return "block"
    
    # Cerca policy specifiche tra le zone
    policies = get_policy_between_zones(source_zone, destination_zone)
    
    for policy in policies:
        # Controlla se il protocollo corrisponde
        if not check_protocol_match(policy.get("protocol", ""), protocol):
            continue
        
        # Controlla source_port se specificata
        source_port_rule = policy.get("source_port", "")
        if source_port_rule and not check_port_match(source_port_rule, port):
            continue
        
        # Controlla destination_port se specificata  
        dest_port_rule = policy.get("destination_port", "")
        if dest_port_rule and not check_port_match(dest_port_rule, port):
            continue
        
        # Policy trovata e corrisponde
        action = policy.get("action", "block")
        
        # Log se richiesto
        if policy.get("log_traffic", True):
            log_decision(source_zone, destination_zone, protocol, port, action, 
                        f"Policy '{policy.get('name', 'unnamed')}' matched")
        
        return action
    
    # Nessuna policy specifica trovata, usa azione di default delle zone
    # Nel modello XML attuale, le zone hanno solo default_action
    src_default = src_config.get("default_action", "pass")
    dst_default = dst_config.get("default_action", "pass")
    
    # Se una delle zone ha default "block" o "reject", blocca
    if src_default in ["block", "reject"] or dst_default in ["block", "reject"]:
        log_decision(source_zone, destination_zone, protocol, port, "block", 
                    "Zone default action blocks traffic")
        return "block"
    
    # Default: permetti se entrambe le zone hanno "pass"
    if src_default == "pass" and dst_default == "pass":
        log_decision(source_zone, destination_zone, protocol, port, "pass", 
                    "Zone default action allows traffic")
        return "pass"
    
    # Fallback: blocca per sicurezza
    log_decision(source_zone, destination_zone, protocol, port, "block", 
                "Default block for unknown action")
    return "block"

def log_decision(source_zone, destination_zone, protocol, port, decision, reason, extra_data=None):
    """
    Log delle decisioni per analisi e debugging
    """
    import time
    
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_zone": source_zone,
        "destination_zone": destination_zone,
        "protocol": protocol,
        "port": port,
        "decision": decision,
        "reason": reason,
        "processing_time_ms": 0.1  # Placeholder
    }
    
    # Aggiungi dati extra se forniti
    if extra_data:
        entry["extra"] = extra_data
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to log decision: {e}")

def evaluate_packet(packet):
    """
    Valuta un pacchetto per compatibilità con inspector esistente
    """
    from settings_loader import get_zone_by_ip
    
    src_ip = packet.get("src", "")
    dst_ip = packet.get("dst", "")
    port = packet.get("port", 0)
    protocol = packet.get("protocol", "tcp")
    
    src_zone = get_zone_by_ip(src_ip)
    dst_zone = get_zone_by_ip(dst_ip)
    
    return evaluate_policy(src_zone, dst_zone, protocol, port)

def get_policy_stats():
    """
    Statistiche delle decisioni policy per dashboard
    """
    import time
    from collections import defaultdict
    
    if not os.path.exists(LOG_FILE):
        return {}
    
    stats = {
        "total_decisions": 0,
        "decisions_by_action": defaultdict(int),
        "decisions_by_protocol": defaultdict(int),
        "decisions_by_zone_pair": defaultdict(int),
        "recent_decisions": []
    }
    
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        
        # Processa ultime 1000 righe per performance
        for line in lines[-1000:]:
            try:
                entry = json.loads(line.strip())
                stats["total_decisions"] += 1
                
                action = entry.get("decision", "unknown")
                protocol = entry.get("protocol", "unknown")
                src_zone = entry.get("source_zone", "UNKNOWN")
                dst_zone = entry.get("destination_zone", "UNKNOWN")
                
                stats["decisions_by_action"][action] += 1
                stats["decisions_by_protocol"][protocol] += 1
                stats["decisions_by_zone_pair"][f"{src_zone}->{dst_zone}"] += 1
                
                # Aggiungi alle decisioni recenti (ultime 10)
                if len(stats["recent_decisions"]) < 10:
                    stats["recent_decisions"].append(entry)
                
            except json.JSONDecodeError:
                continue
        
        # Rovescia le decisioni recenti per avere le più nuove prima
        stats["recent_decisions"].reverse()
        
    except Exception as e:
        print(f"[ERROR] Failed to read policy stats: {e}")
    
    return dict(stats)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        # Modalità compatibilità - input JSON
        try:
            data = json.loads(sys.argv[1])
            result = evaluate_policy(
                data.get("source_zone", ""),
                data.get("destination_zone", ""),
                data.get("protocol", ""),
                data.get("port", 0)
            )
            print(result)
        except json.JSONDecodeError:
            print("Invalid JSON input.")
            sys.exit(1)
    else:
        # Modalità test
        print("=== NetZones Decision Engine Test ===")
        
        # Test policy evaluation
        test_cases = [
            ("LAN", "DMZ", "tcp", 502),
            ("LAN", "GUEST", "tcp", 80),
            ("DMZ", "WAN", "tcp", 443),
            ("UNKNOWN", "LAN", "tcp", 22)
        ]
        
        for src, dst, proto, port in test_cases:
            result = evaluate_policy(src, dst, proto, port)
            print(f"{src} -> {dst} ({proto}:{port}): {result}")
        
        # Mostra statistiche
        stats = get_policy_stats()
        print(f"\nPolicy Stats: {stats.get('total_decisions', 0)} total decisions")
        print(f"Actions: {dict(stats.get('decisions_by_action', {}))}")