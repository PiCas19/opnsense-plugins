#!/usr/local/bin/python3

import xml.etree.ElementTree as ET
import ipaddress
import json
import time

CONFIG_PATH = "/conf/config.xml"
CACHE_FILE = "/tmp/netzones_cache.json"
CACHE_TIMEOUT = 30  # seconds

_cache = None
_cache_time = 0

def get_zones():
    """
    Estrae tutti i blocchi <zone> da /OPNsense/NetZones/zone (allineato al modello XML)
    """
    try:
        tree = ET.parse(CONFIG_PATH)
        root = tree.getroot()
        # Corretto path secondo il modello XML: OPNsense/NetZones/zone (non zones/zone)
        return root.findall(".//OPNsense/NetZones/zone")
    except Exception as e:
        print(f"[ERROR] get_zones: {e}")
        return []

def get_inter_zone_policies():
    """
    Estrae tutte le policy inter-zone da /OPNsense/NetZones/inter_zone_policy (allineato al modello XML)
    """
    try:
        tree = ET.parse(CONFIG_PATH)
        root = tree.getroot()
        # Corretto path secondo il modello XML: OPNsense/NetZones/inter_zone_policy (non inter_zone_policies/policy)
        return root.findall(".//OPNsense/NetZones/inter_zone_policy")
    except Exception as e:
        print(f"[ERROR] get_inter_zone_policies: {e}")
        return []

def load_enabled():
    """
    True se almeno una zona è abilitata
    """
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            return True
    return False

def load_verbosity():
    """
    Livello di log (può essere configurabile in futuro)
    """
    return "normal"

def load_inspection_mode():
    """
    Modalità di ispezione (per compatibilità con inspector)
    """
    return "stateful"

def load_ips_mode():
    """
    Se il modo IPS è abilitato (per compatibilità con inspector)
    """
    return True

def load_promiscuous_mode():
    """
    Modalità promiscua per network interfaces
    """
    return False

def load_home_networks():
    """
    Reti domestiche/interne per filtraggio
    """
    networks = set()
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            subnets = zone.findtext("subnets", "")
            for subnet in subnets.split(","):
                subnet = subnet.strip()
                if subnet:
                    networks.add(subnet)
    return list(networks)

def load_interfaces():
    """
    Ritorna tutte le interfacce configurate nelle zone
    """
    interfaces = set()
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            interface_list = zone.findtext("interface", "")
            for iface in interface_list.split(","):
                iface = iface.strip()
                if iface:
                    interfaces.add(iface.lower())
    
    # Se nessuna interfaccia specificata, usa quelle standard
    if not interfaces:
        interfaces = {"lan", "wan", "dmz"}
    
    return list(interfaces)

def load_zone_subnet_map():
    """
    Ritorna mappa subnet → nome zona
    """
    subnet_map = {}
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            name = zone.findtext("name")
            subnets = zone.findtext("subnets", "")
            for subnet in subnets.split(","):
                subnet = subnet.strip()
                if subnet and name:
                    subnet_map[subnet] = name
    return subnet_map

def get_zone_by_ip(ip):
    """
    Ritorna la zona corrispondente all'IP, o 'UNKNOWN'
    """
    zone_map = load_zone_subnet_map()
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return "UNKNOWN"
    
    for subnet, zone in zone_map.items():
        try:
            if ip_obj in ipaddress.ip_network(subnet, strict=False):
                return zone
        except ValueError:
            continue
    
    return "UNKNOWN"

def get_zone_config(zone_name):
    """
    Ottiene la configurazione completa di una zona (allineato ai campi del modello XML)
    """
    for zone in get_zones():
        if zone.findtext("name") == zone_name and zone.findtext("enabled", "0") == "1":
            return {
                "name": zone.findtext("name", ""),
                "description": zone.findtext("description", ""),
                "enabled": zone.findtext("enabled", "0") == "1",
                "subnets": [s.strip() for s in zone.findtext("subnets", "").split(",") if s.strip()],
                "interface": [i.strip() for i in zone.findtext("interface", "").split(",") if i.strip()],
                "default_action": zone.findtext("default_action", "pass"),  # Corretto default
                "log_traffic": zone.findtext("log_traffic", "0") == "1",
                "priority": int(zone.findtext("priority", "100") or 100),
                # Rimossi campi non presenti nel modello XML:
                # - security_level, isolation_level, allowed_protocols, custom_ports
                # - log_level, traffic_monitoring, bandwidth_limit, connection_limit
                # - schedule, tags, notes
            }
    return None

def get_policy_between_zones(source_zone, destination_zone):
    """
    Trova policy specifiche tra due zone (allineato ai campi del modello XML)
    """
    policies = []
    for policy in get_inter_zone_policies():
        if (policy.findtext("enabled", "0") == "1" and
            policy.findtext("source_zone") == source_zone and
            policy.findtext("destination_zone") == destination_zone):
            
            policies.append({
                "name": policy.findtext("name", ""),
                "description": policy.findtext("description", ""),
                "action": policy.findtext("action", "block"),
                "protocol": policy.findtext("protocol", ""),  # Singolo protocollo, non lista
                "source_port": policy.findtext("source_port", ""),
                "destination_port": policy.findtext("destination_port", ""),
                "log_traffic": policy.findtext("log_traffic", "0") == "1",
                "priority": int(policy.findtext("priority", "100") or 100),
                # Rimossi campi non presenti nel modello XML:
                # - allowed_protocols, allowed_ports, schedule, bandwidth_limit
                # - connection_limit, tags
            })
    
    # Ordina per priorità (numero più basso = priorità più alta)
    return sorted(policies, key=lambda p: p["priority"])

def get_all_zones_info():
    """
    Ritorna informazioni su tutte le zone per dashboard
    """
    zones_info = []
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            zone_info = get_zone_config(zone.findtext("name"))
            if zone_info:
                zones_info.append(zone_info)
    return zones_info

def get_all_policies_info():
    """
    Ritorna informazioni su tutte le policy per dashboard (allineato al modello XML)
    """
    policies_info = []
    for policy in get_inter_zone_policies():
        if policy.findtext("enabled", "0") == "1":
            policies_info.append({
                "name": policy.findtext("name", ""),
                "description": policy.findtext("description", ""),
                "source_zone": policy.findtext("source_zone", ""),
                "destination_zone": policy.findtext("destination_zone", ""),
                "action": policy.findtext("action", "block"),
                "protocol": policy.findtext("protocol", ""),
                "source_port": policy.findtext("source_port", ""),
                "destination_port": policy.findtext("destination_port", ""),
                "log_traffic": policy.findtext("log_traffic", "0") == "1",
                "priority": int(policy.findtext("priority", "100") or 100),
            })
    return policies_info

def get_system_stats():
    """
    Statistiche di sistema per dashboard
    """
    zones = get_zones()
    policies = get_inter_zone_policies()
    
    active_zones = sum(1 for zone in zones if zone.findtext("enabled", "0") == "1")
    active_policies = sum(1 for policy in policies if policy.findtext("enabled", "0") == "1")
    
    return {
        "zones": {
            "total": len(zones),
            "active": active_zones
        },
        "policies": {
            "total": len(policies),
            "active": active_policies
        },
        # Rimosso templates che non sono nel modello XML
    }

def cache_config():
    """
    Cache della configurazione per performance
    """
    global _cache, _cache_time
    
    current_time = time.time()
    if _cache and (current_time - _cache_time) < CACHE_TIMEOUT:
        return _cache
    
    _cache = {
        "zones": get_all_zones_info(),
        "policies": get_all_policies_info(),
        "zone_subnet_map": load_zone_subnet_map(),
        "system_stats": get_system_stats()
    }
    _cache_time = current_time
    
    # Salva cache su file per debugging
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(_cache, f, indent=2)
    except Exception:
        pass
    
    return _cache

# Funzioni di compatibilità per l'inspector esistente
def evaluate_packet(packet):
    """
    Compatibilità con inspector - valutazione base del pacchetto
    """
    return "allow"  # L'inspector ora usa principalmente netzones per le decisioni

if __name__ == "__main__":
    # Test delle funzioni
    print("=== NetZones Settings Loader Test ===")
    print(f"Enabled: {load_enabled()}")
    print(f"Interfaces: {load_interfaces()}")
    print(f"Home Networks: {load_home_networks()}")
    print(f"Zone Subnet Map: {load_zone_subnet_map()}")
    
    # Test IP lookup
    test_ip = "192.168.1.100"
    zone = get_zone_by_ip(test_ip)
    print(f"IP {test_ip} is in zone: {zone}")
    
    # Test zone config
    if zone != "UNKNOWN":
        config = get_zone_config(zone)
        print(f"Zone config: {config}")
    
    # Test cache
    cache = cache_config()
    print(f"Cached {len(cache['zones'])} zones, {len(cache['policies'])} policies")