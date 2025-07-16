import json
import ipaddress
import os

RULES_FILE = "/usr/local/etc/advinspector/rules.json"

def load_rules():
    if not os.path.isfile(RULES_FILE):
        return []
    with open(RULES_FILE, "r") as f:
        try:
            return json.load(f).get("rules", [])
        except json.JSONDecodeError:
            return []

def ip_match(rule_ip, pkt_ip):
    try:
        return ipaddress.ip_address(pkt_ip) in ipaddress.ip_network(rule_ip, strict=False)
    except ValueError:
        return False

def port_match(rule_ports, pkt_port):
    try:
        pkt_port = int(pkt_port)
        for part in rule_ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start <= pkt_port <= end:
                    return True
            elif int(part) == pkt_port:
                return True
    except Exception:
        pass
    return False

def evaluate_packet(packet):
    rules = [r for r in load_rules() if r.get("enabled", "1") == "1"]
    for rule in rules:
        if (
            ip_match(rule.get("source", ""), packet.get("src")) and
            ip_match(rule.get("destination", ""), packet.get("dst")) and
            port_match(rule.get("port", ""), packet.get("port")) and
            rule.get("protocol", "").lower() == packet.get("protocol", "").lower()
        ):
            return rule.get("action", "allow")
    return "allow"