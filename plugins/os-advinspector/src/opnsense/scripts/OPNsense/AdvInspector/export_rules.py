#!/usr/local/bin/python3
import os
import json
import xml.etree.ElementTree as ET

CONFIG_PATH = "/conf/config.xml"
OUTPUT_PATH = "/usr/local/etc/advinspector/rules.json"

def parse_rules():
    if not os.path.isfile(CONFIG_PATH):
        return []

    tree = ET.parse(CONFIG_PATH)
    root = tree.getroot()
    rules = []
    for rule in root.findall(".//AdvInspector/rules/rule"):
        rule_data = {"uuid": rule.get("uuid")}
        for elem in rule:
            rule_data[elem.tag] = elem.text or ""
        rules.append(rule_data)
    return rules

def save_json(data):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"rules": data}, f, indent=2)

if __name__ == "__main__":
    rules = parse_rules()
    save_json(rules)
    print(f"[✓] Exported {len(rules)} rules to {OUTPUT_PATH}")