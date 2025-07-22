#!/usr/local/bin/python3.11
"""
WebGuard Rules Update Script (completo)
- Scarica OWASP CRS
- Genera waf_rules.json e attack_patterns.json
"""

import os
import re
import io
import tarfile
import json
import time
import shutil
import hashlib
from datetime import datetime, timezone

import requests

# Paths
BASE_DIR = "/usr/local/etc/webguard"
WAF_RULES_FILE = f"{BASE_DIR}/waf_rules.json"
ATTACK_PATTERNS_FILE = f"{BASE_DIR}/attack_patterns.json"
BACKUP_DIR = f"{BASE_DIR}/backup"

# Settings
CRS_VERSION = "latest"  # es. "v4.5.0" per bloccare una versione
CRS_REPO = "https://github.com/coreruleset/coreruleset"
UPDATE_INTERVAL_SECONDS = 86400  # 24h

# Categories mapping (regex on tag or name -> category)
CATEGORY_MAP = [
    (re.compile(r"sql|sqli", re.I), "sql_injection"),
    (re.compile(r"xss", re.I), "xss"),
    (re.compile(r"(lfi|path[_-]?traversal)", re.I), "path_traversal"),
    (re.compile(r"rfi", re.I), "rfi"),
    (re.compile(r"(rce|code[_-]?execution|exec)", re.I), "rce"),
    (re.compile(r"(cmdi|command[_-]?injection)", re.I), "command_injection"),
    (re.compile(r"ssrf", re.I), "ssrf"),
    (re.compile(r"csrf", re.I), "csrf"),
    (re.compile(r"webshell", re.I), "webshell"),
]

STATIC_PATTERNS = {
    "malware": [
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
        "TVqQAAMAAAAEAAAA", "\\x4d\\x5a\\x90\\x00", "PK\\x03\\x04", "\\x7fELF", "%PDF-1\\.", "GIF89a"
    ],
    "crypto_mining": [
        "coinhive", "cryptonight", "monero", "stratum\\+tcp", "webminerpool", "crypto-loot", "coinimp", "authedmine"
    ],
    "suspicious_domains": [
        "bit\\.ly", "tinyurl\\.com", "t\\.co", "goo\\.gl", "ngrok\\.io",
        "duckdns\\.org", "no-ip\\.org", "ddns\\.net", "\\d{1,3}(?:\\.\\d{1,3}){3}"
    ]
}

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def file_age_seconds(path):
    return time.time() - os.path.getmtime(path)

def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def backup_file(path):
    if not os.path.exists(path):
        return
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.basename(path)
    shutil.copy2(path, f"{BACKUP_DIR}/{ts}-{base}")

def need_update():
    if not os.path.exists(WAF_RULES_FILE):
        return True
    try:
        return file_age_seconds(WAF_RULES_FILE) > UPDATE_INTERVAL_SECONDS
    except Exception:
        return True

def get_crs_tarball_bytes():
    if CRS_VERSION == "latest":
        # Follow redirects to find latest tarball
        r = requests.get(f"{CRS_REPO}/releases/latest", allow_redirects=True, timeout=20)
        m = re.search(r'href="([^"]+\.tar\.gz)"', r.text)
        if not m:
            raise RuntimeError("Impossibile trovare tarball CRS")
        url = "https://github.com" + m.group(1)
    else:
        url = f"{CRS_REPO}/archive/refs/tags/{CRS_VERSION}.tar.gz"
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.content

def parse_modsec_rules(text: str):
    """Return list of dict for each SecRule found"""
    rules = []
    # Unisci linee spezzate con backslash
    text = re.sub(r"\\\s*\n", " ", text)
    # Trova blocchi SecRule ... "msg:..." ... id:xxxx ...
    for line in re.findall(r'(?m)^\s*SecRule.*$', text):
        # Opz: line continua fino a "ctl:" etc. ma prendiamo tutto
        # Splitta su spazi tenendo quote
        # Più semplice: prendiamo param2 (regex) come gruppo tra doppi apici dopo la prima parola
        m = re.match(r'SecRule\s+([^\s"]+)\s+"([^"]+)"\s+"([^"]+)"', line)
        if not m:
            continue
        targets_raw, operator_pat, actions_raw = m.groups()

        # Targets
        targets = [t.strip() for t in re.split(r'\|', targets_raw)]
        # Normalizza
        tmap = {
            "ARGS": "args", "REQUEST_BODY": "body", "REQUEST_HEADERS": "headers",
            "REQUEST_COOKIES": "cookie", "REQUEST_COOKIES_NAMES": "cookie", "REQUEST_URI": "uri",
            "REQUEST_URI_RAW": "uri", "REQUEST_FILENAME": "uri", "REQUEST_METHOD": "method",
            "TX": "tx"
        }
        norm_targets = []
        for t in targets:
            t = t.replace("REQUEST_", "")
            norm_targets.append(tmap.get(t, t.lower()))
        norm_targets = sorted(set(norm_targets))

        # Actions
        actions = {}
        for kv in actions_raw.split(','):
            if ':' in kv:
                k, v = kv.split(':', 1)
                actions[k.strip()] = v.strip().strip('"')
            else:
                actions[kv.strip()] = True

        rid = int(actions.get("id", 0)) if actions.get("id", "0").isdigit() else None
        if not rid:
            continue

        msg = actions.get("msg", "")
        sev = actions.get("severity", "medium").lower()
        phase = "request" if actions.get("phase", "2") == "1" else "response"
        tags = [v for k, v in actions.items() if k == "tag"]

        rules.append({
            "id": rid,
            "name": msg or f"Rule {rid}",
            "phase": phase,
            "severity": sev,
            "tags": tags,
            "targets": norm_targets or ["args"],
            "operator": "regex",
            "pattern": operator_pat.replace('\\', '\\\\'),
            "transformations": ["none"],
            "action": "block" if "deny" in actions else "log",
            "score": int(actions.get("t:none", 5)) if actions.get("t:none","").isdigit() else 5,
            "msg": msg,
            "ref": "https://coreruleset.org/"
        })
    return rules

def build_waf_and_patterns(crs_bytes: bytes):
    waf = {
        "version": "2.0",
        "updated": utc_now(),
        "source": "OWASP CRS",
        "rules": []
    }

    # initialize patterns dict
    patterns = {
        "sql_injection": [],
        "xss": [],
        "path_traversal": [],
        "rfi": [],
        "rce": [],
        "command_injection": [],
        "ssrf": [],
        "csrf": [],
        "webshell": [],
        "malware": [],
        "crypto_mining": [],
        "suspicious_domains": []
    }

    # read tarball
    with tarfile.open(fileobj=io.BytesIO(crs_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if not member.name.endswith(".conf"):
                continue
            f = tar.extractfile(member)
            if not f:
                continue
            text = f.read().decode("utf-8", "ignore")
            rules = parse_modsec_rules(text)
            waf["rules"].extend(rules)

    # Fill patterns from waf
    for r in waf["rules"]:
        pat = r["pattern"]
        cat = None
        for cre, cname in CATEGORY_MAP:
            if any(cre.search(tag or "") for tag in r["tags"]) or cre.search(r["name"]):
                cat = cname
                break
        if cat:
            patterns[cat].append(pat)

    # Add static patterns
    for cat, pats in STATIC_PATTERNS.items():
        patterns.setdefault(cat, [])
        patterns[cat].extend(pats)

    # dedup/sort
    for k in patterns:
        patterns[k] = sorted(set(patterns[k]))

    attack = {
        "version": "2.0",
        "updated": utc_now(),
        "patterns": patterns
    }

    return waf, attack

def write_if_changed(path, data_bytes):
    """Write only if content changed; return True if written"""
    if os.path.exists(path):
        with open(path, "rb") as f:
            old = f.read()
        if checksum(old) == checksum(data_bytes):
            return False
        backup_file(path)
    with open(path, "wb") as f:
        f.write(data_bytes)
    return True

def download_rules():
    try:
        print("Updating WebGuard rules...")
        os.makedirs(BASE_DIR, exist_ok=True)

        crs_bytes = get_crs_tarball_bytes()
        waf, attack = build_waf_and_patterns(crs_bytes)

        waf_bytes = json.dumps(waf, indent=2).encode()
        attack_bytes = json.dumps(attack, indent=2).encode()

        changed_waf = write_if_changed(WAF_RULES_FILE, waf_bytes)
        changed_att = write_if_changed(ATTACK_PATTERNS_FILE, attack_bytes)

        print("Rules updated successfully")
        print(f"WAF rules: {len(waf['rules'])} rules (written: {changed_waf})")
        total_patterns = sum(len(v) for v in attack["patterns"].values())
        print(f"Attack patterns: {total_patterns} (written: {changed_att})")
        return True
    except Exception as e:
        print(f"Error updating rules: {e}")
        return False

def main():
    if need_update():
        download_rules()
    else:
        print("Rules are up to date")

if __name__ == "__main__":
    main()
