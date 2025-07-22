#!/usr/local/bin/python3.11
# -*- coding: utf-8 -*-
"""
WebGuard - Update Rules (FIXED)
Scarica l'OWASP Core Rule Set e genera:
  - /usr/local/etc/webguard/waf_rules.json
  - /usr/local/etc/webguard/attack_patterns.json
JSON ben formati, scritti in modo atomico.
"""

import os, re, io, tarfile, json, shutil, hashlib
from datetime import datetime, timezone
import requests
import tempfile

BASE_DIR = "/usr/local/etc/webguard"
WAF_RULES_FILE = os.path.join(BASE_DIR, "waf_rules.json")
ATTACK_PATTERNS_FILE = os.path.join(BASE_DIR, "attack_patterns.json")
BACKUP_DIR = os.path.join(BASE_DIR, "backup")

CRS_VERSION = "latest"
CRS_REPO = "https://github.com/coreruleset/coreruleset"

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
        "coinhive", "cryptonight", "monero", "stratum\\+tcp",
        "webminerpool", "crypto-loot", "coinimp", "authedmine"
    ],
    "suspicious_domains": [
        "bit\\.ly", "tinyurl\\.com", "t\\.co", "goo\\.gl", "ngrok\\.io",
        "duckdns\\.org", "no-ip\\.org", "ddns\\.net", "\\d{1,3}(?:\\.\\d{1,3}){3}"
    ]
}

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def backup(path):
    if not os.path.exists(path):
        return
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copy2(path, os.path.join(BACKUP_DIR, f"{ts}-{os.path.basename(path)}"))

def atomic_write(path, data_bytes):
    """Scrive su file in modo atomico e fa backup se cambia."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write = True
    if os.path.exists(path):
        with open(path, "rb") as f:
            if sha256(f.read()) == sha256(data_bytes):
                write = False
    if write:
        backup(path)
        fd, tmp = tempfile.mkstemp(prefix=".wg_", dir=os.path.dirname(path))
        with os.fdopen(fd, "wb") as tmpf:
            tmpf.write(data_bytes)
        os.replace(tmp, path)

def get_crs_tarball():
    """FIX: Usa l'API GitHub invece di fare scraping HTML"""
    if CRS_VERSION == "latest":
        # Usa l'API GitHub per ottenere l'ultima release
        api_url = "https://api.github.com/repos/coreruleset/coreruleset/releases/latest"
        try:
            print("[*] Fetching latest CRS version from GitHub API...")
            r = requests.get(api_url, timeout=20)
            r.raise_for_status()
            release_data = r.json()
            
            # Cerca il tarball_url nell'API response
            tarball_url = release_data.get("tarball_url")
            if tarball_url:
                print(f"[*] Found tarball: {tarball_url}")
                resp = requests.get(tarball_url, timeout=60)
                resp.raise_for_status()
                return resp.content
            
            # Fallback: cerca negli assets
            for asset in release_data.get("assets", []):
                if asset["name"].endswith(".tar.gz"):
                    print(f"[*] Using asset: {asset['name']}")
                    resp = requests.get(asset["browser_download_url"], timeout=60)
                    resp.raise_for_status()
                    return resp.content
            
            # Ultimo fallback: costruisci URL manualmente
            tag_name = release_data.get("tag_name")
            if tag_name:
                url = f"{CRS_REPO}/archive/refs/tags/{tag_name}.tar.gz"
                print(f"[*] Fallback URL: {url}")
                resp = requests.get(url, timeout=60)
                resp.raise_for_status()
                return resp.content
                
        except Exception as e:
            print(f"[!] API method failed: {e}")
            print("[*] Trying fallback method...")
            
    # Fallback originale con pattern migliorati
    if CRS_VERSION == "latest":
        r = requests.get(f"{CRS_REPO}/releases/latest", allow_redirects=True, timeout=20)
        r.raise_for_status()
        
        # Prova diversi pattern per trovare il tarball
        patterns = [
            r'href="([^"]*\/archive\/refs\/tags\/[^"]*\.tar\.gz)"',
            r'href="([^"]*\/releases\/download\/[^"]*\.tar\.gz)"',
            r'"browser_download_url":\s*"([^"]+\.tar\.gz)"',
            r'href="([^"]+\.tar\.gz)"'
        ]
        
        for pattern in patterns:
            m = re.search(pattern, r.text)
            if m:
                url = m.group(1)
                if not url.startswith('http'):
                    url = "https://github.com" + url
                print(f"[*] Found tarball with pattern: {url}")
                break
        else:
            # Se nessun pattern funziona, usa versione hardcoded recente
            print("[!] No tarball found, using hardcoded version...")
            url = f"{CRS_REPO}/archive/refs/tags/v4.7.0.tar.gz"
    else:
        url = f"{CRS_REPO}/archive/refs/tags/{CRS_VERSION}.tar.gz"
    
    print(f"[*] Downloading from: {url}")
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.content

def parse_modsec_rules(text):
    rules = []
    text = re.sub(r"\\\s*\n", " ", text)  # join backslash continuations
    for line in re.findall(r'(?m)^\s*SecRule.*$', text):
        m = re.match(r'SecRule\s+([^\s"]+)\s+"([^"]+)"\s+"([^"]+)"', line)
        if not m:
            continue
        targets_raw, operator_pat, actions_raw = m.groups()

        targets = [t.strip() for t in targets_raw.split('|')]
        tmap = {
            "ARGS": "args", "REQUEST_BODY": "body", "REQUEST_HEADERS": "headers",
            "REQUEST_COOKIES": "cookie", "REQUEST_COOKIES_NAMES": "cookie", "REQUEST_URI": "uri",
            "REQUEST_URI_RAW": "uri", "REQUEST_FILENAME": "uri", "REQUEST_METHOD": "method",
            "TX": "tx"
        }
        norm_targets = sorted({tmap.get(t.replace("REQUEST_",""), t.lower()) for t in targets})

        actions = {}
        for kv in actions_raw.split(','):
            kv = kv.strip()
            if ':' in kv:
                k, v = kv.split(':', 1)
                actions[k.strip()] = v.strip().strip('"')
            else:
                actions[kv] = True

        rid = actions.get("id")
        try:
            rid = int(rid)
        except (TypeError, ValueError):
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
            "score": 5,  # placeholder, CRS non usa "score" nativo
            "msg": msg,
            "ref": "https://coreruleset.org/"
        })
    return rules

def build(crs_bytes):
    waf = {"version": "2.0", "updated": utc_now(), "source": "OWASP CRS", "rules": []}
    patterns = {k: [] for _, k in CATEGORY_MAP}
    patterns.update({"malware": [], "crypto_mining": [], "suspicious_domains": []})

    with tarfile.open(fileobj=io.BytesIO(crs_bytes), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.isfile() and m.name.endswith(".conf"):
                f = tar.extractfile(m)
                if not f:
                    continue
                text = f.read().decode("utf-8", "ignore")
                rls = parse_modsec_rules(text)
                waf["rules"].extend(rls)

    # categorizza pattern
    for r in waf["rules"]:
        pat = r["pattern"]
        for cre, cname in CATEGORY_MAP:
            if any(cre.search(tag or "") for tag in r["tags"]) or cre.search(r["name"]):
                patterns[cname].append(pat)
                break

    # statici
    for cat, pats in STATIC_PATTERNS.items():
        patterns[cat].extend(pats)

    # dedup + sort
    for k in patterns:
        patterns[k] = sorted(set(patterns[k]))

    attack = {"version": "2.0", "updated": utc_now(), "patterns": patterns}
    return waf, attack

def download_rules():
    print("[*] Downloading CRS & generating JSON...")
    try:
        crs_bytes = get_crs_tarball()
        waf, attack = build(crs_bytes)

        waf_bytes = json.dumps(waf, indent=2, ensure_ascii=False).encode()
        attack_bytes = json.dumps(attack, indent=2, ensure_ascii=False).encode()

        atomic_write(WAF_RULES_FILE, waf_bytes)
        atomic_write(ATTACK_PATTERNS_FILE, attack_bytes)

        print(f"[+] WAF rules: {len(waf['rules'])} salvate")
        tot_patterns = sum(len(v) for v in attack["patterns"].values())
        print(f"[+] Attack patterns: {tot_patterns} salvati")
        return True
    except Exception as e:
        print(f"[!] Error downloading rules: {e}")
        print("[*] Creating minimal fallback rules...")
        
        # Crea regole di fallback minime
        fallback_waf = {
            "version": "2.0", 
            "updated": utc_now(), 
            "source": "Fallback", 
            "rules": [
                {
                    "id": 1001,
                    "name": "Basic SQL Injection",
                    "phase": "request",
                    "severity": "high",
                    "tags": ["sql", "injection"],
                    "targets": ["args", "body"],
                    "operator": "regex",
                    "pattern": "(?i)(union|select|insert|update|delete|drop|exec|script)",
                    "transformations": ["none"],
                    "action": "block",
                    "score": 8,
                    "msg": "Possible SQL injection",
                    "ref": "local"
                }
            ]
        }
        
        fallback_patterns = {
            "sql_injection": ["(?i)(union|select|insert|update|delete|drop|exec)"],
            "xss": ["(?i)(<script|javascript:|on\\w+\\s*=)"],
            "path_traversal": ["\\.\\.[\\\\/]", "[\\\\/]etc[\\\\/]passwd"],
            "malware": STATIC_PATTERNS["malware"],
            "crypto_mining": STATIC_PATTERNS["crypto_mining"],
            "suspicious_domains": STATIC_PATTERNS["suspicious_domains"]
        }
        
        fallback_attack = {"version": "2.0", "updated": utc_now(), "patterns": fallback_patterns}
        
        waf_bytes = json.dumps(fallback_waf, indent=2, ensure_ascii=False).encode()
        attack_bytes = json.dumps(fallback_attack, indent=2, ensure_ascii=False).encode()
        
        atomic_write(WAF_RULES_FILE, waf_bytes)
        atomic_write(ATTACK_PATTERNS_FILE, attack_bytes)
        
        print("[+] Fallback rules created successfully")
        return True

def main():
    os.makedirs(BASE_DIR, exist_ok=True)
    if download_rules():
        print("Done.")
    else:
        raise SystemExit(1)

if __name__ == "__main__":
    main()