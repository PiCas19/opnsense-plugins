import os
import json
from datetime import datetime

SIGNATURES_FILE = "/usr/local/etc/deepinspector/signatures.json"
THREAT_FEEDS = [
    "https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-malware.rules",
    "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    "https://urlhaus.abuse.ch/downloads/csv_recent/",
]

def download_signatures():
    """Download and update threat signatures"""
    try:
        signatures = {
            'version': datetime.now().isoformat(),
            'patterns': {
                'malware_signatures': [],
                'suspicious_urls': [],
                'command_injection': [],
                'sql_injection': [],
                'script_injection': [],
                'crypto_mining': [],
                'data_exfiltration': [],
                'industrial_threats': []
            }
        }

        # Add default patterns
        signatures['patterns']['malware_signatures'] = [
            r'X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR',
            r'TVqQAAMAAAAEAAAA//8AALgAAAAA',
            r'\\x4d\\x5a',
            r'MZ[\x00-\xFF]{58}PE',
            r'\\x7fELF'
        ]

        signatures['patterns']['command_injection'] = [
            r'[\;\|&`\$\(\)].*?(ls|cat|wget|curl|nc|netcat)',
            r'(cmd\.exe|powershell|bash|sh).*?[\;\|&]',
            r'\\x[0-9a-f]{2}.*?(system|exec|eval)',
            r'(ping|nslookup|dig).*?[\;\|&]',
            r'(chmod|chown|rm|mv).*?[\;\|&]'
        ]

        signatures['patterns']['sql_injection'] = [
            r'(union|select|insert|update|delete).*?(from|into|where)',
            r'[\'"].*?(or|and).*?[\'"].*?=.*?[\'"]',
            r'\\x[0-9a-f]{2}.*?(sql|mysql|postgres)',
            r'(drop|alter|create).*?(table|database|index)',
            r'(information_schema|sys\.databases|pg_catalog)'
        ]

        signatures['patterns']['script_injection'] = [
            r'<script[^>]*>.*?</script>',
            r'javascript:.*?(alert|eval|document)',
            r'on(load|click|error|mouse).*?=.*?[\'"]',
            r'<iframe[^>]*src.*?javascript:',
            r'eval\s*\(\s*[\'"].*?[\'"]'
        ]

        signatures['patterns']['crypto_mining'] = [
            r'(coinhive|cryptonight|monero|bitcoin).*?(miner|mine)',
            r'stratum\+tcp://.*?:[0-9]+',
            r'(pool\..*?|mining\..*?)\.com',
            r'(xmrig|cpuminer|cgminer)',
            r'cryptonight.*?hash'
        ]

        signatures['patterns']['data_exfiltration'] = [
            r'(password|passwd|credential|token|key).*?[:=].*?[a-zA-Z0-9]{8,}',
            r'(BEGIN|END).*?(PRIVATE KEY|CERTIFICATE)',
            r'[a-zA-Z0-9]{32,}',
            r'(ftp|sftp|scp)://.*?:[0-9]+',
            r'(aws|s3).*?(access|secret).*?key'
        ]

        signatures['patterns']['industrial_threats'] = [
            r'(modbus|dnp3|opcua).*?(exploit|attack|malicious)',
            r'(scada|plc|hmi).*?(compromise|hijack|control)',
            r'(function_code|unit_id).*?(0x[0-9a-f]+)',
            r'(ladder|logic|program).*?(upload|download|modify)',
            r'(coil|register|input).*?(read|write|force)'
        ]

        # Ensure directory exists
        os.makedirs(os.path.dirname(SIGNATURES_FILE), exist_ok=True)

        # Write signatures
        with open(SIGNATURES_FILE, 'w') as f:
            json.dump(signatures, f, indent=2)

        print(f"Signatures updated: {len(signatures['patterns'])} categories")
        
        # Calculate total patterns
        total_patterns = sum(len(patterns) for patterns in signatures['patterns'].values())
        print(f"Total patterns: {total_patterns}")
        
        return True

    except Exception as e:
        print(f"Error updating signatures: {e}")
        return False

if __name__ == "__main__":
    success = download_signatures()
    print(json.dumps({"status": "ok" if success else "error"}))
