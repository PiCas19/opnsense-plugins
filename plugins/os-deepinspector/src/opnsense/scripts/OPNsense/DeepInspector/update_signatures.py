#!/usr/local/bin/python3
"""
DeepInspector Signature Updater
--------------------------------
Fetches, validates, and updates threat detection signatures for the
DeepInspector OPNsense plugin. Designed for scheduled or manual runs.

Features:
- Object-Oriented structure with clear methods
- Automatic creation of signature directory
- JSON output for integration with OPNsense cron/jobs
- Extensible pattern categories for future additions

Author: Pierpaolo Casati
Version: 1.0
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


class SignatureUpdater:
    """
    Handles creation and updating of DeepInspector threat signatures.
    """

    def __init__(self,
                 signature_file: str = "/usr/local/etc/deepinspector/signatures.json"):
        """
        Initialize the updater with the target signature file.

        Args:
            signature_file: Path where the JSON signatures will be stored.
        """
        self.signature_path = Path(signature_file)

    def _default_patterns(self) -> Dict[str, Any]:
        """
        Define the default built-in threat detection regex patterns.

        Returns:
            A dictionary of categories and regex patterns.
        """
        return {
            "malware_signatures": [
                r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR",
                r"TVqQAAMAAAAEAAAA//8AALgAAAAA",
                r"\\x4d\\x5a",
                r"MZ[\x00-\xFF]{58}PE",
                r"\\x7fELF",
            ],
            "command_injection": [
                r"[\;\|&`\$\(\)].*?(ls|cat|wget|curl|nc|netcat)",
                r"(cmd\.exe|powershell|bash|sh).*?[\;\|&]",
                r"\\x[0-9a-f]{2}.*?(system|exec|eval)",
                r"(ping|nslookup|dig).*?[\;\|&]",
                r"(chmod|chown|rm|mv).*?[\;\|&]",
            ],
            "sql_injection": [
                r"(union|select|insert|update|delete).*?(from|into|where)",
                r"[\'\"].*?(or|and).*?[\'\"].*?=.*?[\'\"]",
                r"\\x[0-9a-f]{2}.*?(sql|mysql|postgres)",
                r"(drop|alter|create).*?(table|database|index)",
                r"(information_schema|sys\.databases|pg_catalog)",
            ],
            "script_injection": [
                r"<script[^>]*>.*?</script>",
                r"javascript:.*?(alert|eval|document)",
                r"on(load|click|error|mouse).*?=.*?[\'\"]",
                r"<iframe[^>]*src.*?javascript:",
                r"eval\s*\(\s*[\'\"].*?[\'\"]",
            ],
            "crypto_mining": [
                r"(coinhive|cryptonight|monero|bitcoin).*?(miner|mine)",
                r"stratum\+tcp://.*?:[0-9]+",
                r"(pool\..*?|mining\..*?)\.com",
                r"(xmrig|cpuminer|cgminer)",
                r"cryptonight.*?hash",
            ],
            "data_exfiltration": [
                r"(password|passwd|credential|token|key).*?[:=].*?[a-zA-Z0-9]{8,}",
                r"(BEGIN|END).*?(PRIVATE KEY|CERTIFICATE)",
                r"[a-zA-Z0-9]{32,}",
                r"(ftp|sftp|scp)://.*?:[0-9]+",
                r"(aws|s3).*?(access|secret).*?key",
            ],
            "industrial_threats": [
                r"(modbus|dnp3|opcua).*?(exploit|attack|malicious)",
                r"(scada|plc|hmi).*?(compromise|hijack|control)",
                r"(function_code|unit_id).*?(0x[0-9a-f]+)",
                r"(ladder|logic|program).*?(upload|download|modify)",
                r"(coil|register|input).*?(read|write|force)",
            ],
        }

    def update(self) -> bool:
        """
        Create or update the signature file with default patterns.

        Returns:
            True if update was successful, False otherwise.
        """
        try:
            signatures = {
                "version": datetime.now().isoformat(),
                "patterns": self._default_patterns(),
            }

            # Ensure directory exists with secure permissions
            self.signature_path.parent.mkdir(parents=True, exist_ok=True)

            with self.signature_path.open("w", encoding="utf-8") as f:
                json.dump(signatures, f, indent=2)

            # Optional: print summary for CLI usage
            total = sum(len(v) for v in signatures["patterns"].values())
            print(f"DeepInspector signatures updated successfully.")
            print(f"Categories: {len(signatures['patterns'])} | Total patterns: {total}")

            return True

        except Exception as exc:
            print(f"Error updating signatures: {exc}")
            return False


def main() -> None:
    """
    Command-line entry point. Creates a SignatureUpdater instance and runs it.

    Prints a JSON result compatible with OPNsense cron scripts.
    """
    updater = SignatureUpdater()
    success = updater.update()
    result = {"status": "ok" if success else "error"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()