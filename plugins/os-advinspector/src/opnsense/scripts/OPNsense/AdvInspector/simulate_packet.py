#!/usr/local/bin/python3

import json
import sys
from packet_inspector import inspect_packet

REQUIRED_FIELDS = ["src", "dst", "port", "interface"]

def validate_packet(packet):
    missing = [field for field in REQUIRED_FIELDS if field not in packet]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")

def read_packet_input():
    # Supporta sia argomento CLI che stdin
    if len(sys.argv) == 2:
        return json.loads(sys.argv[1])
    elif not sys.stdin.isatty():
        return json.load(sys.stdin)
    else:
        raise ValueError("No packet input provided. Use CLI arg or pipe JSON to stdin.")

def main():
    try:
        packet = read_packet_input()
        validate_packet(packet)
        result = inspect_packet(packet, packet["interface"])
        print(json.dumps({
            "success": True,
            "result": result
        }))
    except Exception as e:
        print(json.dumps({
            "success": False,
            "error": str(e)
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()