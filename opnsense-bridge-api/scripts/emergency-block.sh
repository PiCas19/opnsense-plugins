#!/bin/bash

# emergency-block.sh - Emergency IP blocking script
# Calls /emergency/block-ip or /emergency/bulk-block endpoints

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

# Check for JWT_SECRET_KEY
if [ -z "$JWT_SECRET_KEY" ]; then
    echo "Error: JWT_SECRET_KEY not set in .env"
    exit 1
fi

# Generate JWT token (requires python-jose)
JWT_TOKEN=$(python3 -c "import os; from jose import jwt; from datetime import datetime, timedelta; payload = {'exp': datetime.utcnow() + timedelta(hours=1), 'iat': datetime.utcnow(), 'sub': 'emergency_script', 'role': 'admin'}; print(jwt.encode(payload, os.getenv('JWT_SECRET_KEY'), algorithm='HS256'))")
if [ $? -ne 0 ]; then
    echo "Error: Failed to generate JWT token"
    exit 1
fi

# Check for input
if [ $# -lt 1 ]; then
    echo "Usage: $0 <ip_address> [reason] or $0 <ip_file> [reason] --bulk"
    exit 1
fi

URL="https://$BRIDGE_IP:$BRIDGE_PORT/emergency/block-ip"
METHOD="POST"
DATA="{\"ip_address\": \"$1\", \"reason\": \"${2:-Emergency block from script}\"}"

if [ "$3" == "--bulk" ]; then
    URL="https://$BRIDGE_IP:$BRIDGE_PORT/emergency/bulk-block"
    DATA=$(jq -R -s '{ip_addresses: [split("\n")[] | select(. != "")], reason: "'"${2:-Bulk emergency block}"'"}' "$1")
fi

# Send request
response=$(curl -k -X $METHOD -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" -d "$DATA" "$URL")
if [ $? -eq 0 ]; then
    echo "Success: $response"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Blocked IPs: $1, Reason: ${2:-Emergency block}" >> logs/emergency.log
else
    echo "Error: Failed to block IPs. Response: $response"
    exit 1
fi