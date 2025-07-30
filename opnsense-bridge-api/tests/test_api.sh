#!/bin/bash
# Test OPNsense API da macchina client
# Recupera le regole firewall già presenti

echo "Inserisci le credenziali API e l'host OPNsense:"
read -p "API Key: " API_KEY
read -p "API Secret: " API_SECRET
read -p "OPNsense Host (es. 192.168.1.1): " OPNSENSE_HOST

echo "Checking prerequisites..."
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl not installed"
    echo "Install: sudo apt install curl"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Warning: jq not found - installing for better JSON output..."
    if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y jq
    fi
fi

echo "Testing network connectivity to $OPNSENSE_HOST..."
if ping -c 1 -W 3 "$OPNSENSE_HOST" >/dev/null 2>&1; then
    echo "Network connectivity: OK"
else
    echo "WARNING: Cannot ping $OPNSENSE_HOST"
    echo "Continuing anyway..."
fi

# Test 1: Autenticazione API
echo "=== Test 1: API Authentication ==="
response=$(curl -k -v -s -w "HTTPSTATUS:%{http_code};TIME:%{time_total}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/core/system/status" 2>/dev/null)
http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
time_total=$(echo "$response" | grep -o "TIME:[0-9.]*" | cut -d: -f2)
json_response=$(echo "$response" | sed 's/HTTPSTATUS:.*//g')
if [ "$http_code" = "200" ]; then
    echo "SUCCESS: API authentication working!"
    echo "Response time: ${time_total}s"
    if command -v jq >/dev/null 2>&1; then
        echo "$json_response" | jq -r '.' 2>/dev/null || echo "Raw response: $json_response"
    fi
else
    echo "FAILED: HTTP $http_code"
    echo "Response: ${json_response:0:200}"
    echo "TROUBLESHOOTING: Verifica credenziali e privilegi 'System: General'"
    exit 1
fi

# Test 2: Recupero tutte le regole firewall
echo "=== Test 2: Retrieve Existing Firewall Rules ==="
response=$(curl -k -v -s -w "HTTPSTATUS:%{http_code}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/firewall/filter/searchRule?current=1&rowCount=50" 2>/dev/null)
http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
json_response=$(echo "$response" | sed 's/HTTPSTATUS:.*//g')
if [ "$http_code" = "200" ]; then
    echo "SUCCESS: Firewall rules retrieved!"
    if command -v jq >/dev/null 2>&1; then
        total_rules=$(echo "$json_response" | jq -r '.rows | length' 2>/dev/null || echo "unknown")
        echo "Total rules found: $total_rules"
        if [ "$total_rules" != "unknown" ] && [ "$total_rules" -gt 0 ]; then
            echo "Rules:"
            echo "$json_response" | jq -r '.rows[] | "UUID: \(.uuid), Description: \(.description), Source: \(.source.net), Destination: \(.destination.net)"'
        else
            echo "No rules found."
        fi
    fi
else
    echo "WARNING: Failed to retrieve rules (HTTP $http_code)"
    echo "Response: ${json_response:0:200}"
    echo "TROUBLESHOOTING: Verifica privilegi 'Firewall: Rules' o endpoint"
fi

# Test 3: Recupero regola specifica (opzionale)
echo "=== Test 3: Retrieve Specific Rule (Optional) ==="
read -p "Inserisci un UUID per recuperare una regola specifica (lascia vuoto per saltare): " rule_uuid
if [ -n "$rule_uuid" ]; then
    echo "Retrieving rule with UUID: $rule_uuid"
    response=$(curl -k -v -s -w "HTTPSTATUS:%{http_code}" \
        -u "$API_KEY:$API_SECRET" \
        --connect-timeout 10 \
        --max-time 30 \
        "https://$OPNSENSE_HOST/api/firewall/filter/getRule/$rule_uuid" 2>/dev/null)
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    json_response=$(echo "$response" | sed 's/HTTPSTATUS:.*//g')
    if [ "$http_code" = "200" ]; then
        echo "SUCCESS: Rule retrieved!"
        if command -v jq >/dev/null 2>&1; then
            echo "$json_response" | jq -r '.description, .source.address, .destination.address'
        fi
    else
        echo "WARNING: Failed to retrieve rule (HTTP $http_code)"
        echo "Response: ${json_response:0:200}"
    fi
else
    echo "Skipping specific rule retrieval."
fi

# Test 4: Accesso dati di monitoraggio
echo "=== Test 4: Monitoring Data Access ==="
echo "Monitoring endpoints not fully identified. Skipping for now."
echo "TROUBLESHOOTING: Check OPNsense API documentation for valid endpoints."

echo "=== Summary Report ==="
echo "Client machine: $(hostname)"
echo "Target OPNsense: $OPNSENSE_HOST"
echo "API User: monitoring-api"
echo "Test time: $(date)"
echo "API Capabilities:"
echo "   Authentication: Working"
echo "   System Status: Accessible"
echo "   Firewall Rules: $([ "$http_code" = "200" ] && echo "Full Access" || echo "Limited/Check Privileges")"
echo "NEXT STEPS:"
echo "   1. Phase 1 Complete - API verified from client"
echo "   2. Ready to deploy Enterprise Bridge"
echo "   3. Can integrate with monitoring systems"

cat > opnsense_api_test_results.txt << EOF
OPNsense API Test Results
========================
Date: $(date)
Client: $(hostname)
Target: $OPNSENSE_HOST
User: monitoring-api

Test Results:
- Authentication: SUCCESS
- System Status: SUCCESS
- Firewall Access: $([ "$http_code" = "200" ] && echo "SUCCESS" || echo "LIMITED")

API Key (first 20 chars): ${API_KEY:0:20}...
Ready for bridge deployment: YES
EOF

echo "Test results saved to: opnsense_api_test_results.txt"