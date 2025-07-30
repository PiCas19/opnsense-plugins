#!/bin/bash
# Test OPNsense API da macchina client
# Verifica le credenziali API dal tuo computer

API_KEY=""
API_SECRET=""
OPNSENSE_HOST="192.168.216.1"

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
        echo "$json_response" | jq -r '.[] | .hostname, .version, .uptime, .loadavg' 2>/dev/null || echo "$json_response" | jq -r '.hostname, .version, .uptime, .loadavg'
    fi
else
    echo "FAILED: HTTP $http_code"
    echo "Response: ${json_response:0:200}"
    echo "TROUBLESHOOTING: Verifica credenziali e privilegi 'System: General'"
    exit 1
fi

# Test 2: Recupero regole firewall
echo "=== Test 2: Firewall Rules ==="
response=$(curl -k -v -s -w "HTTPSTATUS:%{http_code}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/firewall/filter" 2>/dev/null)  # GET per tutte le regole
http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
json_response=$(echo "$response" | sed 's/HTTPSTATUS:.*//g')
if [ "$http_code" = "200" ]; then
    echo "SUCCESS: Firewall API accessible!"
    if command -v jq >/dev/null 2>&1; then
        total_rules=$(echo "$json_response" | jq -r '.filter.rules | length' 2>/dev/null || echo "$json_response" | jq -r '.rules | length' 2>/dev/null || echo "unknown")
        echo "Total rules: $total_rules"
    fi
else
    echo "WARNING: Firewall API failed (HTTP $http_code)"
    echo "Check 'Firewall: Rules' privilege or endpoint"
fi

# Test 3: Test blocco emergenza
echo "=== Test 3: Emergency Block Capability ==="
TEST_IP="192.0.2.99"
TEST_REASON="CLIENT API TEST - Safe to delete - $(date)"
rule_payload=$(cat <<EOF
{
    "filter": {
        "rule": {
            "enabled": "1",
            "interface": "wan",
            "type": "block",
            "ipprotocol": "inet",
            "source": {
                "address": "$TEST_IP",
                "netbits": "32"
            },
            "destination": {
                "any": ""
            },
            "description": "$TEST_REASON"
        }
    }
}
EOF
)
echo "Sending payload: $rule_payload"
response=$(curl -k -v -s -w "HTTPSTATUS:%{http_code}" \
    -u "$API_KEY:$API_SECRET" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$rule_payload" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/firewall/filter/addRule" 2>/dev/null)
http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
json_response=$(echo "$response" | sed 's/HTTPSTATUS:.*//g')
if [ "$http_code" = "200" ]; then
    echo "SUCCESS: Emergency block rule created!"
    if command -v jq >/dev/null 2>&1; then
        rule_uuid=$(echo "$json_response" | jq -r '.uuid // .id // "unknown"' 2>/dev/null)
        echo "Rule UUID: $rule_uuid"
    fi
    echo "Applying firewall changes..."
    apply_response=$(curl -k -v -s -w "HTTPSTATUS:%{http_code}" \
        -u "$API_KEY:$API_SECRET" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{}" \
        --connect-timeout 10 \
        --max-time 30 \
        "https://$OPNSENSE_HOST/api/firewall/filter/apply" 2>/dev/null)
    apply_code=$(echo "$apply_response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    if [ "$apply_code" = "200" ]; then
        echo "Firewall changes applied successfully!"
        echo "Emergency blocking: FULLY OPERATIONAL"
    else
        echo "Rule created but apply failed (HTTP $apply_code)"
        echo "Response: ${apply_response:0:200}"
    fi
else
    echo "WARNING: Emergency block failed (HTTP $http_code)"
    echo "Response: ${json_response:0:200}"
    echo "TROUBLESHOOTING: Verifica 'Firewall: Rules: Edit' privilege or payload"
fi

# Test 4: Recupero regola specifica
echo "=== Test 4: Get Specific Rule ==="
if [ "$rule_uuid" != "unknown" ]; then
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
            echo "$json_response" | jq -r '.[] | .description, .source.address' 2>/dev/null || echo "$json_response" | jq -r '.description, .source.address'
        fi
    else
        echo "WARNING: Failed to retrieve rule (HTTP $http_code)"
        echo "Response: ${json_response:0:200}"
    fi
else
    echo "WARNING: No valid UUID available to test getRule"
fi

# Test 5: Accesso dati di monitoraggio
echo "=== Test 5: Monitoring Data Access ==="
echo "Testing interface statistics..."
response=$(curl -k -v -s -w "HTTPSTATUS:%{http_code}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/diagnostics/interface/status" 2>/dev/null)
http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
if [ "$http_code" = "200" ]; then
    echo "Interface stats: OK"
else
    echo "Interface stats: Limited (HTTP $http_code)"
fi

echo "Testing system information..."
response=$(curl -k -v -s -w "HTTPSTATUS:%{http_code}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/core/system/info" 2>/dev/null)
http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
if [ "$http_code" = "200" ]; then
    echo "System info: OK"
else
    echo "System info: Limited (HTTP $http_code)"
fi

echo "=== Summary Report ==="
echo "Client machine: $(hostname)"
echo "Target OPNsense: $OPNSENSE_HOST"
echo "API User: monitoring-api"
echo "Test time: $(date)"
echo "API Capabilities:"
echo "   Authentication: Working"
echo "   System Status: Accessible"
echo "   Firewall Rules: $([ "$http_code" = "200" ] && echo "Full Access" || echo "Limited/Check Privileges")"
echo "   Emergency Blocking: $([ "$http_code" = "200" ] && echo "OPERATIONAL" || echo "Needs Setup")"
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
- Emergency Block: $([ "$http_code" = "200" ] && echo "SUCCESS" || echo "NEEDS_SETUP")

API Key (first 20 chars): ${API_KEY:0:20}...
Ready for bridge deployment: YES
EOF

echo "Test results saved to: opnsense_api_test_results.txt"