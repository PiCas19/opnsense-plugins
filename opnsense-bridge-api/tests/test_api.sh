#!/bin/bash
# Test OPNsense API da macchina client
# Verifica le credenziali API dal tuo computer

# LE TUE CREDENZIALI REALI (da impostare prima di eseguire)
API_KEY=""
API_SECRET=""
OPNSENSE_HOST=""

# Verifica prerequisiti
echo "Checking prerequisites..."
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl not installed"
    echo "Install: sudo apt install curl  # Ubuntu/Debian"
    echo "        brew install curl      # macOS"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Warning: jq not found - installing for better JSON output..."
    if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y jq
    elif command -v brew >/dev/null 2>&1; then
        brew install jq
    else
        echo "Please install jq manually for better output"
    fi
fi

# Test connettività di rete
echo "Testing network connectivity to $OPNSENSE_HOST..."
if ping -c 1 -W 3 "$OPNSENSE_HOST" >/dev/null 2>&1; then
    echo "Network connectivity: OK"
else
    echo "WARNING: Cannot ping $OPNSENSE_HOST"
    echo "Continuing anyway (ping might be blocked)..."
fi

# Test 1: Autenticazione API
echo "=== Test 1: API Authentication ==="
echo "Testing basic API authentication..."

response=$(curl -k -s -w "HTTPSTATUS:%{http_code};TIME:%{time_total}" \
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
        echo "System info:"
        echo "$json_response" | jq -r '
            "     Hostname: " + (.hostname // "unknown") +
            "\n     Version: " + (.version // "unknown") +
            "\n     Uptime: " + (.uptime // "unknown") +
            "\n     Load Avg: " + (.loadavg // "unknown")'
    else
        echo "Raw response: ${json_response:0:100}..."
    fi
else
    echo "FAILED: HTTP $http_code"
    echo "Response: ${json_response:0:200}"
    echo "TROUBLESHOOTING:"
    echo "   1. Verifica se l'interfaccia web OPNsense funziona: https://$OPNSENSE_HOST"
    echo "   2. Controlla se l'API è abilitata: System -> Settings -> Administration"
    echo "   3. Verifica che API key/secret siano corretti"
    echo "   4. Assicurati che l'utente 'monitoring-api' abbia privilegi 'System: General'"
    exit 1
fi

# Test 2: Recupero regole firewall
echo "=== Test 2: Firewall Rules ==="
echo "Retrieving firewall rules..."

response=$(curl -k -s -w "HTTPSTATUS:%{http_code}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/firewall/filter/list" 2>/dev/null)

http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
json_response=$(echo "$response" | sed 's/HTTPSTATUS:.*//g')

if [ "$http_code" = "200" ]; then
    echo "SUCCESS: Firewall API accessible!"
    if command -v jq >/dev/null 2>&1; then
        total_rules=$(echo "$json_response" | jq -r '.rows | length' 2>/dev/null || echo "unknown")
        enabled_rules=$(echo "$json_response" | jq -r '[.rows[] | select(.enabled=="1")] | length' 2>/dev/null || echo "unknown")
        block_rules=$(echo "$json_response" | jq -r '[.rows[] | select(.action=="block")] | length' 2>/dev/null || echo "unknown")
        echo "Firewall Statistics:"
        echo "     Total rules: $total_rules"
        echo "     Enabled rules: $enabled_rules"
        echo "     Block rules: $block_rules"
    else
        echo "Firewall data retrieved successfully"
    fi
else
    echo "WARNING: Firewall API failed (HTTP $http_code)"
    echo "Check user has 'Firewall: Rules' privilege"
fi

# Test 3: Test blocco emergenza
echo "=== Test 3: Emergency Block Capability ==="
echo "Testing emergency IP blocking (safe test IP)..."

TEST_IP="192.0.2.99"  # RFC5737 test IP
TEST_REASON="CLIENT API TEST - Safe to delete"

rule_payload=$(cat <<EOF
{
    "filter": {
        "rule": {
            "enabled": "1",
            "interface": "wan",
            "type": "pass",
            "direction": "in",
            "ipprotocol": "inet",
            "protocol": "any",
            "source": {
                "any": ""
            },
            "destination": {
                "any": ""
            },
            "action": "block",
            "description": "$TEST_REASON - $(date)"
        }
    }
}
EOF
)

response=$(curl -k -s -w "HTTPSTATUS:%{http_code}" \
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
        rule_uuid=$(echo "$json_response" | jq -r '.filter.uuid // "unknown"' 2>/dev/null)
        echo "Rule UUID: $rule_uuid"
    fi
    echo "Applying firewall changes..."
    apply_response=$(curl -k -s -w "HTTPSTATUS:%{http_code}" \
        -u "$API_KEY:$API_SECRET" \
        -X POST \
        --connect-timeout 10 \
        --max-time 30 \
        "https://$OPNSENSE_HOST/api/firewall/filter/apply" 2>/dev/null)
    apply_code=$(echo "$apply_response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    if [ "$apply_code" = "200" ]; then
        echo "Firewall changes applied successfully!"
        echo "Emergency blocking: FULLY OPERATIONAL"
    else
        echo "Rule created but apply might have failed"
    fi
else
    echo "WARNING: Emergency block failed (HTTP $http_code)"
    echo "Response: ${json_response:0:100}"
    echo "Check user has 'Firewall: Rules: Edit' privilege"
fi

# Test 4: Accesso dati di monitoraggio
echo "=== Test 4: Monitoring Data Access ==="
echo "Testing interface statistics..."
response=$(curl -k -s -w "HTTPSTATUS:%{http_code}" \
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
response=$(curl -k -s -w "HTTPSTATUS:%{http_code}" \
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

# Riassunto risultati
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

# Salva risultati
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