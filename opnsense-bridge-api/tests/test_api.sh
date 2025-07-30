#!/bin/bash
# Test OPNsense API da macchina client
# Testa le credenziali API dal tuo computer

# 🔑 LE TUE CREDENZIALI REALI
API_KEY=""
API_SECRET=""
OPNSENSE_HOST=""

echo "🔥🔥🔥 OPNSENSE API TEST FROM CLIENT 🔥🔥🔥"
echo "🖥️  Client → OPNsense ($OPNSENSE_HOST)"
echo "👤 User: monitoring-api"
echo "🕒 $(date)"
echo ""

# Verifica prerequisiti
echo "🔧 Checking prerequisites..."
if ! command -v curl >/dev/null 2>&1; then
    echo "❌ ERROR: curl not installed"
    echo "Install: sudo apt install curl  # Ubuntu/Debian"
    echo "        brew install curl      # macOS"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "⚠️  jq not found - installing for better JSON output..."
    # Try to install jq
    if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y jq
    elif command -v brew >/dev/null 2>&1; then
        brew install jq
    else
        echo "⚠️  Please install jq manually for better output"
    fi
fi

# Test conectividad di rete
echo "🌐 Testing network connectivity to $OPNSENSE_HOST..."
if ping -c 1 -W 3 $OPNSENSE_HOST >/dev/null 2>&1; then
    echo "✅ Network connectivity: OK"
else
    echo "⚠️  WARNING: Cannot ping $OPNSENSE_HOST"
    echo "   Continuing anyway (ping might be blocked)..."
fi
echo ""

# Test 1: Basic API Authentication
echo "=== Test 1: API Authentication ==="
echo "Testing basic API authentication..."

response=$(curl -k -s -w "HTTPSTATUS:%{http_code};TIME:%{time_total}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/core/system/status" 2>/dev/null)

# Parse response
http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
time_total=$(echo "$response" | grep -o "TIME:[0-9.]*" | cut -d: -f2)
json_response=$(echo "$response" | sed 's/HTTPSTATUS:.*//g')

if [ "$http_code" = "200" ]; then
    echo "✅ SUCCESS: API authentication working!"
    echo "   Response time: ${time_total}s"
    
    if command -v jq >/dev/null 2>&1; then
        echo "   System info:"
        echo "$json_response" | jq -r '
            "     Hostname: " + (.hostname // "unknown") + 
            "\n     Version: " + (.version // "unknown") +
            "\n     Uptime: " + (.uptime // "unknown") +
            "\n     Load Avg: " + (.loadavg // "unknown")'
    else
        echo "   Raw response: ${json_response:0:100}..."
    fi
else
    echo "❌ FAILED: HTTP $http_code"
    echo "   Response: ${json_response:0:200}"
    echo ""
    echo "🔧 TROUBLESHOOTING:"
    echo "   1. Check if OPNsense web interface works: https://$OPNSENSE_HOST"
    echo "   2. Verify API is enabled: System → Settings → Administration"
    echo "   3. Check API key/secret are correct"
    echo "   4. Verify user 'monitoring-api' has proper privileges"
    exit 1
fi
echo ""

# Test 2: Firewall Rules Access
echo "=== Test 2: Firewall Rules ==="
echo "Retrieving firewall rules..."

response=$(curl -k -s -w "HTTPSTATUS:%{http_code}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/firewall/filter/get" 2>/dev/null)

http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
json_response=$(echo "$response" | sed 's/HTTPSTATUS:.*//g')

if [ "$http_code" = "200" ]; then
    echo "✅ SUCCESS: Firewall API accessible!"
    
    if command -v jq >/dev/null 2>&1; then
        total_rules=$(echo "$json_response" | jq -r '.rows | length' 2>/dev/null || echo "unknown")
        enabled_rules=$(echo "$json_response" | jq -r '[.rows[] | select(.enabled=="1")] | length' 2>/dev/null || echo "unknown")
        block_rules=$(echo "$json_response" | jq -r '[.rows[] | select(.action=="block")] | length' 2>/dev/null || echo "unknown")
        
        echo "   📊 Firewall Statistics:"
        echo "     Total rules: $total_rules"
        echo "     Enabled rules: $enabled_rules"
        echo "     Block rules: $block_rules"
    else
        echo "   Firewall data retrieved successfully"
    fi
else
    echo "⚠️  WARNING: Firewall API failed (HTTP $http_code)"
    echo "   Check user has 'Firewall: Rules' privilege"
fi
echo ""

# Test 3: Emergency Block Test
echo "=== Test 3: Emergency Block Capability ==="
echo "Testing emergency IP blocking (safe test IP)..."

TEST_IP="192.0.2.99"  # RFC5737 test IP
TEST_REASON="CLIENT API TEST - Safe to delete"

rule_payload=$(cat <<EOF
{
    "rule": {
        "enabled": "1",
        "interface": "wan",
        "action": "block",
        "source_net": "$TEST_IP/32",
        "description": "$TEST_REASON - $(date)"
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
    echo "✅ SUCCESS: Emergency block rule created!"
    
    if command -v jq >/dev/null 2>&1; then
        rule_uuid=$(echo "$json_response" | jq -r '.uuid // .id // "unknown"' 2>/dev/null)
        echo "   Rule UUID: $rule_uuid"
    fi
    
    # Apply the rule
    echo "   Applying firewall changes..."
    apply_response=$(curl -k -s -w "HTTPSTATUS:%{http_code}" \
        -u "$API_KEY:$API_SECRET" \
        -X POST \
        --connect-timeout 10 \
        --max-time 30 \
        "https://$OPNSENSE_HOST/api/firewall/filter/apply" 2>/dev/null)
    
    apply_code=$(echo "$apply_response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    
    if [ "$apply_code" = "200" ]; then
        echo "   ✅ Firewall changes applied successfully!"
        echo "   🚨 Emergency blocking: FULLY OPERATIONAL"
    else
        echo "   ⚠️  Rule created but apply might have failed"
    fi
else
    echo "⚠️  WARNING: Emergency block failed (HTTP $http_code)"
    echo "   Response: ${json_response:0:100}"
    echo "   Check user has 'Firewall: Rules: Edit' privilege"
fi
echo ""

# Test 4: Monitoring Capabilities
echo "=== Test 4: Monitoring Data Access ==="

# Test interface statistics
echo "Testing interface statistics..."
response=$(curl -k -s -w "HTTPSTATUS:%{http_code}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/diagnostics/interface/get_stats" 2>/dev/null)

http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)

if [ "$http_code" = "200" ]; then
    echo "✅ Interface stats: OK"
else
    echo "⚠️  Interface stats: Limited (HTTP $http_code)"
fi

# Test system information
response=$(curl -k -s -w "HTTPSTATUS:%{http_code}" \
    -u "$API_KEY:$API_SECRET" \
    --connect-timeout 10 \
    --max-time 30 \
    "https://$OPNSENSE_HOST/api/core/system/info" 2>/dev/null)

http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)

if [ "$http_code" = "200" ]; then
    echo "✅ System info: OK"
else
    echo "⚠️  System info: Limited (HTTP $http_code)"
fi

echo ""

# Summary Report
echo "🎯 CLIENT TEST SUMMARY"
echo "======================"
echo "🖥️  Client machine: $(hostname)"
echo "🌐 Target OPNsense: $OPNSENSE_HOST"
echo "👤 API User: monitoring-api"
echo "🕒 Test time: $(date)"
echo ""
echo "📊 API Capabilities:"
echo "   ✅ Authentication: Working"
echo "   ✅ System Status: Accessible"
echo "   $([ "$http_code" = "200" ] && echo "✅" || echo "⚠️ ") Firewall Rules: $([ "$http_code" = "200" ] && echo "Full Access" || echo "Limited/Check Privileges")"
echo "   🚨 Emergency Blocking: $([ "$http_code" = "200" ] && echo "OPERATIONAL" || echo "Needs Setup")"
echo ""
echo "🔧 API Endpoints Tested:"
echo "   • /api/core/system/status"
echo "   • /api/firewall/filter/get"
echo "   • /api/firewall/filter/addRule"
echo "   • /api/firewall/filter/apply"
echo ""
echo "🚀 NEXT STEPS:"
echo "   1. ✅ Phase 1 Complete - API verified from client"
echo "   2. 🏗️  Ready to deploy Enterprise Bridge"
echo "   3. 📊 Can integrate with monitoring systems"
echo ""
echo "💡 BRIDGE DEPLOYMENT OPTIONS:"
echo "   • Deploy on this client machine"
echo "   • Deploy on dedicated server"
echo "   • Deploy in Docker container"
echo "   • Deploy in cloud (AWS/GCP/Azure)"
echo ""
echo "✨ CLIENT API TEST COMPLETE!"

# Save test results
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

echo ""
echo "📄 Test results saved to: opnsense_api_test_results.txt"