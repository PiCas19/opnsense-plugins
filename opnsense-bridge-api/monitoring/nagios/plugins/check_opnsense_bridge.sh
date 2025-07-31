#!/bin/bash

# Nagios plugin to check OPNsense Monitoring Bridge status
# Queries /nagios/firewall-rules and /nagios/system-health endpoints

BRIDGE_HOST="https://172.16.216.10:8443"
WARNING_RULES=50
CRITICAL_RULES=100
WARNING_CPU=80
CRITICAL_CPU=95
WARNING_MEMORY=85
CRITICAL_MEMORY=95

# Function to check HTTP response
check_endpoint() {
    local endpoint=$1
    local output=$(curl -s -k "${BRIDGE_HOST}${endpoint}")
    if [ $? -ne 0 ]; then
        echo "CRITICAL: Failed to reach ${endpoint}"
        exit 2
    fi
    echo "$output"
}

# Check firewall rules
rules_output=$(check_endpoint "/nagios/firewall-rules")
if echo "$rules_output" | grep -q "OK"; then
    rules_count=$(echo "$rules_output" | grep -oP 'rules=\K\d+')
    if [ "$rules_count" -ge "$CRITICAL_RULES" ]; then
        echo "CRITICAL: $rules_output"
        exit 2
    elif [ "$rules_count" -ge "$WARNING_RULES" ]; then
        echo "WARNING: $rules_output"
        exit 1
    else
        echo "OK: $rules_output"
        exit 0
    fi
else
    echo "$rules_output"
    exit 2
fi

# Check system health
health_output=$(check_endpoint "/nagios/system-health")
if echo "$health_output" | grep -q "OK"; then
    cpu_usage=$(echo "$health_output" | grep -oP 'cpu=\K[\d.]+')
    memory_usage=$(echo "$health_output" | grep -oP 'memory=\K[\d.]+')
    status=0
    message="OK: $health_output"
    if (( $(echo "$cpu_usage > $CRITICAL_CPU" | bc -l) )); then
        message="CRITICAL: CPU usage $cpu_usage% exceeds critical threshold $CRITICAL_CPU%"
        status=2
    elif (( $(echo "$cpu_usage > $WARNING_CPU" | bc -l) )); then
        message="WARNING: CPU usage $cpu_usage% exceeds warning threshold $WARNING_CPU%"
        status=1
    elif (( $(echo "$memory_usage > $CRITICAL_MEMORY" | bc -l) )); then
        message="CRITICAL: Memory usage $memory_usage% exceeds critical threshold $CRITICAL_MEMORY%"
        status=2
    elif (( $(echo "$memory_usage > $WARNING_MEMORY" | bc -l) )); then
        message="WARNING: Memory usage $memory_usage% exceeds warning threshold $WARNING_MEMORY%"
        status=1
    fi
    echo "$message"
    exit $status
else
    echo "$health_output"
    exit 2
fi