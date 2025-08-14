#!/usr/bin/env bash
set -euo pipefail

# Nagios plugin to check OPNsense API health
# Author: OPNsense Monitoring
# Version: 1.0

HOST=""
PORT="3000"
TIMEOUT=10
PATH_ENDPOINT="/api/v1/health"
VERBOSE=0

# Nagios exit codes
OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

# Help function
usage() {
    cat << EOF
Usage: $0 -H <host> [-p <port>] [-t <timeout>] [-P <path>] [-v]

Options:
  -H <host>     Host or IP to check (REQUIRED)
  -p <port>     Port (default: 3000)
  -t <timeout>  Timeout in seconds (default: 10)
  -P <path>     Endpoint path (default: /api/v1/health)
  -v            Verbose mode
  -h            Show this help

Examples:
  $0 -H 192.168.1.100
  $0 -H 192.168.1.100 -p 8080 -t 15
  $0 -H api.example.com -P /health -v

Exit codes:
  0 - OK: API working
  1 - WARNING: Minor issues
  2 - CRITICAL: API not available
  3 - UNKNOWN: Plugin error
EOF
}

# Verbose logging function
log() {
    if [[ $VERBOSE -eq 1 ]]; then
        echo "DEBUG: $1" >&2
    fi
}

# Parse arguments
while getopts "H:p:t:P:vh" opt; do
    case "$opt" in
        H) HOST="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        P) PATH_ENDPOINT="$OPTARG" ;;
        v) VERBOSE=1 ;;
        h) usage; exit $OK ;;
        *) usage; exit $UNKNOWN ;;
    esac
done

# Check that host is specified
if [[ -z "$HOST" ]]; then
    echo "UNKNOWN - Host not specified. Use -H <host>"
    exit $UNKNOWN
fi

# Check that timeout is numeric
if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
    echo "UNKNOWN - Timeout must be numeric"
    exit $UNKNOWN
fi

# Check that port is numeric
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
    echo "UNKNOWN - Port must be numeric"
    exit $UNKNOWN
fi

# Build URL
URL="http://${HOST}:${PORT}${PATH_ENDPOINT}"

log "Checking URL: $URL"
log "Timeout: ${TIMEOUT}s"

# Variables for results
HTTP_CODE=""
RESPONSE_TIME=""
RESPONSE_BODY=""

# Execute HTTP request
START_TIME=$(date +%s.%N)

if command -v curl >/dev/null 2>&1; then
    log "Using curl for HTTP request"
    
    # Use curl to make request
    CURL_OUTPUT=$(curl -m "$TIMEOUT" -s -w "%{http_code}|%{time_total}" -o /tmp/nagios_check_response "$URL" 2>&1 || true)
    
    if [[ $? -eq 0 ]]; then
        HTTP_CODE=$(echo "$CURL_OUTPUT" | cut -d'|' -f1)
        RESPONSE_TIME=$(echo "$CURL_OUTPUT" | cut -d'|' -f2)
        
        if [[ -f /tmp/nagios_check_response ]]; then
            RESPONSE_BODY=$(cat /tmp/nagios_check_response 2>/dev/null || echo "")
            rm -f /tmp/nagios_check_response
        fi
    else
        log "Curl error: $CURL_OUTPUT"
        HTTP_CODE="000"
    fi
    
elif command -v wget >/dev/null 2>&1; then
    log "Using wget for HTTP request"
    
    # Use wget as fallback
    WGET_OUTPUT=$(wget --timeout="$TIMEOUT" --tries=1 -q -O /tmp/nagios_check_response --server-response "$URL" 2>&1 || true)
    
    if [[ $? -eq 0 ]]; then
        HTTP_CODE=$(echo "$WGET_OUTPUT" | grep "HTTP/" | tail -1 | awk '{print $2}' || echo "000")
        
        if [[ -f /tmp/nagios_check_response ]]; then
            RESPONSE_BODY=$(cat /tmp/nagios_check_response 2>/dev/null || echo "")
            rm -f /tmp/nagios_check_response
        fi
    else
        log "Wget error: $WGET_OUTPUT"
        HTTP_CODE="000"
    fi
    
else
    echo "UNKNOWN - Neither curl nor wget are available"
    exit $UNKNOWN
fi

END_TIME=$(date +%s.%N)
RESPONSE_TIME=${RESPONSE_TIME:-$(echo "$END_TIME - $START_TIME" | bc 2>/dev/null || echo "0")}

log "HTTP code: $HTTP_CODE"
log "Response time: ${RESPONSE_TIME}s"
log "Response body: $RESPONSE_BODY"

# Analyze the response
case "$HTTP_CODE" in
    200)
        # Check if response contains health indicators
        if [[ -n "$RESPONSE_BODY" ]]; then
            if echo "$RESPONSE_BODY" | grep -q -i "healthy\|ok\|success\|running"; then
                echo "OK - OPNsense API healthy (${RESPONSE_TIME}s) | response_time=${RESPONSE_TIME}s;;;0"
                exit $OK
            elif echo "$RESPONSE_BODY" | grep -q -i "error\|fail\|down"; then
                echo "WARNING - API responds but reports errors: $RESPONSE_BODY | response_time=${RESPONSE_TIME}s;;;0"
                exit $WARNING
            else
                echo "OK - OPNsense API responds HTTP 200 (${RESPONSE_TIME}s) | response_time=${RESPONSE_TIME}s;;;0"
                exit $OK
            fi
        else
            echo "OK - OPNsense API responds HTTP 200 (${RESPONSE_TIME}s) | response_time=${RESPONSE_TIME}s;;;0"
            exit $OK
        fi
        ;;
    000)
        echo "CRITICAL - No response from OPNsense API at $URL (timeout: ${TIMEOUT}s)"
        exit $CRITICAL
        ;;
    4*)
        echo "WARNING - HTTP client error $HTTP_CODE from OPNsense API | response_time=${RESPONSE_TIME}s;;;0"
        exit $WARNING
        ;;
    5*)
        echo "CRITICAL - HTTP server error $HTTP_CODE from OPNsense API | response_time=${RESPONSE_TIME}s;;;0"
        exit $CRITICAL
        ;;
    *)
        echo "WARNING - Unexpected HTTP code $HTTP_CODE from OPNsense API | response_time=${RESPONSE_TIME}s;;;0"
        exit $WARNING
        ;;
esac