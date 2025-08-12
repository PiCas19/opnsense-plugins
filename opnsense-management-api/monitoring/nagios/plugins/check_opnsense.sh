#!/usr/bin/env bash
set -euo pipefail

HOST=""
PORT="3000"
TIMEOUT=5

while getopts "H:p:t:" opt; do
  case "$opt" in
    H) HOST="$OPTARG" ;;
    p) PORT="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
  esac
done

if [[ -z "$HOST" ]]; then
  echo "UNKNOWN - Missing -H <host>"
  exit 3
fi

URL="http://${HOST}:${PORT}/api/v1/health"
HTTP_CODE=$(curl -m "$TIMEOUT" -s -o /dev/null -w "%{http_code}" "$URL" || true)

if [[ "$HTTP_CODE" == "200" ]]; then
  echo "OK - OPNsense API healthy"
  exit 0
elif [[ "$HTTP_CODE" == "000" ]]; then
  echo "CRITICAL - No response from $URL"
  exit 2
else
  echo "CRITICAL - HTTP $HTTP_CODE from $URL"
  exit 2
fi