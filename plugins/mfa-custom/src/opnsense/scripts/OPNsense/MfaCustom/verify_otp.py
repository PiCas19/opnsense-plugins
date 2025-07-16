#!/usr/local/bin/python3

import sys
import pyotp
import logging
import os
import json

log_path = "/var/log/mfacustom.log"
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def log_result(user, status):
    ip = os.getenv("REMOTE_ADDR", "unknown")
    logging.info(f"User: {user} | Result: {status} | IP: {ip}")

if len(sys.argv) != 3:
    print("FAIL")
    log_result("unknown", "FAIL (args)")
    sys.exit(1)

username = sys.argv[1]
otp = sys.argv[2]

try:
    with os.popen("/usr/local/sbin/configctl -j configd show OPNsense.MfaCustom.settings") as conf:
        data = json.load(conf)
        secret_map = json.loads(data.get("secrets", "{}"))
        secret = secret_map.get(username)
except Exception as e:
    print("FAIL")
    log_result(username, f"ERROR (read config: {str(e)})")
    sys.exit(1)

if not secret:
    print("FAIL")
    log_result(username, "FAIL (no secret)")
    sys.exit(1)

try:
    if pyotp.TOTP(secret).verify(otp):
        print("OK")
        log_result(username, "OK")
    else:
        print("FAIL")
        log_result(username, "FAIL (bad OTP)")
except Exception as e:
    print("FAIL")
    log_result(username, f"ERROR ({str(e)})")
    sys.exit(1)
