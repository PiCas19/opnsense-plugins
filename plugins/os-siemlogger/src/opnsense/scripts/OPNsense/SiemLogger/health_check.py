#!/usr/bin/env python3
import json
import logging
import time
import psutil
from datetime import datetime
import sys

CONFIG_FILE = "/usr/local/opnsense/mvc/app/config/config.json"
LOG_FILE = "/var/log/siemlogger.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"{datetime.now()}: Failed to load config: {str(e)}")
        return {}

def get_stats(type="all"):
    config = load_config()
    stats = {}
    try:
        if type == "all" or type == "disk":
            disk_usage = psutil.disk_usage('/var/log').percent
            stats["disk_usage"] = {
                "percentage": round(disk_usage, 2),
                "threshold_exceeded": disk_usage >= int(config.get('monitoring', {}).get('disk_usage_threshold', 80))
            }
        if type == "all" or type == "events":
            event_count = 0
            log_file = LOG_FILE
            if config.get('logging_rules', {}).get('log_network_events') and config.get('general', {}).get('enabled'):
                with open(log_file, 'r') as f:
                    event_count = sum(1 for line in f if "network" in line.lower())
            stats["event_count"] = event_count
        if type == "all" or type == "audit":
            audit_count = 0
            if config.get('audit_settings', {}).get('audit_enabled'):
                with open(log_file, 'r') as f:
                    audit_count = sum(1 for line in f if "audit" in line.lower())
            stats["audit_count"] = audit_count
        return {"status": "ok", "data": stats}
    except Exception as e:
        logging.error(f"{datetime.now()}: Failed to retrieve stats: {str(e)}")
        return {"status": "error", "message": str(e), "data": {}}

def health_check(config):
    monitoring = config.get('monitoring', {})
    interval = int(monitoring.get('health_check_interval', 300))
    while True:
        if monitoring.get('metrics_collection'):
            metrics = get_stats("all")["data"]
            logging.info(f"{datetime.now()}: Health metrics: {json.dumps(metrics)}")
            if monitoring.get('disk_usage_threshold') and metrics.get('disk_usage', {}).get('percentage', 0) >= int(monitoring['disk_usage_threshold']):
                send_notification(config, f"Disk usage threshold exceeded: {metrics['disk_usage']['percentage']}%")
        time.sleep(interval)

def send_notification(config, message):
    if config['notifications']['email_alerts']:
        for recipient in config['notifications']['email_recipients'].split(','):
            logging.info(f"{datetime.now()}: Sending email to {recipient}: {message}")
    if config['notifications']['webhook_url']:
        try:
            requests.post(config['notifications']['webhook_url'], json={"message": message})
        except Exception as e:
            logging.error(f"{datetime.now()}: Webhook notification failed: {str(e)}")

if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "run"
    if action == "stats":
        type = sys.argv[2] if len(sys.argv) > 2 else "all"
        result = get_stats(type)
        print(json.dumps(result))
    else:
        config = load_config()
        health_check(config)