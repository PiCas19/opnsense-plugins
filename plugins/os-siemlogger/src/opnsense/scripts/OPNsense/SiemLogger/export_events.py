#!/usr/bin/env python3

"""
SIEM Logger Event Exporter
Copyright (C) 2025 OPNsense SiemLogger Plugin
All rights reserved.
"""

import json
import logging
import socket
import ssl
import sys
import time  
import requests
from datetime import datetime

CONFIG_FILE = "/usr/local/etc/siemlogger/config.json"  
LOG_FILE = "/var/log/siemlogger/export_events.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

def load_config():
    """Load configuration file"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"{datetime.now().isoformat()}: Failed to load config: {str(e)}")
        # Ritorna una configurazione di default se il file non esiste
        return {
            "siem_export": {
                "export_enabled": False,
                "siem_server": "",
                "siem_port": 514,
                "protocol": "udp",
                "export_format": "json",
                "facility": "local0"
            },
            "notifications": {
                "alert_on_failed_export": False,
                "email_alerts": False,
                "email_recipients": "",
                "webhook_url": ""
            },
            "logging_rules": {
                "log_authentication": True,
                "log_network_events": True
            }
        }

def format_event(event, export_format):
    """Format event for export"""
    if export_format == "json":
        return json.dumps(event)
    elif export_format == "cef":
        return f"CEF:0|OPNsense|SiemLogger|1.0|{event['event_type']}|{event['description']}|{event['severity']}|src={event['source_ip']} user={event['user']} details={event['details']}"
    elif export_format == "leef":
        return f"LEEF:1.0|OPNsense|SiemLogger|{event['event_type']}|{event['severity']}|src={event['source_ip']}\tuser={event['user']}\tdesc={event['description']}\tdetails={event['details']}"
    else:  # syslog
        return f"{event['timestamp']} {event['event_type']}: {event['description']} {event['details']}"

def export_to_siem(events, config):
    """Export events to SIEM/NDR"""
    if not config.get('siem_export', {}).get('export_enabled', False):
        return {"status": "error", "message": "SIEM export is disabled"}
    try:
        siem_server = config['siem_export']['siem_server']
        siem_port = int(config['siem_export']['siem_port'])
        protocol = config['siem_export']['protocol']
        export_format = config['siem_export']['export_format']
        facility = config['siem_export']['facility']

        if protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for event in events:
                message = format_event(event, export_format)
                sock.sendto(message.encode(), (siem_server, siem_port))
            sock.close()
        elif protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((siem_server, siem_port))
            for event in events:
                message = format_event(event, export_format) + "\n"
                sock.send(message.encode())
            sock.close()
        elif protocol == "tls":
            context = ssl.create_default_context()
            if config['siem_export'].get('tls_cert'):
                context.load_cert_chain(certfile=config['siem_export']['tls_cert'])
            sock = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=siem_server)
            sock.connect((siem_server, siem_port))
            for event in events:
                message = format_event(event, export_format) + "\n"
                sock.send(message.encode())
            sock.close()

        logging.info(f"{datetime.now().isoformat()}: Successfully exported {len(events)} events to SIEM")
        return {"status": "ok", "message": f"Exported {len(events)} events"}
    except Exception as e:
        logging.error(f"{datetime.now().isoformat()}: Error exporting to SIEM: {str(e)}")
        if config.get('notifications', {}).get('alert_on_failed_export', False):
            send_notification(config, f"SIEM export failed: {str(e)}")
        return {"status": "error", "message": str(e)}

def send_notification(config, message):
    """Send notifications via email or webhook"""
    notifications = config.get('notifications', {})
    if notifications.get('email_alerts', False):
        for recipient in notifications.get('email_recipients', '').split(','):
            if recipient.strip():
                logging.info(f"{datetime.now().isoformat()}: Sending email to {recipient.strip()}: {message}")
    if notifications.get('webhook_url'):
        try:
            requests.post(notifications['webhook_url'], json={"message": message})
        except Exception as e:
            logging.error(f"{datetime.now().isoformat()}: Webhook notification failed: {str(e)}")

def collect_events(config):
    """Collect sample events for testing"""
    events = []
    logging_rules = config.get('logging_rules', {})
    current_timestamp = int(time.time())
    
    if logging_rules.get('log_authentication', True):
        events.append({
            "timestamp": current_timestamp,
            "event_type": "authentication",
            "user": "admin",
            "source_ip": "127.0.0.1",
            "description": "Login attempt",
            "details": json.dumps({"log_line": "Test authentication event"}),
            "severity": "info",
            "source_log": "test"
        })
    if logging_rules.get('log_network_events', True):
        events.append({
            "timestamp": current_timestamp,
            "event_type": "network",
            "user": "system",
            "source_ip": "127.0.0.1",
            "description": "Network connection detected",
            "details": json.dumps({"log_line": "Test network event"}),
            "severity": "info",
            "source_log": "test"
        })
    return events

def get_logs(page, limit):
    """Get log entries with pagination"""
    logs = []
    log_file = LOG_FILE
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
        start = (int(page) - 1) * int(limit)
        end = start + int(limit)
        logs = lines[start:end]
        return {
            "status": "ok",
            "data": logs,
            "total": len(lines),
            "page": int(page),
            "limit": int(limit)
        }
    except Exception as e:
        logging.error(f"{datetime.now().isoformat()}: Failed to retrieve logs: {str(e)}")
        return {"status": "error", "message": str(e), "data": []}

def test_config():
    """Test configuration validity"""
    config = load_config()
    if not config.get('siem_export', {}).get('siem_server'):
        return {"status": "error", "message": "SIEM server not configured"}
    return {"status": "ok", "message": "Configuration is valid"}

if __name__ == "__main__":
    config = load_config()
    action = sys.argv[1] if len(sys.argv) > 1 else "export"
    
    if action == "export":
        format_type = sys.argv[2] if len(sys.argv) > 2 else "json"
        events = collect_events(config)
        result = export_to_siem(events, config)
        print(json.dumps(result))
    elif action == "get_logs":
        page = sys.argv[2] if len(sys.argv) > 2 else "1"
        limit = sys.argv[3] if len(sys.argv) > 3 else "100"
        result = get_logs(page, limit)
        print(json.dumps(result))
    elif action == "test":
        format_type = sys.argv[2] if len(sys.argv) > 2 else "json"
        events = [{
            "timestamp": int(time.time()),
            "event_type": "test",
            "user": "test_user",
            "source_ip": "127.0.0.1",
            "description": "Test event",
            "details": json.dumps({"log_line": "Test event"}),
            "severity": "info",
            "source_log": "test"
        }]
        result = export_to_siem(events, config)
        print(json.dumps(result))
    elif action == "test_config":
        result = test_config()
        print(json.dumps(result))
    elif action == "configure":
        logging.info(f"{datetime.now().isoformat()}: Configuration reloaded")
        print(json.dumps({"status": "ok", "message": "Configuration reloaded"}))
    else:
        print(json.dumps({"status": "error", "message": f"Unknown action: {action}"}))
        sys.exit(1)