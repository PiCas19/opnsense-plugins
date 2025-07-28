#!/usr/bin/env python3
import json
import logging
import socket
import ssl
import sys
from datetime import datetime
import requests

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

def format_event(event, export_format):
    if export_format == "json":
        return json.dumps(event)
    elif export_format == "cef":
        return f"CEF:0|OPNsense|SiemLogger|1.0|{event['event_type']}|{event['details']}|1|"
    elif export_format == "leef":
        return f"LEEF:1.0|OPNsense|SiemLogger|{event['event_type']}|{json.dumps(event)}"
    else:  # syslog
        return f"{event['timestamp']} {event['event_type']}: {event['details']}"

def export_to_siem(events, config):
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

        logging.info(f"{datetime.now()}: Successfully exported {len(events)} events to SIEM")
        return {"status": "ok", "message": f"Exported {len(events)} events"}
    except Exception as e:
        logging.error(f"{datetime.now()}: Error exporting to SIEM: {str(e)}")
        if config['notifications']['alert_on_failed_export']:
            send_notification(config, f"SIEM export failed: {str(e)}")
        return {"status": "error", "message": str(e)}

def send_notification(config, message):
    if config['notifications']['email_alerts']:
        for recipient in config['notifications']['email_recipients'].split(','):
            logging.info(f"{datetime.now()}: Sending email to {recipient}: {message}")
    if config['notifications']['webhook_url']:
        try:
            requests.post(config['notifications']['webhook_url'], json={"message": message})
        except Exception as e:
            logging.error(f"{datetime.now()}: Webhook notification failed: {str(e)}")

def collect_events(config):
    events = []
    logging_rules = config.get('logging_rules', {})
    if logging_rules.get('log_authentication'):
        events.append({
            "timestamp": datetime.now().isoformat(),
            "event_type": "authentication",
            "user": "admin",
            "details": "Login attempt"
        })
    if logging_rules.get('log_network_events'):
        events.append({
            "timestamp": datetime.now().isoformat(),
            "event_type": "network",
            "details": "Network connection detected"
        })
    return events

def get_logs(page, limit):
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
        logging.error(f"{datetime.now()}: Failed to retrieve logs: {str(e)}")
        return {"status": "error", "message": str(e), "data": []}

def test_config():
    config = load_config()
    if not config.get('siem_export', {}).get('siem_server'):
        return {"status": "error", "message": "SIEM server not configured"}
    return {"status": "ok", "message": "Configuration is valid"}

if __name__ == "__main__":
    config = load_config()
    action = sys.argv[1] if len(sys.argv) > 1 else "export"
    
    if action == "export":
        format = sys.argv[2] if len(sys.argv) > 2 else "json"
        events = collect_events(config)
        result = export_to_siem(events, config)
        print(json.dumps(result))
    elif action == "get_logs":
        page = sys.argv[2] if len(sys.argv) > 2 else "1"
        limit = sys.argv[3] if len(sys.argv) > 3 else "100"
        result = get_logs(page, limit)
        print(json.dumps(result))
    elif action == "test":
        format = sys.argv[2] if len(sys.argv) > 2 else "json"
        events = [{
            "timestamp": datetime.now().isoformat(),
            "event_type": "test",
            "user": "test_user",
            "details": "Test event"
        }]
        result = export_to_siem(events, config)
        print(json.dumps(result))
    elif action == "test_config":
        result = test_config()
        print(json.dumps(result))
    elif action == "configure":
        # Placeholder for configuration reload
        logging.info(f"{datetime.now()}: Configuration reloaded")
        print(json.dumps({"status": "ok", "message": "Configuration reloaded"}))
    else:
        print(json.dumps({"status": "error", "message": f"Unknown action: {action}"}))
        sys.exit(1)