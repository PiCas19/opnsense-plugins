
#!/usr/local/bin/python3.11

"""
SIEM Logger Settings Loader
Copyright (C) 2025 OPNsense SiemLogger Plugin
All rights reserved.
"""

import xml.etree.ElementTree as ET
import json
import time
import os
import logging

CONFIG_PATH = "/conf/config.xml"
CACHE_FILE = "/tmp/siemlogger_cache.json"
CACHE_TIMEOUT = 30  # seconds
LOG_DIR = "/var/log/siemlogger"
LOG_FILE = f"{LOG_DIR}/settings.log"

# FIXED: Ensure log directory and file exist BEFORE initializing logging
os.makedirs(LOG_DIR, exist_ok=True)
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as f:
        f.write("")

# Initialize logging
try:
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
except Exception as e:
    # Fallback to console logging if file logging fails
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not initialize file logging: {e}")

_cache = None
_cache_time = 0

def get_siemlogger_config():
    """Extracts SIEM Logger configuration from /OPNsense/SiemLogger"""
    try:
        if not os.path.exists(CONFIG_PATH):
            logger.error(f"Configuration file {CONFIG_PATH} not found")
            return None

        tree = ET.parse(CONFIG_PATH)
        root = tree.getroot()
        siemlogger = root.find(".//OPNsense/SiemLogger")
        if siemlogger is None:
            logger.warning("SIEM Logger configuration not found in XML")
            return None
        return siemlogger
    except Exception as e:
        logger.error(f"Failed to parse configuration: {e}")
        return None

def load_config():
    """Loads SIEM Logger configuration from XML or cache"""
    global _cache, _cache_time

    current_time = time.time()
    if _cache and (current_time - _cache_time) < CACHE_TIMEOUT:
        logger.debug("Returning cached configuration")
        return _cache

    siemlogger = get_siemlogger_config()
    if siemlogger is None:
        logger.warning("Using default configuration")
        _cache = create_default_config()
    else:
        general = siemlogger.find("general") or ET.Element("general")
        siem_export = siemlogger.find("siem_export") or ET.Element("siem_export")
        logging_rules = siemlogger.find("logging_rules") or ET.Element("logging_rules")
        audit_settings = siemlogger.find("audit_settings") or ET.Element("audit_settings")
        notifications = siemlogger.find("notifications") or ET.Element("notifications")
        monitoring = siemlogger.find("monitoring") or ET.Element("monitoring")

        _cache = {
            "general": {
                "enabled": general.findtext("enabled", "1") == "1",  # FIXED: Changed default to "1"
                "log_level": general.findtext("log_level", "INFO").upper(),
                "max_log_size": int(general.findtext("max_log_size", "100")),
                "event_retention_days": int(general.findtext("retention_days", "30")),
                "log_sources": ["/var/log/system/latest.log"]  # Default source
            },
            "siem_export": {
                "export_enabled": siem_export.findtext("export_enabled", "0") == "1",
                "export_format": siem_export.findtext("export_format", "json"),
                "siem_server": siem_export.findtext("siem_server", ""),
                "siem_port": int(siem_export.findtext("siem_port", "514")),
                "protocol": siem_export.findtext("protocol", "udp"),
                "facility": siem_export.findtext("facility", "local0"),
                "tls_cert": siem_export.findtext("tls_cert", ""),
                "batch_size": int(siem_export.findtext("batch_size", "100")),
                "export_interval": int(siem_export.findtext("export_interval", "60")),
                "enabled_formats": ["json", "syslog", "cef", "leef"]  # Default formats
            },
            "logging_rules": {
                "log_authentication": logging_rules.findtext("log_authentication", "1") == "1",
                "log_authorization": logging_rules.findtext("log_authorization", "1") == "1",
                "log_configuration_changes": logging_rules.findtext("log_configuration_changes", "1") == "1",
                "log_network_events": logging_rules.findtext("log_network_events", "1") == "1",
                "log_system_events": logging_rules.findtext("log_system_events", "1") == "1",
                "log_firewall_events": logging_rules.findtext("log_firewall_events", "1") == "1",
                "log_vpn_events": logging_rules.findtext("log_vpn_events", "1") == "1",
                "custom_log_paths": [p.strip() for p in logging_rules.findtext("custom_log_paths", "").split(",") if p.strip()]
            },
            "audit_settings": {
                "audit_enabled": audit_settings.findtext("audit_enabled", "1") == "1",
                "audit_failed_logins": audit_settings.findtext("audit_failed_logins", "1") == "1",
                "audit_admin_actions": audit_settings.findtext("audit_admin_actions", "1") == "1",
                "audit_privilege_escalation": audit_settings.findtext("audit_privilege_escalation", "1") == "1",
                "audit_file_access": audit_settings.findtext("audit_file_access", "0") == "1",
                "suspicious_activity_threshold": int(audit_settings.findtext("suspicious_activity_threshold", "5"))
            },
            "notifications": {
                "email_alerts": notifications.findtext("email_alerts", "0") == "1",
                "email_recipients": notifications.findtext("email_recipients", ""),
                "alert_on_failed_logins": notifications.findtext("alert_on_failed_logins", "1") == "1",
                "alert_on_suspicious_activity": notifications.findtext("alert_on_suspicious_activity", "1") == "1",
                "webhook_url": notifications.findtext("webhook_url", "")
            },
            "monitoring": {
                "health_check_interval": int(monitoring.findtext("health_check_interval", "300")),
                "metrics_collection": monitoring.findtext("metrics_collection", "1") == "1",
                "performance_monitoring": monitoring.findtext("performance_monitoring", "1") == "1",
                "disk_usage_threshold": int(monitoring.findtext("disk_usage_threshold", "80"))
            }
        }

    _cache_time = current_time
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump(_cache, f, indent=2)
        logger.info("Configuration cached successfully")
    except Exception as e:
        logger.error(f"Failed to cache configuration: {e}")

    return _cache

def create_default_config():
    """Creates default SIEM Logger configuration"""
    logger.info("Creating default configuration")  # ADDED: Log when using defaults
    return {
        "general": {
            "enabled": True,
            "log_level": "INFO",
            "max_log_size": 100,
            "event_retention_days": 30,
            "log_sources": ["/var/log/system/latest.log"]
        },
        "siem_export": {
            "export_enabled": False,
            "export_format": "json",
            "siem_server": "",
            "siem_port": 514,
            "protocol": "udp",
            "facility": "local0",
            "tls_cert": "",
            "batch_size": 100,
            "export_interval": 60,
            "enabled_formats": ["json", "syslog", "cef", "leef"]
        },
        "logging_rules": {
            "log_authentication": True,
            "log_authorization": True,
            "log_configuration_changes": True,
            "log_network_events": True,
            "log_system_events": True,
            "log_firewall_events": True,
            "log_vpn_events": True,
            "custom_log_paths": []
        },
        "audit_settings": {
            "audit_enabled": True,
            "audit_failed_logins": True,
            "audit_admin_actions": True,
            "audit_privilege_escalation": True,
            "audit_file_access": False,
            "suspicious_activity_threshold": 5
        },
        "notifications": {
            "email_alerts": False,
            "email_recipients": "",
            "alert_on_failed_logins": True,
            "alert_on_suspicious_activity": True,
            "webhook_url": ""
        },
        "monitoring": {
            "health_check_interval": 300,
            "metrics_collection": True,
            "performance_monitoring": True,
            "disk_usage_threshold": 80
        }
    }

def get_system_stats():
    """Returns system statistics for dashboard"""
    siemlogger = get_siemlogger_config()
    if siemlogger is None:
        return {
            "general": {"enabled": False},
            "siem_export": {"export_enabled": False}
        }

    general = siemlogger.find("general") or ET.Element("general")
    siem_export = siemlogger.find("siem_export") or ET.Element("siem_export")

    return {
        "general": {
            "enabled": general.findtext("enabled", "0") == "1",
            "log_level": general.findtext("log_level", "INFO")
        },
        "siem_export": {
            "export_enabled": siem_export.findtext("export_enabled", "0") == "1",
            "export_format": siem_export.findtext("export_format", "json")
        }
    }

if __name__ == "__main__":
    print("=== SIEM Logger Settings Loader Test ===")
    config = load_config()
    print(f"Configuration: {json.dumps(config, indent=2)}")
    stats = get_system_stats()
    print(f"System Stats: {json.dumps(stats, indent=2)}")