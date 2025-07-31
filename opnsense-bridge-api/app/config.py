"""
Configuration management for OPNsense Bridge
Reads all settings from .env file
"""

import os
from functools import lru_cache
from typing import List
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    """Application settings from .env file"""
    
    # =============================================================================
    # OPNsense Configuration
    # =============================================================================
    opnsense_host: str = Field(..., env="OPNSENSE_HOST")
    opnsense_api_key: str = Field(..., env="OPNSENSE_API_KEY") 
    opnsense_api_secret: str = Field(..., env="OPNSENSE_API_SECRET")
    opnsense_verify_ssl: bool = Field(False, env="OPNSENSE_VERIFY_SSL")
    
    # =============================================================================
    # Bridge Configuration
    # =============================================================================
    bridge_host: str = Field("0.0.0.0", env="BRIDGE_HOST")
    bridge_port: int = Field(8443, env="BRIDGE_PORT")
    bridge_ip: str = Field("172.16.216.10", env="BRIDGE_IP")
    use_ssl: bool = Field(True, env="USE_SSL")
    
    # =============================================================================
    # Network Configuration
    # =============================================================================
    dmz_network: str = Field("172.16.216.0/24", env="DMZ_NETWORK")
    lan_network: str = Field("192.168.216.0/24", env="LAN_NETWORK")
    
    # =============================================================================
    # Security Configuration
    # =============================================================================
    jwt_secret_key: str = Field("change-me-in-production", env="JWT_SECRET_KEY")
    allowed_ips: str = Field("", env="ALLOWED_IPS")
    allowed_origins: List[str] = Field(["*"], env="ALLOWED_ORIGINS")
    
    # =============================================================================
    # Application Configuration
    # =============================================================================
    debug: bool = Field(False, env="DEBUG")
    log_level: str = Field("INFO", env="LOG_LEVEL")
    allow_startup_without_opnsense: bool = Field(False, env="ALLOW_STARTUP_WITHOUT_OPNSENSE")
    
    # =============================================================================
    # Monitoring Configuration
    # =============================================================================
    enable_metrics: bool = Field(True, env="ENABLE_METRICS")
    metrics_port: int = Field(9090, env="METRICS_PORT")
    
    # =============================================================================
    # Rate Limiting
    # =============================================================================
    rate_limit_requests: int = Field(100, env="RATE_LIMIT_REQUESTS")
    rate_limit_period: int = Field(60, env="RATE_LIMIT_PERIOD")
    
    # =============================================================================
    # Gmail SMTP Configuration
    # =============================================================================
    smtp_server: str = Field("smtp.gmail.com", env="SMTP_SERVER")
    smtp_port: int = Field(587, env="SMTP_PORT")
    smtp_username: str = Field("", env="SMTP_USERNAME")
    smtp_password: str = Field("", env="SMTP_PASSWORD")
    smtp_use_tls: bool = Field(True, env="SMTP_USE_TLS")
    smtp_use_ssl: bool = Field(False, env="SMTP_USE_SSL")
    smtp_from_address: str = Field("", env="SMTP_FROM_ADDRESS")
    smtp_from_name: str = Field("OPNsense Bridge DMZ", env="SMTP_FROM_NAME")
    
    # =============================================================================
    # Notification Recipients
    # =============================================================================
    admin_emails: str = Field("", env="ADMIN_EMAILS")
    security_emails: str = Field("", env="SECURITY_EMAILS")
    ops_emails: str = Field("", env="OPS_EMAILS")
    emergency_emails: str = Field("", env="EMERGENCY_EMAILS")
    
    # =============================================================================
    # Internal Webhook Configuration
    # =============================================================================
    internal_webhook_enabled: bool = Field(True, env="INTERNAL_WEBHOOK_ENABLED")
    internal_webhook_url: str = Field("", env="INTERNAL_WEBHOOK_URL")
    internal_webhook_api_key: str = Field("", env="INTERNAL_WEBHOOK_API_KEY")
    
    grafana_webhook_enabled: bool = Field(False, env="GRAFANA_WEBHOOK_ENABLED")
    grafana_webhook_url: str = Field("", env="GRAFANA_WEBHOOK_URL")
    grafana_webhook_token: str = Field("", env="GRAFANA_WEBHOOK_TOKEN")
    
    ticketing_webhook_enabled: bool = Field(False, env="TICKETING_WEBHOOK_ENABLED")
    ticketing_webhook_url: str = Field("", env="TICKETING_WEBHOOK_URL")
    ticketing_webhook_token: str = Field("", env="TICKETING_WEBHOOK_TOKEN")
    
    # =============================================================================
    # Slack Configuration
    # =============================================================================
    slack_enabled: bool = Field(False, env="SLACK_ENABLED")
    slack_webhook_url: str = Field("", env="SLACK_WEBHOOK_URL")
    slack_default_channel: str = Field("#dmz-alerts", env="SLACK_DEFAULT_CHANNEL")
    slack_emergency_channel: str = Field("#emergency", env="SLACK_EMERGENCY_CHANNEL")
    
    # =============================================================================
    # Microsoft Teams Configuration
    # =============================================================================
    teams_enabled: bool = Field(False, env="TEAMS_ENABLED")
    teams_webhook_url: str = Field("", env="TEAMS_WEBHOOK_URL")
    
    # =============================================================================
    # Alert Thresholds
    # =============================================================================
    cpu_warning_threshold: int = Field(80, env="CPU_WARNING_THRESHOLD")
    cpu_critical_threshold: int = Field(95, env="CPU_CRITICAL_THRESHOLD")
    memory_warning_threshold: int = Field(85, env="MEMORY_WARNING_THRESHOLD")
    memory_critical_threshold: int = Field(95, env="MEMORY_CRITICAL_THRESHOLD")
    disk_warning_threshold: int = Field(90, env="DISK_WARNING_THRESHOLD")
    disk_critical_threshold: int = Field(95, env="DISK_CRITICAL_THRESHOLD")
    
    firewall_rules_warning: int = Field(5, env="FIREWALL_RULES_WARNING")
    firewall_rules_critical: int = Field(2, env="FIREWALL_RULES_CRITICAL")
    blocked_events_warning: int = Field(1000, env="BLOCKED_EVENTS_WARNING")
    blocked_events_critical: int = Field(5000, env="BLOCKED_EVENTS_CRITICAL")
    
    risk_score_warning: int = Field(50, env="RISK_SCORE_WARNING")
    risk_score_critical: int = Field(80, env="RISK_SCORE_CRITICAL")
    failed_logins_warning: int = Field(10, env="FAILED_LOGINS_WARNING")
    failed_logins_critical: int = Field(50, env="FAILED_LOGINS_CRITICAL")
    
    response_time_warning: int = Field(2000, env="RESPONSE_TIME_WARNING")
    response_time_critical: int = Field(5000, env="RESPONSE_TIME_CRITICAL")
    
    # =============================================================================
    # Emergency Response Configuration
    # =============================================================================
    emergency_auto_block: bool = Field(True, env="EMERGENCY_AUTO_BLOCK")
    emergency_block_threshold: int = Field(100, env="EMERGENCY_BLOCK_THRESHOLD")
    emergency_bulk_limit: int = Field(1000, env="EMERGENCY_BULK_LIMIT")
    emergency_block_duration: int = Field(86400, env="EMERGENCY_BLOCK_DURATION")
    
    emergency_notification_cooldown: int = Field(0, env="EMERGENCY_NOTIFICATION_COOLDOWN")
    emergency_escalation_delay: int = Field(300, env="EMERGENCY_ESCALATION_DELAY")
    emergency_max_retries: int = Field(5, env="EMERGENCY_MAX_RETRIES")
    
    # =============================================================================
    # File Logging Configuration
    # =============================================================================
    alert_backup_enabled: bool = Field(True, env="ALERT_BACKUP_ENABLED")
    alert_backup_file: str = Field("/app/logs/alerts_backup.jsonl", env="ALERT_BACKUP_FILE")
    alert_backup_max_size: str = Field("50MB", env="ALERT_BACKUP_MAX_SIZE")
    alert_backup_backup_count: int = Field(10, env="ALERT_BACKUP_BACKUP_COUNT")
    
    log_max_size: str = Field("10MB", env="LOG_MAX_SIZE")
    log_backup_count: int = Field(5, env="LOG_BACKUP_COUNT")
    emergency_log_backup_count: int = Field(10, env="EMERGENCY_LOG_BACKUP_COUNT")
    audit_log_backup_count: int = Field(20, env="AUDIT_LOG_BACKUP_COUNT")
    
    # =============================================================================
    # DMZ Specific Configuration
    # =============================================================================
    dmz_outbound_allowed: str = Field("smtp.gmail.com:587", env="DMZ_OUTBOUND_ALLOWED")
    dmz_internal_networks: str = Field("192.168.216.0/24", env="DMZ_INTERNAL_NETWORKS")
    
    dmz_offline_mode: bool = Field(True, env="DMZ_OFFLINE_MODE")
    dmz_alert_buffer_size: int = Field(1000, env="DMZ_ALERT_BUFFER_SIZE")
    dmz_retry_delay: int = Field(60, env="DMZ_RETRY_DELAY")
    dmz_max_retry_attempts: int = Field(5, env="DMZ_MAX_RETRY_ATTEMPTS")
    
    dmz_batch_notifications: bool = Field(True, env="DMZ_BATCH_NOTIFICATIONS")
    dmz_batch_size: int = Field(10, env="DMZ_BATCH_SIZE")
    dmz_batch_timeout: int = Field(30, env="DMZ_BATCH_TIMEOUT")
    
    # =============================================================================
    # SSL/TLS Configuration
    # =============================================================================
    ssl_cert_path: str = Field("/app/certs/server.crt", env="SSL_CERT_PATH")
    ssl_key_path: str = Field("/app/certs/server.key", env="SSL_KEY_PATH")
    ssl_ca_path: str = Field("/app/certs/ca.crt", env="SSL_CA_PATH")
    ssl_verify_peer: bool = Field(False, env="SSL_VERIFY_PEER")
    ssl_min_version: str = Field("TLSv1.2", env="SSL_MIN_VERSION")
    
    # =============================================================================
    # Health Check Configuration
    # =============================================================================
    health_check_interval: int = Field(60, env="HEALTH_CHECK_INTERVAL")
    health_check_timeout: int = Field(30, env="HEALTH_CHECK_TIMEOUT")
    health_check_retries: int = Field(3, env="HEALTH_CHECK_RETRIES")
    opnsense_health_timeout: int = Field(10, env="OPNSENSE_HEALTH_TIMEOUT")
    
    # =============================================================================
    # Prometheus Configuration
    # =============================================================================
    prometheus_enabled: bool = Field(True, env="PROMETHEUS_ENABLED")
    prometheus_port: int = Field(9090, env="PROMETHEUS_PORT")
    prometheus_path: str = Field("/metrics", env="PROMETHEUS_PATH")
    prometheus_namespace: str = Field("opnsense_bridge_dmz", env="PROMETHEUS_NAMESPACE")
    
    # =============================================================================
    # Development/Testing
    # =============================================================================
    test_mode: bool = Field(False, env="TEST_MODE")
    test_email_recipient: str = Field("", env="TEST_EMAIL_RECIPIENT")
    test_webhook_url: str = Field("", env="TEST_WEBHOOK_URL")
    mock_opnsense_api: bool = Field(False, env="MOCK_OPNSENSE_API")
    
    debug_smtp: bool = Field(False, env="DEBUG_SMTP")
    debug_webhooks: bool = Field(False, env="DEBUG_WEBHOOKS")
    debug_notifications: bool = Field(False, env="DEBUG_NOTIFICATIONS")
    
    # =============================================================================
    # Timezone Configuration
    # =============================================================================
    timezone: str = Field("Europe/Zurich", env="TZ")
    log_timezone: str = Field("UTC", env="LOG_TIMEZONE")
    alert_timezone: str = Field("Europe/Zurich", env="ALERT_TIMEZONE")
    
    # =============================================================================
    # Helper Methods
    # =============================================================================
    
    def get_admin_emails_list(self) -> List[str]:
        """Get admin emails as list"""
        if not self.admin_emails:
            return []
        return [email.strip() for email in self.admin_emails.split(",") if email.strip()]
    
    def get_security_emails_list(self) -> List[str]:
        """Get security emails as list"""
        if not self.security_emails:
            return []
        return [email.strip() for email in self.security_emails.split(",") if email.strip()]
    
    def get_emergency_emails_list(self) -> List[str]:
        """Get emergency emails as list"""
        if not self.emergency_emails:
            return []
        return [email.strip() for email in self.emergency_emails.split(",") if email.strip()]
    
    def get_allowed_ips_list(self) -> List[str]:
        """Get allowed IPs as list"""
        if not self.allowed_ips:
            return []
        return [ip.strip() for ip in self.allowed_ips.split(",") if ip.strip()]
    
    def get_internal_networks_list(self) -> List[str]:
        """Get DMZ internal networks as list"""
        if not self.dmz_internal_networks:
            return []
        return [net.strip() for net in self.dmz_internal_networks.split(",") if net.strip()]
    
    def is_test_mode(self) -> bool:
        """Check if running in test mode"""
        return self.test_mode or self.debug
    
    def get_webhook_config(self) -> dict:
        """Get webhook configuration"""
        return {
            "internal": {
                "enabled": self.internal_webhook_enabled,
                "url": self.internal_webhook_url,
                "api_key": self.internal_webhook_api_key
            },
            "grafana": {
                "enabled": self.grafana_webhook_enabled,
                "url": self.grafana_webhook_url,
                "token": self.grafana_webhook_token
            },
            "ticketing": {
                "enabled": self.ticketing_webhook_enabled,
                "url": self.ticketing_webhook_url,
                "token": self.ticketing_webhook_token
            }
        }
    
    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'
        case_sensitive = False

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()

# =============================================================================
# SCRIPT DI TEST PER VERIFICARE IL .env
# =============================================================================

if __name__ == "__main__":
    """Script per testare la configurazione .env"""
    
    print("🔧 Testing .env configuration...")
    print("=" * 50)
    
    try:
        settings = get_settings()
        
        # Test OPNsense config
        print(f"OPNsense Host: {settings.opnsense_host}")
        print(f"Bridge IP: {settings.bridge_ip}")
        print(f"SMTP Server: {settings.smtp_server}")
        print(f"Admin Emails: {settings.get_admin_emails_list()}")
        
        # Test required fields
        required_fields = [
            'opnsense_host', 'opnsense_api_key', 'opnsense_api_secret',
            'bridge_ip', 'smtp_username', 'smtp_password'
        ]
        
        missing_fields = []
        for field in required_fields:
            value = getattr(settings, field, '')
            if not value or value in ['your_api_key_here', 'your_api_secret_here', 'your-gmail@gmail.com']:
                missing_fields.append(field.upper())
        
        if missing_fields:
            print("\nWARNING: These fields need to be configured in .env:")
            for field in missing_fields:
                print(f"   - {field}")
        else:
            print("\nAll required fields configured!")
        
        print(f"\nTotal configuration values loaded: {len(settings.__fields__)}")
        print(".env configuration test PASSED")
        
    except Exception as e:
        print(f".env configuration test FAILED: {e}")
        print("\nMake sure:")
        print("   1. .env file exists in the project root")
        print("   2. All required variables are set")
        print("   3. No syntax errors in .env file")