import logging
from email.mime.text import MIMEText
from typing import List, Dict, Any
from datetime import datetime, timezone

import aiohttp
import smtplib

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class NotificationService:
    """Service for sending notifications using .env configuration"""
    
    def __init__(self):
        # Validate required settings
        self.validate_settings()
        
        # SMTP configuration from .env
        self.smtp_server = settings.smtp_server
        self.smtp_port = settings.smtp_port
        self.smtp_username = settings.smtp_username
        self.smtp_password = settings.smtp_password
        self.smtp_use_tls = settings.smtp_use_tls
        self.smtp_use_ssl = settings.smtp_use_ssl
        self.smtp_from_address = settings.smtp_from_address
        self.smtp_from_name = settings.smtp_from_name
        
        # Webhook configurations from .env
        self.slack_webhook = settings.slack_webhook_url
        self.slack_enabled = settings.slack_enabled
        self.slack_default_channel = settings.slack_default_channel
        self.slack_emergency_channel = settings.slack_emergency_channel
        
        self.teams_webhook = settings.teams_webhook_url
        self.teams_enabled = settings.teams_enabled
        
        # Notification recipients from .env
        self.admin_emails = settings.get_admin_emails_list()
        self.emergency_emails = settings.get_emergency_emails_list()
        
        # Debug and test mode settings
        self.debug_smtp = settings.debug_smtp
        self.debug_notifications = settings.debug_notifications
        self.test_mode = settings.is_test_mode()
        self.test_email_recipient = settings.test_email_recipient
        
        # DMZ settings
        self.dmz_offline_mode = settings.dmz_offline_mode
        
        # Logging configuration details
        logger.info("NotificationService initialized")
        logger.info(f"   SMTP Server: {self.smtp_server}:{self.smtp_port}")
        logger.info(f"   SMTP From: {self.smtp_from_name} <{self.smtp_from_address}>")
        logger.info(f"   Slack Enabled: {self.slack_enabled}")
        logger.info(f"   Teams Enabled: {self.teams_enabled}")
        logger.info(f"   DMZ Offline Mode: {self.dmz_offline_mode}")
        logger.info(f"   Test Mode: {self.test_mode}")
    
    def validate_settings(self):
        """Validate required settings from .env"""
        required_fields = ['smtp_server', 'smtp_port']
        if not self.test_mode:
            required_fields.extend(['smtp_username', 'smtp_password', 'smtp_from_address'])
        
        missing = [field for field in required_fields if not getattr(settings, field)]
        if missing:
            logger.error(f"Missing required settings: {missing}")
            raise ValueError(f"Missing required settings: {missing}")
    
    async def send_email_alert(self, 
                             subject: str, 
                             message: str, 
                             recipients: List[str]) -> bool:
        """Send email alert"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - skipping email alert")
            return False
        
        if self.test_mode and self.test_email_recipient:
            recipients = [self.test_email_recipient]
            logger.debug(f"Test mode: redirecting email to {self.test_email_recipient}")
        
        if not recipients:
            logger.warning("No recipients provided for email alert")
            return False
        
        try:
            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From'] = f"{self.smtp_from_name} <{self.smtp_from_address}>"
            msg['To'] = ", ".join(recipients)
            
            if self.debug_smtp:
                logger.debug(f"SMTP Debug: Sending email to {', '.join(recipients)}")
                logger.debug(f"SMTP Debug: Subject: {subject}")
                logger.debug(f"SMTP Debug: Message: {message}")
                return True
            
            if self.smtp_use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                
            if self.smtp_use_tls and not self.smtp_use_ssl:
                server.starttls()
                
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email sent: {subject} to {', '.join(recipients)}")
            return True
            
        except Exception as e:
            logger.error(f"Email failed: {e}")
            return False
    
    async def send_slack_alert(self, message: str, channel: str = None) -> bool:
        """Send Slack alert"""
        if not self.slack_enabled:
            logger.debug("Slack notifications disabled in settings")
            return False
            
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - skipping Slack alert")
            return False
            
        if not self.slack_webhook:
            logger.warning("Slack webhook URL not configured")
            return False
            
        channel = channel or self.slack_default_channel
        
        try:
            slack_data = {
                "channel": channel,
                "text": "OPNsense Bridge Alert",
                "attachments": [
                    {
                        "color": "danger",
                        "text": message,
                        "footer": "OPNsense Monitoring Bridge",
                        "ts": int(datetime.now(timezone.utc).timestamp())
                    }
                ]
            }
            
            if self.debug_notifications:
                logger.debug(f"Slack Debug: Sending to {channel}")
                logger.debug(f"Slack Debug: Message: {message}")
                return True
                
            async with aiohttp.ClientSession() as session:
                async with session.post(self.slack_webhook, json=slack_data) as response:
                    if response.status == 200:
                        logger.info(f"Slack notification sent to {channel}")
                        return True
                    else:
                        logger.error(f"Slack notification failed with status {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return False
    
    async def send_teams_alert(self, message: str) -> bool:
        """Send Microsoft Teams alert"""
        if not self.teams_enabled:
            logger.debug("Teams notifications disabled in settings")
            return False
            
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - skipping Teams alert")
            return False
            
        if not self.teams_webhook:
            logger.warning("Teams webhook URL not configured")
            return False
            
        try:
            teams_data = {
                "@type": "MessageCard",
                "summary": "OPNsense Bridge Alert",
                "themeColor": "FF0000",  # Red color for alerts
                "sections": [{
                    "activityTitle": "OPNsense Bridge Alert",
                    "text": message,
                    "facts": [
                        {"name": "Source", "value": "OPNsense Monitoring Bridge"},
                        {"name": "Timestamp", "value": datetime.now(timezone.utc).isoformat()}
                    ]
                }]
            }
            
            if self.debug_notifications:
                logger.debug("Teams Debug: Sending notification")
                logger.debug(f"Teams Debug: Message: {message}")
                return True
                
            async with aiohttp.ClientSession() as session:
                async with session.post(self.teams_webhook, json=teams_data) as response:
                    if response.status == 200:
                        logger.info("Teams notification sent")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"Teams notification failed with status {response.status}: {error_text}")
                        return False
                        
        except Exception as e:
            logger.error(f"Teams notification failed: {e}")
            return False
    
    async def send_emergency_notification(self, 
                                        event_type: str, 
                                        details: Dict[str, Any]) -> None:
        """Send emergency notification to all channels"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - skipping emergency notification")
            return
        
        message = f"""
EMERGENCY: {event_type}

Details:
{self._format_details(details)}

Timestamp: {datetime.now(timezone.utc).isoformat()}
Source: OPNsense Monitoring Bridge
        """
        
        # Send to email
        if self.emergency_emails or self.test_mode:
            await self.send_email_alert(
                subject=f"EMERGENCY: {event_type}",
                message=message,
                recipients=self.emergency_emails if not self.test_mode else [self.test_email_recipient]
            )
        
        # Send to Slack emergency channel
        await self.send_slack_alert(message, channel=self.slack_emergency_channel)
        
        # Send to Teams
        await self.send_teams_alert(message)
    
    def _format_details(self, details: Dict[str, Any]) -> str:
        """Format details for notification"""
        formatted = []
        for key, value in details.items():
            formatted.append(f"- {key}: {value}")
        return "\n".join(formatted)