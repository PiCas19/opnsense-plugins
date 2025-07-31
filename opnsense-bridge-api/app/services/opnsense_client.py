"""
Complete OPNsense API Client
Uses configuration from .env file via config.py
"""

import asyncio
import logging
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import aiohttp
import backoff
from aiohttp import ClientSession, ClientTimeout, BasicAuth

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class OPNsenseClient:
    """Complete OPNsense API client with .env configuration"""
    
    def __init__(self):
        # Validate required settings
        self.validate_settings()
        
        # Use .env configuration
        self.base_url = f"https://{settings.opnsense_host}/api"
        self.auth = BasicAuth(settings.opnsense_api_key, settings.opnsense_api_secret)
        
        # Timeout configuration from .env
        self.timeout = ClientTimeout(
            total=settings.health_check_timeout,
            connect=5,
            sock_read=settings.opnsense_health_timeout
        )
        
        # SSL context from .env
        self.ssl_context = ssl.create_default_context()
        if not settings.opnsense_verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            logger.warning("SSL verification disabled for OPNsense API")
        
        # SSL version configuration from .env
        ssl_min_version = settings.ssl_min_version
        if ssl_min_version == 'TLSv1.2':
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        elif ssl_min_version == 'TLSv1.3':
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            logger.warning(f"Unsupported SSL minimum version: {ssl_min_version}, defaulting to TLSv1.2")
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        self.connector = aiohttp.TCPConnector(
            ssl=self.ssl_context,
            limit=20,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        
        # Retry configuration from .env
        self.max_retries = settings.health_check_retries
        self.retry_delay = settings.dmz_retry_delay
        
        # DMZ specific settings
        self.dmz_mode = settings.dmz_offline_mode
        self.dmz_network = settings.dmz_network
        self.bridge_ip = settings.bridge_ip
        
        self._session: Optional[ClientSession] = None
        
        # Comprehensive initialization logging
        logger.info("OPNsenseClient initialized for DMZ bridge")
        logger.info(f"   OPNsense Host: {settings.opnsense_host}")
        logger.info(f"   Bridge IP: {self.bridge_ip}")
        logger.info(f"   SSL Verify: {settings.opnsense_verify_ssl}")
        logger.info(f"   SSL Min Version: {ssl_min_version}")
        logger.info(f"   DMZ Network: {self.dmz_network}")
        logger.info(f"   DMZ Offline Mode: {self.dmz_mode}")
        logger.info(f"   Max Retries: {self.max_retries}")
    
    def validate_settings(self):
        """Validate required settings from .env"""
        required_fields = ['opnsense_host', 'opnsense_api_key', 'opnsense_api_secret']
        missing = [field for field in required_fields if not getattr(settings, field)]
        if missing:
            logger.error(f"Missing required settings: {missing}")
            raise ValueError(f"Missing required settings: {missing}")
    
    async def __aenter__(self):
        if self._session is None or self._session.closed:
            self._session = ClientSession(
                auth=self.auth,
                timeout=self.timeout,
                connector=self.connector,
                headers={
                    'User-Agent': 'OPNsense-Bridge-DMZ/1.0.0',
                    'X-Bridge-IP': self.bridge_ip,
                    'X-Bridge-Location': 'DMZ'
                }
            )
            logger.debug("Created new OPNsense API session")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("Closed OPNsense API session")
            global _client
            _client = None  # Reset global client on session close
    
    @backoff.on_exception(
        backoff.expo, 
        (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError), 
        max_tries=lambda: settings.health_check_retries,
        max_time=300
    )
    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request with retry logic from .env settings"""
        if self.dmz_mode:
            logger.warning("DMZ offline mode enabled - skipping API call")
            return {"status": "offline", "message": "DMZ offline mode enabled"}
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        # Add DMZ-specific headers
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers'].update({
            'X-Bridge-Request-ID': f"dmz_{int(datetime.now(timezone.utc).timestamp())}",
            'X-DMZ-Network': self.dmz_network
        })
        
        try:
            logger.debug(f"API Request: {method} {endpoint}")
            
            async with self._session.request(method, url, **kwargs) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.debug(f"API Success: {method} {endpoint}")
                    return result
                elif response.status == 401:
                    logger.error("Authentication failed for OPNsense API")
                    raise Exception("Authentication failed - check OPNSENSE_API_KEY and OPNSENSE_API_SECRET in .env")
                elif response.status == 403:
                    logger.error("Access forbidden - check API user permissions")
                    raise Exception("Access forbidden - check OPNsense API user permissions")
                elif response.status == 404:
                    logger.error(f"API endpoint not found: {endpoint}")
                    raise Exception(f"API endpoint not found: {endpoint}")
                else:
                    error_text = await response.text()
                    logger.error(f"API error {response.status}: {error_text}")
                    raise Exception(f"API error {response.status}: {error_text}")
                    
        except asyncio.TimeoutError:
            logger.error(f"Request timeout: {method} {url}")
            raise Exception(f"Request timeout - check network connectivity to {settings.opnsense_host}")
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Connection error: {e}")
            raise Exception(f"Cannot connect to OPNsense at {settings.opnsense_host} - check network/firewall")
        except Exception as e:
            logger.error(f"Request failed: {method} {url} - {e}")
            raise
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get system status"""
        try:
            if self.dmz_mode:
                logger.warning("DMZ offline mode enabled - returning mock system status")
                return {"status": "offline", "message": "DMZ offline mode enabled"}
            
            status = await self._make_request("GET", "/core/system/status")
            
            # Add bridge info to status
            status['bridge_info'] = {
                'bridge_ip': self.bridge_ip,
                'bridge_location': 'DMZ',
                'request_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            return status
        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            raise
    
    async def get_active_firewall_rules(self) -> List[Dict[str, Any]]:
        """Get only active firewall rules"""
        try:
            if self.dmz_mode:
                logger.warning("DMZ offline mode enabled - returning empty active rules")
                return []
            
            response = await self._make_request("GET", "/firewall/filter/get")
            rules = response.get("rows", [])
            active_rules = [rule for rule in rules if rule.get("enabled") == "1"]
            
            logger.info(f"Retrieved {len(active_rules)} active firewall rules")
            return active_rules
        except Exception as e:
            logger.error(f"Failed to get active firewall rules: {e}")
            raise
    
    async def get_all_firewall_rules(self) -> List[Dict[str, Any]]:
        """Get all firewall rules (active and inactive)"""
        try:
            if self.dmz_mode:
                logger.warning("DMZ offline mode enabled - returning empty rules")
                return []
            
            response = await self._make_request("GET", "/firewall/filter/get")
            rules = response.get("rows", [])
            
            logger.info(f"Retrieved {len(rules)} total firewall rules")
            return rules
        except Exception as e:
            logger.error(f"Failed to get all firewall rules: {e}")
            raise
    
    async def get_firewall_logs(self, limit: int = 100, filter_blocked: bool = False) -> List[Dict[str, Any]]:
        """Get firewall logs"""
        try:
            if self.dmz_mode:
                logger.warning("DMZ offline mode enabled - returning empty logs")
                return []
            
            params = {"limit": limit}
            response = await self._make_request("GET", "/diagnostics/log/core/firewall", params=params)
            logs = response.get("logs", [])
            
            if filter_blocked:
                logs = [log for log in logs if log.get("action") in ["block", "reject"]]
                logger.info(f"Retrieved {len(logs)} blocked firewall log entries")
            else:
                logger.info(f"Retrieved {len(logs)} firewall log entries")
            
            return logs
        except Exception as e:
            logger.error(f"Failed to get firewall logs: {e}")
            raise
    
    async def emergency_add_block_rule(self, ip_address: str, reason: str) -> Dict[str, Any]:
        """EMERGENCY: Add block rule immediately"""
        if self.dmz_mode:
            logger.warning("DMZ offline mode enabled - skipping emergency block rule")
            return {"status": "offline", "message": "DMZ offline mode enabled"}
        
        block_duration = settings.emergency_block_duration
        operation_id = f"emergency_dmz_{int(datetime.now(timezone.utc).timestamp())}"
        
        logger.critical(f"EMERGENCY BLOCK from DMZ: {ip_address}")
        logger.critical(f"   Reason: {reason}")
        logger.critical(f"   Operation ID: {operation_id}")
        logger.critical(f"   Bridge IP: {self.bridge_ip}")
        
        rule_data = {
            "rule": {
                "enabled": "1",
                "interface": "wan",
                "direction": "in", 
                "action": "block",
                "source_net": ip_address,
                "description": f"DMZ-EMERGENCY: {reason} | Bridge: {self.bridge_ip} | Op: {operation_id} | {datetime.now(timezone.utc).isoformat()}",
                "log": "1"
            }
        }
        
        try:
            # Add rule
            add_result = await self._make_request("POST", "/firewall/filter/addRule", json=rule_data)
            
            if add_result.get("result") == "saved":
                logger.critical(f"Emergency rule created: {add_result.get('uuid')}")
                
                # Apply changes immediately
                apply_result = await self._make_request("POST", "/firewall/filter/apply")
                
                if apply_result.get("status") == "ok":
                    logger.critical("Emergency block applied successfully")
                else:
                    logger.error(f"Failed to apply emergency block: {apply_result}")
                
                return {
                    "status": "success",
                    "operation_id": operation_id,
                    "rule_uuid": add_result.get("uuid"),
                    "ip_blocked": ip_address,
                    "applied": apply_result.get("status") == "ok",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "bridge_ip": self.bridge_ip,
                    "bridge_location": "DMZ",
                    "block_duration": block_duration
                }
            else:
                logger.error(f"Failed to create emergency rule: {add_result}")
                raise Exception(f"Failed to create emergency block rule: {add_result}")
                
        except Exception as e:
            logger.critical(f"EMERGENCY BLOCK FAILED: {e}")
            raise
    
    async def emergency_bulk_block(self, ip_addresses: List[str], reason: str) -> Dict[str, Any]:
        """EMERGENCY: Block multiple IPs (bulk operation)"""
        if self.dmz_mode:
            logger.warning("DMZ offline mode enabled - skipping bulk block")
            return {"status": "offline", "message": "DMZ offline mode enabled"}
        
        bulk_limit = settings.emergency_bulk_limit
        
        if len(ip_addresses) > bulk_limit:
            logger.error(f"Bulk block exceeds limit: {len(ip_addresses)} > {bulk_limit}")
            raise Exception(f"Bulk block limit exceeded. Max: {bulk_limit}, Requested: {len(ip_addresses)}")
        
        operation_id = f"bulk_emergency_dmz_{int(datetime.now(timezone.utc).timestamp())}"
        
        logger.critical(f"BULK EMERGENCY BLOCK from DMZ: {len(ip_addresses)} IPs")
        logger.critical(f"   Operation ID: {operation_id}")
        logger.critical(f"   Reason: {reason}")
        
        results = {
            "operation_id": operation_id,
            "blocked_ips": [],
            "failed_ips": [],
            "total_requested": len(ip_addresses),
            "bridge_ip": self.bridge_ip,
            "bridge_location": "DMZ"
        }
        
        for ip in ip_addresses:
            try:
                result = await self.emergency_add_block_rule(
                    ip_address=ip,
                    reason=f"BULK-{reason} [Op: {operation_id}]"
                )
                
                if result.get("status") == "success":
                    results["blocked_ips"].append({
                        "ip": ip,
                        "rule_uuid": result.get("rule_uuid"),
                        "timestamp": result.get("timestamp")
                    })
                    logger.warning(f"BULK BLOCKED: {ip}")
                else:
                    results["failed_ips"].append({"ip": ip, "error": "Block failed"})
                    
            except Exception as e:
                results["failed_ips"].append({"ip": ip, "error": str(e)})
                logger.error(f"BULK BLOCK FAILED for {ip}: {e}")
        
        logger.critical(f"BULK BLOCK COMPLETE: {len(results['blocked_ips'])} success, {len(results['failed_ips'])} failed")
        
        return {
            "status": "completed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **results
        }
    
    async def toggle_firewall_rule(self, rule_uuid: str, enable: bool, reason: str) -> Dict[str, Any]:
        """Toggle firewall rule on/off"""
        if self.dmz_mode:
            logger.warning("DMZ offline mode enabled - skipping rule toggle")
            return {"status": "offline", "message": "DMZ offline mode enabled"}
        
        operation_id = f"toggle_dmz_{int(datetime.now(timezone.utc).timestamp())}"
        action = "ENABLE" if enable else "DISABLE"
        
        logger.warning(f"RULE TOGGLE from DMZ: {action} rule {rule_uuid}")
        logger.warning(f"   Reason: {reason}")
        logger.warning(f"   Operation ID: {operation_id}")
        
        rule_data = {
            "rule": {
                "enabled": "1" if enable else "0",
                "description": f"DMZ-TOGGLE: {reason} | Bridge: {self.bridge_ip} | Op: {operation_id} | {datetime.now(timezone.utc).isoformat()}"
            }
        }
        
        try:
            # Update rule
            update_result = await self._make_request("POST", f"/firewall/filter/setRule/{rule_uuid}", json=rule_data)
            
            if update_result.get("result") == "saved":
                logger.warning(f"Rule updated: {rule_uuid}")
                
                # Apply changes
                apply_result = await self._make_request("POST", "/firewall/filter/apply")
                
                return {
                    "status": "success",
                    "operation_id": operation_id,
                    "rule_uuid": rule_uuid,
                    "enabled": enable,
                    "applied": apply_result.get("status") == "ok",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "bridge_ip": self.bridge_ip,
                    "bridge_location": "DMZ"
                }
            else:
                logger.error(f"Failed to update rule: {update_result}")
                raise Exception(f"Failed to toggle rule: {update_result}")
                
        except Exception as e:
            logger.error(f"RULE TOGGLE FAILED: {e}")
            raise
    
    async def health_check(self) -> bool:
        """Health check with .env configuration"""
        try:
            if self.dmz_mode:
                logger.warning("DMZ offline mode enabled - health check skipped")
                return False
            
            logger.debug(f"Health check: {settings.opnsense_host}")
            
            status = await self.get_system_status()
            is_healthy = isinstance(status, dict) and len(status) > 0 and status.get("status") != "offline"
            
            if is_healthy:
                logger.debug("OPNsense health check passed")
                
                # Log basic system info
                hostname = status.get("hostname", "unknown")
                version = status.get("version", "unknown")
                uptime = status.get("uptime", "unknown")
                
                logger.info("OPNsense Status:")
                logger.info(f"   Hostname: {hostname}")
                logger.info(f"   Version: {version}")
                logger.info(f"   Uptime: {uptime}")
            else:
                logger.error("OPNsense health check failed")
            
            return is_healthy
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    async def get_connection_info(self) -> Dict[str, Any]:
        """Get connection information for diagnostics"""
        return {
            "opnsense_host": settings.opnsense_host,
            "bridge_ip": self.bridge_ip,
            "bridge_location": "DMZ",
            "ssl_verify": settings.opnsense_verify_ssl,
            "ssl_min_version": settings.ssl_min_version,
            "timeout": self.timeout.total,
            "max_retries": self.max_retries,
            "dmz_network": self.dmz_network,
            "dmz_offline_mode": self.dmz_mode,
            "api_base_url": self.base_url,
            "session_active": self._session is not None and not self._session.closed
        }

# Global client instance
_client = None

async def get_opnsense_client() -> OPNsenseClient:
    """Get global OPNsense client instance"""
    global _client
    if _client is None or (_client._session and _client._session.closed):
        _client = OPNsenseClient()
        logger.info("Created global OPNsense client instance")
    return _client

async def test_opnsense_connection() -> bool:
    """Test OPNsense API connection using .env settings"""
    try:
        logger.info(f"Testing OPNsense connection to {settings.opnsense_host}")
        
        async with OPNsenseClient() as client:
            is_connected = await client.health_check()
            
            if is_connected:
                logger.info("OPNsense connection test PASSED")
                
                # Get connection info for logging
                conn_info = await client.get_connection_info()
                logger.info(f"Connection details: {conn_info}")
            else:
                logger.error("OPNsense connection test FAILED")
                
            return is_connected
            
    except Exception as e:
        logger.error(f"OPNsense connection test failed: {e}")
        logger.error(f"   Check OPNSENSE_HOST in .env: {settings.opnsense_host}")
        logger.error(f"   Check OPNSENSE_API_KEY and OPNSENSE_API_SECRET in .env")
        logger.error(f"   Check network connectivity from DMZ to OPNsense")
        return False

async def get_opnsense_diagnostics() -> Dict[str, Any]:
    """Get OPNsense diagnostics information"""
    try:
        async with OPNsenseClient() as client:
            conn_info = await client.get_connection_info()
            health_status = await client.health_check()
            
            diagnostics = {
                "connection_info": conn_info,
                "health_status": health_status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "test_result": "PASSED" if health_status else "FAILED"
            }
            
            if health_status:
                try:
                    system_status = await client.get_system_status()
                    diagnostics["system_status"] = {
                        "hostname": system_status.get("hostname", "unknown"),
                        "version": system_status.get("version", "unknown"),
                        "uptime": system_status.get("uptime", "unknown")
                    }
                except:
                    diagnostics["system_status"] = "Failed to retrieve"
            
            return diagnostics
            
    except Exception as e:
        return {
            "error": str(e),
            "connection_info": {
                "opnsense_host": settings.opnsense_host,
                "bridge_ip": settings.bridge_ip,
                "dmz_offline_mode": settings.dmz_offline_mode
            },
            "health_status": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_result": "FAILED"
        }