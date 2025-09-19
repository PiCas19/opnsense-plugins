#!/usr/local/bin/python3

"""
Settings Loader Module for Advanced Network Inspector

Provides centralized configuration management for OPNsense/pfSense XML configurations.
Handles XML parsing, interface resolution, caching, and validation with comprehensive
error handling and type safety.

Features:
- Thread-safe configuration access
- Automatic interface name resolution (logical -> physical)
- Configuration validation and type conversion
- Caching for improved performance
- Comprehensive error handling and logging

Author: System Administrator
Version: 1.0
"""

import xml.etree.ElementTree as ET
import threading
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set
from enum import Enum
from functools import lru_cache
import time


class InspectionMode(Enum):
    """Available inspection modes for the network inspector."""
    STATELESS = "stateless"
    STATEFUL = "stateful" 
    BOTH = "both"


class VerbosityLevel(Enum):
    """Available verbosity levels for logging."""
    DEFAULT = "default"
    VERBOSE = "v"
    VERY_VERBOSE = "vv"
    DEBUG = "vvv"
    TRACE = "vvvv"
    ULTRA_TRACE = "vvvvv"


@dataclass
class NetworkInterface:
    """Represents a network interface with logical and physical names."""
    logical_name: str
    physical_name: str
    description: str = ""
    enabled: bool = True
    
    def __str__(self) -> str:
        return f"{self.logical_name} -> {self.physical_name}"


@dataclass
class AdvancedInspectorConfig:
    """Complete configuration for Advanced Network Inspector."""
    enabled: bool = False
    inspection_mode: InspectionMode = InspectionMode.STATELESS
    interfaces: List[NetworkInterface] = field(default_factory=list)
    home_networks: List[str] = field(default_factory=list)
    promiscuous_mode: bool = False
    verbosity: VerbosityLevel = VerbosityLevel.DEFAULT
    ips_mode: bool = False
    
    def get_physical_interface_names(self) -> List[str]:
        """Get list of physical interface names only."""
        return [iface.physical_name for iface in self.interfaces if iface.enabled]
    
    def get_logical_interface_names(self) -> List[str]:
        """Get list of logical interface names only."""
        return [iface.logical_name for iface in self.interfaces if iface.enabled]


class ConfigurationError(Exception):
    """Custom exception for configuration-related errors."""
    pass


class XMLConfigParser(ABC):
    """Abstract base class for XML configuration parsers."""
    
    @abstractmethod
    def parse_config(self, config_path: Path) -> AdvancedInspectorConfig:
        """
        Parse configuration from XML file.
        
        Args:
            config_path: Path to XML configuration file
            
        Returns:
            Parsed configuration object
            
        Raises:
            ConfigurationError: If parsing fails
        """
        pass


class OPNsenseConfigParser(XMLConfigParser):
    """
    Configuration parser for OPNsense XML format.
    
    Handles the specific XML structure used by OPNsense firewalls
    for Advanced Inspector configuration.
    """
    
    BASE_XPATH = ".//OPNsense/AdvInspector"
    INTERFACES_XPATH = ".//interfaces"
    
    def __init__(self):
        """Initialize OPNsense configuration parser."""
        self._xml_cache: Optional[ET.ElementTree] = None
        self._cache_timestamp: Optional[float] = None
        self._cache_lock = threading.Lock()
    
    def parse_config(self, config_path: Path) -> AdvancedInspectorConfig:
        """
        Parse OPNsense configuration file.
        
        Args:
            config_path: Path to config.xml file
            
        Returns:
            Parsed AdvancedInspectorConfig object
            
        Raises:
            ConfigurationError: If parsing fails
        """
        try:
            root = self._load_xml_root(config_path)
            
            return AdvancedInspectorConfig(
                enabled=self._get_boolean_value(root, "/general/enabled", False),
                inspection_mode=self._get_inspection_mode(root),
                interfaces=self._resolve_interfaces(root),
                home_networks=self._get_network_list(root, "/general/homenet"),
                promiscuous_mode=self._get_boolean_value(root, "/general/promisc", False),
                verbosity=self._get_verbosity_level(root),
                ips_mode=self._get_boolean_value(root, "/general/ips", False)
            )
            
        except Exception as e:
            raise ConfigurationError(f"Failed to parse configuration: {e}")
    
    def _load_xml_root(self, config_path: Path) -> ET.Element:
        """
        Load and cache XML root element with thread safety.
        
        Args:
            config_path: Path to XML file
            
        Returns:
            Root XML element
            
        Raises:
            ConfigurationError: If XML loading fails
        """
        with self._cache_lock:
            try:
                # Check if we need to reload the file
                if self._should_reload_xml(config_path):
                    tree = ET.parse(config_path)
                    self._xml_cache = tree
                    self._cache_timestamp = config_path.stat().st_mtime
                    logging.debug(f"Loaded XML configuration from {config_path}")
                
                if self._xml_cache is None:
                    raise ConfigurationError("Failed to load XML configuration")
                
                return self._xml_cache.getroot()
                
            except ET.ParseError as e:
                raise ConfigurationError(f"XML parsing error: {e}")
            except FileNotFoundError:
                raise ConfigurationError(f"Configuration file not found: {config_path}")
            except Exception as e:
                raise ConfigurationError(f"Error loading XML: {e}")
    
    def _should_reload_xml(self, config_path: Path) -> bool:
        """Check if XML file should be reloaded based on modification time."""
        try:
            if self._xml_cache is None or self._cache_timestamp is None:
                return True
            
            current_mtime = config_path.stat().st_mtime
            return current_mtime > self._cache_timestamp
        except OSError:
            return True
    
    def _get_config_value(self, root: ET.Element, xpath: str, default: str = "") -> str:
        """
        Get configuration value from XML using XPath.
        
        Args:
            root: XML root element
            xpath: XPath relative to AdvInspector base
            default: Default value if not found
            
        Returns:
            Configuration value as string
        """
        try:
            full_xpath = f"{self.BASE_XPATH}{xpath}"
            element = root.find(full_xpath)
            
            if element is not None and element.text:
                return element.text.strip()
            
            return default
            
        except Exception as e:
            logging.warning(f"Error getting config value for xpath '{xpath}': {e}")
            return default
    
    def _get_boolean_value(self, root: ET.Element, xpath: str, default: bool = False) -> bool:
        """
        Get boolean configuration value.
        
        Args:
            root: XML root element
            xpath: XPath relative to AdvInspector base
            default: Default boolean value
            
        Returns:
            Boolean configuration value
        """
        value = self._get_config_value(root, xpath, "0" if not default else "1")
        return value.lower() in ("1", "true", "yes", "on", "enabled")
    
    def _get_inspection_mode(self, root: ET.Element) -> InspectionMode:
        """
        Get inspection mode from configuration.
        
        Args:
            root: XML root element
            
        Returns:
            InspectionMode enum value
        """
        mode_str = self._get_config_value(root, "/general/inspection_mode", "stateless")
        
        try:
            return InspectionMode(mode_str.lower())
        except ValueError:
            logging.warning(f"Invalid inspection mode '{mode_str}', using stateless")
            return InspectionMode.STATELESS
    
    def _get_verbosity_level(self, root: ET.Element) -> VerbosityLevel:
        """
        Get verbosity level from configuration.
        
        Args:
            root: XML root element
            
        Returns:
            VerbosityLevel enum value
        """
        verbosity_str = self._get_config_value(root, "/general/verbosity", "default")
        
        try:
            return VerbosityLevel(verbosity_str.lower())
        except ValueError:
            logging.warning(f"Invalid verbosity level '{verbosity_str}', using default")
            return VerbosityLevel.DEFAULT
    
    def _get_network_list(self, root: ET.Element, xpath: str) -> List[str]:
        """
        Get list of network addresses from comma-separated configuration value.
        
        Args:
            root: XML root element
            xpath: XPath to network list configuration
            
        Returns:
            List of network addresses
        """
        networks_str = self._get_config_value(root, xpath, "")
        if not networks_str:
            return []
        
        networks = []
        for network in networks_str.split(","):
            network = network.strip()
            if network:
                networks.append(network)
        
        return networks
    
    def _resolve_interfaces(self, root: ET.Element) -> List[NetworkInterface]:
        """
        Resolve logical interface names to physical interface names.
        
        Args:
            root: XML root element
            
        Returns:
            List of NetworkInterface objects with resolved physical names
        """
        # Get logical interface names from configuration
        interfaces_str = self._get_config_value(root, "/general/interfaces", "")
        if not interfaces_str:
            return []
        
        logical_interfaces = [name.strip() for name in interfaces_str.split(",") if name.strip()]
        
        # Resolve each logical interface to physical name
        resolved_interfaces = []
        
        for logical_name in logical_interfaces:
            try:
                physical_name = self._resolve_single_interface(root, logical_name)
                if physical_name:
                    interface = NetworkInterface(
                        logical_name=logical_name,
                        physical_name=physical_name,
                        description=self._get_interface_description(root, logical_name),
                        enabled=True
                    )
                    resolved_interfaces.append(interface)
                else:
                    logging.warning(f"Could not resolve logical interface '{logical_name}' to physical name")
            
            except Exception as e:
                logging.error(f"Error resolving interface '{logical_name}': {e}")
        
        return resolved_interfaces
    
    def _resolve_single_interface(self, root: ET.Element, logical_name: str) -> Optional[str]:
        """
        Resolve a single logical interface name to physical name.
        
        Args:
            root: XML root element
            logical_name: Logical interface name (e.g., 'lan', 'opt1')
            
        Returns:
            Physical interface name or None if not found
        """
        try:
            xpath = f"{self.INTERFACES_XPATH}/{logical_name}/if"
            element = root.find(xpath)
            
            if element is not None and element.text:
                return element.text.strip()
            
            return None
            
        except Exception as e:
            logging.debug(f"Error resolving interface '{logical_name}': {e}")
            return None
    
    def _get_interface_description(self, root: ET.Element, logical_name: str) -> str:
        """
        Get description for a logical interface.
        
        Args:
            root: XML root element
            logical_name: Logical interface name
            
        Returns:
            Interface description or empty string
        """
        try:
            xpath = f"{self.INTERFACES_XPATH}/{logical_name}/descr"
            element = root.find(xpath)
            
            if element is not None and element.text:
                return element.text.strip()
            
            return ""
            
        except Exception:
            return ""


class ConfigurationManager:
    """
    Central configuration manager with caching and validation.
    
    Provides thread-safe access to configuration data with automatic
    reloading when configuration files change.
    """
    
    def __init__(self, 
                 config_path: str = "/conf/config.xml",
                 parser: Optional[XMLConfigParser] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file
            parser: XML parser implementation (defaults to OPNsenseConfigParser)
        """
        self.config_path = Path(config_path)
        self.parser = parser or OPNsenseConfigParser()
        self._config_cache: Optional[AdvancedInspectorConfig] = None
        self._cache_lock = threading.Lock()
        self._last_reload_time: Optional[float] = None
    
    def get_config(self, force_reload: bool = False) -> AdvancedInspectorConfig:
        """
        Get current configuration with automatic caching.
        
        Args:
            force_reload: Force reload from file even if cached
            
        Returns:
            Current AdvancedInspectorConfig
            
        Raises:
            ConfigurationError: If configuration loading fails
        """
        with self._cache_lock:
            if force_reload or self._should_reload_config():
                self._reload_config()
            
            if self._config_cache is None:
                raise ConfigurationError("No configuration available")
            
            return self._config_cache
    
    def _should_reload_config(self) -> bool:
        """Check if configuration should be reloaded."""
        if self._config_cache is None or self._last_reload_time is None:
            return True
        
        try:
            # Check if file has been modified
            current_mtime = self.config_path.stat().st_mtime
            return current_mtime > self._last_reload_time
        except OSError:
            # File may not exist or be accessible
            return True
    
    def _reload_config(self) -> None:
        """Reload configuration from file."""
        try:
            self._config_cache = self.parser.parse_config(self.config_path)
            self._last_reload_time = time.time()
            
            logging.info(f"Configuration reloaded from {self.config_path}")
            logging.debug(f"Config: enabled={self._config_cache.enabled}, "
                         f"mode={self._config_cache.inspection_mode.value}, "
                         f"interfaces={len(self._config_cache.interfaces)}")
            
        except Exception as e:
            logging.error(f"Failed to reload configuration: {e}")
            # Don't clear the cache - keep using the old config if possible
            if self._config_cache is None:
                raise ConfigurationError(f"Initial configuration load failed: {e}")
    
    def validate_config(self) -> Dict[str, Any]:
        """
        Validate current configuration and return validation report.
        
        Returns:
            Dictionary with validation results and recommendations
        """
        try:
            config = self.get_config()
            
            validation_report = {
                "valid": True,
                "warnings": [],
                "errors": [],
                "recommendations": []
            }
            
            # Check if inspector is enabled
            if not config.enabled:
                validation_report["warnings"].append("Advanced Inspector is disabled")
            
            # Check interface configuration
            if not config.interfaces:
                validation_report["errors"].append("No interfaces configured for monitoring")
                validation_report["valid"] = False
            
            # Check home networks
            if not config.home_networks:
                validation_report["warnings"].append("No home networks defined - all traffic will be processed")
            
            # Validate network specifications
            for network in config.home_networks:
                if not self._is_valid_network(network):
                    validation_report["errors"].append(f"Invalid network specification: {network}")
                    validation_report["valid"] = False
            
            # Performance recommendations
            if config.promiscuous_mode:
                validation_report["recommendations"].append(
                    "Promiscuous mode enabled - may impact network performance"
                )
            
            if config.verbosity in (VerbosityLevel.TRACE, VerbosityLevel.ULTRA_TRACE):
                validation_report["recommendations"].append(
                    "High verbosity level may impact performance and generate large logs"
                )
            
            return validation_report
            
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Configuration validation failed: {e}"],
                "warnings": [],
                "recommendations": []
            }
    
    def _is_valid_network(self, network_spec: str) -> bool:
        """Check if network specification is valid."""
        try:
            import ipaddress
            # Try to parse as network or single IP
            if "/" in network_spec:
                ipaddress.ip_network(network_spec, strict=False)
            else:
                ipaddress.ip_address(network_spec)
            return True
        except ValueError:
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get configuration manager statistics."""
        return {
            "config_file": str(self.config_path),
            "config_exists": self.config_path.exists(),
            "last_reload": self._last_reload_time,
            "cache_loaded": self._config_cache is not None
        }


# Global configuration manager instance
_config_manager = ConfigurationManager()


def get_config_manager() -> ConfigurationManager:
    """
    Get the global configuration manager instance.
    
    Returns:
        ConfigurationManager instance
    """
    return _config_manager


# Backward compatibility functions
def get_config_value(xpath: str, default: Optional[str] = None) -> Optional[str]:
    """
    Get configuration value using XPath (legacy compatibility function).
    
    Args:
        xpath: XPath expression relative to AdvInspector base
        default: Default value if not found
        
    Returns:
        Configuration value or default
    """
    try:
        parser = OPNsenseConfigParser()
        config_path = Path("/conf/config.xml")
        root = parser._load_xml_root(config_path)
        return parser._get_config_value(root, xpath, default or "")
    except Exception as e:
        logging.error(f"get_config_value({xpath}): {e}")
        return default


def resolve_physical_interfaces(logical_ifnames: List[str]) -> List[str]:
    """
    Resolve logical interface names to physical names (legacy compatibility function).
    
    Args:
        logical_ifnames: List of logical interface names
        
    Returns:
        List of resolved physical interface names
    """
    try:
        config = _config_manager.get_config()
        resolved = []
        
        for logical_name in logical_ifnames:
            for interface in config.interfaces:
                if interface.logical_name == logical_name:
                    resolved.append(interface.physical_name)
                    break
            else:
                logging.warning(f"Logical interface '{logical_name}' not found")
        
        return resolved
        
    except Exception as e:
        logging.error(f"Error resolving interfaces: {e}")
        return []


def load_enabled() -> bool:
    """Check if Advanced Inspector is enabled."""
    try:
        config = _config_manager.get_config()
        return config.enabled
    except Exception:
        return False


def load_inspection_mode() -> str:
    """Get inspection mode as string."""
    try:
        config = _config_manager.get_config()
        return config.inspection_mode.value
    except Exception:
        return InspectionMode.STATELESS.value


def load_interfaces() -> List[str]:
    """Get list of physical interface names for monitoring."""
    try:
        config = _config_manager.get_config()
        return config.get_physical_interface_names()
    except Exception:
        return []


def load_home_networks() -> List[str]:
    """Get list of home network specifications."""
    try:
        config = _config_manager.get_config()
        return config.home_networks
    except Exception:
        return []


def load_promiscuous_mode() -> bool:
    """Check if promiscuous mode is enabled."""
    try:
        config = _config_manager.get_config()
        return config.promiscuous_mode
    except Exception:
        return False


def load_verbosity() -> str:
    """Get verbosity level as string."""
    try:
        config = _config_manager.get_config()
        return config.verbosity.value
    except Exception:
        return VerbosityLevel.DEFAULT.value


def load_ips_mode() -> bool:
    """Check if IPS mode is enabled."""
    try:
        config = _config_manager.get_config()
        return config.ips_mode
    except Exception:
        return False


if __name__ == "__main__":
    # Module loaded directly - use as import only
    print("SettingsLoader module - use as import only")
    import sys
    sys.exit(1)