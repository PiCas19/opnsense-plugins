"""
settings_loader.py - OPNsense Advanced Inspector Settings Loader

This module handles loading configuration settings from OPNsense XML configuration
for the Advanced Inspector plugin. It provides a clean interface for accessing
all plugin settings with proper error handling and caching.

Author: Pierpaolo Casati
Version: 2.0
License: BSD 2-Clause
"""

import xml.etree.ElementTree as ET
import logging
import time
from typing import List, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass


@dataclass
class InspectorSettings:
    """Data class representing all inspector settings."""
    enabled: bool = False  # Default from XML: 0
    ips_mode: bool = True   # Default from XML: 1 
    promiscuous_mode: bool = False  # Default from XML: 0
    inspection_mode: str = "stateless"  # Default from XML: stateless
    interfaces: List[str] = None  # Required field
    home_networks: List[str] = None  # Optional field
    verbosity: str = "default"  # Default from XML: default
    
    def __post_init__(self):
        if self.interfaces is None:
            self.interfaces = []
        if self.home_networks is None:
            self.home_networks = []
    
    def validate(self) -> List[str]:
        """
        Validate settings according to XML model constraints.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check required interfaces when enabled
        if self.enabled and not self.interfaces:
            errors.append("At least one interface must be selected when Advanced Packet Inspector is enabled.")
        
        # Validate inspection mode
        valid_modes = ["stateless", "stateful", "both"]
        if self.inspection_mode not in valid_modes:
            errors.append(f"Invalid inspection mode: {self.inspection_mode}. Must be one of: {', '.join(valid_modes)}")
        
        # Validate verbosity
        valid_verbosity = ["default", "v", "vv", "vvv", "vvvv", "vvvvv"]
        if self.verbosity not in valid_verbosity:
            errors.append(f"Invalid verbosity level: {self.verbosity}. Must be one of: {', '.join(valid_verbosity)}")
        
        # Validate home networks format (basic CIDR check)
        for network in self.home_networks:
            if network and not self._is_valid_cidr(network):
                errors.append(f"Invalid network format: {network}. Must be in CIDR format (e.g., 192.168.1.0/24)")
        
        return errors
    
    def _is_valid_cidr(self, network: str) -> bool:
        """Check if network string is valid CIDR format."""
        try:
            import ipaddress
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False


class SettingsLoader:
    """
    Handles loading and caching of OPNsense Advanced Inspector settings.
    
    This class provides a clean interface for accessing plugin configuration
    with automatic caching and error handling. It monitors the configuration
    file for changes and reloads as needed.
    """
    
    def __init__(self, config_path: str = "/conf/config.xml"):
        """
        Initialize the settings loader.
        
        Args:
            config_path: Path to OPNsense configuration file
        """
        self.config_path = Path(config_path)
        self.logger = self._setup_logger()
        self._settings_cache: Optional[InspectorSettings] = None
        self._last_load_time: float = 0
        self._config_mtime: float = 0
        
    def _setup_logger(self) -> logging.Logger:
        """
        Set up logging for the settings loader.
        
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger('settings_loader')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.WARNING)  # Default to WARNING to reduce noise
        return logger
    
    def _needs_reload(self) -> bool:
        """
        Check if configuration needs to be reloaded.
        
        Returns:
            True if reload is needed, False otherwise
        """
        if not self.config_path.exists():
            return False
            
        current_mtime = self.config_path.stat().st_mtime
        return current_mtime > self._config_mtime
    
    def _get_config_value(self, xpath: str, default: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a configuration value from XML using XPath.
        
        Args:
            xpath: XPath relative to /OPNsense/AdvInspector
            default: Default value if not found
            
        Returns:
            Configuration value or default
        """
        try:
            if not self.config_path.exists():
                self.logger.warning(f"Configuration file not found: {self.config_path}")
                return default
                
            tree = ET.parse(self.config_path)
            root = tree.getroot()
            
            # Search under the correct node
            full_xpath = f".//OPNsense/AdvInspector{xpath}"
            node = root.find(full_xpath)
            
            if node is not None and node.text:
                return node.text.strip()
            
            return default
            
        except ET.ParseError as e:
            self.logger.error(f"XML parse error reading {xpath}: {e}")
            return default
        except Exception as e:
            self.logger.error(f"Error reading config value {xpath}: {e}")
            return default
    
    def _resolve_physical_interfaces(self, logical_interfaces: List[str]) -> List[str]:
        """
        Resolve logical interface names to physical interface names.
        
        Args:
            logical_interfaces: List of logical interface names (e.g., ['lan', 'opt1'])
            
        Returns:
            List of physical interface names (e.g., ['em0', 'igb1'])
        """
        if not logical_interfaces:
            return []
            
        try:
            if not self.config_path.exists():
                self.logger.warning(f"Configuration file not found: {self.config_path}")
                return []
                
            tree = ET.parse(self.config_path)
            root = tree.getroot()
            physical_interfaces = []
            
            for logical_name in logical_interfaces:
                xpath = f".//interfaces/{logical_name}/if"
                node = root.find(xpath)
                
                if node is not None and node.text:
                    physical_name = node.text.strip()
                    physical_interfaces.append(physical_name)
                    self.logger.debug(f"Resolved {logical_name} -> {physical_name}")
                else:
                    self.logger.warning(f"Logical interface '{logical_name}' not found in configuration")
            
            return physical_interfaces
            
        except ET.ParseError as e:
            self.logger.error(f"XML parse error resolving interfaces: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error resolving physical interfaces: {e}")
            return []
    
    def load_settings(self, force_reload: bool = False) -> InspectorSettings:
        """
        Load all inspector settings with caching.
        
        Args:
            force_reload: Force reload from disk even if cached
            
        Returns:
            InspectorSettings object with all configuration
        """
        # Check if we need to reload
        if not force_reload and self._settings_cache is not None:
            if not self._needs_reload():
                return self._settings_cache
        
        try:
            self.logger.debug("Loading inspector settings from configuration")
            
            # Load basic settings
            enabled = self._get_config_value("/general/enabled", "0") == "1"
            ips_mode = self._get_config_value("/general/ips", "0") == "1"
            promiscuous_mode = self._get_config_value("/general/promisc", "0") == "1"
            inspection_mode = self._get_config_value("/general/inspection_mode", "stateless")
            verbosity = self._get_config_value("/general/verbosity", "default")
            
            # Load and resolve interfaces
            interfaces_str = self._get_config_value("/general/interfaces", "")
            logical_interfaces = [i.strip() for i in interfaces_str.split(",") if i.strip()]
            physical_interfaces = self._resolve_physical_interfaces(logical_interfaces)
            
            # Load home networks
            homenet_str = self._get_config_value("/general/homenet", "")
            home_networks = [n.strip() for n in homenet_str.split(",") if n.strip()]
            
            # Create settings object
            settings = InspectorSettings(
                enabled=enabled,
                ips_mode=ips_mode,
                promiscuous_mode=promiscuous_mode,
                inspection_mode=inspection_mode,
                interfaces=physical_interfaces,
                home_networks=home_networks,
                verbosity=verbosity
            )
            
            # Validate settings according to XML model constraints
            validation_errors = settings.validate()
            if validation_errors:
                for error in validation_errors:
                    self.logger.warning(f"Settings validation warning: {error}")
            
            # Update cache
            self._settings_cache = settings
            self._last_load_time = time.time()
            if self.config_path.exists():
                self._config_mtime = self.config_path.stat().st_mtime
            
            self.logger.info(f"Loaded settings: enabled={enabled}, interfaces={len(physical_interfaces)}, ips_mode={ips_mode}")
            return settings
            
        except Exception as e:
            self.logger.error(f"Error loading settings: {e}")
            # Return default settings on error
            return InspectorSettings()
    
    def get_settings_dict(self, force_reload: bool = False) -> Dict[str, Any]:
        """
        Get settings as a dictionary.
        
        Args:
            force_reload: Force reload from disk
            
        Returns:
            Dictionary representation of settings
        """
        settings = self.load_settings(force_reload)
        return {
            'enabled': settings.enabled,
            'ips_mode': settings.ips_mode,
            'promiscuous_mode': settings.promiscuous_mode,
            'inspection_mode': settings.inspection_mode,
            'interfaces': settings.interfaces,
            'home_networks': settings.home_networks,
            'verbosity': settings.verbosity,
            'last_loaded': self._last_load_time
        }
    
    def validate_current_settings(self) -> Dict[str, Any]:
        """
        Validate current settings and return validation report.
        
        Returns:
            Dictionary containing validation results
        """
        settings = self.load_settings()
        validation_errors = settings.validate()
        
        return {
            'valid': len(validation_errors) == 0,
            'errors': validation_errors,
            'settings': self.get_settings_dict(),
            'model_compliance': {
                'enabled_default_correct': settings.enabled == False,  # XML default: 0
                'ips_default_correct': settings.ips_mode == True,      # XML default: 1
                'promisc_default_correct': settings.promiscuous_mode == False,  # XML default: 0
                'inspection_mode_valid': settings.inspection_mode in ['stateless', 'stateful', 'both'],
                'verbosity_valid': settings.verbosity in ['default', 'v', 'vv', 'vvv', 'vvvv', 'vvvvv']
            }
        }


# Global instance for easy access
_settings_loader = SettingsLoader()


# Legacy functions for backward compatibility
def load_enabled() -> bool:
    """Load enabled setting. Use SettingsLoader.load_settings() instead."""
    return _settings_loader.load_settings().enabled


def load_inspection_mode() -> str:
    """Load inspection mode. Use SettingsLoader.load_settings() instead."""
    return _settings_loader.load_settings().inspection_mode


def load_interfaces() -> List[str]:
    """Load physical interfaces. Use SettingsLoader.load_settings() instead."""
    return _settings_loader.load_settings().interfaces


def load_home_networks() -> List[str]:
    """Load home networks. Use SettingsLoader.load_settings() instead."""
    return _settings_loader.load_settings().home_networks


def load_promiscuous_mode() -> bool:
    """Load promiscuous mode setting. Use SettingsLoader.load_settings() instead."""
    return _settings_loader.load_settings().promiscuous_mode


def load_verbosity() -> str:
    """Load verbosity level. Use SettingsLoader.load_settings() instead."""
    return _settings_loader.load_settings().verbosity


def load_ips_mode() -> bool:
    """Load IPS mode setting. Use SettingsLoader.load_settings() instead."""
    return _settings_loader.load_settings().ips_mode

