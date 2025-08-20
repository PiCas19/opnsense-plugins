#!/usr/bin/env python3
"""
Configuration module for OPNsense Firewall Demo App
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'demo-secret-key-change-me-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # OPNsense API configuration
    OPNSENSE_HOST = os.environ.get('OPNSENSE_HOST', '192.168.216.1')
    OPNSENSE_PORT = os.environ.get('OPNSENSE_PORT', '443')
    OPNSENSE_API_KEY = os.environ.get('OPNSENSE_API_KEY', '')
    OPNSENSE_API_SECRET = os.environ.get('OPNSENSE_API_SECRET', '')
    OPNSENSE_VERIFY_SSL = os.environ.get('OPNSENSE_VERIFY_SSL', 'False').lower() == 'true'
    OPNSENSE_TIMEOUT = int(os.environ.get('OPNSENSE_TIMEOUT', '30'))
    
    # Application settings
    APP_NAME = 'OPNsense Firewall Demo'
    APP_VERSION = '1.0.0'
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    
    # Demo settings
    DEMO_MODE = os.environ.get('DEMO_MODE', 'True').lower() == 'true'
    MAX_DEMO_RULES = int(os.environ.get('MAX_DEMO_RULES', '10'))
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_DEFAULT = '100/hour'
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # SIEM simulation settings
    SIEM_INCIDENTS = {
        'malicious_ip': {
            'name': 'Malicious IP Detection',
            'severity_levels': ['low', 'medium', 'high', 'critical'],
            'auto_response': True,
            'keywords': ['malicious', 'blacklist', 'threat']
        },
        'port_scan': {
            'name': 'Port Scan Detection', 
            'severity_levels': ['medium', 'high'],
            'auto_response': True,
            'keywords': ['port scan', 'scanning', 'reconnaissance']
        },
        'brute_force': {
            'name': 'Brute Force Attack',
            'severity_levels': ['high', 'critical'],
            'auto_response': True,
            'keywords': ['brute force', 'login', 'authentication']
        },
        'suspicious_traffic': {
            'name': 'Suspicious Network Traffic',
            'severity_levels': ['low', 'medium', 'high'],
            'auto_response': False,
            'keywords': ['suspicious', 'anomaly', 'unusual']
        }
    }
    
    # Monitoring settings
    HEALTH_CHECK_INTERVAL = int(os.environ.get('HEALTH_CHECK_INTERVAL', '30'))
    OPNSENSE_CONNECTION_RETRY = int(os.environ.get('OPNSENSE_CONNECTION_RETRY', '3'))
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        pass

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    DEMO_MODE = True
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    OPNSENSE_VERIFY_SSL = True
    LOG_LEVEL = 'INFO'
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Production-specific logging
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug:
            file_handler = RotatingFileHandler(
                'logs/firewall-demo.log',
                maxBytes=10240000,  # 10MB
                backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('Firewall Demo startup')

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEMO_MODE = True
    OPNSENSE_API_KEY = 'test_key'
    OPNSENSE_API_SECRET = 'test_secret'
    LOG_LEVEL = 'DEBUG'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])