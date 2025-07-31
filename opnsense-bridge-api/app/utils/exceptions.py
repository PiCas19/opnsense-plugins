class OPNsenseBridgeException(Exception):
    """Base exception for OPNsense Bridge"""
    pass

class OPNsenseAPIException(OPNsenseBridgeException):
    """Exception for OPNsense API errors"""
    def __init__(self, message: str, status_code: int = None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class ConfigurationException(OPNsenseBridgeException):
    """Exception for configuration errors"""
    pass

class AuthenticationException(OPNsenseBridgeException):
    """Exception for authentication errors"""
    pass

class ValidationException(OPNsenseBridgeException):
    """Exception for validation errors"""
    pass

class RateLimitException(OPNsenseBridgeException):
    """Exception for rate limiting"""
    pass

class EmergencyOperationException(OPNsenseBridgeException):
    """Exception for emergency operations"""
    pass