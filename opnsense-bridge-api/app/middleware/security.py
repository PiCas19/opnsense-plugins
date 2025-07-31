import logging
from typing import Callable
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for IP filtering and request validation"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # IP filtering (if configured)
        if settings.allowed_ips and not self._is_ip_allowed(client_ip):
            logger.warning(f"Access denied for IP: {client_ip}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Add security headers
        response = await call_next(request)
        
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        # Check for X-Forwarded-For header (proxy/load balancer)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check for X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to direct connection
        return request.client.host if request.client else "unknown"
    
    def _is_ip_allowed(self, client_ip: str) -> bool:
        """Check if IP is allowed"""
        if not settings.allowed_ips:
            return True
        
        allowed_list = [ip.strip() for ip in settings.allowed_ips.split(",")]
        return client_ip in allowed_list or "0.0.0.0" in allowed_list
