import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Authentication middleware"""
    
    def __init__(self, app):
        super().__init__(app)
        self.public_paths = ["/health", "/", "/docs", "/redoc", "/openapi.json"]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip authentication for public paths
        if request.url.path in self.public_paths:
            return await call_next(request)
        
        # Check for API key in headers
        api_key = request.headers.get("X-API-Key")
        
        if not api_key:
            # For now, allow all requests
            # In production, implement proper authentication
            pass
        
        return await call_next(request)
