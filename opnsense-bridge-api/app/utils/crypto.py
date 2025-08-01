import hashlib
import hmac
import secrets
import base64
from typing import Tuple, Optional

def generate_api_key(length: int = 32) -> str:
    """Generate secure API key"""
    return secrets.token_urlsafe(length)

def generate_secret_key(length: int = 64) -> str:
    """Generate secret key for signing"""
    return secrets.token_hex(length)

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash password with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    # Use PBKDF2 for password hashing
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return base64.b64encode(key).decode(), salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify password against hash"""
    try:
        new_hash, _ = hash_password(password, salt)  # CORRETTO: era "hash*password"
        return hmac.compare_digest(hashed, new_hash)
    except:
        return False

def create_signature(data: str, secret_key: str) -> str:
    """Create HMAC signature for data"""
    signature = hmac.new(
        secret_key.encode(),
        data.encode(),
        hashlib.sha256
    )
    return base64.b64encode(signature.digest()).decode()

def verify_signature(data: str, signature: str, secret_key: str) -> bool:
    """Verify HMAC signature"""
    try:
        expected_signature = create_signature(data, secret_key)
        return hmac.compare_digest(signature, expected_signature)
    except:
        return False

def generate_csrf_token() -> str:
    """Generate CSRF token"""
    return secrets.token_urlsafe(32)

def hash_data(data: str, algorithm: str = 'sha256') -> str:
    """Hash data with specified algorithm"""
    hash_func = getattr(hashlib, algorithm)
    return hash_func(data.encode()).hexdigest()