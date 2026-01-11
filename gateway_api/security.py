# gateway_api/security.py
"""
Secure HMAC authentication for gateway API requests.
Signs timestamp + SHA256(body) to prevent tampering.
"""
import hmac
import hashlib
import time
from fastapi import HTTPException
from config import get_settings
import logging

logger = logging.getLogger(__name__)

# Maximum allowed clock drift (seconds)
MAX_TIMESTAMP_DRIFT = 60


def verify_admin_request(signature: str, timestamp: str, body: str = "") -> bool:
    """
    Verify request came from authorized backend using HMAC-SHA256.
    
    Signs: timestamp + SHA256(body) - prevents body tampering.
    
    Args:
        signature: HMAC signature from request header
        timestamp: Unix timestamp from request header
        body: Request body (empty string for GET/DELETE)
    
    Returns:
        True if valid
        
    Raises:
        HTTPException: 401 if invalid signature or expired timestamp
    """
    try:
        # Check timestamp freshness
        request_time = int(timestamp)
        current_time = int(time.time())
        time_diff = abs(current_time - request_time)
        
        if time_diff > MAX_TIMESTAMP_DRIFT:
            logger.warning(f"Timestamp expired: drift={time_diff}s > max={MAX_TIMESTAMP_DRIFT}s")
            raise HTTPException(status_code=401, detail="Timestamp expired")
        
        # Get the API key
        settings = get_settings()
        api_key = settings.GATEWAY_API_KEY
        
        # Hash the body content (empty body = empty hash)
        body_bytes = body.encode() if isinstance(body, str) else body
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        
        # Generate expected signature: timestamp + body_hash
        message = f"timestamp={timestamp}, body_hash={body_hash}"
        expected_signature = hmac.new(
            api_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Constant-time comparison
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("Invalid HMAC signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        return True

    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")
