# gateway_api/security.py
import hmac
import hashlib
import time
from fastapi import HTTPException
from config import get_settings
import logging

logger = logging.getLogger(__name__)

def verify_admin_request(signature: str, timestamp: str, body: str = "") -> bool:
    """
    Verify that the request came from the authorized backend server
    using HMAC-SHA256 authentication
    """
    try:
        # Check timestamp freshness
        request_time = int(timestamp)
        current_time = int(time.time())
        time_diff = abs(current_time - request_time)
        
        logger.debug(f"Request timestamp: {request_time}, Current time: {current_time}, Difference: {time_diff}s")
        
        if time_diff > 60:  # Allow 60 seconds of clock drift
            raise HTTPException(status_code=401, detail="Timestamp too old")
        
        # Get the API key from settings
        settings = get_settings()
        api_key = settings.GATEWAY_API_KEY
        
        logger.debug(f"Message for signature: timestamp={timestamp}, body_length={len(body)}")
        logger.debug(f"Received signature: {signature}")
        
        # Generate expected signature
        expected_signature = hmac.new(
            api_key.encode(),
            f"timestamp={timestamp}, body_length={len(body)}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        logger.debug(f"Expected signature: {expected_signature}")
        
        # Compare signatures using constant-time comparison
        if not hmac.compare_digest(signature, expected_signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

        return True

    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")
