# gateway_api/security.py
"""
Secure HMAC authentication for gateway API requests.
Signs timestamp + nonce + SHA256(body) to prevent tampering and replay attacks.
"""
import hmac
import hashlib
import time
import threading
from collections import OrderedDict
from fastapi import HTTPException
from config import get_settings
import logging

logger = logging.getLogger(__name__)

# Maximum allowed clock drift (seconds)
MAX_TIMESTAMP_DRIFT = 60

# Nonce cache for replay prevention
# Maps nonce -> expiry_time
_nonce_cache: OrderedDict = OrderedDict()
_nonce_lock = threading.Lock()
_MAX_NONCE_CACHE_SIZE = 10000  # Limit memory usage


def _cleanup_expired_nonces():
    """Remove expired nonces from cache (called under lock)"""
    current_time = time.time()
    # Remove expired entries from front of OrderedDict
    while _nonce_cache:
        oldest_nonce, expiry = next(iter(_nonce_cache.items()))
        if current_time > expiry:
            _nonce_cache.pop(oldest_nonce)
        else:
            break
    
    # Also trim if cache is too large
    while len(_nonce_cache) > _MAX_NONCE_CACHE_SIZE:
        _nonce_cache.popitem(last=False)


def _is_nonce_used(nonce: str) -> bool:
    """Check if nonce was already used (and not expired)"""
    with _nonce_lock:
        _cleanup_expired_nonces()
        return nonce in _nonce_cache


def _mark_nonce_used(nonce: str, ttl: int = MAX_TIMESTAMP_DRIFT):
    """Mark nonce as used with TTL for automatic expiry"""
    with _nonce_lock:
        _cleanup_expired_nonces()
        expiry = time.time() + ttl
        _nonce_cache[nonce] = expiry


def verify_admin_request(signature: str, timestamp: str, body: str = "", nonce: str = None) -> bool:
    """
    Verify request came from authorized backend using HMAC-SHA256.
    
    Signs: timestamp + nonce + SHA256(body) - prevents body tampering and replay attacks.
    
    Args:
        signature: HMAC signature from request header
        timestamp: Unix timestamp from request header
        body: Request body (empty string for GET/DELETE)
        nonce: Optional unique request identifier for replay prevention
    
    Returns:
        True if valid
        
    Raises:
        HTTPException: 401 if invalid signature, expired timestamp, or replayed nonce
    """
    try:
        # Check timestamp freshness
        request_time = int(timestamp)
        current_time = int(time.time())
        time_diff = abs(current_time - request_time)
        
        if time_diff > MAX_TIMESTAMP_DRIFT:
            logger.warning(f"Timestamp expired: drift={time_diff}s > max={MAX_TIMESTAMP_DRIFT}s")
            raise HTTPException(status_code=401, detail="Timestamp expired")
        
        # Check nonce for replay prevention (if provided)
        if nonce:
            if _is_nonce_used(nonce):
                logger.warning(f"Replay attack detected: nonce already used")
                raise HTTPException(status_code=401, detail="Replay detected")
        
        # Get the API key
        settings = get_settings()
        api_key = settings.GATEWAY_API_KEY
        
        # Hash the body content (empty body = empty hash)
        body_bytes = body.encode() if isinstance(body, str) else body
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        
        # Generate expected signature: timestamp + nonce (if present) + body_hash
        if nonce:
            message = f"timestamp={timestamp}, nonce={nonce}, body_hash={body_hash}"
        else:
            # Backward compatibility: support requests without nonce
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
        
        # Mark nonce as used AFTER successful verification
        if nonce:
            _mark_nonce_used(nonce)
            logger.debug(f"Nonce accepted and marked as used")

        return True

    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")


def get_nonce_cache_stats() -> dict:
    """Return nonce cache stats for monitoring"""
    with _nonce_lock:
        return {
            "size": len(_nonce_cache),
            "max_size": _MAX_NONCE_CACHE_SIZE
        }
