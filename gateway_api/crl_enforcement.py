# gateway_api/crl_enforcement.py
"""
CRL (Certificate Revocation List) Enforcement Module

This module provides middleware and utilities for enforcing certificate
revocation across the gateway mesh. When a certificate is revoked,
connections from that gateway should be rejected.

Security Model:
- CRL is synchronized via Whisper protocol from backend
- Each gateway maintains a local copy of the CRL
- All inter-gateway and backend-to-gateway requests are validated
- Revoked certificates result in immediate connection rejection
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Set
from functools import wraps
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

# CRL storage path (same location as whisper node uses)
CRL_FILE = Path(os.environ.get("WHISPER_DATA", "/dev/shm/whisper_data")) / "crl.json"

# In-memory CRL cache for fast lookups
_crl_cache: Set[str] = set()
_crl_version: int = 0
_crl_loaded_at: Optional[datetime] = None


def load_crl_from_disk() -> bool:
    """
    Load CRL from disk into memory cache.
    Called on startup and periodically.
    Returns True if CRL was loaded successfully.
    """
    global _crl_cache, _crl_version, _crl_loaded_at
    
    if not CRL_FILE.exists():
        logger.debug("No CRL file found - mesh CRL enforcement inactive")
        return False
    
    try:
        with open(CRL_FILE) as f:
            data = json.load(f)
        
        entries = data.get("entries", [])
        new_cache = {e["serial_number"] for e in entries}
        version = data.get("version", 0)
        
        if version > _crl_version or new_cache != _crl_cache:
            _crl_cache = new_cache
            _crl_version = version
            _crl_loaded_at = datetime.utcnow()
            logger.info(f"CRL v{version} loaded: {len(new_cache)} revoked certificates")
        
        return True
    except Exception as e:
        logger.error(f"Failed to load CRL: {e}")
        return False


def is_certificate_revoked(serial_number: str) -> bool:
    """
    Check if a certificate serial number is in the CRL.
    This is a fast O(1) lookup against the in-memory cache.
    """
    if not serial_number:
        return False
    
    # Normalize serial number (uppercase, no leading zeros except for single digit)
    normalized = serial_number.upper().lstrip('0') or '0'
    
    # Also check with original format
    return normalized in _crl_cache or serial_number in _crl_cache


def get_crl_status() -> dict:
    """Return current CRL status for monitoring"""
    return {
        "version": _crl_version,
        "entries_count": len(_crl_cache),
        "loaded_at": _crl_loaded_at.isoformat() if _crl_loaded_at else None,
        "enforcement_active": _crl_version > 0,
        "revoked_serials": list(_crl_cache)  # For debugging only
    }


def refresh_crl_cache():
    """Force refresh the CRL cache from disk"""
    load_crl_from_disk()


class CRLEnforcementMiddleware:
    """
    FastAPI middleware that checks incoming requests against the CRL.
    
    For requests from other gateways or the backend (identified by 
    client certificate), validates that the certificate is not revoked.
    """
    
    def __init__(self, app, extract_cert_serial_func=None):
        self.app = app
        self.extract_cert_serial = extract_cert_serial_func or self._default_extract_serial
    
    def _default_extract_serial(self, request: Request) -> Optional[str]:
        """
        Extract certificate serial from request.
        This can come from:
        1. TLS client certificate (mTLS)
        2. X-Certificate-Serial header (when behind reverse proxy)
        3. Custom header from authenticated request
        """
        # Try header first (for proxy setups)
        serial = request.headers.get("X-Certificate-Serial")
        if serial:
            return serial
        
        # Try to get from TLS info (uvicorn with ssl)
        # Note: This requires proper TLS configuration
        if hasattr(request, "scope"):
            tls_info = request.scope.get("tls", {})
            peer_cert = tls_info.get("peer_cert")
            if peer_cert and hasattr(peer_cert, "serial_number"):
                return format(peer_cert.serial_number, 'X')
        
        return None
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Refresh CRL periodically (every request for now, can be optimized)
            load_crl_from_disk()
            
            # Build a pseudo-request to extract serial
            # In production, this would come from actual mTLS
            request = Request(scope, receive)
            serial = self.extract_cert_serial(request)
            
            if serial and is_certificate_revoked(serial):
                logger.warning(f"BLOCKED: Request from revoked certificate {serial}")
                # Return 403 Forbidden for revoked certificates
                response = {
                    "detail": "Certificate has been revoked",
                    "error_code": "CERT_REVOKED",
                    "serial": serial
                }
                body = json.dumps(response).encode()
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"x-crl-enforcement", b"active"],
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": body,
                })
                return
        
        await self.app(scope, receive, send)


def enforce_crl(func):
    """
    Decorator for individual endpoints that need CRL enforcement.
    Use this when you can't use middleware (e.g., selective enforcement).
    
    Usage:
        @app.get("/some-endpoint")
        @enforce_crl
        async def some_endpoint(request: Request):
            ...
    """
    @wraps(func)
    async def wrapper(*args, request: Request = None, **kwargs):
        if request:
            serial = request.headers.get("X-Certificate-Serial")
            if serial and is_certificate_revoked(serial):
                logger.warning(f"BLOCKED by decorator: Request from revoked cert {serial}")
                raise HTTPException(
                    status_code=403,
                    detail="Certificate has been revoked",
                    headers={"X-CRL-Enforcement": "active"}
                )
        return await func(*args, request=request, **kwargs)
    return wrapper


# Load CRL on module import
load_crl_from_disk()

