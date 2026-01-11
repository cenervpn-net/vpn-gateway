"""
E2E Encryption Module for Gateway API
======================================
Implements X25519 ECDH key exchange with AES-256-GCM encryption for
zero-knowledge VPN configuration. Backend cannot decrypt client↔gateway traffic.

Security Properties:
- Forward secrecy via ephemeral client keys
- Backend is a blind relay (cannot compute shared secret)
- Constant-time operations (no timing attacks)
- Authenticated encryption (AES-GCM)
- Request-scoped state (no global context, thread-safe)

Protocol:
1. Client generates ephemeral X25519 keypair
2. Client computes shared_secret = X25519(eph_priv, gateway_pub)
3. Client derives AES key via HKDF(shared_secret, info="e2e-req")
4. Client encrypts config and sends (eph_pub, encrypted_blob) to backend
5. Backend relays blindly to gateway
6. Gateway computes same shared_secret = X25519(gateway_priv, eph_pub)
7. Gateway decrypts, processes, encrypts response with HKDF(shared, info="e2e-resp")
8. Backend relays encrypted response to client
9. Client decrypts with same derived key
"""

import os
import json
import base64
import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

logger = logging.getLogger(__name__)

# .env loading flag
_env_loaded = False


@dataclass
class E2EContext:
    """
    Per-request E2E encryption context.
    Stores shared secret for response encryption.
    Must be passed through request handling, NOT stored globally.
    """
    shared_secret: bytes
    ephemeral_pub: str


class E2ECrypto:
    """
    E2E Encryption handler using X25519 ECDH + AES-256-GCM
    
    Thread-safe: All state is passed explicitly, no globals.
    
    Usage:
        crypto = E2ECrypto(gateway_private_key_b64)
        config, ctx = crypto.decrypt_request(ephemeral_pub_b64, encrypted_blob)
        encrypted_response = crypto.encrypt_response(response, ctx)
    """
    
    def __init__(self, private_key_b64: str):
        """
        Initialize with gateway's X25519 private key
        
        Args:
            private_key_b64: Base64-encoded 32-byte private key
        """
        try:
            private_key_bytes = base64.b64decode(private_key_b64)
            if len(private_key_bytes) != 32:
                raise ValueError(f"Invalid private key length: {len(private_key_bytes)} (expected 32)")
            
            self._private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
            self._public_key = self._private_key.public_key()
            
            # Cache public key as base64
            public_bytes = self._public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self._public_key_b64 = base64.b64encode(public_bytes).decode()
            
            logger.info(f"E2E Crypto initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize E2E crypto: {e}")
            raise ValueError(f"Invalid ECDH private key: {e}")
    
    @property
    def public_key_b64(self) -> str:
        """Get gateway's X25519 public key (base64)"""
        return self._public_key_b64
    
    def compute_shared_secret(self, ephemeral_public_b64: str) -> bytes:
        """
        Compute ECDH shared secret from client's ephemeral public key
        
        Args:
            ephemeral_public_b64: Client's ephemeral X25519 public key (base64)
            
        Returns:
            32-byte shared secret
        """
        eph_pub_bytes = base64.b64decode(ephemeral_public_b64)
        if len(eph_pub_bytes) != 32:
            raise ValueError(f"Invalid ephemeral public key length: {len(eph_pub_bytes)}")
        
        eph_public = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        shared_secret = self._private_key.exchange(eph_public)
        
        return shared_secret
    
    def derive_key(self, shared_secret: bytes, info: bytes) -> bytes:
        """
        Derive AES-256 key from shared secret using HKDF
        
        Args:
            shared_secret: 32-byte ECDH shared secret
            info: Context info string (e.g., b"e2e-req" or b"e2e-resp")
            
        Returns:
            32-byte AES key
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',
            info=info,
        )
        return hkdf.derive(shared_secret)
    
    def decrypt_request(self, ephemeral_public_b64: str, encrypted_blob: str) -> Tuple[Dict[str, Any], E2EContext]:
        """
        Decrypt client's encrypted configuration request
        
        Args:
            ephemeral_public_b64: Client's ephemeral X25519 public key (base64)
            encrypted_blob: Base64-encoded (nonce || ciphertext || tag)
            
        Returns:
            Tuple of (decrypted config dict, E2EContext for response encryption)
        """
        # Compute shared secret
        shared_secret = self.compute_shared_secret(ephemeral_public_b64)
        
        # Create context for response encryption (returned, not stored globally!)
        ctx = E2EContext(
            shared_secret=shared_secret,
            ephemeral_pub=ephemeral_public_b64
        )
        
        # Derive request decryption key
        aes_key = self.derive_key(shared_secret, b'e2e-req')
        
        # Decode encrypted blob
        combined = base64.b64decode(encrypted_blob)
        if len(combined) < 12 + 16:  # nonce (12) + minimum ciphertext with tag
            raise ValueError("Encrypted blob too short")
        
        # Extract nonce (first 12 bytes) and ciphertext+tag
        nonce = combined[:12]
        ciphertext = combined[12:]
        
        # Decrypt
        aesgcm = AESGCM(aes_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            logger.error(f"E2E decryption failed: {e}")
            raise ValueError("Failed to decrypt request (invalid key or corrupted data)")
        
        # Parse JSON
        try:
            config = json.loads(plaintext.decode('utf-8'))
        except json.JSONDecodeError as e:
            logger.error(f"E2E decryption produced invalid JSON: {e}")
            raise ValueError("Decrypted data is not valid JSON")
        
        return config, ctx
    
    def encrypt_response(self, response_data: Dict[str, Any], ctx: E2EContext) -> str:
        """
        Encrypt response data for the client
        
        Args:
            response_data: Response dictionary to encrypt
            ctx: E2EContext from decrypt_request (contains shared secret)
            
        Returns:
            Base64-encoded encrypted response
        """
        # Derive response encryption key (different from request key!)
        aes_key = self.derive_key(ctx.shared_secret, b'e2e-resp')
        
        # Generate random nonce
        nonce = os.urandom(12)
        
        # Encrypt
        aesgcm = AESGCM(aes_key)
        plaintext = json.dumps(response_data).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Combine nonce + ciphertext and encode
        combined = nonce + ciphertext
        encrypted_b64 = base64.b64encode(combined).decode()
        
        return encrypted_b64


def get_e2e_crypto() -> Optional[E2ECrypto]:
    """
    Get E2E crypto instance from environment
    
    Returns:
        E2ECrypto instance if ECDH_PRIVATE_KEY is set, None otherwise
    """
    private_key = os.environ.get('ECDH_PRIVATE_KEY')
    if not private_key:
        logger.warning("ECDH_PRIVATE_KEY not set - E2E encryption disabled")
        return None
    
    try:
        return E2ECrypto(private_key)
    except Exception as e:
        logger.error(f"Failed to initialize E2E crypto: {e}")
        return None


# Singleton instance (thread-safe: instance is immutable after creation)
_e2e_crypto: Optional[E2ECrypto] = None


def init_e2e_crypto() -> Optional[E2ECrypto]:
    """Initialize and cache E2E crypto instance"""
    global _e2e_crypto, _env_loaded
    
    # Ensure .env is loaded (may not be loaded by systemd service)
    if not _env_loaded:
        env_file = Path(__file__).parent / '.env'
        if env_file.exists():
            load_dotenv(env_file)
        _env_loaded = True
    
    if _e2e_crypto is None:
        _e2e_crypto = get_e2e_crypto()
    return _e2e_crypto


def is_e2e_request(request_data: Dict[str, Any]) -> bool:
    """Check if request is E2E encrypted"""
    return 'eph_pub' in request_data and 'encrypted_blob' in request_data


def decrypt_e2e_request(request_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[E2EContext]]:
    """
    Attempt to decrypt E2E request
    
    Args:
        request_data: Request data that may contain E2E encryption
        
    Returns:
        Tuple of (decrypted_config, E2EContext or None)
        If not E2E, returns (request_data, None)
    """
    if not is_e2e_request(request_data):
        return request_data, None
    
    crypto = init_e2e_crypto()
    if not crypto:
        logger.warning("E2E request received but ECDH_PRIVATE_KEY not configured")
        raise ValueError("E2E encryption not configured on this gateway")
    
    eph_pub = request_data['eph_pub']
    encrypted_blob = request_data['encrypted_blob']
    
    config, ctx = crypto.decrypt_request(eph_pub, encrypted_blob)
    
    # Merge non-encrypted fields (public_key is sent in both places for routing)
    if 'public_key' in request_data:
        config['public_key'] = request_data['public_key']
    
    return config, ctx


def encrypt_e2e_response(response_data: Dict[str, Any], ctx: Optional[E2EContext] = None) -> Dict[str, Any]:
    """
    Encrypt response if E2E context exists
    
    Args:
        response_data: Response to encrypt
        ctx: E2EContext from decrypt_e2e_request
        
    Returns:
        {'encrypted_response': '...'} if E2E, or original response
    """
    if ctx is None:
        return response_data
    
    crypto = init_e2e_crypto()
    if not crypto:
        return response_data
    
    encrypted = crypto.encrypt_response(response_data, ctx)
    return {'encrypted_response': encrypted}
