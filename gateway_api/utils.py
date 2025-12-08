import base64
import json
import logging
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from typing import Dict, Any
from config import get_settings

logger = logging.getLogger(__name__)

# Global variables to store encryption context
_encryption_context = {
    "key": None,
    "last_iv": None
}

def decrypt_payload(encrypted_payload: str) -> Dict[str, Any]:
    """Decrypt the encrypted payload and save encryption context for response"""
    try:
        logger.debug(f"Decrypting payload of length: {len(encrypted_payload)}")
        
        # Get the Gateway's public key from settings
        settings = get_settings()
        gateway_public_key_b64 = settings.GATEWAY_PUBLIC_KEY
        
        if not gateway_public_key_b64:
            logger.warning("GATEWAY_PUBLIC_KEY not set, cannot decrypt payload")
            return {}
        
        logger.debug(f"Using Gateway public key: {gateway_public_key_b64[:10]}...")
        
        # Decode the base64 encrypted payload
        combined = base64.b64decode(encrypted_payload)
        
        # Extract IV (first 12 bytes) and ciphertext
        iv = combined[:12]
        ciphertext = combined[12:]
        
        logger.debug(f"IV length: {len(iv)}, Ciphertext length: {len(ciphertext)}")
        
        # Derive the same encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',
            info=b'handshake data',
        ).derive(gateway_public_key_b64.encode())
        
        logger.debug(f"Derived key length: {len(derived_key)}")
        
        # Save the encryption context for response
        _encryption_context["key"] = derived_key
        _encryption_context["last_iv"] = iv
        
        # Use AES-GCM for decryption
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(derived_key)
        
        try:
            # Decrypt the data
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            logger.debug(f"Successfully decrypted payload")
            
            # Parse the JSON data
            result = json.loads(plaintext.decode('utf-8'))
            logger.debug(f"Successfully parsed decrypted JSON: {result}")
            return result
            
        except Exception as e:
            logger.error(f"AES-GCM decryption failed: {str(e)}")
            raise ValueError(f"AES-GCM decryption failed: {str(e)}")
            
    except Exception as e:
        logger.error(f"Unexpected error during decryption: {str(e)}")
        # Return empty dict to allow fallback to direct parameters
        return {}

def encrypt_response(data: Dict[str, Any]) -> str:
    """Encrypt the response data using the same encryption context"""
    try:
        # Convert data to JSON string
        plaintext = json.dumps(data).encode('utf-8')
        
        # Check if we have a saved encryption context
        if _encryption_context["key"] is None:
            logger.warning("No encryption context available, generating new key")
            settings = get_settings()
            gateway_public_key_b64 = settings.GATEWAY_PUBLIC_KEY
            
            if not gateway_public_key_b64:
                logger.warning("GATEWAY_PUBLIC_KEY not set, returning unencrypted")
                return json.dumps(data)
                
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'',
                info=b'handshake data',
            ).derive(gateway_public_key_b64.encode())
        else:
            logger.debug("Using saved encryption context for response")
            derived_key = _encryption_context["key"]
        
        # Use AES-GCM for encryption
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(derived_key)
        
        # Generate a new IV (must be different from the request IV)
        if _encryption_context["last_iv"] is not None:
            # XOR the last IV with a constant to create a new one
            last_iv = _encryption_context["last_iv"]
            iv = bytes(a ^ b for a, b in zip(last_iv, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C'))
            logger.debug(f"Derived new IV from last IV")
        else:
            # Generate a random IV if no last IV is available
            iv = os.urandom(12)
            logger.debug(f"Generated random IV")
        
        # Encrypt the data
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        
        # Combine IV and ciphertext
        combined = iv + ciphertext
        
        # Return as base64
        return base64.b64encode(combined).decode('utf-8')
        
    except Exception as e:
        logger.error(f"Response encryption failed: {str(e)}")
        # Return original data if encryption fails
        return json.dumps(data)

