from pydantic_settings import BaseSettings
from typing import Dict
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    # Security
    GATEWAY_API_KEY: str
    GATEWAY_PUBLIC_KEY: str = ""  # Optional for payload encryption/decryption
    MAX_TIMESTAMP_DIFF: int = 300  # 5 minutes

    # Network Configuration
    WG_IPV4_SUBNET: str = "10.0.1.0/24"
    WG_IPV6_SUBNET: str = "fd42:4242:1::/64"
    WG_DEFAULT_PORT: int = 51820

    # DNS Configuration
    # Internal DNS IPs (gateway-local Unbound) - set by provisioning
    # Falls back to external DNS if not configured
    DNS_D1: str = "1.1.1.1"     # Default: Cloudflare (overridden to 10.65.1.1 when DNS deployed)
    DNS_D2: str = "8.8.8.8"     # Default: Google (future: 10.65.1.2 with ad-blocking)
    DNS_D3: str = "9.9.9.9"     # Default: Quad9 (future: 10.65.1.3 with max blocking)
    
    @property
    def DNS_SERVERS(self) -> Dict[str, str]:
        """Dynamic DNS mapping that uses internal DNS when available"""
        return {
            'd1': self.DNS_D1,
            'd2': self.DNS_D2,
            'd3': self.DNS_D3
        }

    # RAM-only mode: No database - peers are stored in memory and recovered from mesh

    model_config = {
        "env_file": ".env",
        "extra": "allow"
    }

@lru_cache()
def get_settings():
    settings = Settings()
    logger.debug(f"Loaded settings: GATEWAY_PUBLIC_KEY exists: {bool(settings.GATEWAY_PUBLIC_KEY)}")
    return settings
