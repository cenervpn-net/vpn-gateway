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
    DNS_SERVERS: Dict[str, str] = {
        'd1': '1.1.1.1',    # Cloudflare
        'd2': '8.8.8.8',    # Google
        'd3': '9.9.9.9'     # Quad9
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
